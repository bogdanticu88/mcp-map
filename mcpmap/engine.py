from __future__ import annotations

import json
import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from mcpmap.models import (
    AnalysisResult,
    Finding,
    MitreAtlasRef,
    OwaspLLMRef,
    RuleDefinition,
    Severity,
    SEVERITY_ORDER,
)
from mcpmap.parsers.base import ParsedAgent, ParsedServer, ParsedTool
from mcpmap.parsers.mcp_config import MCPConfigParser
from mcpmap.parsers.openai_tools import OpenAIToolsParser


_PARSERS = [MCPConfigParser(), OpenAIToolsParser()]

_HIGH_RISK_RULES = {
    "MCM-001", "MCM-002", "MCM-003", "MCM-004",
    "MCM-005", "MCM-006", "MCM-007", "MCM-008", "MCM-009", "MCM-010", "MCM-011",
    "MCM-020", "MCM-021", "MCM-022", "MCM-024",
}

_DEFAULT_RULES_PATH = Path(__file__).parent / "mcpmap_rules.yaml"

_VERSION_PIN_RE = re.compile(r"@\d+[\.\d]*")
_REMEDIATION_PATH_RE = re.compile(r"argument '([^']+)' is a broad")
_REMEDIATION_ENVKEY_RE = re.compile(r"environment variable '([^']+)'")
_REMEDIATION_ENTROPY_RE = re.compile(r"env var '([^']+)'")


class RulesLoadError(Exception):
    pass


class TargetNotFoundError(Exception):
    pass


# ── Rule loading ──────────────────────────────────────────────────────────────

def _load_rules(rules_path: Path | None = None) -> list[RuleDefinition]:
    path = rules_path or _DEFAULT_RULES_PATH
    try:
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except OSError as exc:
        raise RulesLoadError(f"Cannot read rules file {path}: {exc}")
    except yaml.YAMLError as exc:
        raise RulesLoadError(f"Rules file is not valid YAML: {path}: {exc}")

    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise RulesLoadError(
            f"Rules file {path}: expected a YAML mapping at the top level, got {type(raw).__name__}"
        )

    raw_rules = raw.get("rules", [])
    if not isinstance(raw_rules, list):
        raise RulesLoadError(
            f"Rules file {path}: 'rules' must be a list, got {type(raw_rules).__name__}"
        )

    rules = []
    for i, r in enumerate(raw_rules):
        try:
            owasp = [OwaspLLMRef(**o) for o in r.get("owasp_llm", [])]
            atlas = [MitreAtlasRef(**a) for a in r.get("mitre_atlas", [])]
            rules.append(RuleDefinition(
                id=r["id"],
                name=r["name"],
                description=r["description"].strip(),
                severity=Severity(r["severity"]),
                category=r["category"],
                owasp_llm=owasp,
                mitre_atlas=atlas,
                remediation=r["remediation"].strip(),
                detection=r.get("detection", {}),
            ))
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            rule_id = r.get("id", f"index {i}") if isinstance(r, dict) else f"index {i}"
            raise RulesLoadError(f"Invalid rule {rule_id} in {path}: {exc}")
    return rules


# ── Pattern matching helpers ──────────────────────────────────────────────────

def _matches_any(text: str, patterns: list[str]) -> str:
    text_lower = text.lower()
    for p in patterns:
        if p.lower() in text_lower:
            return p
    return ""


def _matches_path(arg: str, patterns: list[str]) -> str:
    """Exact or subdirectory-prefix match for filesystem path patterns.

    Strips trailing separators before comparing. Skips prefix matching when the
    normalised pattern is empty (the bare '/' root) so that legitimate project
    paths like '/workspace/docs' are not flagged — only the literal string '/'
    is treated as a broad-path match.
    """
    arg_norm = arg.rstrip("/\\").lower()
    for p in patterns:
        p_norm = p.rstrip("/\\").lower()
        if arg_norm == p_norm:
            return p
        if p_norm and (
            arg_norm.startswith(p_norm + "/") or arg_norm.startswith(p_norm + "\\")
        ):
            return p
    return ""


# ── New detection helpers ─────────────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _is_high_entropy_secret(value: str, threshold: float, min_length: int) -> bool:
    if len(value) < min_length:
        return False
    low = value.lower()
    if low in ("true", "false", "yes", "no", "1", "0", "null", "none", ""):
        return False
    if value.startswith(("http://", "https://", "ftp://", "/", "~")):
        return False
    # Windows paths and env-var references are not secrets
    if re.match(r"^[A-Za-z]:[/\\]", value) or value.startswith("%"):
        return False
    return _shannon_entropy(value) >= threshold


def _is_unpinned(server: ParsedServer) -> bool:
    if server.command not in ("npx", "uvx", "bunx"):
        return False
    if not any(a in ("-y", "--yes") for a in server.args):
        return False
    for arg in server.args:
        if not arg.startswith("-") and _VERSION_PIN_RE.search(arg):
            return False
    return True


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    prev = list(range(lb + 1))
    for ca in a:
        curr = [prev[0] + 1]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (0 if ca == cb else 1)))
        prev = curr
    return prev[lb]


# ── Per-rule detection ────────────────────────────────────────────────────────

def _check_server(server: ParsedServer, rule: RuleDefinition) -> str:
    det = rule.detection

    if hit := _matches_any(server.name, det.get("server_name_patterns", [])):
        return f"server name '{server.name}' matches pattern '{hit}'"
    if hit := _matches_any(server.package, det.get("package_patterns", [])):
        return f"package '{server.package}' matches pattern '{hit}'"
    for arg in server.args:
        if _matches_path(arg, det.get("broad_path_patterns", [])):
            return f"argument '{arg}' is a broad filesystem path"
        if hit := _matches_any(arg, det.get("sensitive_path_patterns", [])):
            return f"argument '{arg}' references sensitive path '{hit}'"
    for env_key in server.env:
        if hit := _matches_any(env_key, det.get("env_key_patterns", [])):
            return f"environment variable '{env_key}' matches secret pattern '{hit}'"

    # Unpinned package version
    if det.get("check_unpinned_package") and _is_unpinned(server):
        pkg = server.package or "?"
        return (
            f"'{server.command} -y {pkg}' uses no version pin — "
            "the package can be silently updated between runs"
        )

    # Remote server
    if det.get("check_remote_server") and server.is_remote:
        return f"server '{server.name}' connects to remote endpoint: {server.url}"

    # High-entropy env values
    threshold = det.get("env_value_entropy_threshold")
    if threshold is not None:
        min_len = det.get("env_value_min_length", 20)
        for key, value in server.env.items():
            if _is_high_entropy_secret(value, threshold, min_len):
                ent = _shannon_entropy(value)
                return (
                    f"env var '{key}' has a high-entropy value "
                    f"(Shannon entropy {ent:.1f} bits/char) — likely a hardcoded secret"
                )

    return ""


def _check_tool(tool: ParsedTool, rule: RuleDefinition) -> str:
    det = rule.detection

    if det.get("check_empty_description") and not tool.description.strip():
        return f"tool '{tool.name}' has no description"
    if hit := _matches_any(tool.name, det.get("tool_name_patterns", [])):
        return f"tool name '{tool.name}' matches pattern '{hit}'"
    if hit := _matches_any(tool.description, det.get("tool_description_keywords", [])):
        return f"tool '{tool.name}' description contains '{hit}'"

    # Adversarial injection patterns
    for pattern in det.get("description_injection_patterns", []):
        if pattern.lower() in tool.description.lower():
            return f"tool '{tool.name}' description contains adversarial pattern: '{pattern}'"

    props = tool.parameters.get("properties", {}) if isinstance(tool.parameters, dict) else {}
    for param in props:
        if hit := _matches_any(param, det.get("parameter_names", [])):
            return f"tool '{tool.name}' has parameter '{param}' matching '{hit}'"

    return ""


def _check_supply_chain(server: ParsedServer, all_findings: list[Finding], rule: RuleDefinition) -> str:
    if rule.id == "MCM-014":
        pkg = server.package
        if not pkg:
            return ""
        trusted = rule.detection.get("trusted_package_prefixes", [])
        for prefix in trusted:
            if pkg.startswith(prefix):
                return ""
        if "/" in pkg or pkg.startswith("@"):
            return f"server '{server.name}' uses third-party package '{pkg}' from an unverified source"
        return ""

    if rule.id == "MCM-024":
        pkg = server.package
        if not pkg:
            return ""
        trusted = rule.detection.get("trusted_package_prefixes", [])
        max_dist = rule.detection.get("typosquatting_distance", 2)
        # Skip if already an exact match to a trusted prefix
        for prefix in trusted:
            if pkg.startswith(prefix):
                return ""
        # Only check scoped packages
        if "/" not in pkg and not pkg.startswith("@"):
            return ""
        pkg_scope = pkg.split("/")[0]
        for prefix in trusted:
            prefix_scope = prefix.rstrip("/").split("/")[0]
            if not prefix_scope:
                continue
            dist = _levenshtein(pkg_scope.lower(), prefix_scope.lower())
            if 0 < dist <= max_dist:
                return (
                    f"package scope '{pkg_scope}' is {dist} edit(s) from trusted "
                    f"'{prefix_scope}' — possible typosquatting"
                )
        return ""

    return ""


def _check_overprivileged(server: ParsedServer, all_findings: list[Finding], rule: RuleDefinition) -> str:
    if rule.id != "MCM-012":
        return ""
    threshold = rule.detection.get("high_risk_tool_threshold", 5)
    server_tag = f"server:{server.name}"
    high_risk_count = sum(
        1 for f in all_findings
        if server_tag in f.location.split(" > ") and f.rule_id in _HIGH_RISK_RULES
    )
    if high_risk_count >= threshold:
        return f"server '{server.name}' has {high_risk_count} high-risk capability findings"
    return ""


# ── Context-aware remediation ─────────────────────────────────────────────────

def _format_remediation(rule: RuleDefinition, evidence: str) -> str:
    """Augment static remediation text with context extracted from the evidence."""
    base = rule.remediation

    if rule.id == "MCM-011":
        m = _REMEDIATION_PATH_RE.search(evidence)
        if m:
            path = m.group(1)
            return (
                f"'{path}' exposes its entire directory tree to the agent. "
                f"Replace it with a project-specific subdirectory "
                f"(e.g. '{path}/your_project'). {base}"
            )

    elif rule.id == "MCM-010":
        m = _REMEDIATION_ENVKEY_RE.search(evidence)
        if m:
            key = m.group(1)
            return (
                f"Move '{key}' out of the config file. "
                f"Use a secrets manager, OS keychain, or shell variable so the "
                f"secret is never written to disk or committed to version control. {base}"
            )

    elif rule.id == "MCM-022":
        m = _REMEDIATION_ENTROPY_RE.search(evidence)
        if m:
            key = m.group(1)
            return (
                f"The value of '{key}' appears to be a secret. "
                f"Move it to a secrets manager or OS keychain "
                f"and reference it as an environment variable at runtime. {base}"
            )

    elif rule.id == "MCM-020":
        pkg_match = re.search(r"'npx -y ([^']+)'", evidence) or \
                    re.search(r"'uvx -y ([^']+)'", evidence) or \
                    re.search(r"'bunx -y ([^']+)'", evidence)
        if pkg_match:
            pkg = pkg_match.group(1)
            return (
                f"Pin '{pkg}' to a specific version in args "
                f"(e.g. '{pkg}@1.2.3'). {base}"
            )

    return base


# ── Finding factory ───────────────────────────────────────────────────────────

def _make_finding(rule: RuleDefinition, location: str, evidence: str) -> Finding:
    return Finding(
        rule_id=rule.id,
        rule_name=rule.name,
        severity=rule.severity,
        category=rule.category,
        description=rule.description,
        remediation=_format_remediation(rule, evidence),
        owasp_llm=rule.owasp_llm,
        mitre_atlas=rule.mitre_atlas,
        location=location,
        evidence=evidence,
    )


# ── Core analysis ─────────────────────────────────────────────────────────────

def analyze_agent(agent: ParsedAgent, rules: list[RuleDefinition]) -> list[Finding]:
    findings: list[Finding] = []

    for rule in rules:
        if rule.id == "MCM-012":
            continue

        for server in agent.servers:
            location = f"{agent.source_path} > server:{server.name}"

            evidence = _check_server(server, rule)
            if evidence:
                findings.append(_make_finding(rule, location, evidence))
                continue

            if rule.id in ("MCM-014", "MCM-024"):
                evidence = _check_supply_chain(server, findings, rule)
                if evidence:
                    findings.append(_make_finding(rule, location, evidence))

            for tool in server.tools:
                evidence = _check_tool(tool, rule)
                if evidence:
                    findings.append(_make_finding(
                        rule,
                        f"{agent.source_path} > server:{server.name} > tool:{tool.name}",
                        evidence,
                    ))

    overprivileged_rule = next((r for r in rules if r.id == "MCM-012"), None)
    if overprivileged_rule:
        for server in agent.servers:
            evidence = _check_overprivileged(server, findings, overprivileged_rule)
            if evidence:
                findings.append(_make_finding(
                    overprivileged_rule,
                    f"{agent.source_path} > server:{server.name}",
                    evidence,
                ))

    seen: set[str] = set()
    unique: list[Finding] = []
    for f in findings:
        key = f"{f.rule_id}|{f.location}"
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return sorted(unique, key=lambda f: SEVERITY_ORDER[f.severity], reverse=True)


def load_file(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        content = fh.read()
    if path.endswith((".yaml", ".yml")):
        return yaml.safe_load(content) or {}
    return json.loads(content)


def scan_path(
    target: str,
    rules_path: Path | None = None,
    fail_on: Severity | None = None,
) -> tuple[list[AnalysisResult], bool, list[tuple[str, str]]]:
    # Let RulesLoadError propagate — it's always a fatal misconfiguration.
    rules = _load_rules(rules_path)

    if not os.path.exists(target):
        raise TargetNotFoundError(f"Target not found: {target}")

    results: list[AnalysisResult] = []
    skipped: list[tuple[str, str]] = []

    paths: list[str] = []
    if os.path.isfile(target):
        paths = [target]
    else:
        for root, _, files in os.walk(target):
            for fname in files:
                if fname.endswith((".json", ".yaml", ".yml")):
                    paths.append(os.path.join(root, fname))

    for p in paths:
        try:
            data = load_file(p)
        except (json.JSONDecodeError, yaml.YAMLError, UnicodeDecodeError) as exc:
            skipped.append((p, f"parse error: {exc}"))
            continue
        except OSError as exc:
            skipped.append((p, f"read error: {exc}"))
            continue

        if not isinstance(data, dict):
            continue

        agent: ParsedAgent | None = None
        for parser in _PARSERS:
            if parser.can_parse(data, p):
                agent = parser.parse(data, p)
                break

        if agent is None:
            continue

        findings = analyze_agent(agent, rules)
        result = AnalysisResult(
            target=p,
            format=agent.format,
            findings=findings,
        )
        result.compute_stats()
        results.append(result)

    failed = False
    if fail_on and results:
        threshold = SEVERITY_ORDER[fail_on]
        for result in results:
            for f in result.findings:
                if SEVERITY_ORDER[f.severity] >= threshold:
                    failed = True
                    break

    return results, failed, skipped
