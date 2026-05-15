from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from mcpmap.models import Finding

DEFAULT_IGNORE_FILENAME = ".mcpmap-ignore"


@dataclass
class Suppression:
    rule_id: str   # rule ID to suppress; "*" matches all rules
    server: str    # server name to target; "*" matches all servers
    reason: str = ""


def load_suppressions(path: Path) -> list[Suppression]:
    """Parse a .mcpmap-ignore file into a list of Suppression entries.

    Format (one rule per line):
        RULE_ID                 suppress this rule everywhere
        RULE_ID:server_name     suppress only for the named server
        *:server_name           suppress all rules for the named server
        # comment lines and blank lines are ignored
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []

    suppressions: list[Suppression] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(":", 1)
        rule_id = parts[0].strip().upper()
        server = parts[1].strip() if len(parts) > 1 else "*"
        if rule_id:
            suppressions.append(Suppression(rule_id=rule_id, server=server))

    return suppressions


def _server_name_from_location(location: str) -> str:
    for segment in location.split(" > "):
        if segment.startswith("server:"):
            return segment[len("server:"):]
    return ""


def apply_suppressions(
    findings: list[Finding],
    suppressions: list[Suppression],
) -> list[Finding]:
    """Mark findings as suppressed in-place. Returns the same list."""
    if not suppressions:
        return findings

    for finding in findings:
        if finding.suppressed:
            continue
        server_name = _server_name_from_location(finding.location)
        for supp in suppressions:
            rule_match = supp.rule_id == "*" or supp.rule_id == finding.rule_id
            server_match = supp.server == "*" or supp.server == server_name
            if rule_match and server_match:
                finding.suppressed = True
                finding.suppression_reason = supp.reason
                break

    return findings


def find_ignore_file(targets: list[str]) -> Path | None:
    """Look for .mcpmap-ignore adjacent to the first target, then in CWD."""
    import os
    if targets:
        candidate = Path(targets[0])
        adjacent = (candidate.parent if candidate.is_file() else candidate) / DEFAULT_IGNORE_FILENAME
        if adjacent.exists():
            return adjacent
    cwd_candidate = Path(os.getcwd()) / DEFAULT_IGNORE_FILENAME
    if cwd_candidate.exists():
        return cwd_candidate
    return None
