from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcpmap.engine import scan_path
from mcpmap.models import Finding, Severity
from mcpmap.suppression import (
    Suppression,
    apply_suppressions,
    find_ignore_file,
    load_suppressions,
)


def _finding(rule_id: str, server: str = "bash", target: str = "config.json") -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_name="Test Rule",
        severity=Severity.HIGH,
        category="Test",
        description="desc",
        remediation="fix it",
        location=f"{target} > server:{server}",
        evidence="test evidence",
    )


# ── load_suppressions ─────────────────────────────────────────────────────────

class TestLoadSuppressions:
    def test_load_rule_only(self, tmp_path):
        f = tmp_path / ".mcpmap-ignore"
        f.write_text("MCM-014\n")
        result = load_suppressions(f)
        assert len(result) == 1
        assert result[0].rule_id == "MCM-014"
        assert result[0].server == "*"

    def test_load_rule_with_server(self, tmp_path):
        f = tmp_path / ".mcpmap-ignore"
        f.write_text("MCM-010:bash\n")
        result = load_suppressions(f)
        assert result[0].rule_id == "MCM-010"
        assert result[0].server == "bash"

    def test_load_wildcard_server(self, tmp_path):
        f = tmp_path / ".mcpmap-ignore"
        f.write_text("*:legacy-server\n")
        result = load_suppressions(f)
        assert result[0].rule_id == "*"
        assert result[0].server == "legacy-server"

    def test_comments_and_blank_lines_ignored(self, tmp_path):
        f = tmp_path / ".mcpmap-ignore"
        f.write_text("# this is a comment\n\nMCM-001\n  # another comment\nMCM-002\n")
        result = load_suppressions(f)
        assert len(result) == 2
        assert {s.rule_id for s in result} == {"MCM-001", "MCM-002"}

    def test_case_normalised_to_upper(self, tmp_path):
        f = tmp_path / ".mcpmap-ignore"
        f.write_text("mcm-014\n")
        result = load_suppressions(f)
        assert result[0].rule_id == "MCM-014"

    def test_missing_file_returns_empty(self, tmp_path):
        result = load_suppressions(tmp_path / "nonexistent.ignore")
        assert result == []

    def test_inline_comment_stripped(self, tmp_path):
        f = tmp_path / ".mcpmap-ignore"
        f.write_text("MCM-014  # we audited this server\n")
        result = load_suppressions(f)
        assert result[0].rule_id == "MCM-014"


# ── apply_suppressions ────────────────────────────────────────────────────────

class TestApplySuppressions:
    def test_suppress_by_rule_id(self):
        findings = [_finding("MCM-014"), _finding("MCM-001")]
        apply_suppressions(findings, [Suppression(rule_id="MCM-014", server="*")])
        assert findings[0].suppressed is True
        assert findings[1].suppressed is False

    def test_suppress_by_rule_and_server(self):
        findings = [_finding("MCM-010", server="bash"), _finding("MCM-010", server="other")]
        apply_suppressions(findings, [Suppression(rule_id="MCM-010", server="bash")])
        assert findings[0].suppressed is True
        assert findings[1].suppressed is False

    def test_wildcard_rule_suppresses_all(self):
        findings = [_finding("MCM-001", "evil"), _finding("MCM-014", "evil"), _finding("MCM-001", "good")]
        apply_suppressions(findings, [Suppression(rule_id="*", server="evil")])
        assert findings[0].suppressed is True
        assert findings[1].suppressed is True
        assert findings[2].suppressed is False

    def test_no_suppressions_leaves_findings_intact(self):
        findings = [_finding("MCM-001")]
        apply_suppressions(findings, [])
        assert findings[0].suppressed is False

    def test_already_suppressed_not_overwritten(self):
        f = _finding("MCM-001")
        f.suppressed = True
        apply_suppressions([f], [Suppression(rule_id="MCM-002", server="*")])
        assert f.suppressed is True


# ── find_ignore_file ──────────────────────────────────────────────────────────

class TestFindIgnoreFile:
    def test_finds_adjacent_to_target_file(self, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text("{}")
        ignore = tmp_path / ".mcpmap-ignore"
        ignore.write_text("MCM-014\n")
        result = find_ignore_file([str(cfg)])
        assert result == ignore

    def test_returns_none_when_not_found(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = find_ignore_file([str(tmp_path / "nonexistent.json")])
        assert result is None


# ── Integration: suppression applied during scan ──────────────────────────────

class TestSuppressionIntegration:
    def test_scan_with_ignore_file_suppresses_finding(self, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({
            "mcpServers": {
                "bash": {
                    "command": "npx",
                    "args": ["-y", "@anthropic-ai/mcp-server-bash"],
                    "env": {"API_KEY": "sk-test"},
                }
            }
        }))
        ignore = tmp_path / ".mcpmap-ignore"
        ignore.write_text("MCM-001\n")

        results, _, _ = scan_path(str(cfg))
        from mcpmap.suppression import load_suppressions, apply_suppressions
        supps = load_suppressions(ignore)
        for r in results:
            apply_suppressions(r.findings, supps)

        suppressed_ids = {f.rule_id for r in results for f in r.findings if f.suppressed}
        assert "MCM-001" in suppressed_ids
        active_ids = {f.rule_id for r in results for f in r.findings if not f.suppressed}
        assert "MCM-001" not in active_ids
