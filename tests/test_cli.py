from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcpmap import __version__
from mcpmap.cli import app

runner = CliRunner()

_DANGEROUS = json.dumps({
    "mcpServers": {
        "bash": {
            "command": "npx",
            "args": ["-y", "@anthropic-ai/mcp-server-bash"],
            "env": {"API_KEY": "sk-test"},
        }
    }
})

_SAFE = json.dumps({
    "mcpServers": {
        "docs": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0", "/workspace/docs"],
            "env": {},
        }
    }
})


@pytest.fixture()
def dangerous_cfg(tmp_path) -> Path:
    p = tmp_path / "dangerous.json"
    p.write_text(_DANGEROUS, encoding="utf-8")
    return p


@pytest.fixture()
def safe_cfg(tmp_path) -> Path:
    p = tmp_path / "safe.json"
    p.write_text(_SAFE, encoding="utf-8")
    return p


# ── --version ─────────────────────────────────────────────────────────────────

class TestVersion:
    def test_version_long_flag(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.output

    def test_version_short_flag(self):
        result = runner.invoke(app, ["-V"])
        assert result.exit_code == 0
        assert __version__ in result.output


# ── scan — exit codes ─────────────────────────────────────────────────────────

class TestScanExitCodes:
    def test_exits_0_without_fail_on(self, dangerous_cfg):
        result = runner.invoke(app, ["scan", str(dangerous_cfg)])
        assert result.exit_code == 0

    def test_exits_0_on_safe_config(self, safe_cfg):
        result = runner.invoke(app, ["scan", str(safe_cfg)])
        assert result.exit_code == 0

    def test_exits_1_when_fail_on_threshold_met(self, dangerous_cfg):
        result = runner.invoke(app, ["scan", str(dangerous_cfg), "--fail-on", "CRITICAL"])
        assert result.exit_code == 1

    def test_exits_1_when_fail_on_lower_severity(self, dangerous_cfg):
        result = runner.invoke(app, ["scan", str(dangerous_cfg), "--fail-on", "HIGH"])
        assert result.exit_code == 1

    def test_exits_0_when_fail_on_not_triggered(self, safe_cfg):
        result = runner.invoke(app, ["scan", str(safe_cfg), "--fail-on", "HIGH"])
        assert result.exit_code == 0

    def test_exits_1_for_invalid_fail_on(self, dangerous_cfg):
        result = runner.invoke(app, ["scan", str(dangerous_cfg), "--fail-on", "EXTREME"])
        assert result.exit_code == 1

    def test_exits_2_for_nonexistent_target(self, tmp_path):
        result = runner.invoke(app, ["scan", str(tmp_path / "missing.json")])
        assert result.exit_code == 2

    def test_exits_2_for_missing_rules_file(self, dangerous_cfg, tmp_path):
        result = runner.invoke(app, ["scan", str(dangerous_cfg), "--rules", str(tmp_path / "no.yaml")])
        assert result.exit_code == 2

    def test_exits_2_for_invalid_rules_file(self, dangerous_cfg, tmp_path):
        bad = tmp_path / "bad_rules.yaml"
        bad.write_text("rules:\n  - id: X\n    name: broken\n", encoding="utf-8")
        result = runner.invoke(app, ["scan", str(dangerous_cfg), "--rules", str(bad)])
        assert result.exit_code == 2

    def test_exits_2_for_unwritable_output_path(self, dangerous_cfg, tmp_path):
        bad_out = tmp_path / "no_dir" / "report.md"
        result = runner.invoke(app, ["scan", str(dangerous_cfg), "--output", str(bad_out)])
        assert result.exit_code == 2

    def test_fail_on_case_insensitive(self, dangerous_cfg):
        result = runner.invoke(app, ["scan", str(dangerous_cfg), "--fail-on", "critical"])
        assert result.exit_code == 1


# ── scan — output formats (stdout capture via print()) ───────────────────────

class TestScanOutputFormats:
    def test_markdown_contains_rule_id(self, dangerous_cfg):
        result = runner.invoke(app, ["scan", str(dangerous_cfg), "--format", "markdown"])
        assert result.exit_code == 0
        assert "MCM-001" in result.output

    def test_markdown_ascii_mode(self, dangerous_cfg):
        result = runner.invoke(app, ["scan", str(dangerous_cfg), "--format", "markdown", "--ascii"])
        assert result.exit_code == 0
        assert "shields.io" not in result.output

    def test_json_is_valid_json(self, dangerous_cfg):
        result = runner.invoke(app, ["scan", str(dangerous_cfg), "--format", "json"])
        assert result.exit_code == 0
        # output contains both the JSON (from print()) and Rich console table
        # extract the JSON portion — it starts with '['
        json_start = result.output.index("[")
        data = json.loads(result.output[json_start:result.output.rindex("]") + 1])
        assert len(data[0]["findings"]) > 0

    def test_sarif_is_valid_json(self, dangerous_cfg):
        result = runner.invoke(app, ["scan", str(dangerous_cfg), "--format", "sarif"])
        assert result.exit_code == 0
        sarif_start = result.output.index("{")
        # Find matching closing brace for the top-level object
        depth = 0
        sarif_end = sarif_start
        for i, ch in enumerate(result.output[sarif_start:], sarif_start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    sarif_end = i + 1
                    break
        data = json.loads(result.output[sarif_start:sarif_end])
        assert data["version"] == "2.1.0"

    def test_html_written_to_output_file(self, dangerous_cfg, tmp_path):
        out = tmp_path / "report.html"
        result = runner.invoke(app, ["scan", str(dangerous_cfg), "--format", "html", "--output", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "MCM-001" in content

    def test_html_default_filename(self, dangerous_cfg, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["scan", str(dangerous_cfg), "--format", "html"])
        assert result.exit_code == 0
        assert (tmp_path / "mcpmap_report.html").exists()

    def test_output_to_file(self, dangerous_cfg, tmp_path):
        out = tmp_path / "report.md"
        result = runner.invoke(app, ["scan", str(dangerous_cfg), "--output", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        assert "MCM-001" in out.read_text(encoding="utf-8")


# ── scan — flags ──────────────────────────────────────────────────────────────

class TestScanFlags:
    def test_summary_flag_exits_0(self, dangerous_cfg):
        result = runner.invoke(app, ["scan", str(dangerous_cfg), "--summary"])
        assert result.exit_code == 0

    def test_summary_with_fail_on_exits_1(self, dangerous_cfg):
        result = runner.invoke(app, ["scan", str(dangerous_cfg), "--summary", "--fail-on", "CRITICAL"])
        assert result.exit_code == 1

    def test_directory_scan(self, tmp_path, dangerous_cfg):
        result = runner.invoke(app, ["scan", str(tmp_path)])
        assert result.exit_code == 0

    def test_multiple_targets(self, dangerous_cfg, safe_cfg):
        result = runner.invoke(app, ["scan", str(dangerous_cfg), str(safe_cfg)])
        assert result.exit_code == 0

    def test_skipped_bad_json_does_not_crash(self, tmp_path, dangerous_cfg):
        bad = tmp_path / "bad.json"
        bad.write_text("{broken", encoding="utf-8")
        # dangerous_cfg is in a different tmp_path, scan the directory with both
        good = tmp_path / "good.json"
        good.write_text(_DANGEROUS, encoding="utf-8")
        result = runner.invoke(app, ["scan", str(tmp_path)])
        assert result.exit_code == 0

    def test_empty_directory_exits_0(self, tmp_path):
        result = runner.invoke(app, ["scan", str(tmp_path)])
        assert result.exit_code == 0

    def test_custom_rules_file(self, dangerous_cfg, tmp_path):
        rules = tmp_path / "rules.yaml"
        rules.write_text(
            "rules:\n"
            "  - id: CUSTOM-001\n"
            "    name: Custom Shell Rule\n"
            "    description: Detects bash.\n"
            "    severity: CRITICAL\n"
            "    category: Excessive Agency\n"
            "    remediation: Remove it.\n"
            "    detection:\n"
            "      server_name_patterns:\n"
            "        - bash\n",
            encoding="utf-8",
        )
        result = runner.invoke(app, ["scan", str(dangerous_cfg), "--rules", str(rules), "--format", "json"])
        assert result.exit_code == 0
        json_start = result.output.index("[")
        data = json.loads(result.output[json_start:result.output.rindex("]") + 1])
        rule_ids = [f["rule_id"] for f in data[0]["findings"]]
        assert "CUSTOM-001" in rule_ids
        assert "MCM-001" not in rule_ids


# ── rules command ─────────────────────────────────────────────────────────────

class TestRulesCommand:
    def test_lists_builtin_rules(self):
        result = runner.invoke(app, ["rules"])
        assert result.exit_code == 0
        assert "MCM-001" in result.output
        assert "MCM-019" in result.output

    def test_shows_all_severity_levels(self):
        result = runner.invoke(app, ["rules"])
        assert result.exit_code == 0
        assert "CRITICAL" in result.output
        assert "HIGH" in result.output
        assert "MEDIUM" in result.output
        assert "LOW" in result.output

    def test_shows_rule_count(self):
        result = runner.invoke(app, ["rules"])
        assert result.exit_code == 0
        assert "24 rules loaded" in result.output

    def test_custom_rules_file(self, tmp_path):
        rules_file = tmp_path / "custom.yaml"
        rules_file.write_text(
            "rules:\n"
            "  - id: CUSTOM-001\n"
            "    name: My Rule\n"
            "    description: A custom rule.\n"
            "    severity: HIGH\n"
            "    category: Excessive Agency\n"
            "    remediation: Fix it.\n"
            "    detection:\n"
            "      server_name_patterns:\n"
            "        - dangerous\n",
            encoding="utf-8",
        )
        result = runner.invoke(app, ["rules", "--rules", str(rules_file)])
        assert result.exit_code == 0
        assert "CUSTOM-001" in result.output
        assert "MCM-001" not in result.output
        assert "1 rule loaded" in result.output

    def test_exits_2_for_missing_rules_file(self, tmp_path):
        result = runner.invoke(app, ["rules", "--rules", str(tmp_path / "missing.yaml")])
        assert result.exit_code == 2

    def test_exits_2_for_invalid_rules_file(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("rules:\n  - id: X\n    name: broken\n", encoding="utf-8")
        result = runner.invoke(app, ["rules", "--rules", str(bad)])
        assert result.exit_code == 2


# ── find command ──────────────────────────────────────────────────────────────

class TestFindCommand:
    def test_exits_0(self):
        result = runner.invoke(app, ["find"])
        assert result.exit_code == 0

    def test_output_contains_path_fragment(self):
        result = runner.invoke(app, ["find"])
        assert result.exit_code == 0
        assert "claude_desktop_config.json" in result.output

    def test_shows_found_or_not_found(self):
        result = runner.invoke(app, ["find"])
        assert result.exit_code == 0
        assert ("found" in result.output) or ("not found" in result.output) or ("No Claude Desktop" in result.output)
