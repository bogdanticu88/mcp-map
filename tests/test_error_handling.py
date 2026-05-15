import json
import os
import tempfile
import pytest
from mcpmap.engine import _load_rules, scan_path, RulesLoadError, TargetNotFoundError


class TestLoadRules:
    def test_missing_rules_file_raises(self, tmp_path):
        with pytest.raises(RulesLoadError, match="Cannot read"):
            _load_rules(tmp_path / "nonexistent.yaml")

    def test_invalid_yaml_raises(self, tmp_path):
        bad = tmp_path / "rules.yaml"
        bad.write_text("rules:\n  - ][invalid yaml", encoding="utf-8")
        with pytest.raises(RulesLoadError, match="not valid YAML"):
            _load_rules(bad)

    def test_empty_rules_file_returns_empty_list(self, tmp_path):
        empty = tmp_path / "rules.yaml"
        empty.write_text("", encoding="utf-8")
        assert _load_rules(empty) == []

    def test_rule_missing_required_field_raises(self, tmp_path):
        bad = tmp_path / "rules.yaml"
        bad.write_text(
            "rules:\n  - id: X001\n    name: Missing fields\n",
            encoding="utf-8",
        )
        with pytest.raises(RulesLoadError, match="Invalid rule"):
            _load_rules(bad)

    def test_rule_invalid_severity_raises(self, tmp_path):
        bad = tmp_path / "rules.yaml"
        bad.write_text(
            "rules:\n"
            "  - id: X001\n"
            "    name: Bad severity\n"
            "    description: desc\n"
            "    severity: EXTREME\n"
            "    category: Test\n"
            "    remediation: fix it\n",
            encoding="utf-8",
        )
        with pytest.raises(RulesLoadError, match="Invalid rule"):
            _load_rules(bad)

    def test_rules_value_not_a_list_raises(self, tmp_path):
        bad = tmp_path / "rules.yaml"
        bad.write_text("rules: not-a-list\n", encoding="utf-8")
        with pytest.raises(RulesLoadError, match="must be a list"):
            _load_rules(bad)

    def test_yaml_top_level_list_raises(self, tmp_path):
        bad = tmp_path / "rules.yaml"
        bad.write_text("- item1\n- item2\n", encoding="utf-8")
        with pytest.raises(RulesLoadError, match="expected a YAML mapping"):
            _load_rules(bad)

    def test_default_rules_load_successfully(self):
        rules = _load_rules()
        assert len(rules) >= 19


class TestScanPath:
    def test_nonexistent_target_raises(self, tmp_path):
        with pytest.raises(TargetNotFoundError, match="not found"):
            scan_path(str(tmp_path / "does_not_exist.json"))

    def test_unparseable_json_is_skipped(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not valid json", encoding="utf-8")
        results, failed, skipped = scan_path(str(tmp_path))
        assert any(str(bad) in p for p, _ in skipped)
        assert any("parse error" in r for _, r in skipped)

    def test_unrecognised_json_is_silently_ignored(self, tmp_path):
        other = tmp_path / "other.json"
        other.write_text('{"foo": "bar"}', encoding="utf-8")
        results, failed, skipped = scan_path(str(tmp_path))
        assert results == []
        assert skipped == []

    def test_skipped_files_reported_separately(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{broken", encoding="utf-8")
        good = tmp_path / "good.json"
        good.write_text(
            '{"mcpServers": {"bash": {"command": "npx", "args": ["-y", "@anthropic-ai/mcp-server-bash"], "env": {}}}}',
            encoding="utf-8",
        )
        results, _, skipped = scan_path(str(tmp_path))
        assert len(results) == 1
        assert len(skipped) == 1

    def test_invalid_rules_path_raises(self, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text('{"mcpServers": {}}', encoding="utf-8")
        with pytest.raises(RulesLoadError):
            scan_path(str(cfg), rules_path=tmp_path / "no_such_rules.yaml")

    def test_binary_file_is_skipped(self, tmp_path):
        binary = tmp_path / "binary.json"
        binary.write_bytes(b"\xff\xfe{binary content}")
        results, _, skipped = scan_path(str(tmp_path))
        assert any(str(binary) in p for p, _ in skipped)

    def test_json_array_file_is_silently_ignored(self, tmp_path):
        arr = tmp_path / "array.json"
        arr.write_text('[{"type": "function"}]', encoding="utf-8")
        results, _, skipped = scan_path(str(tmp_path))
        assert results == []
        assert skipped == []

    def test_returns_three_tuple(self, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text('{"mcpServers": {}}', encoding="utf-8")
        result = scan_path(str(cfg))
        assert len(result) == 3


class TestAPIErrorHandling:
    def test_analyze_returns_500_on_bad_rules(self, tmp_path):
        from mcpmap.api import build_app
        from fastapi.testclient import TestClient

        bad_rules = tmp_path / "bad_rules.yaml"
        bad_rules.write_text("rules:\n  - id: BAD\n    name: missing\n", encoding="utf-8")
        client = TestClient(build_app(rules_path=bad_rules))
        resp = client.post("/analyze", json={"content": {"mcpServers": {}}, "filename": "config.json"})
        assert resp.status_code == 500
        assert "Rules configuration error" in resp.json()["detail"]

    def test_rules_endpoint_returns_500_on_bad_rules(self, tmp_path):
        from mcpmap.api import build_app
        from fastapi.testclient import TestClient

        bad_rules = tmp_path / "bad_rules.yaml"
        bad_rules.write_text("rules:\n  - id: BAD\n    name: missing\n", encoding="utf-8")
        client = TestClient(build_app(rules_path=bad_rules))
        resp = client.get("/rules")
        assert resp.status_code == 500
        assert "Rules configuration error" in resp.json()["detail"]

    def test_analyze_with_invalid_fail_on_returns_400(self):
        from mcpmap.api import build_app
        from fastapi.testclient import TestClient

        client = TestClient(build_app())
        resp = client.post("/analyze", json={
            "content": {"mcpServers": {}},
            "filename": "config.json",
            "fail_on": "EXTREME",
        })
        assert resp.status_code == 400
