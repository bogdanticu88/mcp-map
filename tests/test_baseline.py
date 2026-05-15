from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcpmap.baseline import BaselineLoadError, load_baseline, mark_new_findings, save_baseline
from mcpmap.models import AnalysisResult, Finding, Severity


def _result(rule_id: str, target: str = "config.json") -> AnalysisResult:
    f = Finding(
        rule_id=rule_id,
        rule_name="Test",
        severity=Severity.HIGH,
        category="Test",
        description="desc",
        remediation="fix",
        location=f"{target} > server:bash",
        evidence="evidence",
    )
    r = AnalysisResult(target=target, format="mcp-config", findings=[f])
    r.compute_stats()
    return r


# ── load_baseline ─────────────────────────────────────────────────────────────

class TestLoadBaseline:
    def test_loads_valid_json(self, tmp_path):
        r = _result("MCM-001")
        p = tmp_path / "baseline.json"
        p.write_text(json.dumps([r.model_dump()], default=str))
        loaded = load_baseline(p)
        assert len(loaded) == 1
        assert loaded[0].findings[0].rule_id == "MCM-001"

    def test_raises_on_missing_file(self, tmp_path):
        with pytest.raises(BaselineLoadError):
            load_baseline(tmp_path / "missing.json")

    def test_raises_on_invalid_json(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{broken")
        with pytest.raises(BaselineLoadError):
            load_baseline(p)

    def test_raises_on_non_array(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text('{"not": "an array"}')
        with pytest.raises(BaselineLoadError):
            load_baseline(p)

    def test_skips_malformed_entries(self, tmp_path):
        p = tmp_path / "baseline.json"
        r = _result("MCM-001")
        p.write_text(json.dumps([r.model_dump(), {"invalid": True}], default=str))
        loaded = load_baseline(p)
        assert len(loaded) == 1


# ── mark_new_findings ─────────────────────────────────────────────────────────

class TestMarkNewFindings:
    def test_marks_finding_absent_from_baseline_as_new(self):
        current = [_result("MCM-002")]
        baseline = [_result("MCM-001")]
        updated, resolved = mark_new_findings(current, baseline)
        assert updated[0].findings[0].is_new is True
        assert resolved == 1

    def test_does_not_mark_existing_finding_as_new(self):
        r = _result("MCM-001")
        current = [_result("MCM-001")]
        baseline = [_result("MCM-001")]
        updated, resolved = mark_new_findings(current, baseline)
        assert updated[0].findings[0].is_new is False
        assert resolved == 0

    def test_resolved_count_when_finding_disappears(self):
        current = [_result("MCM-001")]
        baseline = [_result("MCM-001"), _result("MCM-002")]
        # MCM-002 is in baseline but not current → resolved
        _, resolved = mark_new_findings(current, baseline)
        assert resolved == 1

    def test_all_new_when_baseline_empty(self):
        current = [_result("MCM-001"), _result("MCM-002")]
        updated, resolved = mark_new_findings(current, [])
        for r in updated:
            for f in r.findings:
                assert f.is_new is True
        assert resolved == 0

    def test_none_new_when_all_in_baseline(self):
        current = [_result("MCM-001")]
        updated, resolved = mark_new_findings(current, [_result("MCM-001")])
        assert updated[0].findings[0].is_new is False
        assert resolved == 0


# ── save_baseline ─────────────────────────────────────────────────────────────

class TestSaveBaseline:
    def test_roundtrip(self, tmp_path):
        r = _result("MCM-001")
        p = tmp_path / "baseline.json"
        save_baseline([r], p)
        loaded = load_baseline(p)
        assert len(loaded) == 1
        assert loaded[0].findings[0].rule_id == "MCM-001"

    def test_output_is_valid_json_array(self, tmp_path):
        r = _result("MCM-001")
        p = tmp_path / "baseline.json"
        save_baseline([r], p)
        data = json.loads(p.read_text())
        assert isinstance(data, list)
