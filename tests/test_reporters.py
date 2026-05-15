import json
import pytest
from mcpmap.engine import _load_rules, analyze_agent
from mcpmap.parsers.mcp_config import MCPConfigParser
from mcpmap.reporters.markdown import MarkdownReporter
from mcpmap.reporters.json_reporter import JSONReporter
from mcpmap.reporters.sarif import SARIFReporter
from mcpmap.reporters.html import HTMLReporter
from mcpmap.models import AnalysisResult


_DANGEROUS_MCP = {
    "mcpServers": {
        "bash": {
            "command": "npx",
            "args": ["-y", "@anthropic-ai/mcp-server-bash"],
            "env": {"API_KEY": "sk-test"},
        }
    }
}

_SAFE_MCP = {
    "mcpServers": {
        "docs": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0", "/workspace/docs"],
            "env": {},
        }
    }
}


@pytest.fixture(scope="module")
def dangerous_result() -> AnalysisResult:
    rules = _load_rules()
    agent = MCPConfigParser().parse(_DANGEROUS_MCP, "config.json")
    findings = analyze_agent(agent, rules)
    result = AnalysisResult(target="config.json", format="mcp-config", findings=findings)
    result.compute_stats()
    return result


@pytest.fixture(scope="module")
def safe_result() -> AnalysisResult:
    rules = _load_rules()
    agent = MCPConfigParser().parse(_SAFE_MCP, "safe.json")
    findings = analyze_agent(agent, rules)
    result = AnalysisResult(target="safe.json", format="mcp-config", findings=findings)
    result.compute_stats()
    return result


class TestMarkdownReporter:
    def test_contains_summary_table(self, dangerous_result):
        md = MarkdownReporter().render([dangerous_result])
        assert "## Summary" in md
        assert "CRITICAL" in md

    def test_contains_finding_rule_id(self, dangerous_result):
        md = MarkdownReporter().render([dangerous_result])
        assert "MCM-001" in md

    def test_contains_remediation(self, dangerous_result):
        md = MarkdownReporter().render([dangerous_result])
        assert "Remediation" in md

    def test_contains_owasp_reference(self, dangerous_result):
        md = MarkdownReporter().render([dangerous_result])
        assert "OWASP" in md

    def test_contains_mitre_reference(self, dangerous_result):
        md = MarkdownReporter().render([dangerous_result])
        assert "MITRE" in md

    def test_no_findings_message(self, safe_result):
        md = MarkdownReporter().render([safe_result])
        assert "No findings detected" in md

    def test_ascii_mode_no_badges(self, dangerous_result):
        md = MarkdownReporter(ascii_mode=True).render([dangerous_result])
        assert "shields.io" not in md
        assert "CRITICAL" in md

    def test_empty_results(self):
        md = MarkdownReporter().render([])
        assert "No findings detected" in md


class TestJSONReporter:
    def test_valid_json(self, dangerous_result):
        output = JSONReporter().render([dangerous_result])
        data = json.loads(output)
        assert isinstance(data, list)

    def test_contains_findings(self, dangerous_result):
        data = json.loads(JSONReporter().render([dangerous_result]))
        assert len(data[0]["findings"]) > 0

    def test_finding_has_required_fields(self, dangerous_result):
        data = json.loads(JSONReporter().render([dangerous_result]))
        finding = data[0]["findings"][0]
        assert "rule_id" in finding
        assert "severity" in finding
        assert "location" in finding
        assert "evidence" in finding

    def test_empty_results(self):
        data = json.loads(JSONReporter().render([]))
        assert data == []


class TestSARIFReporter:
    def test_valid_json(self, dangerous_result):
        output = SARIFReporter().render([dangerous_result])
        data = json.loads(output)
        assert data["version"] == "2.1.0"

    def test_has_runs(self, dangerous_result):
        data = json.loads(SARIFReporter().render([dangerous_result]))
        assert len(data["runs"]) == 1

    def test_rules_populated(self, dangerous_result):
        data = json.loads(SARIFReporter().render([dangerous_result]))
        assert len(data["runs"][0]["tool"]["driver"]["rules"]) > 0

    def test_results_have_level(self, dangerous_result):
        data = json.loads(SARIFReporter().render([dangerous_result]))
        for r in data["runs"][0]["results"]:
            assert r["level"] in ("error", "warning", "note", "none")

    def test_critical_maps_to_error(self, dangerous_result):
        data = json.loads(SARIFReporter().render([dangerous_result]))
        critical_results = [
            r for r in data["runs"][0]["results"]
            if r["properties"]["severity"] == "CRITICAL"
        ]
        assert all(r["level"] == "error" for r in critical_results)

    def test_empty_results(self):
        data = json.loads(SARIFReporter().render([]))
        assert data["runs"][0]["results"] == []


class TestHTMLReporter:
    def test_valid_html(self, dangerous_result):
        html = HTMLReporter().render([dangerous_result])
        assert "<!DOCTYPE html>" in html
        assert "</html>" in html

    def test_contains_rule_id(self, dangerous_result):
        html = HTMLReporter().render([dangerous_result])
        assert "MCM-001" in html

    def test_contains_severity_badge(self, dangerous_result):
        html = HTMLReporter().render([dangerous_result])
        assert "badge-CRITICAL" in html or "CRITICAL" in html

    def test_empty_results(self):
        html = HTMLReporter().render([])
        assert "<!DOCTYPE html>" in html
