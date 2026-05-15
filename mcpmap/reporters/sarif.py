from __future__ import annotations

import json
from mcpmap import __version__
from mcpmap.models import AnalysisResult, Severity

_LEVEL_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


class SARIFReporter:
    def render(self, results: list[AnalysisResult]) -> str:
        rules_seen: dict[str, dict] = {}
        run_results = []

        for result in results:
            for finding in result.findings:
                if finding.rule_id not in rules_seen:
                    refs = []
                    for o in finding.owasp_llm:
                        refs.append({"url": o.url, "text": f"{o.id}: {o.name}"})
                    for m in finding.mitre_atlas:
                        refs.append({"url": m.url, "text": f"{m.id}: {m.name}"})

                    rules_seen[finding.rule_id] = {
                        "id": finding.rule_id,
                        "name": finding.rule_name,
                        "shortDescription": {"text": finding.rule_name},
                        "fullDescription": {"text": finding.description},
                        "help": {"text": finding.remediation, "markdown": finding.remediation},
                        "properties": {
                            "tags": [finding.category],
                            "security-severity": self._cvss_score(finding.severity),
                        },
                        "helpUri": refs[0]["url"] if refs else "",
                        "relationships": [
                            {"target": {"id": r["text"], "toolComponent": {"name": "OWASP-LLM"}}}
                            for r in refs
                        ],
                    }

                run_results.append({
                    "ruleId": finding.rule_id,
                    "level": _LEVEL_MAP[finding.severity],
                    "message": {
                        "text": f"{finding.evidence} — {finding.description[:200]}"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": result.target},
                                "region": {"startLine": 1},
                            },
                            "logicalLocations": [
                                {"name": finding.location, "kind": "module"}
                            ],
                        }
                    ],
                    "properties": {
                        "severity": finding.severity.value,
                        "category": finding.category,
                    },
                })

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "mcpmap",
                            "version": __version__,
                            "informationUri": "https://github.com/bogdanticu88/mcpmap",
                            "rules": list(rules_seen.values()),
                        }
                    },
                    "results": run_results,
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    def _cvss_score(self, severity: Severity) -> str:
        return {
            Severity.CRITICAL: "9.0",
            Severity.HIGH: "7.5",
            Severity.MEDIUM: "5.0",
            Severity.LOW: "2.5",
            Severity.INFO: "0.0",
        }[severity]
