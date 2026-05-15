from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class OwaspLLMRef(BaseModel):
    id: str
    name: str
    url: str


class MitreAtlasRef(BaseModel):
    id: str
    name: str
    url: str


class RuleDefinition(BaseModel):
    id: str
    name: str
    description: str
    severity: Severity
    category: str
    owasp_llm: list[OwaspLLMRef] = Field(default_factory=list)
    mitre_atlas: list[MitreAtlasRef] = Field(default_factory=list)
    remediation: str
    detection: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    rule_id: str
    rule_name: str
    severity: Severity
    category: str
    description: str
    remediation: str
    owasp_llm: list[OwaspLLMRef] = Field(default_factory=list)
    mitre_atlas: list[MitreAtlasRef] = Field(default_factory=list)
    location: str
    evidence: str = ""
    suppressed: bool = False
    suppression_reason: str = ""
    is_new: bool = False


class AnalysisResult(BaseModel):
    target: str
    format: str
    findings: list[Finding] = Field(default_factory=list)
    stats: dict[str, int] = Field(default_factory=dict)
    framework: str = "owasp-llm"

    def compute_stats(self) -> None:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        counts["TOTAL"] = len(self.findings)
        self.stats = counts

