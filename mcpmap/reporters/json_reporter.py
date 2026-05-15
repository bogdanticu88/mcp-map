from __future__ import annotations

import json

from mcpmap.models import AnalysisResult


class JSONReporter:
    def render(self, results: list[AnalysisResult]) -> str:
        payload = [r.model_dump() for r in results]
        return json.dumps(payload, indent=2, default=str)
