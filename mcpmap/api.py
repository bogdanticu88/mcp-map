from __future__ import annotations

import tempfile
import os
import json
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from mcpmap import __version__
from mcpmap.engine import scan_path, _load_rules, RulesLoadError
from mcpmap.models import AnalysisResult, Severity
from mcpmap.reporters import JSONReporter, MarkdownReporter, HTMLReporter, SARIFReporter


class AnalyzeRequest(BaseModel):
    content: dict[str, Any]
    filename: str = "config.json"
    format: str = "json"
    fail_on: Optional[str] = None


class AnalyzeResponse(BaseModel):
    results: list[dict[str, Any]]
    summary: dict[str, int]
    failed: bool = False
    report: str = ""


def build_app(rules_path: Path | None = None) -> FastAPI:
    app = FastAPI(
        title="mcpmap",
        description="Static attack surface analyzer for AI agents and MCP servers.",
        version=__version__,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health")
    def health():
        return {"status": "ok", "version": __version__}

    @app.get("/version")
    def version():
        return {"version": __version__}

    @app.get("/rules")
    def rules():
        try:
            loaded = _load_rules(rules_path)
        except RulesLoadError as exc:
            raise HTTPException(status_code=500, detail=f"Rules configuration error: {exc}")
        return [
            {
                "id": r.id,
                "name": r.name,
                "severity": r.severity.value,
                "category": r.category,
                "owasp_llm": [o.model_dump() for o in r.owasp_llm],
                "mitre_atlas": [m.model_dump() for m in r.mitre_atlas],
            }
            for r in loaded
        ]

    @app.post("/analyze", response_model=AnalyzeResponse)
    def analyze(req: AnalyzeRequest):
        fail_severity: Severity | None = None
        if req.fail_on:
            try:
                fail_severity = Severity(req.fail_on.upper())
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid fail_on value: {req.fail_on}")

        suffix = ".json" if req.filename.endswith(".json") else ".yaml"
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=suffix, delete=False, encoding="utf-8"
            ) as tmp:
                json.dump(req.content, tmp)
                tmp_path = tmp.name
            results, failed, _ = scan_path(tmp_path, rules_path=rules_path, fail_on=fail_severity)
        except RulesLoadError as exc:
            raise HTTPException(status_code=500, detail=f"Rules configuration error: {exc}")
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

        summary = {
            "CRITICAL": sum(r.stats.get("CRITICAL", 0) for r in results),
            "HIGH": sum(r.stats.get("HIGH", 0) for r in results),
            "MEDIUM": sum(r.stats.get("MEDIUM", 0) for r in results),
            "LOW": sum(r.stats.get("LOW", 0) for r in results),
            "TOTAL": sum(r.stats.get("TOTAL", 0) for r in results),
        }

        report = ""
        fmt = req.format.lower()
        if fmt == "markdown":
            report = MarkdownReporter().render(results)
        elif fmt == "html":
            report = HTMLReporter().render(results)
        elif fmt == "sarif":
            report = SARIFReporter().render(results)
        else:
            report = JSONReporter().render(results)

        return AnalyzeResponse(
            results=[r.model_dump() for r in results],
            summary=summary,
            failed=failed,
            report=report,
        )

    return app
