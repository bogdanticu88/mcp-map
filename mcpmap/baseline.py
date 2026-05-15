from __future__ import annotations

import json
from pathlib import Path

from mcpmap.models import AnalysisResult, Finding


class BaselineLoadError(Exception):
    pass


def load_baseline(path: Path) -> list[AnalysisResult]:
    """Load a previous scan's JSON output as a baseline for diff comparison."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise BaselineLoadError(f"Cannot read baseline file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise BaselineLoadError(f"Baseline file {path} is not valid JSON: {exc}") from exc

    if not isinstance(data, list):
        raise BaselineLoadError(f"Baseline file {path}: expected a JSON array at the top level")

    results: list[AnalysisResult] = []
    for item in data:
        try:
            results.append(AnalysisResult.model_validate(item))
        except Exception:
            continue
    return results


def _finding_key(f: Finding) -> str:
    return f"{f.rule_id}|{f.location}"


def mark_new_findings(
    current: list[AnalysisResult],
    baseline: list[AnalysisResult],
) -> tuple[list[AnalysisResult], int]:
    """Compare current scan results against a baseline.

    Marks each finding that did not exist in the baseline as is_new=True.
    Returns the updated results and the count of findings that were in the
    baseline but are no longer present (resolved).
    """
    baseline_keys: set[str] = {
        _finding_key(f)
        for result in baseline
        for f in result.findings
    }
    current_keys: set[str] = {
        _finding_key(f)
        for result in current
        for f in result.findings
    }

    resolved_count = len(baseline_keys - current_keys)

    for result in current:
        for finding in result.findings:
            if _finding_key(finding) not in baseline_keys:
                finding.is_new = True

    return current, resolved_count


def save_baseline(results: list[AnalysisResult], path: Path) -> None:
    """Write current scan results to a baseline JSON file."""
    payload = [r.model_dump() for r in results]
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
