from __future__ import annotations

from jinja2 import Environment, BaseLoader
from mcpmap.models import AnalysisResult, Severity

_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>mcpmap Report</title>
<style>
  :root {
    --critical: #dc2626; --high: #ea580c; --medium: #ca8a04;
    --low: #16a34a; --info: #6b7280; --bg: #0f172a; --surface: #1e293b;
    --border: #334155; --text: #e2e8f0; --muted: #94a3b8;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; }
  h1 { font-size: 1.75rem; margin-bottom: 0.25rem; }
  .subtitle { color: var(--muted); margin-bottom: 2rem; font-size: 0.9rem; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }
  .stat-card .number { font-size: 2rem; font-weight: 700; }
  .stat-card .label { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
  .c-critical .number { color: var(--critical); }
  .c-high .number { color: var(--high); }
  .c-medium .number { color: var(--medium); }
  .c-low .number { color: var(--low); }
  .finding { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1rem; overflow: hidden; }
  .finding-header { display: flex; align-items: center; gap: 0.75rem; padding: 1rem; cursor: pointer; }
  .finding-header:hover { background: rgba(255,255,255,0.03); }
  .badge { padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.05em; color: #fff; flex-shrink: 0; }
  .badge-CRITICAL { background: var(--critical); }
  .badge-HIGH { background: var(--high); }
  .badge-MEDIUM { background: var(--medium); }
  .badge-LOW { background: var(--low); }
  .finding-title { font-weight: 600; font-size: 0.95rem; }
  .finding-rule { color: var(--muted); font-size: 0.8rem; font-family: monospace; }
  .finding-body { padding: 0 1rem 1rem; border-top: 1px solid var(--border); }
  .field { margin-top: 0.75rem; }
  .field-label { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); margin-bottom: 0.25rem; }
  .field-value { font-size: 0.875rem; line-height: 1.5; }
  code { background: rgba(255,255,255,0.07); padding: 0.1rem 0.4rem; border-radius: 3px; font-size: 0.82rem; word-break: break-all; }
  .refs { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.25rem; }
  .ref-tag { padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.72rem; background: rgba(255,255,255,0.08); border: 1px solid var(--border); }
  .ref-tag a { color: var(--text); text-decoration: none; }
  .ref-tag a:hover { text-decoration: underline; }
  .file-section { margin-bottom: 2rem; }
  .file-heading { font-size: 1rem; color: var(--muted); margin-bottom: 1rem; font-family: monospace; }
  .no-findings { color: var(--low); font-size: 0.9rem; padding: 0.5rem 0; }
  details > summary { list-style: none; }
  details > summary::-webkit-details-marker { display: none; }
</style>
</head>
<body>
<h1>mcpmap</h1>
<p class="subtitle">AI Agent Attack Surface Report</p>

<div class="summary-grid">
  <div class="stat-card"><div class="number">{{ total_files }}</div><div class="label">Files Scanned</div></div>
  <div class="stat-card c-critical"><div class="number">{{ total_critical }}</div><div class="label">Critical</div></div>
  <div class="stat-card c-high"><div class="number">{{ total_high }}</div><div class="label">High</div></div>
  <div class="stat-card c-medium"><div class="number">{{ total_medium }}</div><div class="label">Medium</div></div>
  <div class="stat-card c-low"><div class="number">{{ total_low }}</div><div class="label">Low</div></div>
  <div class="stat-card"><div class="number">{{ total_findings }}</div><div class="label">Total</div></div>
</div>

{% for result in results %}
<div class="file-section">
  <div class="file-heading">{{ result.target }}</div>
  {% if not result.findings %}
    <div class="no-findings">No findings detected.</div>
  {% else %}
    {% for finding in result.findings %}
    <details class="finding" open>
      <summary class="finding-header">
        <span class="badge badge-{{ finding.severity }}">{{ finding.severity }}</span>
        <div>
          <div class="finding-title">{{ finding.rule_name }}</div>
          <div class="finding-rule">{{ finding.rule_id }} &bull; {{ finding.category }}</div>
        </div>
      </summary>
      <div class="finding-body">
        <div class="field">
          <div class="field-label">Location</div>
          <div class="field-value"><code>{{ finding.location }}</code></div>
        </div>
        <div class="field">
          <div class="field-label">Evidence</div>
          <div class="field-value">{{ finding.evidence }}</div>
        </div>
        <div class="field">
          <div class="field-label">Description</div>
          <div class="field-value">{{ finding.description }}</div>
        </div>
        <div class="field">
          <div class="field-label">Remediation</div>
          <div class="field-value">{{ finding.remediation }}</div>
        </div>
        {% if finding.owasp_llm %}
        <div class="field">
          <div class="field-label">OWASP LLM Top 10</div>
          <div class="refs">
            {% for o in finding.owasp_llm %}
            <span class="ref-tag"><a href="{{ o.url }}" target="_blank">{{ o.id }}: {{ o.name }}</a></span>
            {% endfor %}
          </div>
        </div>
        {% endif %}
        {% if finding.mitre_atlas %}
        <div class="field">
          <div class="field-label">MITRE ATLAS</div>
          <div class="refs">
            {% for m in finding.mitre_atlas %}
            <span class="ref-tag"><a href="{{ m.url }}" target="_blank">{{ m.id }}: {{ m.name }}</a></span>
            {% endfor %}
          </div>
        </div>
        {% endif %}
      </div>
    </details>
    {% endfor %}
  {% endif %}
</div>
{% endfor %}

<p style="color: var(--muted); font-size: 0.75rem; margin-top: 2rem;">Generated by <a href="https://github.com/bogdanticu88/mcpmap" style="color: var(--muted);">mcpmap</a></p>
</body>
</html>
"""


class HTMLReporter:
    def render(self, results: list[AnalysisResult]) -> str:
        env = Environment(loader=BaseLoader(), autoescape=True)
        template = env.from_string(_TEMPLATE)

        total_findings = sum(len(r.findings) for r in results)
        return template.render(
            results=results,
            total_files=len(results),
            total_findings=total_findings,
            total_critical=sum(r.stats.get("CRITICAL", 0) for r in results),
            total_high=sum(r.stats.get("HIGH", 0) for r in results),
            total_medium=sum(r.stats.get("MEDIUM", 0) for r in results),
            total_low=sum(r.stats.get("LOW", 0) for r in results),
        )
