from __future__ import annotations

import os
import platform
from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from rich import box
from rich.console import Console
from rich.table import Table

from mcpmap import __version__
from mcpmap.baseline import BaselineLoadError, load_baseline, mark_new_findings, save_baseline
from mcpmap.engine import RulesLoadError, TargetNotFoundError, _load_rules, scan_path
from mcpmap.models import Severity
from mcpmap.reporters import HTMLReporter, JSONReporter, MarkdownReporter, SARIFReporter
from mcpmap.suppression import find_ignore_file, load_suppressions, apply_suppressions

app = typer.Typer(
    name="mcpmap",
    help=(
        "[bold]mcpmap[/bold] — Static attack surface analyzer for MCP servers and AI agent "
        "tool definitions.\n\n"
        "Scans [cyan]claude_desktop_config.json[/cyan], MCP server configs, and OpenAI-style "
        "tool definitions for security risks. Every finding is mapped to "
        "[link=https://genai.owasp.org/]OWASP LLM Top 10[/link] and "
        "[link=https://atlas.mitre.org/]MITRE ATLAS[/link].\n\n"
        "[dim]Tip: set [cyan]NO_COLOR=1[/cyan] to disable all colour output.[/dim]"
    ),
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()

_SEV_COLOR = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFO": "dim",
}

_CLAUDE_CONFIG_PATHS: dict[str, list[Path]] = {
    "Darwin": [
        Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        Path.home() / ".config" / "Claude" / "claude_desktop_config.json",
    ],
    "Windows": [
        Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        / "Claude"
        / "claude_desktop_config.json",
    ],
    "Linux": [
        Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
        / "Claude"
        / "claude_desktop_config.json",
    ],
}


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"mcpmap {__version__}")
        raise typer.Exit(0)


@app.callback()
def _main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    pass


class OutputFormat(str, Enum):
    markdown = "markdown"
    json = "json"
    html = "html"
    sarif = "sarif"


_SCAN_EPILOG = (
    "\b\nOutput formats:\n"
    "  markdown  Human-readable report with badges (default)\n"
    "  json      Machine-readable array, one object per file\n"
    "  html      Self-contained dark-mode HTML report\n"
    "  sarif     SARIF 2.1.0 for GitHub Code Scanning\n"
    "\nExit codes:\n"
    "  0  Scan completed — no findings at or above --fail-on threshold\n"
    "  1  Findings detected at or above --fail-on severity\n"
    "  2  Error — bad --rules path, target not found, or output not writable\n"
    "\nExamples:\n"
    "  # Locate your Claude Desktop config first\n"
    "  mcpmap find\n\n"
    "  # Scan a single file\n"
    "  mcpmap scan claude_desktop_config.json\n\n"
    "  # Scan all configs in a directory\n"
    "  mcpmap scan ./configs/\n\n"
    "  # Fail CI on any HIGH or CRITICAL finding\n"
    "  mcpmap scan config.json --fail-on HIGH\n\n"
    "  # SARIF report for GitHub Code Scanning\n"
    "  mcpmap scan config.json --format sarif --output results.sarif\n\n"
    "  # Self-contained HTML report\n"
    "  mcpmap scan config.json --format html --output report.html\n\n"
    "  # Use a custom rule set\n"
    "  mcpmap scan config.json --rules my_rules.yaml\n"
)


@app.command(epilog=_SCAN_EPILOG)
def scan(
    targets: list[str] = typer.Argument(
        ...,
        help=(
            "One or more files or directories to scan. "
            "Directories are walked recursively for [cyan].json[/cyan], "
            "[cyan].yaml[/cyan], and [cyan].yml[/cyan] files. "
            "Run [cyan]mcpmap find[/cyan] to locate your Claude Desktop config."
        ),
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.markdown,
        "--format",
        "-f",
        help=(
            "Report format. "
            "[cyan]markdown[/cyan] and [cyan]json[/cyan] print to stdout; "
            "[cyan]html[/cyan] writes to a file (requires [cyan]--output[/cyan] "
            "or defaults to [cyan]mcpmap_report.html[/cyan]); "
            "[cyan]sarif[/cyan] is for GitHub Code Scanning."
        ),
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help=(
            "Write the report to this file instead of stdout. "
            "Parent directory must exist. "
            "Required for [cyan]html[/cyan] format (or a default filename is used)."
        ),
    ),
    fail_on: Optional[str] = typer.Option(
        None,
        "--fail-on",
        metavar="LEVEL",
        help=(
            "Exit with code [red]1[/red] if any finding is at or above this severity. "
            "Valid values: [red]CRITICAL[/red] [red]HIGH[/red] [yellow]MEDIUM[/yellow] [green]LOW[/green]. "
            "Case-insensitive. Designed for CI gates."
        ),
    ),
    summary: bool = typer.Option(
        False,
        "--summary",
        help=(
            "Print only the terminal severity-count table — no full report. "
            "Useful for a quick overview in CI logs."
        ),
    ),
    ascii_mode: bool = typer.Option(
        False,
        "--ascii",
        help=(
            "Plain-text output: no emoji, no badge images, no Unicode. "
            "Use when piping to tools that don't handle Unicode, "
            "or set [cyan]NO_COLOR=1[/cyan] to also strip colour."
        ),
    ),
    rules: Optional[Path] = typer.Option(
        None,
        "--rules",
        help=(
            "Path to a custom rules YAML file. "
            "[bold]Replaces[/bold] the built-in rule set entirely. "
            "Run [cyan]mcpmap rules[/cyan] to see the built-in rules and their format."
        ),
    ),
    ignore_file: Optional[Path] = typer.Option(
        None,
        "--ignore-file",
        help=(
            "Path to a suppression file. "
            "Defaults to [cyan].mcpmap-ignore[/cyan] in the target directory or CWD if present. "
            "Each line: [cyan]RULE_ID[/cyan] or [cyan]RULE_ID:server_name[/cyan] or [cyan]*:server_name[/cyan]."
        ),
    ),
    no_ignore: bool = typer.Option(
        False,
        "--no-ignore",
        help="Disable all suppression file loading, even if .mcpmap-ignore exists.",
    ),
    show_suppressed: bool = typer.Option(
        False,
        "--show-suppressed",
        help="Include suppressed findings in the report (marked as suppressed).",
    ),
    baseline: Optional[Path] = typer.Option(
        None,
        "--baseline",
        help=(
            "Path to a previous scan's JSON output. "
            "Findings not present in the baseline are marked [bold]NEW[/bold]. "
            "Generate a baseline with [cyan]--save-baseline[/cyan]."
        ),
    ),
    save_baseline: Optional[Path] = typer.Option(
        None,
        "--save-baseline",
        help="Save the current scan results as a baseline JSON file for future diff comparisons.",
    ),
) -> None:
    """Scan MCP configs and AI agent tool definitions for security risks."""
    fail_severity: Severity | None = None
    if fail_on:
        try:
            fail_severity = Severity(fail_on.upper())
        except ValueError:
            console.print(
                f"[red]Invalid --fail-on value:[/red] [bold]{fail_on}[/bold]\n"
                "Valid values: CRITICAL, HIGH, MEDIUM, LOW"
            )
            raise typer.Exit(1)

    all_results = []
    all_skipped = []
    for target in targets:
        try:
            results, _, skipped = scan_path(target, rules_path=rules, fail_on=None)
        except RulesLoadError as exc:
            console.print(f"[bold red]Error loading rules:[/bold red] {exc}")
            raise typer.Exit(2)
        except TargetNotFoundError as exc:
            console.print(f"[bold red]Error:[/bold red] {exc}")
            raise typer.Exit(2)
        all_results.extend(results)
        all_skipped.extend(skipped)

    stderr_console = Console(stderr=True)
    for path, reason in all_skipped:
        stderr_console.print(f"[yellow]Skipped {path}:[/yellow] {reason}")

    # Apply suppressions
    suppressed_count = 0
    if not no_ignore:
        ign_path = ignore_file or find_ignore_file(list(targets))
        if ign_path:
            suppressions = load_suppressions(ign_path)
            if suppressions:
                for result in all_results:
                    apply_suppressions(result.findings, suppressions)
                suppressed_count = sum(
                    1 for r in all_results for f in r.findings if f.suppressed
                )
                console.print(
                    f"[dim]Loaded {len(suppressions)} suppression(s) from {ign_path} "
                    f"— {suppressed_count} finding(s) suppressed.[/dim]"
                )

    # Apply baseline diff
    resolved_count = 0
    if baseline:
        try:
            baseline_results = load_baseline(baseline)
            all_results, resolved_count = mark_new_findings(all_results, baseline_results)
            new_count = sum(1 for r in all_results for f in r.findings if f.is_new)
            console.print(
                f"[dim]Baseline: {new_count} new finding(s), {resolved_count} resolved.[/dim]"
            )
        except BaselineLoadError as exc:
            console.print(f"[bold red]Error loading baseline:[/bold red] {exc}")
            raise typer.Exit(2)

    # Save baseline if requested
    if save_baseline:
        try:
            save_baseline_fn = save_baseline  # avoid shadowing
            from mcpmap.baseline import save_baseline as _save
            _save(all_results, save_baseline_fn)
            console.print(f"[green]Baseline saved to {save_baseline_fn}[/green]")
        except OSError as exc:
            console.print(f"[bold red]Error saving baseline:[/bold red] {exc}")
            raise typer.Exit(2)

    # Filter suppressed findings unless --show-suppressed
    visible_results = all_results
    if not show_suppressed:
        visible_results = [
            r.model_copy(update={"findings": [f for f in r.findings if not f.suppressed]})
            for r in all_results
        ]
        for r in visible_results:
            r.compute_stats()

    _, failed = ([], False) if not fail_severity else _check_fail(visible_results, fail_severity)

    if summary:
        _print_summary_table(visible_results, suppressed_count if not show_suppressed else 0)
        if failed:
            console.print(f"\n[bold red]FAILED:[/bold red] findings at or above {fail_severity.value} detected.")
            raise typer.Exit(1)
        return

    rendered = _render(visible_results, format, ascii_mode)

    if output:
        try:
            output.write_text(rendered, encoding="utf-8")
        except OSError as exc:
            console.print(f"[bold red]Error writing report to {output}:[/bold red] {exc}")
            raise typer.Exit(2)
        console.print(f"[green]Report written to {output}[/green]")
    else:
        if format in (OutputFormat.markdown, OutputFormat.json, OutputFormat.sarif):
            print(rendered)
        else:
            output_path = Path("mcpmap_report.html")
            try:
                output_path.write_text(rendered, encoding="utf-8")
            except OSError as exc:
                console.print(f"[bold red]Error writing report to {output_path}:[/bold red] {exc}")
                raise typer.Exit(2)
            console.print(f"[green]HTML report written to {output_path}[/green]")

    _print_summary_table(visible_results, suppressed_count if not show_suppressed else 0)

    if failed:
        console.print(f"\n[bold red]FAILED:[/bold red] findings at or above {fail_severity.value} detected.")
        raise typer.Exit(1)


_RULES_EPILOG = (
    "\b\nExamples:\n"
    "  mcpmap rules\n"
    "  mcpmap rules --rules my_rules.yaml\n"
    "\nRule IDs follow the pattern MCM-NNN for built-in rules.\n"
    "Use any prefix for custom rules.\n"
)


@app.command(epilog=_RULES_EPILOG)
def rules(
    rules_path: Optional[Path] = typer.Option(
        None,
        "--rules",
        help="Custom rules YAML to list. Defaults to the built-in rule set.",
    ),
) -> None:
    """List all detection rules with severity, category, and description."""
    try:
        rule_list = _load_rules(rules_path)
    except RulesLoadError as exc:
        console.print(f"[bold red]Error loading rules:[/bold red] {exc}")
        raise typer.Exit(2)

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold", show_lines=False)
    table.add_column("ID", style="cyan", no_wrap=True, min_width=10)
    table.add_column("Severity", no_wrap=True, min_width=10)
    table.add_column("Category", min_width=20)
    table.add_column("Name")

    for rule in rule_list:
        color = _SEV_COLOR.get(rule.severity.value, "white")
        table.add_row(
            rule.id,
            f"[{color}]{rule.severity.value}[/{color}]",
            rule.category,
            rule.name,
        )

    console.print(table)
    console.print(f"\n[dim]{len(rule_list)} rule{'s' if len(rule_list) != 1 else ''} loaded[/dim]")


_FIND_EPILOG = (
    "\b\nConfig file locations by OS:\n"
    "  macOS    ~/Library/Application Support/Claude/claude_desktop_config.json\n"
    "  Windows  %APPDATA%\\Claude\\claude_desktop_config.json\n"
    "  Linux    ~/.config/Claude/claude_desktop_config.json\n"
    "           (or $XDG_CONFIG_HOME/Claude/ if set)\n"
    "\nExample:\n"
    "  mcpmap find          # see what was found\n"
    "  mcpmap scan <path>   # then scan it\n"
)


@app.command(epilog=_FIND_EPILOG)
def find() -> None:
    """Locate Claude Desktop config files on this system."""
    system = platform.system()
    candidates = _CLAUDE_CONFIG_PATHS.get(system, _CLAUDE_CONFIG_PATHS["Linux"])

    found: list[str] = []
    for p in candidates:
        if p.exists():
            console.print(f"[green]  found[/green]  {p}")
            found.append(str(p))
        else:
            console.print(f"[dim]not found  {p}[/dim]")

    if found:
        paths_str = " ".join(f'"{p}"' if " " in p else p for p in found)
        console.print(f"\n[bold]Found {len(found)} config file(s).[/bold]")
        console.print(f"Run: [cyan]mcpmap scan {paths_str}[/cyan]")
    else:
        console.print("\n[yellow]No Claude Desktop config found.[/yellow]")
        console.print("Specify a path directly:  [cyan]mcpmap scan /path/to/config.json[/cyan]")


_SERVE_EPILOG = (
    "\b\nEndpoints:\n"
    "  POST /analyze   Scan a config payload, returns findings + report\n"
    "  GET  /rules     List all loaded detection rules\n"
    '  GET  /health    Health check: {"status": "ok", "version": "..."}\n'
    "\nExamples:\n"
    "  mcpmap serve\n"
    "  mcpmap serve --host 0.0.0.0 --port 9000\n"
    "  mcpmap serve --rules my_rules.yaml\n"
)


@app.command(epilog=_SERVE_EPILOG)
def serve(
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help=(
            "Interface to bind to. "
            "Use [cyan]0.0.0.0[/cyan] to accept connections from any address "
            "(not recommended on untrusted networks)."
        ),
    ),
    port: int = typer.Option(
        8000,
        "--port",
        "-p",
        help="Port to listen on.",
        min=1,
        max=65535,
    ),
    rules: Optional[Path] = typer.Option(
        None,
        "--rules",
        help=(
            "Path to a custom rules YAML file. "
            "Replaces the built-in rule set for all API requests."
        ),
    ),
) -> None:
    """Start the mcpmap REST API server."""
    import uvicorn

    from mcpmap.api import build_app

    try:
        _load_rules(rules)
    except RulesLoadError as exc:
        console.print(f"[bold red]Error loading rules:[/bold red] {exc}")
        raise typer.Exit(2)

    api_app = build_app(rules_path=rules)
    console.print(f"[green]mcpmap API server running on http://{host}:{port}[/green]")
    console.print("  [cyan]POST /analyze[/cyan]  — scan a config payload")
    console.print("  [cyan]GET  /rules[/cyan]    — list loaded rules")
    console.print("  [cyan]GET  /health[/cyan]   — health check")
    uvicorn.run(api_app, host=host, port=port, log_level="warning")


def _render(results, format: OutputFormat, ascii_mode: bool) -> str:
    if format == OutputFormat.json:
        return JSONReporter().render(results)
    if format == OutputFormat.html:
        return HTMLReporter().render(results)
    if format == OutputFormat.sarif:
        return SARIFReporter().render(results)
    return MarkdownReporter(ascii_mode=ascii_mode).render(results)


def _check_fail(results, fail_severity: Severity):
    from mcpmap.models import SEVERITY_ORDER

    threshold = SEVERITY_ORDER[fail_severity]
    for result in results:
        for f in result.findings:
            if SEVERITY_ORDER[f.severity] >= threshold:
                return results, True
    return results, False


def _print_summary_table(results, suppressed_count: int = 0) -> None:
    if not results:
        console.print("[yellow]No supported config files found.[/yellow]")
        return

    total_findings = sum(len(r.findings) for r in results)
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
    table.add_column("File", style="dim", no_wrap=False)
    table.add_column("CRITICAL", style="bold red", justify="center")
    table.add_column("HIGH", style="red", justify="center")
    table.add_column("MEDIUM", style="yellow", justify="center")
    table.add_column("LOW", style="green", justify="center")
    table.add_column("Total", justify="center")

    for result in results:
        s = result.stats
        table.add_row(
            result.target,
            str(s.get("CRITICAL", 0)) if s.get("CRITICAL") else "-",
            str(s.get("HIGH", 0)) if s.get("HIGH") else "-",
            str(s.get("MEDIUM", 0)) if s.get("MEDIUM") else "-",
            str(s.get("LOW", 0)) if s.get("LOW") else "-",
            str(s.get("TOTAL", 0)),
        )

    console.print(table)
    suffix = f" ([dim]{suppressed_count} suppressed[/dim])" if suppressed_count else ""
    console.print(f"Total findings: [bold]{total_findings}[/bold]{suffix}")
