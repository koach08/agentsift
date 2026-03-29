"""CLI entry point for AgentSift."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agentsift import __version__
from agentsift.models import Ecosystem, PackageInfo, ScanResult, Severity
from agentsift.analyzers.static import StaticAnalyzer
from agentsift.scanners.local import LocalScanner
from agentsift.scanners.registry import parse_target

console = Console()


def _severity_color(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }[severity]


def _risk_color(score: int) -> str:
    if score <= 10:
        return "green"
    if score <= 30:
        return "blue"
    if score <= 60:
        return "yellow"
    if score <= 85:
        return "red"
    return "red bold"


def _render_result(result: ScanResult) -> None:
    """Render scan results to the terminal."""
    pkg = result.package

    # Header
    console.print()
    console.print(
        Panel(
            f"[bold]{pkg.name}[/bold] {pkg.version or ''}\n"
            f"Ecosystem: {pkg.ecosystem.value} | Files scanned: {result.files_scanned} | "
            f"Duration: {result.scan_duration_ms}ms",
            title="AgentSift Scan Report",
        )
    )

    # Risk Score
    color = _risk_color(result.risk_score.score)
    console.print(
        f"\n  Risk Score: [{color}]{result.risk_score.score}/100 "
        f"({result.risk_score.label.upper()})[/{color}]"
    )

    if result.risk_score.factors:
        for factor in result.risk_score.factors:
            console.print(f"    - {factor}")

    # Findings
    if not result.findings:
        console.print("\n  [green]No security issues found.[/green]\n")
        return

    console.print(f"\n  [bold]Findings ({len(result.findings)}):[/bold]\n")

    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity", width=10)
    table.add_column("Rule", width=16)
    table.add_column("Description", min_width=40)
    table.add_column("Location", width=30)

    for f in sorted(result.findings, key=lambda x: list(Severity).index(x.severity)):
        color = _severity_color(f.severity)
        location = ""
        if f.file_path:
            location = f.file_path
            if f.line_number:
                location += f":{f.line_number}"

        table.add_row(
            f"[{color}]{f.severity.value.upper()}[/{color}]",
            f.rule_id,
            f.description,
            location,
        )

    console.print(table)
    console.print()


@click.group()
@click.version_option(__version__, prog_name="agentsift")
def main() -> None:
    """AgentSift -- Security scanner for AI agent plugins and MCP packages."""


@main.command()
@click.argument("target")
@click.option("--deep", is_flag=True, help="Enable behavioral sandbox analysis")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["human", "json", "sarif"]),
    default="human",
    help="Output format",
)
@click.option("-o", "--output", "output_file", type=click.Path(), help="Write output to file")
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low"]),
    default=None,
    help="Exit with code 1 if findings at or above this severity",
)
def scan(
    target: str,
    deep: bool,
    output_format: str,
    output_file: str | None,
    fail_on: str | None,
) -> None:
    """Scan an AI agent package for security issues.

    TARGET can be:
      - clawhub:package-name
      - npm:@scope/package-name
      - pypi:package-name
      - ./local/path/
    """
    console.print(f"[bold]AgentSift v{__version__}[/bold] -- Scanning {target}\n")

    start_time = time.time()

    # Resolve target
    ecosystem, package_name, local_path = parse_target(target)

    if local_path:
        scanner = LocalScanner()
        scan_dir = local_path
    else:
        # TODO: Implement registry scanners (download + extract)
        console.print(f"[yellow]Registry scanning for {ecosystem.value} is not yet implemented.[/yellow]")
        console.print(f"[dim]For now, use a local path: agentsift scan ./path/to/plugin/[/dim]")
        sys.exit(1)

    # Fetch files
    files = scanner.collect_files(scan_dir)
    console.print(f"  Collected {len(files)} files for analysis")

    # Run analyzers
    analyzer = StaticAnalyzer()
    findings = analyzer.analyze(files, scan_dir)

    if deep:
        console.print("  [yellow]Behavioral sandbox not yet implemented[/yellow]")

    elapsed_ms = int((time.time() - start_time) * 1000)

    # Build result
    package_info = PackageInfo(
        name=package_name,
        ecosystem=ecosystem,
    )

    result = ScanResult(
        package=package_info,
        findings=findings,
        files_scanned=len(files),
        scan_duration_ms=elapsed_ms,
        analyzers_used=["static"],
    )

    # Calculate risk score
    result.risk_score = analyzer.calculate_risk_score(result.findings)

    # Output
    if output_format == "json":
        json_output = result.model_dump_json(indent=2)
        if output_file:
            Path(output_file).write_text(json_output)
            console.print(f"  Results written to {output_file}")
        else:
            click.echo(json_output)
    elif output_format == "sarif":
        console.print("[yellow]SARIF output not yet implemented[/yellow]")
    else:
        _render_result(result)

    # Exit code for CI/CD
    if fail_on:
        severity_order = ["critical", "high", "medium", "low"]
        threshold = severity_order.index(fail_on)
        for finding in result.findings:
            if severity_order.index(finding.severity.value) <= threshold:
                sys.exit(1)


@main.command()
@click.argument("target")
@click.option(
    "--format",
    "sbom_format",
    type=click.Choice(["cyclonedx", "spdx"]),
    default="cyclonedx",
)
@click.option("-o", "--output", "output_file", type=click.Path(), help="Write SBOM to file")
def sbom(target: str, sbom_format: str, output_file: str | None) -> None:
    """Generate Software Bill of Materials for an agent package."""
    console.print(f"[yellow]SBOM generation not yet implemented[/yellow]")


if __name__ == "__main__":
    main()
