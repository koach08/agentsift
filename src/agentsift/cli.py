"""CLI entry point for AgentSift."""

from __future__ import annotations

import shutil
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agentsift import __version__
from agentsift.models import Ecosystem, PackageInfo, ScanResult, Severity
from agentsift.analyzers.metadata import MetadataAnalyzer
from agentsift.analyzers.static import StaticAnalyzer
from agentsift.reporters.sarif import sarif_to_json
from agentsift.rules.engine import load_rules_dir
from agentsift.scanners.clawhub import ClawHubScanner
from agentsift.scanners.local import LocalScanner
from agentsift.scanners.npm import NpmScanner
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
@click.option(
    "--rules",
    "rules_dir",
    type=click.Path(exists=True, file_okay=False),
    default=None,
    help="Directory containing custom YAML detection rules",
)
def scan(
    target: str,
    deep: bool,
    output_format: str,
    output_file: str | None,
    fail_on: str | None,
    rules_dir: str | None,
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

    temp_dir: Path | None = None
    npm_package_info: dict | None = None
    clawhub_package_info: dict | None = None

    if local_path:
        scan_dir = local_path
    elif ecosystem in (Ecosystem.NPM, Ecosystem.MCP_NPM):
        console.print(f"  Fetching {package_name} from npm registry...")
        with NpmScanner() as npm:
            temp_dir, scan_dir, version_meta, version = npm.download_and_extract(package_name)
            npm_package_info = npm.extract_package_info(package_name, version_meta, version)
        console.print(f"  Downloaded {package_name}@{version}")
    elif ecosystem == Ecosystem.CLAWHUB:
        console.print(f"  Fetching {package_name} from ClawHub registry...")
        with ClawHubScanner() as ch:
            temp_dir, scan_dir, meta, version = ch.download_and_extract(package_name)
            clawhub_package_info = ch.extract_package_info(package_name, meta, version)
            # Also parse SKILL.md for additional metadata
            skill_meta = ch.parse_skill_md(scan_dir)
            if skill_meta and not clawhub_package_info.get("description"):
                clawhub_package_info["description"] = skill_meta.get("description", "")
        console.print(f"  Downloaded {package_name}@{version}")
    else:
        console.print(f"[yellow]Registry scanning for {ecosystem.value} is not yet implemented.[/yellow]")
        console.print(f"[dim]For now, use a local path: agentsift scan ./path/to/plugin/[/dim]")
        sys.exit(1)

    try:
        # Fetch files
        local_scanner = LocalScanner()
        files = local_scanner.collect_files(scan_dir)
        console.print(f"  Collected {len(files)} files for analysis")

        # Load custom rules if provided
        extra_rules = None
        if rules_dir:
            extra_rules = load_rules_dir(Path(rules_dir))
            console.print(f"  Loaded {len(extra_rules)} custom rules from {rules_dir}")

        # Run static analyzer
        static = StaticAnalyzer(extra_rules=extra_rules)
        findings = static.analyze(files, scan_dir)

        # Run metadata analyzer for npm packages
        analyzers_used = ["static"]
        if npm_package_info:
            meta_analyzer = MetadataAnalyzer()
            findings.extend(meta_analyzer.analyze_npm(npm_package_info))
            analyzers_used.append("metadata")

        if deep:
            console.print("  [yellow]Behavioral sandbox not yet implemented[/yellow]")

        elapsed_ms = int((time.time() - start_time) * 1000)

        # Build result
        pkg_info = npm_package_info or clawhub_package_info or {}
        package_info = PackageInfo(
            name=package_name,
            version=pkg_info.get("version"),
            ecosystem=ecosystem,
            author=pkg_info.get("author"),
            description=pkg_info.get("description"),
        )

        result = ScanResult(
            package=package_info,
            findings=findings,
            files_scanned=len(files),
            scan_duration_ms=elapsed_ms,
            analyzers_used=analyzers_used,
        )

        # Calculate risk score
        result.risk_score = static.calculate_risk_score(result.findings)

    finally:
        # Clean up temp directory
        if temp_dir and temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)

    # Output
    if output_format == "json":
        json_output = result.model_dump_json(indent=2)
        if output_file:
            Path(output_file).write_text(json_output)
            console.print(f"  Results written to {output_file}")
        else:
            click.echo(json_output)
    elif output_format == "sarif":
        sarif_output = sarif_to_json(result)
        if output_file:
            Path(output_file).write_text(sarif_output)
            console.print(f"  SARIF results written to {output_file}")
        else:
            click.echo(sarif_output)
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
