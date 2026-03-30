"""Tests for the CycloneDX SBOM generator."""

from __future__ import annotations

import json

from agentsift.models import (
    Ecosystem,
    Finding,
    FindingCategory,
    PackageInfo,
    RiskScore,
    ScanResult,
    Severity,
)
from agentsift.reporters.cyclonedx import cyclonedx_to_json, generate_cyclonedx


def _make_result() -> ScanResult:
    return ScanResult(
        package=PackageInfo(
            name="@modelcontextprotocol/server-memory",
            version="2026.1.26",
            ecosystem=Ecosystem.NPM,
            description="MCP server for memory management",
        ),
        findings=[
            Finding(
                rule_id="AS-050",
                name="npm-lifecycle-script",
                severity=Severity.MEDIUM,
                category=FindingCategory.SUSPICIOUS_NETWORK,
                description="Package has a 'prepare' lifecycle script",
                file_path="package.json",
            ),
        ],
        risk_score=RiskScore(score=8),
        files_scanned=5,
    )


class TestCycloneDX:
    def test_valid_format(self) -> None:
        result = _make_result()
        bom = generate_cyclonedx(result)

        assert bom["bomFormat"] == "CycloneDX"
        assert bom["specVersion"] == "1.5"
        assert "serialNumber" in bom
        assert len(bom["components"]) >= 1

    def test_main_component(self) -> None:
        result = _make_result()
        bom = generate_cyclonedx(result)
        comp = bom["components"][0]

        assert comp["name"] == "@modelcontextprotocol/server-memory"
        assert comp["version"] == "2026.1.26"
        assert "purl" in comp

    def test_includes_dependencies(self) -> None:
        result = _make_result()
        deps = [
            {"name": "zod", "version": "^3.22"},
            {"name": "@modelcontextprotocol/sdk", "version": "^1.0"},
        ]
        bom = generate_cyclonedx(result, deps)

        assert len(bom["components"]) == 3  # main + 2 deps

    def test_includes_vulnerabilities(self) -> None:
        result = _make_result()
        bom = generate_cyclonedx(result)

        assert "vulnerabilities" in bom
        assert len(bom["vulnerabilities"]) == 1
        assert bom["vulnerabilities"][0]["id"] == "AS-050"

    def test_no_vulns_when_clean(self) -> None:
        result = ScanResult(
            package=PackageInfo(name="clean-pkg", ecosystem=Ecosystem.LOCAL),
            findings=[],
        )
        bom = generate_cyclonedx(result)
        assert "vulnerabilities" not in bom

    def test_json_serializable(self) -> None:
        result = _make_result()
        output = cyclonedx_to_json(result)
        parsed = json.loads(output)
        assert parsed["bomFormat"] == "CycloneDX"

    def test_risk_score_in_properties(self) -> None:
        result = _make_result()
        bom = generate_cyclonedx(result)
        props = {p["name"]: p["value"] for p in bom["components"][0]["properties"]}
        assert props["agentsift:risk-score"] == "8"
        assert props["agentsift:risk-label"] == "safe"
