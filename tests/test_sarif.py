"""Tests for the SARIF output reporter."""

from __future__ import annotations

import json
from datetime import datetime

from agentsift.models import (
    Finding,
    FindingCategory,
    PackageInfo,
    Ecosystem,
    RiskScore,
    ScanResult,
    Severity,
)
from agentsift.reporters.sarif import generate_sarif, sarif_to_json


def _make_result() -> ScanResult:
    return ScanResult(
        package=PackageInfo(
            name="test-package",
            version="1.0.0",
            ecosystem=Ecosystem.NPM,
        ),
        findings=[
            Finding(
                rule_id="AS-001",
                name="test-finding",
                severity=Severity.HIGH,
                category=FindingCategory.CREDENTIAL_THEFT,
                description="Test finding description",
                file_path="src/index.js",
                line_number=42,
                code_snippet="os.environ['API_KEY']",
            ),
            Finding(
                rule_id="AS-030",
                name="prompt-injection",
                severity=Severity.CRITICAL,
                category=FindingCategory.PROMPT_INJECTION,
                description="Prompt injection detected",
                file_path="SKILL.md",
                line_number=5,
            ),
        ],
        risk_score=RiskScore(score=40),
        files_scanned=10,
        scan_duration_ms=500,
    )


class TestSarifGeneration:
    def test_valid_sarif_schema(self) -> None:
        result = _make_result()
        sarif = generate_sarif(result)

        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1

    def test_tool_info(self) -> None:
        result = _make_result()
        sarif = generate_sarif(result)
        driver = sarif["runs"][0]["tool"]["driver"]

        assert driver["name"] == "AgentSift"
        assert "rules" in driver
        assert len(driver["rules"]) == 2  # Two unique rules

    def test_results_count(self) -> None:
        result = _make_result()
        sarif = generate_sarif(result)
        results = sarif["runs"][0]["results"]

        assert len(results) == 2

    def test_severity_mapping(self) -> None:
        result = _make_result()
        sarif = generate_sarif(result)
        results = sarif["runs"][0]["results"]

        # HIGH -> error
        assert results[0]["level"] == "error"
        # CRITICAL -> error
        assert results[1]["level"] == "error"

    def test_location_info(self) -> None:
        result = _make_result()
        sarif = generate_sarif(result)
        results = sarif["runs"][0]["results"]

        location = results[0]["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "src/index.js"
        assert location["region"]["startLine"] == 42

    def test_json_serializable(self) -> None:
        result = _make_result()
        json_str = sarif_to_json(result)
        parsed = json.loads(json_str)
        assert parsed["version"] == "2.1.0"

    def test_empty_findings(self) -> None:
        result = ScanResult(
            package=PackageInfo(name="clean", ecosystem=Ecosystem.LOCAL),
            findings=[],
        )
        sarif = generate_sarif(result)
        assert len(sarif["runs"][0]["results"]) == 0
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 0
