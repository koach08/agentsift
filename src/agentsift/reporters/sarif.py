"""SARIF (Static Analysis Results Interchange Format) output for CI/CD integration.

Generates SARIF v2.1.0 compatible output for:
- GitHub Advanced Security (Code Scanning)
- GitLab SAST
- Azure DevOps
"""

from __future__ import annotations

import json
from typing import Any

from agentsift import __version__
from agentsift.models import Finding, ScanResult, Severity

# SARIF severity mapping
_SARIF_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}

# SARIF security-severity scores (for GitHub Code Scanning)
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.5",
    Severity.INFO: "0.5",
}


def generate_sarif(result: ScanResult) -> dict[str, Any]:
    """Generate a SARIF v2.1.0 document from scan results."""
    rules = _build_rules(result.findings)
    results = _build_results(result.findings, rules)

    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AgentSift",
                        "version": __version__,
                        "informationUri": "https://github.com/koach08/agentsift",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": [],
                    }
                ],
            }
        ],
    }


def sarif_to_json(result: ScanResult, indent: int = 2) -> str:
    """Generate SARIF JSON string from scan results."""
    return json.dumps(generate_sarif(result), indent=indent)


def _build_rules(findings: list[Finding]) -> dict[str, dict[str, Any]]:
    """Build unique SARIF rule definitions from findings."""
    rules: dict[str, dict[str, Any]] = {}

    for f in findings:
        if f.rule_id in rules:
            continue

        rules[f.rule_id] = {
            "id": f.rule_id,
            "name": f.name,
            "shortDescription": {"text": f.description},
            "fullDescription": {"text": f.description},
            "defaultConfiguration": {
                "level": _SARIF_LEVELS[f.severity],
            },
            "properties": {
                "tags": ["security", f.category.value],
                "security-severity": _SECURITY_SEVERITY[f.severity],
            },
        }

    return rules


def _build_results(
    findings: list[Finding], rules: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """Build SARIF result entries from findings."""
    results: list[dict[str, Any]] = []
    rule_ids = list(rules.keys())

    for f in findings:
        result_entry: dict[str, Any] = {
            "ruleId": f.rule_id,
            "ruleIndex": rule_ids.index(f.rule_id),
            "level": _SARIF_LEVELS[f.severity],
            "message": {"text": f.description},
        }

        # Add location if available
        if f.file_path:
            location: dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.file_path,
                        "uriBaseId": "%SRCROOT%",
                    },
                }
            }
            if f.line_number:
                location["physicalLocation"]["region"] = {
                    "startLine": f.line_number,
                }
            result_entry["locations"] = [location]

        # Add code snippet if available
        if f.code_snippet:
            result_entry["fingerprints"] = {}
            result_entry["relatedLocations"] = []

        results.append(result_entry)

    return results
