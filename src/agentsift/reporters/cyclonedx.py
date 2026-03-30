"""CycloneDX SBOM (Software Bill of Materials) generator.

Generates CycloneDX v1.5 compatible BOM for AI agent packages,
including their dependencies, license information, and security metadata.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from agentsift import __version__
from agentsift.models import ScanResult


def generate_cyclonedx(result: ScanResult, dependencies: list[dict] | None = None) -> dict[str, Any]:
    """Generate a CycloneDX v1.5 BOM from scan results."""
    pkg = result.package
    serial = f"urn:uuid:{uuid.uuid4()}"

    components: list[dict[str, Any]] = [
        {
            "type": "library",
            "bom-ref": f"{pkg.ecosystem.value}:{pkg.name}@{pkg.version or 'unknown'}",
            "name": pkg.name,
            "version": pkg.version or "unknown",
            "description": pkg.description or "",
            "purl": _build_purl(pkg.ecosystem.value, pkg.name, pkg.version),
            "properties": [
                {"name": "agentsift:ecosystem", "value": pkg.ecosystem.value},
                {"name": "agentsift:risk-score", "value": str(result.risk_score.score)},
                {"name": "agentsift:risk-label", "value": result.risk_score.label},
            ],
        }
    ]

    # Add dependencies as components
    if dependencies:
        for dep in dependencies:
            dep_name = dep.get("name", "")
            dep_version = dep.get("version", "*")
            components.append({
                "type": "library",
                "bom-ref": f"{dep_name}@{dep_version}",
                "name": dep_name,
                "version": dep_version,
            })

    # Add vulnerability entries from findings
    vulnerabilities: list[dict[str, Any]] = []
    for finding in result.findings:
        vuln: dict[str, Any] = {
            "id": finding.rule_id,
            "source": {
                "name": "AgentSift",
                "url": "https://github.com/koach08/agentsift",
            },
            "ratings": [
                {
                    "severity": finding.severity.value,
                    "method": "other",
                    "source": {"name": "AgentSift"},
                }
            ],
            "description": finding.description,
            "affects": [
                {
                    "ref": components[0]["bom-ref"],
                }
            ],
            "properties": [
                {"name": "agentsift:category", "value": finding.category.value},
                {"name": "agentsift:confidence", "value": str(finding.confidence)},
            ],
        }
        if finding.file_path:
            vuln["properties"].append(
                {"name": "agentsift:file", "value": finding.file_path}
            )
        vulnerabilities.append(vuln)

    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "AgentSift",
                        "version": __version__,
                        "description": "Security scanner for AI agent plugins and MCP packages",
                    }
                ]
            },
            "component": components[0],
        },
        "components": components,
    }

    if vulnerabilities:
        bom["vulnerabilities"] = vulnerabilities

    return bom


def cyclonedx_to_json(result: ScanResult, dependencies: list[dict] | None = None) -> str:
    """Generate CycloneDX JSON string."""
    return json.dumps(generate_cyclonedx(result, dependencies), indent=2)


def _build_purl(ecosystem: str, name: str, version: str | None) -> str:
    """Build Package URL (purl) for the component."""
    purl_type_map = {
        "npm": "npm",
        "mcp-npm": "npm",
        "pypi": "pypi",
        "mcp-pypi": "pypi",
        "clawhub": "generic",
        "local": "generic",
    }
    purl_type = purl_type_map.get(ecosystem, "generic")
    ver = f"@{version}" if version else ""

    if purl_type == "npm" and "/" in name:
        # Scoped npm packages: @scope/name -> pkg:npm/%40scope/name
        scope, pkg_name = name.split("/", 1)
        return f"pkg:{purl_type}/{scope}/{pkg_name}{ver}"

    return f"pkg:{purl_type}/{name}{ver}"
