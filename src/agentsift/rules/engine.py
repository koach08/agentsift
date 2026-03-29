"""YAML-based detection rule engine.

Loads custom detection rules from YAML files, enabling community-contributed
rules and organization-specific policies.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from agentsift.analyzers.static import DetectionRule
from agentsift.models import FindingCategory, Severity

# Mapping from YAML string values to enum values
_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

_CATEGORY_MAP = {
    "exfiltration": FindingCategory.EXFILTRATION,
    "credential-theft": FindingCategory.CREDENTIAL_THEFT,
    "code-obfuscation": FindingCategory.CODE_OBFUSCATION,
    "prompt-injection": FindingCategory.PROMPT_INJECTION,
    "privilege-escalation": FindingCategory.PRIVILEGE_ESCALATION,
    "suspicious-network": FindingCategory.SUSPICIOUS_NETWORK,
    "malicious-dependency": FindingCategory.MALICIOUS_DEPENDENCY,
}


class RuleLoadError(Exception):
    """Error loading a detection rule."""


def load_rule_file(path: Path) -> list[DetectionRule]:
    """Load detection rules from a YAML file.

    A YAML file can contain a single rule (dict) or multiple rules (list).
    """
    with open(path) as f:
        data = yaml.safe_load(f)

    if data is None:
        return []

    if isinstance(data, dict):
        return [_parse_rule(data, path)]
    if isinstance(data, list):
        return [_parse_rule(item, path) for item in data if isinstance(item, dict)]

    raise RuleLoadError(f"Invalid rule file format: {path}")


def load_rules_dir(directory: Path) -> list[DetectionRule]:
    """Load all YAML rules from a directory (non-recursive)."""
    rules: list[DetectionRule] = []
    if not directory.is_dir():
        raise RuleLoadError(f"Rules directory not found: {directory}")

    for path in sorted(directory.glob("*.yaml")):
        rules.extend(load_rule_file(path))
    for path in sorted(directory.glob("*.yml")):
        rules.extend(load_rule_file(path))

    return rules


def _parse_rule(data: dict[str, Any], source: Path) -> DetectionRule:
    """Parse a single rule from YAML data."""
    try:
        rule_id = data["id"]
        name = data["name"]
        severity_str = data["severity"].lower()
        category_str = data.get("category", "suspicious-network").lower()
        description = data["description"]
    except KeyError as e:
        raise RuleLoadError(f"Missing required field {e} in {source}") from e

    severity = _SEVERITY_MAP.get(severity_str)
    if severity is None:
        raise RuleLoadError(
            f"Invalid severity '{severity_str}' in {source}. "
            f"Must be one of: {', '.join(_SEVERITY_MAP.keys())}"
        )

    category = _CATEGORY_MAP.get(category_str)
    if category is None:
        raise RuleLoadError(
            f"Invalid category '{category_str}' in {source}. "
            f"Must be one of: {', '.join(_CATEGORY_MAP.keys())}"
        )

    # Build regex pattern from patterns list
    patterns = data.get("patterns", [])
    if not patterns:
        raise RuleLoadError(f"Rule {rule_id} in {source} has no patterns")

    # Combine code patterns into a single regex
    regex_parts: list[str] = []
    for p in patterns:
        if isinstance(p, str):
            regex_parts.append(p)
        elif isinstance(p, dict) and p.get("type") == "code":
            regex_parts.append(p["match"])
        elif isinstance(p, dict) and p.get("match"):
            regex_parts.append(p["match"])

    if not regex_parts:
        raise RuleLoadError(f"Rule {rule_id} in {source} has no code patterns")

    combined = "|".join(f"(?:{part})" for part in regex_parts)

    flags = re.IGNORECASE if data.get("case_insensitive", False) else 0

    try:
        pattern = re.compile(combined, flags)
    except re.error as e:
        raise RuleLoadError(f"Invalid regex in rule {rule_id}: {e}") from e

    # File type filtering
    file_types = data.get("file_types")
    file_types_set = set(file_types) if file_types else None

    return DetectionRule(
        rule_id=rule_id,
        name=name,
        severity=severity,
        category=category,
        description=description,
        pattern=pattern,
        file_types=file_types_set,
    )
