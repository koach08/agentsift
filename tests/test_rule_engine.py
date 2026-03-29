"""Tests for the YAML rule engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentsift.analyzers.static import StaticAnalyzer
from agentsift.models import Severity
from agentsift.rules.engine import RuleLoadError, load_rule_file, load_rules_dir


def _write_yaml(directory: Path, name: str, content: str) -> Path:
    path = directory / name
    path.write_text(content)
    return path


class TestLoadRuleFile:
    def test_loads_single_rule(self, tmp_path: Path) -> None:
        _write_yaml(
            tmp_path,
            "test.yaml",
            """
id: TEST-001
name: test-rule
severity: high
category: exfiltration
description: Test rule for unit testing
patterns:
  - type: code
    match: 'dangerous_function\('
""",
        )
        rules = load_rule_file(tmp_path / "test.yaml")
        assert len(rules) == 1
        assert rules[0].rule_id == "TEST-001"
        assert rules[0].severity == Severity.HIGH

    def test_loads_multiple_rules(self, tmp_path: Path) -> None:
        _write_yaml(
            tmp_path,
            "multi.yaml",
            """
- id: TEST-002
  name: rule-a
  severity: critical
  category: credential-theft
  description: First rule
  patterns:
    - match: "steal_creds"

- id: TEST-003
  name: rule-b
  severity: low
  category: suspicious-network
  description: Second rule
  patterns:
    - match: "phone_home"
""",
        )
        rules = load_rule_file(tmp_path / "multi.yaml")
        assert len(rules) == 2

    def test_rejects_missing_fields(self, tmp_path: Path) -> None:
        _write_yaml(
            tmp_path,
            "bad.yaml",
            """
id: TEST-BAD
name: no-patterns
severity: high
description: Missing patterns field
""",
        )
        with pytest.raises(RuleLoadError, match="no patterns"):
            load_rule_file(tmp_path / "bad.yaml")

    def test_rejects_invalid_severity(self, tmp_path: Path) -> None:
        _write_yaml(
            tmp_path,
            "bad_sev.yaml",
            """
id: TEST-BAD2
name: bad-severity
severity: super-high
category: exfiltration
description: Invalid severity
patterns:
  - match: "test"
""",
        )
        with pytest.raises(RuleLoadError, match="Invalid severity"):
            load_rule_file(tmp_path / "bad_sev.yaml")


class TestLoadRulesDir:
    def test_loads_all_yaml_files(self, tmp_path: Path) -> None:
        for i in range(3):
            _write_yaml(
                tmp_path,
                f"rule_{i}.yaml",
                f"""
id: DIR-{i:03d}
name: dir-rule-{i}
severity: medium
category: exfiltration
description: Directory rule {i}
patterns:
  - match: "pattern_{i}"
""",
            )
        rules = load_rules_dir(tmp_path)
        assert len(rules) == 3

    def test_raises_on_missing_directory(self) -> None:
        with pytest.raises(RuleLoadError, match="not found"):
            load_rules_dir(Path("/nonexistent"))


class TestCustomRulesIntegration:
    def test_custom_rule_detects_pattern(self, tmp_path: Path) -> None:
        # Write custom rule
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        _write_yaml(
            rules_dir,
            "custom.yaml",
            """
id: CUSTOM-001
name: custom-detect
severity: critical
category: exfiltration
description: Detects custom evil pattern
patterns:
  - match: "super_evil_function"
""",
        )

        # Write target file
        code_dir = tmp_path / "code"
        code_dir.mkdir()
        (code_dir / "app.py").write_text("result = super_evil_function(data)")

        # Load rules and scan
        custom_rules = load_rules_dir(rules_dir)
        analyzer = StaticAnalyzer(extra_rules=custom_rules)
        files = list(code_dir.glob("*.py"))
        findings = analyzer.analyze(files, code_dir)

        assert any(f.rule_id == "CUSTOM-001" for f in findings)
