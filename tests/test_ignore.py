"""Tests for the ignore / whitelist engine."""

from pathlib import Path

from agentsift.ignore import IgnoreConfig, load_ignore_config, parse_ignore_file
from agentsift.models import Finding, FindingCategory, Severity


def _make_finding(
    rule_id: str = "AS-001",
    file_path: str = "src/main.py",
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        name="test-finding",
        severity=severity,
        category=FindingCategory.CREDENTIAL_THEFT,
        description="Test finding",
        file_path=file_path,
        line_number=10,
    )


class TestIgnoreConfig:
    def test_ignore_by_rule_id(self) -> None:
        config = IgnoreConfig(ignored_rules={"AS-001"})
        finding = _make_finding(rule_id="AS-001")
        assert config.should_ignore(finding) is True

    def test_not_ignored_rule(self) -> None:
        config = IgnoreConfig(ignored_rules={"AS-002"})
        finding = _make_finding(rule_id="AS-001")
        assert config.should_ignore(finding) is False

    def test_ignore_by_file_pattern_glob(self) -> None:
        config = IgnoreConfig(ignored_file_patterns=["vendor/**"])
        finding = _make_finding(file_path="vendor/lib/pkg.js")
        assert config.should_ignore(finding) is True

    def test_ignore_by_file_pattern_prefix(self) -> None:
        config = IgnoreConfig(ignored_file_patterns=["tests/*"])
        finding = _make_finding(file_path="tests/test_main.py")
        assert config.should_ignore(finding) is True

    def test_file_pattern_no_match(self) -> None:
        config = IgnoreConfig(ignored_file_patterns=["vendor/**"])
        finding = _make_finding(file_path="src/main.py")
        assert config.should_ignore(finding) is False

    def test_filter_findings(self) -> None:
        config = IgnoreConfig(ignored_rules={"AS-001"})
        findings = [
            _make_finding(rule_id="AS-001"),
            _make_finding(rule_id="AS-002"),
            _make_finding(rule_id="AS-003"),
        ]
        filtered = config.filter_findings(findings)
        assert len(filtered) == 2
        assert all(f.rule_id != "AS-001" for f in filtered)

    def test_filter_findings_combined(self) -> None:
        config = IgnoreConfig(
            ignored_rules={"AS-001"},
            ignored_file_patterns=["tests/*"],
        )
        findings = [
            _make_finding(rule_id="AS-001", file_path="src/main.py"),
            _make_finding(rule_id="AS-010", file_path="tests/test_foo.py"),
            _make_finding(rule_id="AS-020", file_path="src/lib.py"),
        ]
        filtered = config.filter_findings(findings)
        assert len(filtered) == 1
        assert filtered[0].rule_id == "AS-020"

    def test_merge(self) -> None:
        a = IgnoreConfig(ignored_rules={"AS-001"}, ignored_file_patterns=["vendor/*"])
        b = IgnoreConfig(ignored_rules={"AS-002"}, ignored_file_patterns=["tests/*"])
        a.merge(b)
        assert a.ignored_rules == {"AS-001", "AS-002"}
        assert a.ignored_file_patterns == ["vendor/*", "tests/*"]

    def test_no_file_path_not_ignored_by_file_pattern(self) -> None:
        config = IgnoreConfig(ignored_file_patterns=["vendor/*"])
        finding = _make_finding()
        finding.file_path = None
        assert config.should_ignore(finding) is False


class TestParseIgnoreFile:
    def test_parse_basic(self, tmp_path: Path) -> None:
        ignore_file = tmp_path / ".agentsift-ignore"
        ignore_file.write_text(
            "# A comment\n"
            "rule:AS-001\n"
            "rule:AS-010,AS-011\n"
            "file:vendor/**\n"
            "file:tests/*\n"
        )
        config = parse_ignore_file(ignore_file)
        assert config.ignored_rules == {"AS-001", "AS-010", "AS-011"}
        assert config.ignored_file_patterns == ["vendor/**", "tests/*"]

    def test_parse_inline_comments(self, tmp_path: Path) -> None:
        ignore_file = tmp_path / ".agentsift-ignore"
        ignore_file.write_text("rule:AS-001 # env var access is expected\n")
        config = parse_ignore_file(ignore_file)
        assert config.ignored_rules == {"AS-001"}

    def test_parse_empty_lines(self, tmp_path: Path) -> None:
        ignore_file = tmp_path / ".agentsift-ignore"
        ignore_file.write_text("\n\n# only comments\n\n")
        config = parse_ignore_file(ignore_file)
        assert config.ignored_rules == set()
        assert config.ignored_file_patterns == []

    def test_parse_nonexistent_file(self, tmp_path: Path) -> None:
        config = parse_ignore_file(tmp_path / "nope")
        assert config.ignored_rules == set()


class TestLoadIgnoreConfig:
    def test_from_scan_dir(self, tmp_path: Path) -> None:
        ignore_file = tmp_path / ".agentsift-ignore"
        ignore_file.write_text("rule:AS-040\nfile:dist/*\n")
        config = load_ignore_config(scan_dir=tmp_path)
        assert "AS-040" in config.ignored_rules
        assert "dist/*" in config.ignored_file_patterns

    def test_from_cli_rules(self) -> None:
        config = load_ignore_config(ignore_rules=["AS-001,AS-002", "AS-003"])
        assert config.ignored_rules == {"AS-001", "AS-002", "AS-003"}

    def test_combined(self, tmp_path: Path) -> None:
        ignore_file = tmp_path / ".agentsift-ignore"
        ignore_file.write_text("rule:AS-001\n")
        config = load_ignore_config(scan_dir=tmp_path, ignore_rules=["AS-010"])
        assert config.ignored_rules == {"AS-001", "AS-010"}

    def test_no_ignore_file(self, tmp_path: Path) -> None:
        config = load_ignore_config(scan_dir=tmp_path)
        assert config.ignored_rules == set()
