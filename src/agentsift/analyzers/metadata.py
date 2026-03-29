"""Metadata analyzer -- detect suspicious patterns in package metadata."""

from __future__ import annotations

import re

from agentsift.models import Finding, FindingCategory, Severity


class MetadataAnalyzer:
    """Analyze package metadata for suspicious patterns."""

    def analyze_npm(self, package_info: dict) -> list[Finding]:
        """Analyze npm package metadata for security issues."""
        findings: list[Finding] = []

        # Check lifecycle scripts (postinstall, preinstall, etc.)
        findings.extend(self._check_npm_scripts(package_info))

        # Check for suspicious dependencies
        findings.extend(self._check_suspicious_deps(package_info))

        # Check author/metadata anomalies
        findings.extend(self._check_author_anomalies(package_info))

        return findings

    def _check_npm_scripts(self, info: dict) -> list[Finding]:
        """Check for dangerous lifecycle scripts."""
        findings: list[Finding] = []
        scripts = info.get("scripts", {})

        # Dangerous lifecycle hooks
        dangerous_hooks = {
            "preinstall", "install", "postinstall",
            "preuninstall", "postuninstall",
            "prepublish", "prepare",
        }

        dangerous_patterns = [
            (re.compile(r"curl\s+.*\|\s*(?:bash|sh|node)", re.IGNORECASE),
             "Downloads and executes remote script"),
            (re.compile(r"wget\s+.*&&\s*(?:bash|sh|chmod)", re.IGNORECASE),
             "Downloads and executes remote script via wget"),
            (re.compile(r"node\s+-e\s+['\"]", re.IGNORECASE),
             "Executes inline Node.js code"),
            (re.compile(r"powershell|cmd\s*/c", re.IGNORECASE),
             "Executes system shell commands"),
            (re.compile(r"rm\s+-rf\s+/|del\s+/[sf]", re.IGNORECASE),
             "Destructive file deletion command"),
            (re.compile(r"nc\s+-|ncat\s|netcat", re.IGNORECASE),
             "Uses netcat (potential reverse shell)"),
            (re.compile(r"https?://(?!registry\.npmjs\.org|github\.com|githubusercontent\.com)",
                        re.IGNORECASE),
             "Contacts external URL during install"),
        ]

        for hook_name, script_value in scripts.items():
            if hook_name not in dangerous_hooks:
                continue

            # Any lifecycle script is worth flagging
            findings.append(Finding(
                rule_id="AS-050",
                name="npm-lifecycle-script",
                severity=Severity.MEDIUM,
                category=FindingCategory.SUSPICIOUS_NETWORK,
                description=f"Package has a '{hook_name}' lifecycle script: {script_value[:100]}",
                file_path="package.json",
                confidence=0.6,
            ))

            # Check for dangerous patterns in scripts
            for pattern, desc in dangerous_patterns:
                if pattern.search(script_value):
                    findings.append(Finding(
                        rule_id="AS-051",
                        name="npm-dangerous-script",
                        severity=Severity.CRITICAL,
                        category=FindingCategory.EXFILTRATION,
                        description=f"Dangerous pattern in '{hook_name}': {desc}",
                        file_path="package.json",
                        code_snippet=script_value[:200],
                        confidence=0.9,
                    ))

        return findings

    def _check_suspicious_deps(self, info: dict) -> list[Finding]:
        """Check for suspicious dependency patterns."""
        findings: list[Finding] = []
        deps = info.get("dependencies", {})

        # Known suspicious package name patterns (typosquatting indicators)
        suspicious_patterns = [
            re.compile(r"^@[a-z]+-[a-z]+/"),  # Scoped packages mimicking orgs
            re.compile(r"(?:crypt[o0]|wall[e3]t|s[e3][e3]d|k[e3]y)", re.IGNORECASE),
        ]

        for dep_name, dep_version in deps.items():
            # Check for git/URL dependencies (bypass npm registry)
            if any(dep_version.startswith(prefix)
                   for prefix in ("git+", "http://", "https://", "git://")):
                findings.append(Finding(
                    rule_id="AS-052",
                    name="npm-git-dependency",
                    severity=Severity.HIGH,
                    category=FindingCategory.MALICIOUS_DEPENDENCY,
                    description=f"Dependency '{dep_name}' installed from URL: {dep_version}",
                    file_path="package.json",
                    confidence=0.7,
                ))

        return findings

    def _check_author_anomalies(self, info: dict) -> list[Finding]:
        """Check for suspicious author/metadata patterns."""
        findings: list[Finding] = []

        # No author info at all
        if not info.get("author"):
            findings.append(Finding(
                rule_id="AS-053",
                name="npm-no-author",
                severity=Severity.LOW,
                category=FindingCategory.SUSPICIOUS_NETWORK,
                description="Package has no author information",
                file_path="package.json",
                confidence=0.4,
            ))

        # Empty or suspiciously short description
        desc = info.get("description", "")
        if len(desc) < 10:
            findings.append(Finding(
                rule_id="AS-054",
                name="npm-sparse-metadata",
                severity=Severity.LOW,
                category=FindingCategory.SUSPICIOUS_NETWORK,
                description="Package has minimal or no description",
                file_path="package.json",
                confidence=0.3,
            ))

        return findings
