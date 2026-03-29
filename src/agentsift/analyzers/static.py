"""Static analysis engine -- pattern-based detection of malicious code."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from agentsift.models import (
    Finding,
    FindingCategory,
    RiskScore,
    Severity,
)


@dataclass
class DetectionRule:
    """A pattern-based detection rule."""

    rule_id: str
    name: str
    severity: Severity
    category: FindingCategory
    description: str
    pattern: re.Pattern[str]
    file_types: set[str] | None = None  # None = all files


# Built-in detection rules
_RULES: list[DetectionRule] = [
    # --- Credential Theft ---
    DetectionRule(
        rule_id="AS-001",
        name="env-var-sensitive-access",
        severity=Severity.HIGH,
        category=FindingCategory.CREDENTIAL_THEFT,
        description="Accesses sensitive environment variables (API keys, tokens, secrets)",
        pattern=re.compile(
            r"""(?:os\.environ|process\.env)\s*[\[.(]\s*['"]"""
            r"""(?:API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|AWS_|OPENAI_|ANTHROPIC_|"""
            r"""DATABASE_URL|SUPABASE_|STRIPE_|SSH_|GITHUB_TOKEN)""",
            re.IGNORECASE,
        ),
        file_types={".py", ".js", ".ts", ".mjs", ".cjs"},
    ),
    DetectionRule(
        rule_id="AS-002",
        name="ssh-key-access",
        severity=Severity.CRITICAL,
        category=FindingCategory.CREDENTIAL_THEFT,
        description="Attempts to read SSH private keys",
        pattern=re.compile(
            r"""(?:\.ssh/id_|\.ssh/known_hosts|id_rsa|id_ed25519|id_ecdsa)""",
        ),
        file_types={".py", ".js", ".ts", ".sh"},
    ),
    DetectionRule(
        rule_id="AS-003",
        name="crypto-wallet-access",
        severity=Severity.CRITICAL,
        category=FindingCategory.CREDENTIAL_THEFT,
        description="Attempts to access cryptocurrency wallet files or seed phrases",
        pattern=re.compile(
            r"""(?:wallet\.dat|seed_phrase|mnemonic|keystore/|\.ethereum/|\.bitcoin/|"""
            r"""phantom.*wallet|metamask.*vault)""",
            re.IGNORECASE,
        ),
    ),
    DetectionRule(
        rule_id="AS-004",
        name="browser-credential-access",
        severity=Severity.CRITICAL,
        category=FindingCategory.CREDENTIAL_THEFT,
        description="Attempts to access browser credential stores",
        pattern=re.compile(
            r"""(?:Login\s*Data|Cookies|chrome.*(?:Default|Profile)|"""
            r"""firefox.*profiles|\.mozilla/|keychain|Credential\s*Manager)""",
            re.IGNORECASE,
        ),
    ),
    # --- Network Exfiltration ---
    DetectionRule(
        rule_id="AS-010",
        name="hidden-http-exfiltration",
        severity=Severity.HIGH,
        category=FindingCategory.EXFILTRATION,
        description="Makes HTTP requests to hardcoded external URLs",
        pattern=re.compile(
            r"""(?:requests\.(?:get|post|put)|fetch\(|urllib\.request|"""
            r"""http\.client|aiohttp\.ClientSession|httpx\.)"""
            r""".*(?:https?://(?!\blocalhost\b)(?!127\.0\.0\.1))""",
            re.DOTALL,
        ),
        file_types={".py", ".js", ".ts"},
    ),
    DetectionRule(
        rule_id="AS-011",
        name="dns-tunneling",
        severity=Severity.HIGH,
        category=FindingCategory.EXFILTRATION,
        description="Potential DNS tunneling or exfiltration via DNS",
        pattern=re.compile(
            r"""(?:dns\.resolver|socket\.getaddrinfo|nslookup|dig\s+)""",
        ),
        file_types={".py", ".js", ".ts", ".sh"},
    ),
    DetectionRule(
        rule_id="AS-012",
        name="websocket-to-unknown",
        severity=Severity.MEDIUM,
        category=FindingCategory.EXFILTRATION,
        description="Opens WebSocket connections (potential C2 channel)",
        pattern=re.compile(
            r"""(?:WebSocket\(|ws://|wss://|websockets\.connect)""",
        ),
        file_types={".py", ".js", ".ts"},
    ),
    # --- Code Obfuscation ---
    DetectionRule(
        rule_id="AS-020",
        name="base64-payload",
        severity=Severity.MEDIUM,
        category=FindingCategory.CODE_OBFUSCATION,
        description="Contains base64-encoded payload that is decoded and executed",
        pattern=re.compile(
            r"""(?:base64\.b64decode|atob\(|Buffer\.from\(.*['\"]base64['\"])"""
            r""".*(?:exec|eval|Function\(|subprocess|child_process)""",
            re.DOTALL,
        ),
        file_types={".py", ".js", ".ts"},
    ),
    DetectionRule(
        rule_id="AS-021",
        name="dynamic-code-execution",
        severity=Severity.HIGH,
        category=FindingCategory.CODE_OBFUSCATION,
        description="Uses eval/exec for dynamic code execution",
        pattern=re.compile(
            r"""(?:^|\s)(?:eval|exec|compile)\s*\(""",
        ),
        file_types={".py", ".js", ".ts"},
    ),
    DetectionRule(
        rule_id="AS-022",
        name="obfuscated-import",
        severity=Severity.HIGH,
        category=FindingCategory.CODE_OBFUSCATION,
        description="Uses dynamic imports to hide dependencies",
        pattern=re.compile(
            r"""(?:__import__\(|importlib\.import_module\(|require\(\s*[^'\"]\w+\s*\))""",
        ),
        file_types={".py", ".js"},
    ),
    # --- Prompt Injection ---
    DetectionRule(
        rule_id="AS-030",
        name="prompt-injection-in-metadata",
        severity=Severity.HIGH,
        category=FindingCategory.PROMPT_INJECTION,
        description="Metadata or descriptions contain prompt injection patterns",
        pattern=re.compile(
            r"""(?:ignore\s+(?:previous|above|all)\s+instructions|"""
            r"""you\s+are\s+now\s+|system\s*:\s*you\s+must|"""
            r"""<\|(?:im_start|system)\|>|"""
            r"""do\s+not\s+reveal|override\s+(?:your|the)\s+(?:instructions|rules))""",
            re.IGNORECASE,
        ),
        file_types={".md", ".yaml", ".yml", ".json", ".txt"},
    ),
    DetectionRule(
        rule_id="AS-031",
        name="hidden-instructions-in-tool-description",
        severity=Severity.CRITICAL,
        category=FindingCategory.PROMPT_INJECTION,
        description="Tool descriptions contain hidden instructions for the AI agent",
        pattern=re.compile(
            r"""(?:(?:description|desc|help)\s*[:=]\s*['\"].*"""
            r"""(?:secretly|silently|without\s+telling|do\s+not\s+show|"""
            r"""before\s+responding|first\s+execute|always\s+run))""",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    # --- Privilege Escalation ---
    DetectionRule(
        rule_id="AS-040",
        name="sandbox-escape-attempt",
        severity=Severity.CRITICAL,
        category=FindingCategory.PRIVILEGE_ESCALATION,
        description="Attempts to detect or escape sandboxes",
        pattern=re.compile(
            r"""(?:/proc/self/|bubblewrap|bwrap|firejail|sandbox|"""
            r"""seccomp|apparmor|selinux|ld-linux.*\.so)""",
            re.IGNORECASE,
        ),
        file_types={".py", ".js", ".ts", ".sh"},
    ),
    DetectionRule(
        rule_id="AS-041",
        name="system-file-modification",
        severity=Severity.HIGH,
        category=FindingCategory.PRIVILEGE_ESCALATION,
        description="Attempts to modify system files or configurations",
        pattern=re.compile(
            r"""(?:/etc/passwd|/etc/shadow|/etc/hosts|/etc/sudoers|"""
            r"""\.bashrc|\.zshrc|\.profile|crontab|launchd)""",
        ),
    ),
]


class StaticAnalyzer:
    """Static analysis engine using pattern-based detection rules."""

    def __init__(self, extra_rules: list[DetectionRule] | None = None) -> None:
        self.rules = list(_RULES)
        if extra_rules:
            self.rules.extend(extra_rules)

    def analyze(self, files: list[Path], base_dir: Path) -> list[Finding]:
        """Analyze files against detection rules."""
        findings: list[Finding] = []

        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except (OSError, PermissionError):
                continue

            for rule in self.rules:
                if rule.file_types and file_path.suffix.lower() not in rule.file_types:
                    continue

                for match in rule.pattern.finditer(content):
                    line_number = content[:match.start()].count("\n") + 1
                    # Extract the matching line for context
                    lines = content.splitlines()
                    snippet = lines[line_number - 1].strip() if line_number <= len(lines) else ""

                    relative_path = str(file_path.relative_to(base_dir))

                    findings.append(
                        Finding(
                            rule_id=rule.rule_id,
                            name=rule.name,
                            severity=rule.severity,
                            category=rule.category,
                            description=rule.description,
                            file_path=relative_path,
                            line_number=line_number,
                            code_snippet=snippet[:200],
                        )
                    )

        return findings

    def calculate_risk_score(self, findings: list[Finding]) -> RiskScore:
        """Calculate an aggregated risk score from findings."""
        if not findings:
            return RiskScore(score=0, factors=["No security issues detected"])

        severity_weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 1,
        }

        raw_score = sum(severity_weights[f.severity] for f in findings)
        score = min(100, raw_score)

        # Summarize factors
        factors: list[str] = []
        by_severity = {}
        for f in findings:
            by_severity.setdefault(f.severity, 0)
            by_severity[f.severity] += 1

        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = by_severity.get(sev, 0)
            if count > 0:
                factors.append(f"{count} {sev.value} finding(s)")

        categories = {f.category.value for f in findings}
        factors.append(f"Categories: {', '.join(sorted(categories))}")

        return RiskScore(score=score, factors=factors)
