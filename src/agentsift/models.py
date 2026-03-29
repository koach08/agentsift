"""Data models for scan results, findings, and risk scores."""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Ecosystem(str, Enum):
    CLAWHUB = "clawhub"
    MCP_NPM = "mcp-npm"
    MCP_PYPI = "mcp-pypi"
    NPM = "npm"
    PYPI = "pypi"
    LOCAL = "local"


class FindingCategory(str, Enum):
    EXFILTRATION = "exfiltration"
    CREDENTIAL_THEFT = "credential-theft"
    CODE_OBFUSCATION = "code-obfuscation"
    PROMPT_INJECTION = "prompt-injection"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    SUSPICIOUS_NETWORK = "suspicious-network"
    MALICIOUS_DEPENDENCY = "malicious-dependency"


class Finding(BaseModel):
    """A single security finding from analysis."""

    rule_id: str
    name: str
    severity: Severity
    category: FindingCategory
    description: str
    file_path: str | None = None
    line_number: int | None = None
    code_snippet: str | None = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)


class RiskScore(BaseModel):
    """Aggregated risk score for a package."""

    score: int = Field(ge=0, le=100, description="0 = safe, 100 = definitely malicious")
    label: str = ""  # safe / low / medium / high / critical
    factors: list[str] = Field(default_factory=list)

    def model_post_init(self, _context: object) -> None:
        if not self.label:
            if self.score <= 10:
                self.label = "safe"
            elif self.score <= 30:
                self.label = "low"
            elif self.score <= 60:
                self.label = "medium"
            elif self.score <= 85:
                self.label = "high"
            else:
                self.label = "critical"


class PackageInfo(BaseModel):
    """Metadata about the scanned package."""

    name: str
    version: str | None = None
    ecosystem: Ecosystem
    author: str | None = None
    description: str | None = None
    source_url: str | None = None
    download_count: int | None = None


class ScanResult(BaseModel):
    """Complete result of scanning a package."""

    package: PackageInfo
    findings: list[Finding] = Field(default_factory=list)
    risk_score: RiskScore = Field(default_factory=lambda: RiskScore(score=0))
    scanned_at: datetime = Field(default_factory=datetime.now)
    scan_duration_ms: int = 0
    files_scanned: int = 0
    analyzers_used: list[str] = Field(default_factory=list)
