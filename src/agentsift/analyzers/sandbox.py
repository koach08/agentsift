"""Behavioral sandbox analyzer -- execute packages in Docker and monitor syscalls."""

from __future__ import annotations

import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from agentsift.models import Ecosystem, Finding, FindingCategory, Severity

# Image name for the sandbox container
SANDBOX_IMAGE = "agentsift-sandbox:latest"

# Timeout for container execution (seconds)
DEFAULT_TIMEOUT = 30

# strace flags used inside the container
STRACE_CMD = [
    "strace", "-f", "-qq",
    "-e", "trace=openat,connect,execve,socket,read",
    "-e", "signal=none",
    "-o", "/tmp/strace.log",
    "--",
    "python3", "/opt/agentsift/runner.py", "/workspace",
]


# --- Sensitive path patterns for file access detection ---

_SENSITIVE_FILE_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"/\.ssh/"), "SSH directory access", "ssh-keys"),
    (re.compile(r"/\.aws/"), "AWS credentials access", "aws-creds"),
    (re.compile(r"/\.config/gcloud/"), "GCP credentials access", "gcp-creds"),
    (re.compile(r"/\.azure/"), "Azure credentials access", "azure-creds"),
    (re.compile(r"/\.gnupg/"), "GPG keyring access", "gpg-keys"),
    (re.compile(r"/\.kube/config"), "Kubernetes config access", "kube-config"),
    (re.compile(r"/\.docker/config\.json"), "Docker credentials access", "docker-creds"),
    (re.compile(r"/wallet\.dat|/\.ethereum/|/\.bitcoin/|/\.solana/"), "Crypto wallet access", "crypto-wallet"),
    (re.compile(r"/\.mozilla/|/\.chrome/|/chrome/.*(?:Login Data|Cookies)"), "Browser data access", "browser-data"),
    (re.compile(r"/etc/shadow"), "Shadow password file access", "shadow-file"),
    (re.compile(r"/etc/passwd"), "System password file read", "passwd-file"),
    (re.compile(r"/proc/self/(?:environ|maps|status)"), "Process information leak", "proc-self"),
]

# --- Suspicious process execution patterns ---

_SUSPICIOUS_EXEC_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'execve\("(?:/usr)?/bin/(?:curl|wget)"'), "Downloads from external URL"),
    (re.compile(r'execve\("(?:/usr)?/bin/(?:nc|ncat|netcat)"'), "Netcat execution (potential reverse shell)"),
    (re.compile(r'execve\("(?:/usr)?/bin/(?:bash|sh|zsh)".*"-c"'), "Shell command execution"),
    (re.compile(r'execve\("(?:/usr)?/bin/(?:chmod|chown)"'), "File permission modification"),
    (re.compile(r'execve\("(?:/usr)?/bin/(?:base64)"'), "Base64 encoding/decoding (potential obfuscation)"),
    (re.compile(r'execve\("(?:/usr)?/bin/(?:ssh|scp|sftp)"'), "SSH/SCP execution (data exfiltration)"),
]

# --- Network connection patterns ---

_CONNECT_PATTERN = re.compile(
    r'connect\(\d+,\s*\{sa_family=AF_INET6?,\s*'
    r'sin6?_port=htons\((\d+)\),\s*'
    r'sin6?_addr=(?:inet_addr\("([^"]+)"\)|"([^"]+)")'
)

# Loopback addresses to ignore
_LOOPBACK = {"127.0.0.1", "::1", "0.0.0.0"}


@dataclass
class SyscallEvent:
    """A parsed strace syscall event."""

    pid: int
    syscall: str
    args: str
    result: str
    raw_line: str


@dataclass
class SandboxReport:
    """Raw behavioral analysis results from sandbox execution."""

    file_accesses: list[tuple[str, str, str]] = field(default_factory=list)   # (path, description, tag)
    network_connections: list[tuple[str, int]] = field(default_factory=list)   # (ip, port)
    process_executions: list[tuple[str, str]] = field(default_factory=list)    # (raw_line, description)
    exit_code: int = 0
    timed_out: bool = False
    error: str | None = None


def _parse_strace_line(line: str) -> SyscallEvent | None:
    """Parse a single strace output line into a SyscallEvent."""
    # Format: PID  syscall(args) = result
    match = re.match(r"(\d+)\s+(\w+)\((.+?)\)\s*=\s*(.+)", line.strip())
    if not match:
        return None
    return SyscallEvent(
        pid=int(match.group(1)),
        syscall=match.group(2),
        args=match.group(3),
        result=match.group(4).strip(),
        raw_line=line.strip(),
    )


def parse_strace_output(strace_text: str) -> SandboxReport:
    """Parse strace output into a structured SandboxReport."""
    report = SandboxReport()

    for line in strace_text.splitlines():
        event = _parse_strace_line(line)
        if event is None:
            continue

        # --- File access detection ---
        if event.syscall == "openat" and "ENOENT" not in event.result:
            # Extract the file path from openat args
            path_match = re.search(r'"([^"]+)"', event.args)
            if path_match:
                accessed_path = path_match.group(1)
                for pattern, desc, tag in _SENSITIVE_FILE_PATTERNS:
                    if pattern.search(accessed_path):
                        report.file_accesses.append((accessed_path, desc, tag))
                        break

        # --- Network connection detection ---
        if event.syscall == "connect":
            conn_match = _CONNECT_PATTERN.search(line)
            if conn_match:
                port = int(conn_match.group(1))
                ip = conn_match.group(2) or conn_match.group(3)
                if ip and ip not in _LOOPBACK:
                    report.network_connections.append((ip, port))

        # --- Process execution detection ---
        if event.syscall == "execve":
            for pattern, desc in _SUSPICIOUS_EXEC_PATTERNS:
                if pattern.search(line):
                    report.process_executions.append((line.strip(), desc))
                    break

    return report


def report_to_findings(report: SandboxReport) -> list[Finding]:
    """Convert a SandboxReport into a list of Finding objects."""
    findings: list[Finding] = []

    if report.timed_out:
        findings.append(Finding(
            rule_id="AS-069",
            name="sandbox-timeout",
            severity=Severity.MEDIUM,
            category=FindingCategory.SUSPICIOUS_NETWORK,
            description="Package execution timed out in sandbox (possible anti-analysis or hang)",
            confidence=0.5,
        ))

    # Deduplicate file accesses by tag
    seen_tags: set[str] = set()
    for path, desc, tag in report.file_accesses:
        if tag in seen_tags:
            continue
        seen_tags.add(tag)

        severity = Severity.CRITICAL
        if tag in ("passwd-file", "proc-self"):
            severity = Severity.HIGH

        findings.append(Finding(
            rule_id="AS-060",
            name="sandbox-sensitive-file-access",
            severity=severity,
            category=FindingCategory.CREDENTIAL_THEFT,
            description=f"Runtime: {desc} ({path})",
            file_path=path,
            confidence=0.9,
        ))

    # Deduplicate network connections by IP
    seen_ips: set[str] = set()
    for ip, port in report.network_connections:
        if ip in seen_ips:
            continue
        seen_ips.add(ip)

        findings.append(Finding(
            rule_id="AS-061",
            name="sandbox-network-connection",
            severity=Severity.HIGH,
            category=FindingCategory.EXFILTRATION,
            description=f"Runtime: outbound connection to {ip}:{port}",
            confidence=0.85,
        ))

    for raw_line, desc in report.process_executions:
        findings.append(Finding(
            rule_id="AS-062",
            name="sandbox-suspicious-process",
            severity=Severity.HIGH,
            category=FindingCategory.PRIVILEGE_ESCALATION,
            description=f"Runtime: {desc}",
            code_snippet=raw_line[:200],
            confidence=0.85,
        ))

    return findings


class SandboxAnalyzer:
    """Run packages in a Docker container and analyze runtime behavior via strace."""

    def __init__(self, timeout: int = DEFAULT_TIMEOUT) -> None:
        self.timeout = timeout
        self._client = None

    def _get_client(self):
        """Lazy-initialize Docker client."""
        if self._client is None:
            try:
                import docker
            except ImportError:
                raise RuntimeError(
                    "Docker SDK not installed. Install with: pip install agentsift[sandbox]"
                )
            self._client = docker.from_env()
        return self._client

    def _ensure_image(self) -> None:
        """Build the sandbox Docker image if it doesn't exist."""
        client = self._get_client()
        try:
            client.images.get(SANDBOX_IMAGE)
        except Exception:
            # Build from the sandbox/ directory
            sandbox_dir = Path(__file__).resolve().parents[3] / "sandbox"
            if not sandbox_dir.exists():
                raise RuntimeError(
                    f"Sandbox Dockerfile not found at {sandbox_dir}. "
                    "Ensure the 'sandbox/' directory is present in the project root."
                )
            client.images.build(
                path=str(sandbox_dir),
                tag=SANDBOX_IMAGE,
                rm=True,
            )

    def _ecosystem_arg(self, ecosystem: Ecosystem) -> str:
        """Map ecosystem to runner argument."""
        if ecosystem in (Ecosystem.PYPI, Ecosystem.MCP_PYPI):
            return "pypi"
        if ecosystem in (Ecosystem.NPM, Ecosystem.MCP_NPM):
            return "npm"
        return "auto"

    def analyze(self, package_dir: Path, ecosystem: Ecosystem) -> list[Finding]:
        """Execute package in sandbox and return behavioral findings."""
        client = self._get_client()
        self._ensure_image()

        eco_arg = self._ecosystem_arg(ecosystem)
        strace_cmd = STRACE_CMD + [eco_arg]

        report = SandboxReport()

        try:
            container = client.containers.run(
                SANDBOX_IMAGE,
                command=strace_cmd,
                volumes={
                    str(package_dir.resolve()): {
                        "bind": "/workspace",
                        "mode": "ro",
                    }
                },
                # Security: limit resources
                mem_limit="256m",
                cpu_period=100000,
                cpu_quota=50000,  # 50% of one CPU
                network_mode="none",  # No network by default
                read_only=False,  # strace needs to write log
                user="sandboxuser",
                detach=True,
                stderr=True,
            )

            # Wait for completion with timeout
            result = container.wait(timeout=self.timeout)
            report.exit_code = result.get("StatusCode", -1)

            # Read strace log from container
            try:
                bits, _stat = container.get_archive("/tmp/strace.log")
                # Docker archive is a tar stream
                import io
                import tarfile
                tar_bytes = b"".join(bits)
                tar = tarfile.open(fileobj=io.BytesIO(tar_bytes))
                member = tar.getmembers()[0]
                strace_file = tar.extractfile(member)
                if strace_file:
                    strace_text = strace_file.read().decode("utf-8", errors="replace")
                    report = parse_strace_output(strace_text)
                    report.exit_code = result.get("StatusCode", -1)
            except Exception:
                report.error = "Failed to retrieve strace log from container"

        except Exception as e:
            error_msg = str(e)
            if "timeout" in error_msg.lower() or "read timed out" in error_msg.lower():
                report.timed_out = True
                # Kill the container
                try:
                    container.kill()
                except Exception:
                    pass
            else:
                report.error = f"Sandbox execution failed: {error_msg}"

        finally:
            # Always clean up container
            try:
                container.remove(force=True)
            except Exception:
                pass

        return report_to_findings(report)

    def analyze_with_network(self, package_dir: Path, ecosystem: Ecosystem) -> list[Finding]:
        """Execute package with network access enabled to detect exfiltration.

        This is a separate method because enabling network is inherently more risky.
        The container still has resource limits and runs as an unprivileged user.
        """
        client = self._get_client()
        self._ensure_image()

        eco_arg = self._ecosystem_arg(ecosystem)
        strace_cmd = STRACE_CMD + [eco_arg]

        report = SandboxReport()

        try:
            container = client.containers.run(
                SANDBOX_IMAGE,
                command=strace_cmd,
                volumes={
                    str(package_dir.resolve()): {
                        "bind": "/workspace",
                        "mode": "ro",
                    }
                },
                mem_limit="256m",
                cpu_period=100000,
                cpu_quota=50000,
                network_mode="bridge",  # Allow network to detect exfiltration
                read_only=False,
                user="sandboxuser",
                detach=True,
                stderr=True,
            )

            result = container.wait(timeout=self.timeout)
            report.exit_code = result.get("StatusCode", -1)

            try:
                bits, _stat = container.get_archive("/tmp/strace.log")
                import io
                import tarfile
                tar_bytes = b"".join(bits)
                tar = tarfile.open(fileobj=io.BytesIO(tar_bytes))
                member = tar.getmembers()[0]
                strace_file = tar.extractfile(member)
                if strace_file:
                    strace_text = strace_file.read().decode("utf-8", errors="replace")
                    report = parse_strace_output(strace_text)
                    report.exit_code = result.get("StatusCode", -1)
            except Exception:
                report.error = "Failed to retrieve strace log from container"

        except Exception as e:
            error_msg = str(e)
            if "timeout" in error_msg.lower():
                report.timed_out = True
                try:
                    container.kill()
                except Exception:
                    pass
            else:
                report.error = f"Sandbox execution failed: {error_msg}"

        finally:
            try:
                container.remove(force=True)
            except Exception:
                pass

        return report_to_findings(report)
