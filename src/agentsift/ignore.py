"""Ignore / whitelist engine for suppressing false positives.

Supports:
  - .agentsift-ignore files in the scanned directory
  - CLI --ignore-rules option
  - Inline # agentsift-ignore comments in source files

File format (.agentsift-ignore):
  # Comment lines start with #
  rule:AS-001              # Ignore a specific rule everywhere
  rule:AS-010,AS-011       # Ignore multiple rules
  file:vendor/**           # Ignore all files matching a glob
  file:tests/              # Ignore the tests directory
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

from agentsift.models import Finding


@dataclass
class IgnoreConfig:
    """Parsed ignore configuration."""

    ignored_rules: set[str] = field(default_factory=set)
    ignored_file_patterns: list[str] = field(default_factory=list)

    def should_ignore(self, finding: Finding) -> bool:
        """Return True if the finding should be suppressed."""
        if finding.rule_id in self.ignored_rules:
            return True

        if finding.file_path:
            for pattern in self.ignored_file_patterns:
                if fnmatch.fnmatch(finding.file_path, pattern):
                    return True

        return False

    def filter_findings(self, findings: list[Finding]) -> list[Finding]:
        """Return findings that are NOT ignored."""
        return [f for f in findings if not self.should_ignore(f)]

    def merge(self, other: IgnoreConfig) -> None:
        """Merge another IgnoreConfig into this one."""
        self.ignored_rules.update(other.ignored_rules)
        self.ignored_file_patterns.extend(other.ignored_file_patterns)


def parse_ignore_file(path: Path) -> IgnoreConfig:
    """Parse a .agentsift-ignore file."""
    config = IgnoreConfig()

    if not path.is_file():
        return config

    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # Strip inline comments
        if " #" in line:
            line = line[: line.index(" #")].strip()

        if line.startswith("rule:"):
            rules = line[5:].strip()
            for rule_id in rules.split(","):
                rule_id = rule_id.strip()
                if rule_id:
                    config.ignored_rules.add(rule_id)
        elif line.startswith("file:"):
            pattern = line[5:].strip()
            if pattern:
                config.ignored_file_patterns.append(pattern)

    return config


def load_ignore_config(
    scan_dir: Path | None = None,
    ignore_rules: list[str] | None = None,
) -> IgnoreConfig:
    """Build a combined IgnoreConfig from all sources.

    Args:
        scan_dir: Directory being scanned (looks for .agentsift-ignore here)
        ignore_rules: Rule IDs passed via CLI --ignore-rules
    """
    config = IgnoreConfig()

    # Load .agentsift-ignore from scan directory
    if scan_dir:
        ignore_path = scan_dir / ".agentsift-ignore"
        if ignore_path.is_file():
            config.merge(parse_ignore_file(ignore_path))

    # Add CLI-provided rule IDs
    if ignore_rules:
        for rule_id in ignore_rules:
            for r in rule_id.split(","):
                r = r.strip()
                if r:
                    config.ignored_rules.add(r)

    return config
