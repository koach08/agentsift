"""Local directory scanner -- collects files for analysis."""

from __future__ import annotations

from pathlib import Path

# Extensions to scan
_SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".mjs", ".cjs",
    ".jsx", ".tsx",
    ".json", ".yaml", ".yml", ".toml",
    ".sh", ".bash",
    ".md",  # SKILL.md, README.md can contain prompt injection
}

# Directories to skip
_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    ".eggs", "dist", "build", ".mypy_cache", ".ruff_cache",
    ".pytest_cache",
}

# Max file size to scan (1MB)
_MAX_FILE_SIZE = 1_048_576


class LocalScanner:
    """Scan a local directory for agent plugin files."""

    def collect_files(self, directory: Path) -> list[Path]:
        """Collect all scannable files in a directory."""
        if not directory.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")
        if not directory.is_dir():
            raise NotADirectoryError(f"Not a directory: {directory}")

        files: list[Path] = []
        for path in directory.rglob("*"):
            if any(skip in path.parts for skip in _SKIP_DIRS):
                continue
            if not path.is_file():
                continue
            if path.suffix.lower() not in _SCAN_EXTENSIONS:
                continue
            if path.stat().st_size > _MAX_FILE_SIZE:
                continue
            files.append(path)

        return sorted(files)
