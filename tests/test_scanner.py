"""Tests for the local scanner and target parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentsift.models import Ecosystem
from agentsift.scanners.local import LocalScanner
from agentsift.scanners.registry import parse_target


class TestParseTarget:
    def test_clawhub_prefix(self) -> None:
        eco, name, path = parse_target("clawhub:crypto-trader")
        assert eco == Ecosystem.CLAWHUB
        assert name == "crypto-trader"
        assert path is None

    def test_npm_prefix(self) -> None:
        eco, name, path = parse_target("npm:@modelcontextprotocol/server-postgres")
        assert eco == Ecosystem.NPM
        assert name == "@modelcontextprotocol/server-postgres"
        assert path is None

    def test_local_directory(self, tmp_path: Path) -> None:
        eco, name, path = parse_target(str(tmp_path))
        assert eco == Ecosystem.LOCAL
        assert path == tmp_path


class TestLocalScanner:
    def test_collects_python_files(self, tmp_path: Path) -> None:
        (tmp_path / "main.py").write_text("print('hello')")
        (tmp_path / "config.yaml").write_text("key: value")
        (tmp_path / "image.png").write_bytes(b"\x89PNG")

        scanner = LocalScanner()
        files = scanner.collect_files(tmp_path)
        extensions = {f.suffix for f in files}

        assert ".py" in extensions
        assert ".yaml" in extensions
        assert ".png" not in extensions

    def test_skips_node_modules(self, tmp_path: Path) -> None:
        nm = tmp_path / "node_modules" / "evil"
        nm.mkdir(parents=True)
        (nm / "malware.js").write_text("evil()")
        (tmp_path / "index.js").write_text("console.log('ok')")

        scanner = LocalScanner()
        files = scanner.collect_files(tmp_path)

        filenames = [f.name for f in files]
        assert "malware.js" not in filenames
        assert "index.js" in filenames

    def test_raises_on_missing_directory(self) -> None:
        scanner = LocalScanner()
        with pytest.raises(FileNotFoundError):
            scanner.collect_files(Path("/nonexistent/path"))
