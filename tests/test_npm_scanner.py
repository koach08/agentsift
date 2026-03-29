"""Tests for the npm registry scanner."""

from __future__ import annotations

import json
import tarfile
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agentsift.scanners.npm import NpmScanner, NpmScannerError


def _make_tarball(files: dict[str, str]) -> bytes:
    """Create an in-memory npm-style tarball with package/ prefix."""
    buf = BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name=f"package/{name}")
            info.size = len(data)
            tar.addfile(info, BytesIO(data))
    buf.seek(0)
    return buf.read()


class TestNpmScanner:
    def test_extract_tarball(self, tmp_path: Path) -> None:
        tarball = _make_tarball({
            "index.js": "console.log('hello')",
            "package.json": '{"name": "test"}',
        })
        scanner = NpmScanner()
        pkg_dir = scanner.extract_to_dir(tarball, tmp_path)

        assert (pkg_dir / "index.js").exists()
        assert (pkg_dir / "package.json").exists()

    def test_extract_blocks_path_traversal(self, tmp_path: Path) -> None:
        buf = BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            data = b"malicious"
            info = tarfile.TarInfo(name="../../../etc/passwd")
            info.size = len(data)
            tar.addfile(info, BytesIO(data))
        buf.seek(0)

        scanner = NpmScanner()
        with pytest.raises(NpmScannerError, match="Suspicious path"):
            scanner.extract_to_dir(buf.read(), tmp_path)

    def test_collect_files_from_extracted(self, tmp_path: Path) -> None:
        tarball = _make_tarball({
            "index.js": "module.exports = {}",
            "lib/helper.js": "function help() {}",
            "README.md": "# Test",
            "logo.png": "not-really-png",  # Won't be collected (wrong extension content doesn't matter, but suffix matters)
        })
        scanner = NpmScanner()
        pkg_dir = scanner.extract_to_dir(tarball, tmp_path)
        files = scanner.collect_files(pkg_dir)

        names = {f.name for f in files}
        assert "index.js" in names
        assert "helper.js" in names
        assert "README.md" in names


class TestMetadataExtraction:
    def test_extract_author_string(self) -> None:
        scanner = NpmScanner()
        info = scanner.extract_package_info(
            "test-pkg",
            {"author": "John Doe", "description": "A test"},
            "1.0.0",
        )
        assert info["author"] == "John Doe"

    def test_extract_author_object(self) -> None:
        scanner = NpmScanner()
        info = scanner.extract_package_info(
            "test-pkg",
            {"author": {"name": "Jane", "email": "jane@example.com"}},
            "2.0.0",
        )
        assert "Jane" in info["author"]
        assert "jane@example.com" in info["author"]

    def test_extract_repo_url(self) -> None:
        scanner = NpmScanner()
        info = scanner.extract_package_info(
            "test-pkg",
            {"repository": {"type": "git", "url": "https://github.com/test/test.git"}},
            "1.0.0",
        )
        assert info["repository"] == "https://github.com/test/test.git"
