"""Tests for the PyPI registry scanner."""

from __future__ import annotations

import tarfile
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

from agentsift.scanners.pypi import PyPIScanner, PyPIScannerError


def _make_sdist(name: str, files: dict[str, str]) -> bytes:
    """Create an in-memory sdist-style .tar.gz."""
    buf = BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for fname, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name=f"{name}/{fname}")
            info.size = len(data)
            tar.addfile(info, BytesIO(data))
    buf.seek(0)
    return buf.read()


def _make_wheel(files: dict[str, str]) -> bytes:
    """Create an in-memory .whl (zip) file."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for fname, content in files.items():
            zf.writestr(fname, content)
    buf.seek(0)
    return buf.read()


class TestPyPIScanner:
    def test_extract_sdist(self, tmp_path: Path) -> None:
        tarball = _make_sdist("my-package-1.0.0", {
            "setup.py": "from setuptools import setup; setup()",
            "my_package/__init__.py": "__version__ = '1.0.0'",
        })
        scanner = PyPIScanner()
        pkg_dir = scanner.extract_to_dir(tarball, "my-package-1.0.0.tar.gz", tmp_path)

        assert (pkg_dir / "setup.py").exists()
        assert (pkg_dir / "my_package" / "__init__.py").exists()

    def test_extract_wheel(self, tmp_path: Path) -> None:
        wheel = _make_wheel({
            "my_package/__init__.py": "__version__ = '1.0.0'",
            "my_package/core.py": "def run(): pass",
        })
        scanner = PyPIScanner()
        pkg_dir = scanner.extract_to_dir(wheel, "my_package-1.0.0.whl", tmp_path)

        files = list(pkg_dir.rglob("*.py"))
        assert len(files) >= 1

    def test_blocks_path_traversal_tar(self, tmp_path: Path) -> None:
        buf = BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            data = b"malicious"
            info = tarfile.TarInfo(name="../../../etc/passwd")
            info.size = len(data)
            tar.addfile(info, BytesIO(data))
        buf.seek(0)

        scanner = PyPIScanner()
        with pytest.raises(PyPIScannerError, match="Suspicious path"):
            scanner.extract_to_dir(buf.read(), "evil.tar.gz", tmp_path)

    def test_blocks_path_traversal_zip(self, tmp_path: Path) -> None:
        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../../../etc/shadow", "evil")
        buf.seek(0)

        scanner = PyPIScanner()
        with pytest.raises(PyPIScannerError, match="Suspicious path"):
            scanner.extract_to_dir(buf.read(), "evil.whl", tmp_path)

    def test_unsupported_format(self, tmp_path: Path) -> None:
        scanner = PyPIScanner()
        with pytest.raises(PyPIScannerError, match="Unsupported"):
            scanner.extract_to_dir(b"data", "package.rpm", tmp_path)


class TestMetadataExtraction:
    def test_extract_package_info(self) -> None:
        scanner = PyPIScanner()
        meta = {
            "info": {
                "name": "mcp-server-test",
                "version": "0.5.0",
                "summary": "A test MCP server",
                "author": "Test Author",
                "author_email": "test@example.com",
                "license": "MIT",
                "requires_python": ">=3.11",
                "requires_dist": ["httpx>=0.27", "pydantic>=2.0"],
            }
        }
        info = scanner.extract_package_info(meta, "0.5.0")

        assert info["name"] == "mcp-server-test"
        assert info["version"] == "0.5.0"
        assert info["author"] == "Test Author"
        assert len(info["dependencies"]) == 2
