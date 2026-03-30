"""PyPI registry scanner -- download and extract Python packages for analysis."""

from __future__ import annotations

import tarfile
import tempfile
import zipfile
from io import BytesIO
from pathlib import Path

import httpx

from agentsift.scanners.local import LocalScanner

# PyPI JSON API
_PYPI_API = "https://pypi.org/pypi"

# Request timeout (seconds)
_TIMEOUT = 30


class PyPIScannerError(Exception):
    """Error during PyPI package scanning."""


class PyPIScanner:
    """Download and extract PyPI packages for security analysis."""

    def __init__(self) -> None:
        self._client = httpx.Client(timeout=_TIMEOUT, follow_redirects=True)
        self._local_scanner = LocalScanner()

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> PyPIScanner:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def fetch_metadata(self, package_name: str) -> dict:
        """Fetch package metadata from PyPI JSON API."""
        url = f"{_PYPI_API}/{package_name}/json"
        resp = self._client.get(url)

        if resp.status_code == 404:
            raise PyPIScannerError(f"Package not found: {package_name}")
        resp.raise_for_status()

        return resp.json()

    def fetch_version_metadata(
        self, package_name: str, version: str | None = None
    ) -> tuple[dict, str]:
        """Fetch metadata for a specific version (or latest).

        Returns (full_metadata, resolved_version).
        """
        meta = self.fetch_metadata(package_name)
        info = meta.get("info", {})
        resolved = version or info.get("version", "")

        if not resolved:
            raise PyPIScannerError(f"No version found for {package_name}")

        return meta, resolved

    def download_sdist(self, meta: dict, version: str) -> tuple[bytes, str]:
        """Download the source distribution for a given version.

        Prefers sdist (.tar.gz) over bdist (.whl) for source code access.
        Returns (file_bytes, filename).
        """
        releases = meta.get("releases", {})
        version_files = releases.get(version, [])

        # Prefer sdist, fall back to wheel
        sdist = None
        wheel = None
        for f in version_files:
            ptype = f.get("packagetype", "")
            if ptype == "sdist":
                sdist = f
                break
            elif ptype == "bdist_wheel" and wheel is None:
                wheel = f

        target = sdist or wheel
        if not target:
            # Try the urls list from top-level
            urls = meta.get("urls", [])
            for f in urls:
                if f.get("packagetype") == "sdist":
                    target = f
                    break
            if not target and urls:
                target = urls[0]

        if not target:
            raise PyPIScannerError(f"No downloadable files for {meta['info']['name']}@{version}")

        download_url = target["url"]
        resp = self._client.get(download_url)
        resp.raise_for_status()

        return resp.content, target.get("filename", "unknown")

    def extract_to_dir(self, file_data: bytes, filename: str, target_dir: Path) -> Path:
        """Extract a package archive to a target directory.

        Handles .tar.gz (sdist) and .whl/.zip (bdist).
        Returns the path to the extracted package directory.
        """
        if filename.endswith((".tar.gz", ".tgz")):
            return self._extract_tarball(file_data, target_dir)
        elif filename.endswith((".whl", ".zip")):
            return self._extract_zip(file_data, target_dir)
        else:
            raise PyPIScannerError(f"Unsupported archive format: {filename}")

    def _extract_tarball(self, data: bytes, target_dir: Path) -> Path:
        with tarfile.open(fileobj=BytesIO(data), mode="r:gz") as tar:
            for member in tar.getmembers():
                if member.name.startswith("/") or ".." in member.name:
                    raise PyPIScannerError(f"Suspicious path in tarball: {member.name}")
            tar.extractall(target_dir, filter="data")

        # sdist tarballs extract to a <name>-<version>/ subdirectory
        subdirs = [d for d in target_dir.iterdir() if d.is_dir()]
        if len(subdirs) == 1:
            return subdirs[0]
        return target_dir

    def _extract_zip(self, data: bytes, target_dir: Path) -> Path:
        with zipfile.ZipFile(BytesIO(data)) as zf:
            for name in zf.namelist():
                if name.startswith("/") or ".." in name:
                    raise PyPIScannerError(f"Suspicious path in zip: {name}")
            zf.extractall(target_dir)

        subdirs = [d for d in target_dir.iterdir() if d.is_dir()]
        if len(subdirs) == 1:
            return subdirs[0]
        return target_dir

    def download_and_extract(
        self, package_name: str, version: str | None = None
    ) -> tuple[Path, Path, dict, str]:
        """Download, extract, return (temp_dir, package_dir, metadata, version).

        Caller is responsible for cleaning up temp_dir.
        """
        meta, resolved_version = self.fetch_version_metadata(package_name, version)
        file_data, filename = self.download_sdist(meta, resolved_version)

        temp_dir = Path(tempfile.mkdtemp(prefix="agentsift-pypi-"))
        package_dir = self.extract_to_dir(file_data, filename, temp_dir)

        return temp_dir, package_dir, meta, resolved_version

    def collect_files(self, package_dir: Path) -> list[Path]:
        """Collect scannable files from the extracted package."""
        return self._local_scanner.collect_files(package_dir)

    def extract_package_info(self, meta: dict, version: str) -> dict:
        """Extract relevant package info from PyPI metadata."""
        info = meta.get("info", {})
        return {
            "name": info.get("name", ""),
            "version": version,
            "description": info.get("summary", ""),
            "author": info.get("author") or info.get("author_email", ""),
            "homepage": info.get("home_page") or info.get("project_url"),
            "license": info.get("license"),
            "requires_python": info.get("requires_python"),
            "dependencies": info.get("requires_dist", []),
        }
