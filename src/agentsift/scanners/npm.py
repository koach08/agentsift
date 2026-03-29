"""npm registry scanner -- download and extract packages for analysis."""

from __future__ import annotations

import tarfile
import tempfile
from io import BytesIO
from pathlib import Path

import httpx

from agentsift.scanners.local import LocalScanner

# npm registry API
_NPM_REGISTRY = "https://registry.npmjs.org"

# Request timeout (seconds)
_TIMEOUT = 30


class NpmScannerError(Exception):
    """Error during npm package scanning."""


class NpmScanner:
    """Download and extract npm packages for security analysis."""

    def __init__(self) -> None:
        self._client = httpx.Client(timeout=_TIMEOUT, follow_redirects=True)
        self._local_scanner = LocalScanner()

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> NpmScanner:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def fetch_metadata(self, package_name: str) -> dict:
        """Fetch package metadata from npm registry.

        Returns the full package document including all versions.
        """
        url = f"{_NPM_REGISTRY}/{package_name}"
        resp = self._client.get(url, headers={"Accept": "application/json"})

        if resp.status_code == 404:
            raise NpmScannerError(f"Package not found: {package_name}")
        resp.raise_for_status()

        return resp.json()

    def fetch_latest_version(self, package_name: str) -> tuple[dict, str]:
        """Fetch metadata for the latest version.

        Returns (version_metadata, version_string).
        """
        meta = self.fetch_metadata(package_name)
        dist_tags = meta.get("dist-tags", {})
        latest = dist_tags.get("latest")

        if not latest:
            raise NpmScannerError(f"No latest version found for {package_name}")

        versions = meta.get("versions", {})
        version_meta = versions.get(latest)
        if not version_meta:
            raise NpmScannerError(f"Version {latest} not found for {package_name}")

        return version_meta, latest

    def download_tarball(self, package_name: str, version: str | None = None) -> bytes:
        """Download the package tarball.

        If version is None, downloads the latest version.
        """
        if version:
            meta = self.fetch_metadata(package_name)
            versions = meta.get("versions", {})
            version_meta = versions.get(version)
            if not version_meta:
                raise NpmScannerError(f"Version {version} not found for {package_name}")
        else:
            version_meta, version = self.fetch_latest_version(package_name)

        dist = version_meta.get("dist", {})
        tarball_url = dist.get("tarball")

        if not tarball_url:
            raise NpmScannerError(f"No tarball URL for {package_name}@{version}")

        resp = self._client.get(tarball_url)
        resp.raise_for_status()

        return resp.content

    def extract_to_dir(self, tarball_data: bytes, target_dir: Path) -> Path:
        """Extract a tarball to a target directory.

        npm tarballs contain a `package/` top-level directory.
        Returns the path to the extracted package directory.
        """
        with tarfile.open(fileobj=BytesIO(tarball_data), mode="r:gz") as tar:
            # Security: prevent path traversal
            for member in tar.getmembers():
                if member.name.startswith("/") or ".." in member.name:
                    raise NpmScannerError(
                        f"Suspicious path in tarball: {member.name}"
                    )
            tar.extractall(target_dir, filter="data")

        # npm tarballs extract to a `package/` subdirectory
        package_dir = target_dir / "package"
        if package_dir.exists():
            return package_dir

        # Some packages use a different top-level directory
        subdirs = [d for d in target_dir.iterdir() if d.is_dir()]
        if len(subdirs) == 1:
            return subdirs[0]

        return target_dir

    def download_and_extract(
        self, package_name: str, version: str | None = None
    ) -> tuple[Path, Path, dict, str]:
        """Download, extract, and return (temp_dir, package_dir, metadata, version).

        The caller is responsible for cleaning up temp_dir.
        """
        version_meta, resolved_version = (
            self.fetch_latest_version(package_name)
            if version is None
            else (
                self.fetch_metadata(package_name).get("versions", {}).get(version),
                version,
            )
        )

        if not version_meta:
            raise NpmScannerError(f"Version {version} not found for {package_name}")

        tarball_data = self.download_tarball(package_name, resolved_version)

        temp_dir = Path(tempfile.mkdtemp(prefix="agentsift-"))
        package_dir = self.extract_to_dir(tarball_data, temp_dir)

        return temp_dir, package_dir, version_meta, resolved_version

    def collect_files(self, package_dir: Path) -> list[Path]:
        """Collect scannable files from the extracted package."""
        return self._local_scanner.collect_files(package_dir)

    def extract_package_info(self, package_name: str, version_meta: dict, version: str) -> dict:
        """Extract relevant package info from npm metadata."""
        return {
            "name": package_name,
            "version": version,
            "description": version_meta.get("description", ""),
            "author": _extract_author(version_meta),
            "homepage": version_meta.get("homepage"),
            "repository": _extract_repo_url(version_meta),
            "license": version_meta.get("license"),
            "dependencies": version_meta.get("dependencies", {}),
            "scripts": version_meta.get("scripts", {}),
        }


def _extract_author(meta: dict) -> str | None:
    """Extract author string from various npm metadata formats."""
    author = meta.get("author")
    if isinstance(author, str):
        return author
    if isinstance(author, dict):
        name = author.get("name", "")
        email = author.get("email", "")
        return f"{name} <{email}>" if email else name
    # Try maintainers
    maintainers = meta.get("maintainers", [])
    if maintainers and isinstance(maintainers[0], dict):
        return maintainers[0].get("name")
    return None


def _extract_repo_url(meta: dict) -> str | None:
    """Extract repository URL from npm metadata."""
    repo = meta.get("repository")
    if isinstance(repo, str):
        return repo
    if isinstance(repo, dict):
        return repo.get("url")
    return None
