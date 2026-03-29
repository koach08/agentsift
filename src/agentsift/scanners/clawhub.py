"""ClawHub registry scanner -- download and extract OpenClaw skills for analysis."""

from __future__ import annotations

import tempfile
import zipfile
from io import BytesIO
from pathlib import Path

import httpx
import yaml

from agentsift.scanners.local import LocalScanner

# ClawHub registry API
_CLAWHUB_REGISTRY = "https://clawhub.ai/api/v1"

# Request timeout (seconds)
_TIMEOUT = 30


class ClawHubScannerError(Exception):
    """Error during ClawHub skill scanning."""


class ClawHubScanner:
    """Download and extract OpenClaw skills from ClawHub for security analysis."""

    def __init__(self, registry_url: str = _CLAWHUB_REGISTRY) -> None:
        self._registry = registry_url
        self._client = httpx.Client(timeout=_TIMEOUT, follow_redirects=True)
        self._local_scanner = LocalScanner()

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> ClawHubScanner:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def fetch_metadata(self, slug: str) -> dict:
        """Fetch skill metadata from ClawHub registry."""
        url = f"{self._registry}/skills/{slug}"
        resp = self._client.get(url, headers={"Accept": "application/json"})

        if resp.status_code == 404:
            raise ClawHubScannerError(f"Skill not found: {slug}")
        resp.raise_for_status()

        return resp.json()

    def download_skill(self, slug: str, version: str | None = None) -> bytes:
        """Download the skill ZIP archive.

        If version is None, downloads the latest version.
        """
        if not version:
            meta = self.fetch_metadata(slug)
            version = meta.get("version") or meta.get("latest", "latest")

        url = f"{self._registry}/download/{slug}/{version}"
        resp = self._client.get(url)

        if resp.status_code == 404:
            raise ClawHubScannerError(f"Skill not found: {slug}@{version}")
        resp.raise_for_status()

        return resp.content

    def extract_to_dir(self, zip_data: bytes, target_dir: Path) -> Path:
        """Extract a skill ZIP to a target directory.

        Returns the path to the extracted skill directory.
        """
        with zipfile.ZipFile(BytesIO(zip_data)) as zf:
            # Security: check for path traversal
            for name in zf.namelist():
                if name.startswith("/") or ".." in name:
                    raise ClawHubScannerError(
                        f"Suspicious path in ZIP: {name}"
                    )
            zf.extractall(target_dir)

        # Check for common top-level directory patterns
        subdirs = [d for d in target_dir.iterdir() if d.is_dir()]
        if len(subdirs) == 1:
            return subdirs[0]

        return target_dir

    def download_and_extract(
        self, slug: str, version: str | None = None
    ) -> tuple[Path, Path, dict, str]:
        """Download, extract, and return (temp_dir, skill_dir, metadata, version).

        The caller is responsible for cleaning up temp_dir.
        """
        meta = self.fetch_metadata(slug)
        resolved_version = version or meta.get("version") or meta.get("latest", "latest")

        zip_data = self.download_skill(slug, resolved_version)

        temp_dir = Path(tempfile.mkdtemp(prefix="agentsift-clawhub-"))
        skill_dir = self.extract_to_dir(zip_data, temp_dir)

        return temp_dir, skill_dir, meta, resolved_version

    def collect_files(self, skill_dir: Path) -> list[Path]:
        """Collect scannable files from the extracted skill."""
        return self._local_scanner.collect_files(skill_dir)

    def parse_skill_md(self, skill_dir: Path) -> dict | None:
        """Parse SKILL.md frontmatter for metadata extraction."""
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.exists():
            # Try lowercase
            skill_md = skill_dir / "skill.md"
            if not skill_md.exists():
                return None

        content = skill_md.read_text(encoding="utf-8", errors="ignore")

        # Extract YAML frontmatter
        if not content.startswith("---"):
            return None

        end = content.find("---", 3)
        if end == -1:
            return None

        frontmatter = content[3:end].strip()
        try:
            return yaml.safe_load(frontmatter)
        except yaml.YAMLError:
            return None

    def extract_package_info(self, slug: str, meta: dict, version: str) -> dict:
        """Extract relevant info from ClawHub metadata."""
        return {
            "name": slug,
            "version": version,
            "description": meta.get("description", ""),
            "author": meta.get("owner") or meta.get("author"),
            "homepage": _extract_homepage(meta),
            "stars": meta.get("stars"),
            "installs": meta.get("installs") or meta.get("downloads"),
            "tags": meta.get("tags", []),
            "requires_env": _extract_env_requirements(meta),
        }


def _extract_homepage(meta: dict) -> str | None:
    """Extract homepage URL from metadata."""
    # Check various nesting patterns
    for key in ("homepage", "url"):
        if key in meta:
            return meta[key]

    oc_meta = meta.get("metadata", {}).get("openclaw", {})
    return oc_meta.get("homepage")


def _extract_env_requirements(meta: dict) -> list[str]:
    """Extract required environment variables."""
    oc_meta = meta.get("metadata", {}).get("openclaw", {})
    requires = oc_meta.get("requires", {})
    return requires.get("env", [])
