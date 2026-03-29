"""Parse scan targets and resolve ecosystem types."""

from __future__ import annotations

from pathlib import Path

from agentsift.models import Ecosystem

# Prefix-to-ecosystem mapping
_PREFIXES: dict[str, Ecosystem] = {
    "clawhub:": Ecosystem.CLAWHUB,
    "mcp-npm:": Ecosystem.MCP_NPM,
    "mcp-pypi:": Ecosystem.MCP_PYPI,
    "npm:": Ecosystem.NPM,
    "pypi:": Ecosystem.PYPI,
}


def parse_target(target: str) -> tuple[Ecosystem, str, Path | None]:
    """Parse a target string into (ecosystem, package_name, local_path).

    Returns local_path if the target is a local directory, None otherwise.
    """
    # Check if it's a local path
    path = Path(target).expanduser()
    if path.exists() and path.is_dir():
        return Ecosystem.LOCAL, path.name, path

    # Check prefixed targets
    for prefix, ecosystem in _PREFIXES.items():
        if target.startswith(prefix):
            package_name = target[len(prefix):]
            return ecosystem, package_name, None

    # Default: treat as local path (even if it doesn't exist yet -- let scanner handle error)
    return Ecosystem.LOCAL, target, path
