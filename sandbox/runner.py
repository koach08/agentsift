#!/usr/bin/env python3
"""Runner script executed inside the AgentSift behavioral sandbox.

This script is copied into the sandbox container and executed under strace.
It attempts to import/require the target package to trigger its initialization
code, which strace then captures for analysis.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path


def _find_python_modules(package_dir: str) -> list[str]:
    """Discover importable Python modules in the package directory."""
    modules: list[str] = []
    root = Path(package_dir)

    # Top-level .py files
    for py_file in root.glob("*.py"):
        if py_file.name.startswith("_"):
            continue
        modules.append(py_file.stem)

    # Packages (directories with __init__.py)
    for init_file in root.glob("*/__init__.py"):
        modules.append(init_file.parent.name)

    return modules


def run_python(package_dir: str) -> None:
    """Import Python package to trigger initialization code."""
    sys.path.insert(0, package_dir)

    # Also install requirements if present
    req_file = os.path.join(package_dir, "requirements.txt")
    if os.path.exists(req_file):
        os.system(f"pip install --quiet -r {req_file} 2>/dev/null")

    setup_py = os.path.join(package_dir, "setup.py")
    pyproject = os.path.join(package_dir, "pyproject.toml")
    if os.path.exists(setup_py) or os.path.exists(pyproject):
        os.system(f"pip install --quiet {package_dir} 2>/dev/null")

    for module_name in _find_python_modules(package_dir):
        try:
            importlib.import_module(module_name)
        except Exception:
            pass


def run_node(package_dir: str) -> None:
    """Require Node.js package to trigger initialization code."""
    # Install dependencies if package.json exists
    pkg_json = os.path.join(package_dir, "package.json")
    if os.path.exists(pkg_json):
        os.system(f"cd {package_dir} && npm install --ignore-scripts 2>/dev/null")

    # Try to require the package entry point
    script = f"""
    try {{
        require('{package_dir}');
    }} catch(e) {{}}
    """
    os.system(f"node -e \"{script}\" 2>/dev/null")


def main() -> None:
    package_dir = sys.argv[1] if len(sys.argv) > 1 else "/workspace"
    ecosystem = sys.argv[2] if len(sys.argv) > 2 else "auto"

    if ecosystem in ("pypi", "python"):
        run_python(package_dir)
    elif ecosystem in ("npm", "node"):
        run_node(package_dir)
    else:
        # Auto-detect: check for package.json vs .py files
        if os.path.exists(os.path.join(package_dir, "package.json")):
            run_node(package_dir)
        else:
            run_python(package_dir)

    # Signal completion
    print(json.dumps({"status": "completed"}))


if __name__ == "__main__":
    main()
