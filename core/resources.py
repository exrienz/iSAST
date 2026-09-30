"""iSAST home directory locations.

All engine downloads, databases and scan workspaces live under ~/.isast
(blueprint section 8).
"""

from __future__ import annotations

import os
from pathlib import Path

ISAST_VERSION = "1.0.0"


def isast_home() -> Path:
    home = os.environ.get("ISAST_HOME")
    if home:
        return Path(home).expanduser()
    return Path.home() / ".isast"


def bin_dir() -> Path:
    return isast_home() / "bin"


def tools_dir() -> Path:
    return isast_home() / "tools"


def codeql_home() -> Path:
    return tools_dir() / "codeql"


def cache_dir() -> Path:
    return isast_home() / "cache"


def downloads_dir() -> Path:
    return cache_dir() / "downloads"


def checksums_dir() -> Path:
    return cache_dir() / "checksums"


def databases_dir() -> Path:
    return isast_home() / "databases"


def logs_dir() -> Path:
    return isast_home() / "logs"


def config_dir() -> Path:
    return isast_home() / "config"


def scans_dir() -> Path:
    return isast_home() / "scans"


def ensure_layout() -> None:
    """Create the ~/.isast directory tree (idempotent, safe)."""
    for directory in (
        isast_home(),
        bin_dir(),
        tools_dir(),
        codeql_home(),
        cache_dir(),
        downloads_dir(),
        checksums_dir(),
        databases_dir(),
        logs_dir(),
        config_dir(),
        scans_dir(),
    ):
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError:
            # Home dir may be read-only in ephemeral CI pods; iSAST must not
            # crash here — engine installation will surface the real error.
            pass