"""Manifest detection → build-system mapping (blueprint section 11)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional

from detection.language import iter_source_files

# Manifest file → build ecosystem
MANIFEST_MAP: Dict[str, str] = {
    "pyproject.toml": "pip",
    "requirements.txt": "pip",
    "setup.py": "pip",
    "Pipfile": "pipenv",
    "poetry.lock": "pip",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "settings.gradle": "gradle",
    "settings.gradle.kts": "gradle",
    "package.json": "npm",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "package-lock.json": "npm",
    "bun.lockb": "bun",
    "go.mod": "go",
    "go.work": "go",
    "Cargo.toml": "cargo",
    "composer.json": "composer",
    "Gemfile": "bundler",
    "CMakeLists.txt": "cmake",
    "Makefile": "make",
}


class ManifestDetector:
    """Find manifests in the tree and map them to build ecosystems."""

    def detect(self, source_root: Path, excluded: Optional[set] = None) -> List[Dict]:
        """Return [ {path, ecosystem, relative} ] for every manifest found."""
        source_root = Path(source_root).resolve()
        manifests: List[Dict] = []
        for path in iter_source_files(source_root, excluded):
            ecosystem = MANIFEST_MAP.get(path.name)
            if not ecosystem and path.name.endswith((".csproj", ".sln", ".vbproj")):
                ecosystem = "dotnet"
            if ecosystem:
                manifests.append(
                    {
                        "path": path,
                        "relative": str(path.relative_to(source_root)),
                        "ecosystem": ecosystem,
                    }
                )
        # Most-specific first: a lockfile beats a generic manifest.
        manifests.sort(key=lambda m: (m["relative"].count(os.sep), m["relative"]))
        return manifests

    def ecosystems(self, manifests: List[Dict]) -> Dict[str, List[Dict]]:
        """Group manifests by ecosystem."""
        grouped: Dict[str, List[Dict]] = {}
        for manifest in manifests:
            grouped.setdefault(manifest["ecosystem"], []).append(manifest)
        return grouped


def manifest_priority(ecosystem: str) -> int:
    """Prefer lockfile-backed ecosystems when several exist for one language."""
    priority = {
        "yarn": 0,
        "pnpm": 0,
        "bun": 0,
        "npm": 1,
        "pipenv": 1,
        "pip": 1,
    }
    return priority.get(ecosystem, 2)


class MissingManifestError(RuntimeError):
    """Raised when a language requires a manifest that cannot be found."""


def find_primary_manifest(manifests: List[Dict], ecosystem: str) -> Optional[Dict]:
    """Return the manifest representing the given ecosystem (nearest root first)."""
    matches = [m for m in manifests if m["ecosystem"] == ecosystem]
    if not matches:
        return None
    return min(matches, key=lambda m: m["relative"].count(os.sep))