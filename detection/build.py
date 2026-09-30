"""BuildResolver: map ecosystems to concrete BuildPlan objects
(blueprint section 15).

Every command is an argv list — never a shell string.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Dict, List, Optional

from builders.base import BuildPlan
from builders.cargo import CargoBuilder
from builders.cmake import CmakeBuilder
from builders.dotnet import DotnetBuilder
from builders.go import GoBuilder
from builders.gradle import GradleBuilder
from builders.maven import MavenBuilder
from builders.npm import NpmBuilder

from detection.manifest import find_primary_manifest

# Languages whose CodeQL extraction requires project compilation.
BUILD_REQUIRED_LANGUAGES = {"java", "kotlin", "csharp", "c", "cpp", "swift"}

_LANGUAGE_BUILDERS: Dict[str, Callable[[], object]] = {
    "java": MavenBuilder,
    "kotlin": MavenBuilder,
    "csharp": DotnetBuilder,
    "c": CmakeBuilder,
    "cpp": CmakeBuilder,
    "python": lambda: None,
    "javascript": lambda: None,
    "typescript": lambda: None,
    "go": lambda: None,
    "ruby": lambda: None,
}


class BuildResolver:
    """Resolve whether CodeQL needs a project build and, if so, execute what."""

    def __init__(self, manifests: List[Dict]) -> None:
        self.manifests = manifests

    def plan_for_language(self, language: str, source_root: Path) -> BuildPlan:
        """Return the BuildPlan for one detected language."""
        if language not in BUILD_REQUIRED_LANGUAGES:
            return BuildPlan(
                required=False,
                language=language,
                reason=f"'{language}' extraction is source-only; no project build required",
            )
        builder = _LANGUAGE_BUILDERS.get(language)
        if builder is None:
            return BuildPlan(
                required=False,
                language=language,
                reason=f"no build resolver available for '{language}'",
            )
        instance = builder()
        if instance is None:
            return BuildPlan(
                required=False, language=language, reason=f"no build resolver for '{language}'"
            )
        if language in ("java", "kotlin"):
            manifest_ecosystems = [m["ecosystem"] for m in self.manifests]
            if "gradle" in manifest_ecosystems:
                instance = GradleBuilder()
                manifest = find_primary_manifest(self.manifests, "gradle")
            else:
                manifest = find_primary_manifest(self.manifests, "maven")
        else:
            manifest = find_primary_manifest(self.manifests, getattr(instance, "ecosystem", ""))
        if manifest is None:
            return BuildPlan(
                required=False,
                language=language,
                reason=(
                    f"language '{language}' needs a build but no compatible manifest was found; "
                    "attempting source-only extraction"
                ),
            )
        # Python is never built by iSAST (blueprint section 17): python projects
        # reach this point only through a source-only path.
        del source_root
        return instance.plan(Path(manifest["path"]), Path("."))

    def plan_by_ecosystem(self, ecosystem: str, source_root: Path) -> Optional[BuildPlan]:
        manifest = find_primary_manifest(self.manifests, ecosystem)
        if manifest is None:
            return None
        builder = _ECOSYSTEM_BUILDERS.get(ecosystem)
        if builder is None:
            return None
        return builder().plan(Path(manifest["path"]), source_root)


_ECOSYSTEM_BUILDERS: Dict[str, Callable[[], object]] = {
    "maven": MavenBuilder,
    "gradle": GradleBuilder,
    "npm": NpmBuilder,
    "go": GoBuilder,
    "cargo": CargoBuilder,
    "cmake": CmakeBuilder,
    "dotnet": DotnetBuilder,
}


def plans_by_language(
    languages: List, manifests: List[Dict], source_root: Path
) -> Dict[str, BuildPlan]:
    """Convenience: BuildPlan for each detected language."""
    resolver = BuildResolver(manifests)
    return {lang.name: resolver.plan_for_language(lang.name, source_root) for lang in languages}