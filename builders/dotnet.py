"""dotnet build plan."""

from __future__ import annotations

from pathlib import Path

from builders.base import BaseBuilder, BuildPlan


class DotnetBuilder(BaseBuilder):
    ecosystem = "dotnet"

    def plan(self, manifest_path: Path, source_root: Path) -> BuildPlan:
        del source_root
        return BuildPlan(
            required=True,
            ecosystem=self.ecosystem,
            command=["dotnet", "restore"],
            language="csharp",
            manifest_path=str(manifest_path),
            reason="csharp requires 'dotnet restore' before 'dotnet build' for CodeQL tracing",
        )

    def build_after_restore(self, manifest_path: Path) -> BuildPlan:
        """Second phase of the .NET build (run after a successful restore)."""
        return BuildPlan(
            required=True,
            ecosystem=self.ecosystem,
            command=["dotnet", "build", "--nologo"],
            manifest_path=str(manifest_path),
            reason="csharp requires a build for CodeQL tracing",
        )