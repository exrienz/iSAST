"""Gradle build plan."""

from __future__ import annotations

from pathlib import Path

from builders.base import BaseBuilder, BuildPlan


class GradleBuilder(BaseBuilder):
    ecosystem = "gradle"

    def plan(self, manifest_path: Path, source_root: Path) -> BuildPlan:
        del source_root
        manifest_dir = manifest_path.parent
        for wrapper_name in ("gradlew", "gradlew.bat"):
            wrapper = manifest_dir / wrapper_name
            if wrapper.exists():
                command = [str(wrapper), "clean", "build", "-x", "test", "--quiet"]
                return BuildPlan(
                    required=True,
                    ecosystem="gradle",
                    command=command,
                    language="java",
                    manifest_path=str(manifest_path),
                    reason="gradle project requires a build for CodeQL tracing",
                )
        # No wrapper: 'gradle' on PATH is expected in build sandbox images.
        return BuildPlan(
            required=True,
            ecosystem="gradle",
            command=["gradle", "clean", "build", "-x", "test", "--quiet"],
            language="java",
            manifest_path=str(manifest_path),
            reason="gradle project requires a build for CodeQL tracing (no wrapper found)",
        )