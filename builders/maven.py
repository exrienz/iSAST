"""Maven build plan."""

from __future__ import annotations

from pathlib import Path

from builders.base import BaseBuilder, BuildPlan


class MavenBuilder(BaseBuilder):
    ecosystem = "maven"

    def plan(self, manifest_path: Path, source_root: Path) -> BuildPlan:
        del source_root
        manifest_dir = manifest_path.parent
        wrapper = manifest_dir / "mvnw"
        if wrapper.exists():
            command = [str(wrapper), "clean", "package", "-DskipTests", "-q"]
        else:
            command = ["mvn", "clean", "package", "-DskipTests", "-q"]
        return BuildPlan(
            required=True,
            ecosystem=self.ecosystem,
            command=command,
            language="java",
            manifest_path=str(manifest_path),
            reason="maven project requires a build for CodeQL tracing",
        )