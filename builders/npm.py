"""Node npm/yarn/pnpm build plan.

JavaScript/TypeScript CodeQL extraction is source-only, but some projects
need a build step to generate artifacts that CodeQL can parse, so the plan
is available when requested by the build resolver.
"""

from __future__ import annotations

from pathlib import Path

from builders.base import BaseBuilder, BuildPlan


class NpmBuilder(BaseBuilder):
    ecosystem = "npm"

    def plan(self, manifest_path: Path, source_root: Path) -> BuildPlan:
        del source_root
        return BuildPlan(
            required=False,
            ecosystem=self.ecosystem,
            command=["npm", "run", "build"],
            language="javascript",
            manifest_path=str(manifest_path),
            reason="javascript/typescript extraction is source-only; no build required",
        )

    def optional_build(self, manifest_path: Path) -> BuildPlan:
        """Build plan used only when the project defines a build script."""
        try:
            import json

            package_json = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            package_json = {}
        scripts = package_json.get("scripts") or {}
        if "build" not in scripts:
            return BuildPlan(
                required=False,
                ecosystem=self.ecosystem,
                reason="no build script in package.json",
            )
        return BuildPlan(
            required=True,
            ecosystem=self.ecosystem,
            command=["npm", "run", "build", "--silent"],
            manifest_path=str(manifest_path),
            reason="package.json defines a build script",
        )