"""Go build plan (source-only for CodeQL)."""

from __future__ import annotations

from pathlib import Path

from builders.base import BaseBuilder, BuildPlan


class GoBuilder(BaseBuilder):
    ecosystem = "go"

    def plan(self, manifest_path: Path, source_root: Path) -> BuildPlan:
        del source_root
        return BuildPlan(
            required=False,
            ecosystem=self.ecosystem,
            command=None,
            manifest_path=str(manifest_path),
            reason="go extraction is source-only; no build required",
        )