"""Cargo build plan.

Rust has no official CodeQL extractor; the build plan exists for potential
future use and for completeness of the BuildResolver matrix.
"""

from __future__ import annotations

from pathlib import Path

from builders.base import BaseBuilder, BuildPlan


class CargoBuilder(BaseBuilder):
    ecosystem = "cargo"

    def plan(self, manifest_path: Path, source_root: Path) -> BuildPlan:
        del source_root
        return BuildPlan(
            required=False,
            ecosystem=self.ecosystem,
            command=None,
            manifest_path=str(manifest_path),
            reason="rust has no CodeQL extractor; opengrep-only scan",
        )