"""CMake/Make build plan for C/C++."""

from __future__ import annotations

from pathlib import Path

from builders.base import BaseBuilder, BuildPlan


class CmakeBuilder(BaseBuilder):
    ecosystem = "cmake"

    def plan(self, manifest_path: Path, source_root: Path) -> BuildPlan:
        del source_root
        configure = ["cmake", "-S", manifest_path.parent.name, "-B", "build", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"]
        compile_step = ["cmake", "--build", "build", "--parallel"]
        return BuildPlan(
            required=True,
            ecosystem="cmake",
            command=configure + compile_step,
            language="c",
            manifest_path=str(manifest_path),
            reason="c/cpp requires compilation for CodeQL extraction (autobuild may also be used)",
        )


class MakeBuilder(BaseBuilder):
    ecosystem = "make"

    def plan(self, manifest_path: Path, source_root: Path) -> BuildPlan:
        del source_root, manifest_path
        return BuildPlan(
            required=True,
            ecosystem="make",
            command=["make", "-j4"],
            manifest_path=None,
            reason="make-based project requires a build for CodeQL tracing",
        )