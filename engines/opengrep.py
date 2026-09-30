"""OpenGrep engine (blueprint section 13).

Runs across the whole source tree with --config auto, SARIF output and
recall-favoring settings. Excludes standard build/dependency noise.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from core.executor import ProcessResult, run_command

EXCLUDES = [
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    "coverage",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
]

_BASELINE_RULES = "isast-baseline-security.yaml"


def _baseline_rules_path() -> Path:
    """Absolute path of the bundled baseline security ruleset."""
    return Path(__file__).resolve().parent / "rules" / _BASELINE_RULES


def opengrep_flags(extra: Optional[List[str]] = None) -> List[str]:
    """Standard flag set; favor recall over aggressive suppression."""
    flags: List[str] = []
    for exclude in EXCLUDES:
        flags += ["--exclude", exclude]
    return flags + list(extra or [])


class OpenGrepEngine:
    """Run an OpenGrep scan and produce a SARIF artifact."""

    def __init__(self, binary: str) -> None:
        self.binary = binary

    def scan(
        self,
        source_root: Path,
        output_sarif: Path,
        *,
        threads: int = 4,
        timeout: int = 3600,
    ) -> ProcessResult:
        """Execute the scan; the SARIF file must appear on success.

        Config is layered: registry 'auto' first, then iSAST's bundled
        baseline security ruleset (recall over aggressive suppression —
        blueprint section 13). No --severity filter: all severities are kept.
        """
        argv = [
            self.binary,
            "scan",
            "--config",
            "auto",
            "--config",
            str(_baseline_rules_path()),
            "--sarif-output",
            str(output_sarif),
            "--max-target-bytes",
            "2000000",
            "--jobs",
            str(threads),
            "--no-git-ignore",
        ]
        argv += opengrep_flags()
        argv += ["."]
        return run_command(argv, cwd=str(source_root), timeout=timeout)

    def version(self) -> str:
        result = run_command([self.binary, "--version"], timeout=60)
        return (result.stdout.strip() or result.stderr.strip())[:64]