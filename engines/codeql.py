"""CodeQL engine (blueprint section 14).

Per supported language: detect → create CodeQL database → build if required
(via sandbox) → analyze with the security query suite → SARIF.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Tuple

from builders.base import BuildPlan
from core.executor import ProcessResult, run_command
from sandbox.executor import SandboxExecutor
from sandbox.manager import SandboxManager

CODEQL_SECURITY_SUITES = {
    "python": "python-security-extended.qls",
    "javascript-typescript": "javascript-security-extended.qls",
    "java-kotlin": "java-security-extended.qls",
    "go": "go-security-extended.qls",
    "csharp": "csharp-security-extended.qls",
    "c-cpp": "cpp-security-extended.qls",
    "ruby": "ruby-security-extended.qls",
    "swift": "swift-security-extended.qls",
}

DB_TIMEOUT = 3600
ANALYZE_TIMEOUT = 1800


def resolve_suite(codeql_binary: str, codeql_language: str) -> str:
    """Locate the security suite for a CodeQL language inside the installed bundle.

    The bundle ships qlpacks under <home>/qlpacks/codeql/<lang>-queries/<ver>/.
    Falls back to the bare suite name (works when query packs are in CLI
    search path for older bundles).
    """
    suite_file = CODEQL_SECURITY_SUITES.get(codeql_language)
    if not suite_file:
        return "security-extended"
    search_roots = [Path(codeql_binary).resolve().parent.parent / "qlpacks" / "codeql"]
    for root in search_roots:
        if not root.exists():
            continue
        for pack_dir in sorted(root.glob(f"*-queries/*"), reverse=True):
            candidate = pack_dir / "codeql-suites" / suite_file
            if candidate.exists():
                return str(candidate)
    return suite_file


class CodeqlEngine:
    """Create and analyze CodeQL databases for each supported language."""

    def __init__(self, binary: str, sandbox_manager: SandboxManager) -> None:
        self.binary = binary
        self.sandbox = SandboxExecutor(sandbox_manager)
        self.manager = sandbox_manager

    # ------------------------------------------------------------------
    # Database creation
    # ------------------------------------------------------------------

    def create_database(
        self,
        source_root: Path,
        db_path: Path,
        language: str,
        build_plan: Optional[BuildPlan] = None,
        *,
        allow_unsafe_build: bool = False,
        threads: int = 4,
        timeout: int = DB_TIMEOUT,
    ) -> Tuple[ProcessResult, Optional[str]]:
        """Create the CodeQL database. Returns (result, note).

        note explains skipped builds or failsafe decisions.
        """
        argv = [
            self.binary,
            "database",
            "create",
            str(db_path),
            f"--language={language}",
            f"--source-root={source_root}",
            f"--threads={threads}",
            "--overwrite",
            "--no-run-unnecessary-builds",
        ]
        if build_plan is not None and build_plan.required:
            build_result = self.sandbox.run_build(
                build_plan, str(source_root), timeout=max(300, timeout // 2)
            )
            if not build_result.ok:
                note = (
                    f"project build failed for {language} "
                    f"({build_plan.ecosystem}); creating database source-only"
                )
                return run_command(argv, cwd=str(source_root), timeout=timeout), note
            note = f"executed {build_plan.ecosystem} build (sandbox mode: {self.manager.decision.mode})"
            return run_command(argv, cwd=str(source_root), timeout=timeout), note
        return run_command(argv, cwd=str(source_root), timeout=timeout), None

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def analyze(
        self,
        db_path: Path,
        language: str,
        output_sarif: Path,
        *,
        threads: int = 4,
    ) -> ProcessResult:
        suite = resolve_suite(self.binary, language)
        argv = [
            self.binary,
            "database",
            "analyze",
            str(db_path),
            "--format=sarifv2.1.0",
            f"--output={output_sarif}",
            f"--threads={threads}",
            suite,
        ]
        return run_command(argv, timeout=ANALYZE_TIMEOUT)

    # ------------------------------------------------------------------
    # Orchestration for one language
    # ------------------------------------------------------------------

    def scan_language(
        self,
        source_root: Path,
        language: str,
        codeql_language: str,
        db_dir: Path,
        sarif_out: Path,
        build_plan: Optional[BuildPlan],
        *,
        threads: int,
        allow_unsafe_build: bool = False,
        timeout: int = DB_TIMEOUT,
    ) -> Tuple[bool, str]:
        """Full pipeline for one language. Returns (success, message)."""
        db_path = db_dir / f"codeql-{codeql_language}"
        created, note = self.create_database(
            source_root,
            db_path,
            codeql_language,
            build_plan=build_plan,
            allow_unsafe_build=allow_unsafe_build,
            threads=threads,
            timeout=timeout,
        )
        messages: List[str] = [note] if note else []
        if not created.ok:
            return False, f"database create failed for {language}: {created.stderr[-400:]}"
        analyzed = self.analyze(db_path, codeql_language, sarif_out, threads=threads)
        if not analyzed.ok:
            return False, f"analyze failed for {language}: {analyzed.stderr[-400:]}"
        return True, "; ".join(messages) if messages else "ok"

    def full_scan(
        self,
        source_root: Path,
        languages: List[Tuple[str, str]],
        db_dir: Path,
        sarif_dir: Path,
        plans: Dict[str, BuildPlan],
        *,
        threads: int,
        allow_unsafe_build: bool = False,
        timeout: int = DB_TIMEOUT,
    ) -> Dict[str, Tuple[bool, str]]:
        """Scan every (internal_name, codeql_name) pair. Returns per-lang status."""
        results: Dict[str, Tuple[bool, str]] = {}
        for internal_name, codeql_name in languages:
            results[internal_name] = self.scan_language(
                source_root,
                internal_name,
                codeql_name,
                db_dir,
                sarif_dir / f"{internal_name}.sarif",
                plans.get(internal_name),
                threads=threads,
                allow_unsafe_build=allow_unsafe_build,
                timeout=timeout,
            )
        return results

    def version(self) -> str:
        result = run_command([self.binary, "version"], timeout=120)
        return (result.stdout.strip() or result.stderr.strip())[:64]