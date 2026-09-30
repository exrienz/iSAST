"""Process execution primitives.

Blueprint section 35: never use shell strings with repository-controlled
input — always argv arrays, always timeouts, always captured output.
"""

from __future__ import annotations

import os
import signal
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence


class ExecutorError(RuntimeError):
    """Raised when an external process cannot be started at all."""


@dataclass(frozen=True)
class ProcessResult:
    """Outcome of one external process invocation."""

    command: List[str]
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    duration_seconds: float = 0.0

    @property
    def ok(self) -> bool:
        return (not self.timed_out) and self.exit_code == 0


@dataclass
class ExecutionError(Exception):
    """Structured failure for step orchestration (exit-code mapping)."""

    message: str
    result: Optional[ProcessResult] = None
    detail: str = ""

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        base = self.message
        if self.detail:
            base = f"{base}: {self.detail}"
        return base


def run_command(
    argv: Sequence[str],
    *,
    timeout: Optional[int] = None,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    extra_path: Optional[str] = None,
    limits: Optional[Dict[str, int]] = None,
) -> ProcessResult:
    """Run a process safely from an argument vector.

    - ``argv`` must be a list of strings (no shell interpretation).
    - ``timeout`` (seconds) kills the process tree on expiry.
    - ``extra_path`` is prepended to PATH so tools under ~/.isast/bin are found.
    - ``limits`` may contain ``cpu_seconds`` and ``memory_mb`` soft limits
      applied via resource.setrlimit (applies on POSIX only).
    """

    argv_list: List[str] = [str(a) for a in argv]
    if not argv_list:
        raise ExecutorError("empty command vector")

    run_env: Dict[str, str] = dict(os.environ)
    if env:
        run_env.update({str(k): str(v) for k, v in env.items()})
    if extra_path:
        path_current = run_env.get("PATH", os.defpath)
        if extra_path not in path_current.split(os.pathsep):
            run_env["PATH"] = f"{extra_path}{os.pathsep}{path_current}"

    preexec = None
    if limits and hasattr(resource_stub(), "setrlimit"):  # pragma: no branch
        preexec = _make_limiter(limits)

    import time

    started = time.monotonic()
    try:
        completed = subprocess.run(
            argv_list,
            cwd=cwd,
            env=run_env,
            capture_output=True,
            text=True,
            timeout=timeout,
            preexec_fn=preexec,
            check=False,
        )
        duration = time.monotonic() - started
        return ProcessResult(
            command=argv_list,
            exit_code=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
            timed_out=False,
            duration_seconds=duration,
        )
    except subprocess.TimeoutExpired as exc:
        duration = time.monotonic() - started
        return ProcessResult(
            command=argv_list,
            exit_code=-1,
            stdout=(exc.stdout or b"").decode("utf-8", "replace")
            if isinstance(exc.stdout, bytes)
            else (exc.stdout or ""),
            stderr=(exc.stderr or b"").decode("utf-8", "replace")
            if isinstance(exc.stderr, bytes)
            else (exc.stderr or ""),
            timed_out=True,
            duration_seconds=duration,
        )
    except FileNotFoundError as exc:
        raise ExecutorError(f"command not found: {argv_list[0]} ({exc})") from exc
    except PermissionError as exc:
        raise ExecutorError(f"command not executable: {argv_list[0]} ({exc})") from exc


def _make_limiter(limits: Dict[str, int]):
    """Build a POSIX preexec_fn applying CPU/memory soft limits."""

    import resource

    cpu_seconds = int(limits.get("cpu_seconds", 0))
    memory_bytes = int(limits.get("memory_mb", 0)) * 1024 * 1024
    no_file_limit = int(limits.get("max_files", 0))

    def apply_limits() -> None:  # pragma: no cover - runs in child process
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        if cpu_seconds:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds * 2))
        if memory_bytes:
            resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
        if no_file_limit:
            resource.setrlimit(resource.RLIMIT_NOFILE, (no_file_limit, no_file_limit))

    return apply_limits


def resource_stub():  # pragma: no cover - indirection for import guard
    """Return the resource module or None on platforms without it."""
    try:
        import resource

        return resource
    except ImportError:
        return None


@dataclass
class ToolPaths:
    """Resolved filesystem locations of the iSAST-managed tools."""

    isast_home: str
    bin_dir: str
    opengrep_bin: Optional[str] = None
    codeql_bin: Optional[str] = None
    extra: Dict[str, str] = field(default_factory=dict)