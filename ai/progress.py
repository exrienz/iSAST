"""Real-time progress display for the AI analysis stage (blueprint section 21-27).

Rendered states (interactive TTY):
    done 3/24 | in flight 4 | pending 17 | elapsed 12:04
    running:
      ▸ src/routes/projects.py:592 (2m40s)
    recent:
      ✓ LIKELY src/main.py:323 (1m8s)

Three modes, chosen at construction:
    LIVE   - in-place ANSI redraw (interactive TTY, posix; kill switch
             ISAST_AI_DASHBOARD=0). Transient: collapses to a single
             closing line on stop(), so the live rows are not in the logs.
    APPEND - one printed line per event, only when verbose — byte-identical
             to the historical output for live log capture / CI.
    OFF    - --quiet or an empty group list: prints nothing.

Fail-open contract (blueprint section 28): the display layer must never be
able to fail the AI stage. Every public call is exception-guarded and a
broken stream silences the dashboard permanently.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Deque, Dict, IO, List, Optional, Tuple

MAX_RUNNING_ROWS = 8
MAX_RECENT_ROWS = 5
REFRESH_SECONDS = 1.0
MIN_WIDTH = 40

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

GREEN = "\x1b[32m"
RED = "\x1b[31m"
YELLOW = "\x1b[33m"
DIM = "\x1b[2m"
RESET = "\x1b[0m"

_VERDICT = {
    "CONFIRMED": ("✓", GREEN),
    "LIKELY": ("✓", GREEN),
    "FALSE_POSITIVE": ("✗", RED),
    "INSUFFICIENT_EVIDENCE": ("~", YELLOW),
    "UNPROCESSED": ("~", YELLOW),
}

APPEND_PREFIX = "    [ai] "


@dataclass(frozen=True)
class GroupEvent:
    """One transition in the AI validation stage, emitted by AIAnalyzer."""

    kind: str  # "started" | "completed" | "cached" | "dedup"
    index: int  # 1-based submission position (dedup: completed count)
    total: int
    file: str
    line: int
    status: str = ""  # completed/cached: ValidationStatus.value ("" -> UNPROCESSED)
    error: Optional[str] = None  # completed only; cached verdicts stay informational


@dataclass(frozen=True)
class DashboardState:
    """Immutable snapshot of the dashboard for assertions."""

    done: int
    total: int
    in_flight: int
    pending: int
    elapsed: float
    running: Tuple[Tuple[str, int, float], ...]  # (file, line, per-item elapsed)
    recent: Tuple[Tuple[str, int, str, Optional[str], float], ...]
    dedup_done: int = 0
    dedup_total: int = 0


def format_duration(seconds: float) -> str:
    """Per-item duration, e.g. 68 -> '1m8s', 9 -> '9s'."""
    seconds = max(0, int(seconds))
    minutes, secs = divmod(seconds, 60)
    if minutes == 0:
        return f"{secs}s"
    return f"{minutes}m{secs}s"


def format_clock(seconds: float) -> str:
    """Stage-level clock, e.g. 3725 -> '1:02:05', 64 -> '01:04'."""
    seconds = max(0, int(seconds))
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def _verdict(status: str) -> Tuple[str, str]:
    return _VERDICT.get((status or "").strip().upper(), ("~", YELLOW))


def _clip(text: str, width: int) -> str:
    """Truncate so visible text fits; if it must be cut, drop colour codes
    instead of slicing mid-escape (which would garble the following redraw)."""
    visible = ANSI_RE.sub("", text)
    if len(visible) <= width:
        return text
    return visible[: max(1, width - 1)] + "…"


def _verdict_segment(status: str, colored: bool) -> str:
    symbol, color = _verdict(status)
    label = (status or "UNPROCESSED").upper()
    if not colored:
        return f"{symbol} {label}"
    return f"{color}{symbol}\x1b[0m {label}"


@dataclass(frozen=True)
class _RunningItem:
    file: str
    line: int
    started_offset: float  # seconds after stage start


class AIDashboard:
    """Live/APPEND/OFF progress view over AIAnalyzer's GroupEvent stream."""

    def __init__(
        self,
        total: int,
        *,
        quiet: bool = False,
        verbose: bool = False,
        stream: Optional[IO] = None,
        enable_ansi: Optional[bool] = None,
        refresh_seconds: float = REFRESH_SECONDS,
        max_running: int = MAX_RUNNING_ROWS,
        max_recent: int = MAX_RECENT_ROWS,
        clock: Callable[[], float] = time.monotonic,
        terminal_width: Optional[int] = None,
    ) -> None:
        self._total = max(0, int(total))
        self._stream = stream if stream is not None else sys.stdout
        self._refresh_seconds = max(0.1, float(refresh_seconds))
        self._max_running = max(1, int(max_running))
        self._max_recent = max(1, int(max_recent))
        self._clock = clock
        self._terminal_width = terminal_width
        self._verbose = verbose
        self._mode = self._select_mode(quiet, enable_ansi)
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._ticker: Optional[threading.Thread] = None
        self._start_time = self._clock()
        self._running: Dict[int, _RunningItem] = {}
        self._recent: Deque[Tuple[str, int, str, Optional[str], float]] = deque()
        self._done = 0
        self._dedup_done = 0
        self._dedup_total = 0
        self._last_frame_lines = 0
        self._broken = False
        self._finished = False

    def _select_mode(self, quiet: bool, enable_ansi: Optional[bool]) -> str:
        if quiet or self._total <= 0:
            return "off"
        if os.environ.get("ISAST_AI_DASHBOARD", "1") == "0":
            return "append"
        is_tty = callable(getattr(self._stream, "isatty", None)) and self._stream.isatty()
        ansi_ok = os.name == "posix" if enable_ansi is None else bool(enable_ansi)
        if is_tty and ansi_ok:
            return "live"
        return "append"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Begin the display (ticker thread in LIVE mode)."""
        self._guarded(self._start_inner)

    def _start_inner(self) -> None:
        if self._mode == "off":
            return
        self._start_time = self._clock()
        if self._mode == "live":
            self._stop_event.clear()
            self._ticker = threading.Thread(
                target=self._ticker_loop, name="ai-dashboard", daemon=True
            )
            self._ticker.start()

    def stop(self) -> None:
        """Stop the ticker and collapse the live frame (idempotent)."""
        self._stop_event.set()  # start() clears it again, so no re-arm here
        if self._ticker is not None:
            self._ticker.join(timeout=1.0)
            self._ticker = None
        self._guarded(self._finish_live)

    def _finish_live(self) -> None:
        if self._mode != "live" or self._finished:
            return
        self._finished = True
        # Bounded acquire: a slow/blocking stream must not stall the scan in
        # _stage_ai's finally (fail-open contract).
        acquired = self._lock.acquire(timeout=0.5)
        if not acquired:
            return
        try:
            self._redraw_locked()
            closing = (
                f"{APPEND_PREFIX}groups validated: {self._done}/{self._total}"
                f" in {format_clock(self._clock() - self._start_time)}"
            )
            # After a frame the cursor already sits on a fresh line; with no
            # frame it sits right after the "[7/8] AI analysis ..." banner.
            prefix = "" if self._last_frame_lines else "\n"
            self._write_locked(prefix + _clip(closing, self._width()) + "\n")
            self._last_frame_lines = 0
        finally:
            self._lock.release()

    def __enter__(self) -> "AIDashboard":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    def on_event(self, event: GroupEvent) -> None:
        """Analyzer callback; safe to call from worker threads."""
        if self._finished:
            return  # late events must not repaint after the collapse line
        self._guarded(self._handle_event, event)

    def redraw(self) -> None:
        """Public repaint (ticker and tests). Acquires the state lock itself."""
        if self._broken or self._finished:
            return
        try:
            with self._lock:
                self._redraw_locked()
        except Exception:  # noqa: BLE001 — display must never fail the scan
            self._broken = True

    def snapshot(self) -> DashboardState:
        """Lock-consistent view of the observable state."""
        with self._lock:
            now_offset = self._clock() - self._start_time
            running = tuple(
                (item.file, item.line, max(0.0, now_offset - item.started_offset))
                for item in self._running.values()
            )
            recent = tuple(self._recent)
            done = self._done
            total = self._total
            dedup_done = self._dedup_done
            dedup_total = self._dedup_total
        elapsed = now_offset
        in_flight = len(running)
        return DashboardState(
            done=done,
            total=total,
            in_flight=in_flight,
            pending=max(0, total - done - in_flight),
            elapsed=elapsed,
            running=running,
            recent=recent,
            dedup_done=dedup_done,
            dedup_total=dedup_total,
        )

    # ------------------------------------------------------------------
    # Event handling (all state mutation under self._lock)
    # ------------------------------------------------------------------

    def _handle_event(self, event: GroupEvent) -> None:
        with self._lock:
            if event.kind == "started":
                self._on_started(event)
            elif event.kind == "completed":
                self._on_completed(event)
            elif event.kind == "cached":
                self._on_cached(event)
            elif event.kind == "dedup":
                self._on_dedup(event)
            # unknown kinds: display-only — ignore, never count as a completion

    def _on_cached(self, event: GroupEvent) -> None:
        """A restored (checkpointed) verdict — counted as done, never started."""
        self._recent.appendleft((event.file, event.line, (event.status or "").upper(), event.error, 0.0))
        while len(self._recent) > self._max_recent:
            self._recent.pop()
        self._done += 1
        if self._mode == "append" and self._verbose:
            segment = _verdict_segment(event.status, colored=False)
            self._write_locked(
                f"{APPEND_PREFIX}{segment} {event.index}/{event.total}"
                f" {event.file}:{event.line} (restored)\n",
                flush=True,
            )
        elif self._mode == "live":
            self._redraw_locked()

    def _on_dedup(self, event: GroupEvent) -> None:
        """Duplicate-link phase counter; separate from the validation done count."""
        self._dedup_done = event.index
        self._dedup_total = event.total
        if self._mode == "append" and self._verbose:
            self._write_locked(
                f"{APPEND_PREFIX}dedup {event.index}/{event.total} groups\n",
                flush=True,
            )
        elif self._mode == "live":
            self._redraw_locked()

    def _on_started(self, event: GroupEvent) -> None:
        self._running[event.index] = _RunningItem(
            file=event.file,
            line=event.line,
            started_offset=max(0.0, self._clock() - self._start_time),
        )
        if self._mode == "append" and self._verbose:
            self._write_locked(
                f"{APPEND_PREFIX}validating "
                f"{event.index}/{event.total} {event.file}:{event.line}\n",
                flush=True,
            )
        elif self._mode == "live":
            self._redraw_locked()

    def _on_completed(self, event: GroupEvent) -> None:
        started = getattr(self._running.pop(event.index, None), "started_offset", None)
        duration = (
            max(0.0, self._clock() - self._start_time - started)
            if started is not None
            else 0.0
        )
        self._recent.appendleft(
            (event.file, event.line, (event.status or "").upper(), event.error, duration)
        )
        while len(self._recent) > self._max_recent:
            self._recent.pop()
        self._done += 1
        if self._mode == "append" and self._verbose:
            segment = _verdict_segment(event.status, colored=False)
            self._write_locked(
                f"{APPEND_PREFIX}{segment} {event.index}/{event.total}"
                f" {event.file}:{event.line} ({format_duration(duration)})\n",
                flush=True,
            )
        elif self._mode == "live":
            self._redraw_locked()

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def _ticker_loop(self) -> None:
        while not self._stop_event.wait(self._refresh_seconds):
            self.redraw()  # redraw() acquires the lock itself

    def _width(self) -> int:
        if self._terminal_width is not None:
            return max(MIN_WIDTH, int(self._terminal_width) - 1)
        try:
            columns = shutil.get_terminal_size().columns
        except (OSError, ValueError):
            columns = 80
        return max(MIN_WIDTH, columns - 1)

    def _redraw_locked(self) -> None:
        """Repaint the live frame. Caller must hold self._lock."""
        frame = self._build_frame()
        width = self._width()
        frame = [_clip(line, width) for line in frame]
        out: List[str] = []
        if self._last_frame_lines:
            out.append(f"\x1b[{self._last_frame_lines}F\x1b[J")
        out.append("\n".join(frame) + "\n")
        self._write_locked("".join(out), flush=True)
        self._last_frame_lines = len(frame)

    def _build_frame(self) -> List[str]:
        now_offset = self._clock() - self._start_time
        pending = max(0, self._total - self._done - len(self._running))
        header = (
            f"  done {self._done}/{self._total} | in flight {len(self._running)}"
            f" | pending {pending} | elapsed {format_clock(now_offset)}"
        )
        lines = [header]
        if self._dedup_total:
            lines.append(
                f"  dedup {self._dedup_done}/{self._dedup_total} (duplicate-link analysis)"
            )
        lines.append("")
        lines.append("running:")
        running_items = list(self._running.items())
        for _index, item in running_items[: self._max_running]:
            per_item = max(0.0, now_offset - item.started_offset)
            lines.append(f"    ▸ {item.file}:{item.line} ({format_duration(per_item)})")
        overflow = len(running_items) - self._max_running
        if overflow > 0:
            lines.append(f"    … +{overflow} more in flight")
        lines.append("")
        lines.append("recent:")
        if not self._recent:
            lines.append(f"    {DIM}(no completions yet){RESET}")
        for file, line, status, _error, duration in list(self._recent)[: self._max_recent]:
            lines.append(
                f"    {_verdict_segment(status, colored=True)} {file}:{line}"
                f" ({format_duration(duration)})"
            )
        return lines

    # ------------------------------------------------------------------
    # Never-fail plumbing
    # ------------------------------------------------------------------

    def _write_locked(self, text: str, flush: bool = False) -> None:
        self._stream.write(text)
        if flush:
            self._stream.flush()

    def _guarded(self, fn, *args) -> None:
        """Run an operation; any failure permanently silences the dashboard."""
        if self._broken:
            return
        try:
            fn(*args)
        except Exception:  # noqa: BLE001 — display must never fail the scan
            self._broken = True
            try:  # one visible note so a dead dashboard is never silent
                print(
                    "[ai] live dashboard disabled: display failure",
                    file=sys.stderr,
                    flush=True,
                )
            except Exception:  # noqa: BLE001
                pass