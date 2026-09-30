"""Real-time AI progress dashboard tests (offline, stubbed validator)."""

import re
import time
from types import SimpleNamespace

import pytest

from ai.analyzer import AIAnalyzer
from ai.progress import AIDashboard, GroupEvent, format_clock, format_duration
from core.models import ValidationStatus
from findings.grouping import CandidateGroup

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


# ----------------------------------------------------------------------
# Test doubles
# ----------------------------------------------------------------------


class _StubFinding:
    """The fields of core.models.Finding the dashboard/analyzer read."""

    def __init__(self, index: int, file: str = "src/main.py", line: int = 0):
        self.finding_id = f"f{index:04d}aa"  # < 8 chars so [:8] keeps it unique
        self.file = file
        self.line = line
        self.scanner = "opengrep"
        self.rule_id = "sql-injection"
        self.scanner_severity = "HIGH"

    def to_dict(self):
        return {
            "finding_id": self.finding_id,
            "scanner": self.scanner,
            "rule_id": self.rule_id,
            "file": self.file,
            "line": self.line,
            "scanner_severity": self.scanner_severity,
        }


def _finding_stub(index: int) -> _StubFinding:
    return _StubFinding(index, file=f"src/file_{index}.py", line=index * 10)


def _group_of(*findings):
    group = CandidateGroup(key="test")
    group.findings = list(findings)
    return group


class _StatusValidator:
    """Returns one predetermined status for every group."""

    def __init__(self, status=ValidationStatus.CONFIRMED):
        self.status = status
        self.failures = set()

    def validate_group(self, finding, deadline=None):
        if finding["finding_id"] in self.failures:
            raise RuntimeError("boom")
        from ai.validator import ValidationResult as VR

        return VR(finding["finding_id"], self.status, confidence=0.9), None


def _analyzer(validator, concurrency=1):
    analyzer = AIAnalyzer.__new__(AIAnalyzer)
    analyzer.validator = validator
    analyzer.deduplicator = _reducer_no_links()
    analyzer.concurrency = concurrency
    return analyzer


def _reducer_no_links():
    class R:
        def reduce(self, groups, **kwargs):
            return [], []

    return R()


class _FakeStream:
    """Captured stdout stand-in with selectable ttyness."""

    def __init__(self, isatty: bool, columns: int = 80):
        self.buffer = ""
        self._isatty = isatty
        self.columns = columns

    def isatty(self):
        return self._isatty

    def write(self, text):
        self.buffer += text

    def flush(self):
        pass

    # Used by AIDashboard only when terminal_width is not injected.
    @property
    def terminal_size_stub(self):  # pragma: no cover - unused
        return SimpleNamespace(columns=self.columns)

    def lines(self):
        return self.buffer.split("\n")


def _dashboard(stream, total, *, quiet=False, verbose=False, **kwargs):
    fake_clock = kwargs.pop("clock", time.monotonic)
    kwargs.setdefault("terminal_width", stream.columns)
    dash = AIDashboard(total, quiet=quiet, verbose=verbose, stream=stream, clock=fake_clock, **kwargs)
    return dash


def _started_event(index, total, file="src/a.py", line=1):
    return GroupEvent("started", index, total, file, line)


def _completed_event(index, total, status="LIKELY", file="src/a.py", line=1, error=None):
    return GroupEvent("completed", index, total, file, line, status=status, error=error)


# ----------------------------------------------------------------------
# format_duration / format_clock
# ----------------------------------------------------------------------


def test_format_duration_units():
    assert format_duration(9) == "9s"
    assert format_duration(68) == "1m8s"
    assert format_duration(160) == "2m40s"


def test_format_clock_units():
    assert format_clock(64) == "01:04"
    assert format_clock(3725) == "1:02:05"


# ----------------------------------------------------------------------
# Event semantics from AIAnalyzer
# ----------------------------------------------------------------------


def test_analyzer_emits_started_then_completed_for_every_group():
    events = []
    validator = _StatusValidator(ValidationStatus.LIKELY)
    groups = [_group_of(_finding_stub(i)) for i in range(1, 5)]
    analyzer = _analyzer(validator)
    analyzer.analyze_groups(groups, on_event=events.append)

    kinds = [event.kind for event in events]
    started = [event for event in events if event.kind == "started"]
    completed = [event for event in events if event.kind == "completed"]
    assert kinds[:1] == ["started"]  # started fires before any completion
    assert sorted(e.index for e in started) == [1, 2, 3, 4]
    assert sorted(e.index for e in completed) == [1, 2, 3, 4]
    assert all(e.status == "LIKELY" for e in completed)
    assert completed[-1].file == groups[-1].primary().file


def test_analyzer_validator_raise_emits_unprocessed_completion_and_rethrows():
    validator = _StatusValidator(ValidationStatus.CONFIRMED)
    validator.failures = {"f0001aa"}
    events = []
    analyzer = _analyzer(validator)
    with pytest.raises(RuntimeError):
        analyzer.analyze_groups([_group_of(_finding_stub(1))], on_event=events.append)

    completions = [e for e in events if e.kind == "completed"]
    assert len(completions) == 1
    assert completions[0].status == ""  # renders as ~ UNPROCESSED
    assert completions[0].error is not None


def test_analyzer_concurrent_pipeline_keeps_dashboard_healthy():
    """Worker-thread completion events must not break the display layer."""
    class _SlowValidator:
        def validate_group(self, finding, deadline=None):
            time.sleep(0.03)
            from ai.validator import ValidationResult as VR

            return VR(finding["finding_id"], ValidationStatus.LIKELY, confidence=0.5), None

    stream = _FakeStream(isatty=True)
    dash = _dashboard(stream, total=8)
    analyzer = _analyzer(_SlowValidator())
    analyzer.concurrency = 4

    with dash:
        results, links, errors = analyzer.analyze_groups(
            [_group_of(_finding_stub(i)) for i in range(1, 9)],
            on_event=dash.on_event,
        )

    dash.stop()
    assert dash._broken is False
    assert len(results) == 8
    # events fire from worker threads but arrive with valid status per index
    states = dash.snapshot()
    assert states.done == 8
    assert any("✓ LIKELY" in line for line in (_strip_ansi(l) for l in stream.lines()))


# ----------------------------------------------------------------------
# Dashboard modes
# ----------------------------------------------------------------------


def test_append_mode_prints_historical_started_lines_and_verdict_lines():
    stream = _FakeStream(isatty=False)
    dash = _dashboard(stream, total=2, verbose=True)
    with dash:
        dash.on_event(_started_event(1, 2, "src/main.py", 323))
        dash.on_event(_completed_event(1, 2, "LIKELY", "src/main.py", 323))
        dash.on_event(_started_event(2, 2, "src/db.py", 12))
        dash.on_event(_completed_event(2, 2, "FALSE_POSITIVE", "src/db.py", 12))

    assert "\x1b" not in stream.buffer
    assert "    [ai] validating 1/2 src/main.py:323\n" in stream.buffer
    assert "    [ai] ✓ LIKELY 1/2 src/main.py:323" in stream.buffer
    assert "    [ai] ✗ FALSE_POSITIVE 2/2 src/db.py:12" in stream.buffer


def test_append_mode_without_verbose_is_silent_like_the_old_cli():
    stream = _FakeStream(isatty=False)
    dash = _dashboard(stream, total=2, verbose=False)
    with dash:
        dash.on_event(_started_event(1, 2))
        dash.on_event(_completed_event(1, 2))
    assert stream.buffer == ""


def test_quiet_mode_prints_nothing():
    stream = _FakeStream(isatty=True)
    dash = _dashboard(stream, total=0, quiet=True)
    with dash:
        dash.on_event(_started_event(1, 0))
        dash.on_event(_completed_event(1, 0))
    assert stream.buffer == ""


def test_live_mode_redraws_and_collapses_to_closing_line():
    stream = _FakeStream(isatty=True)
    dash = _dashboard(stream, total=2, max_recent=5)
    with dash:
        dash.on_event(_started_event(1, 2, "src/routes/projects.py", 592))
        dash.on_event(_completed_event(1, 2, "LIKELY", "src/routes/projects.py", 592))
        dash.on_event(_started_event(2, 2, "src/api/users.py", 118))

    lines = [line for line in stream.lines() if line]
    plain = [_strip_ansi(line) for line in lines]
    assert stream.buffer.count("\x1b[") > 0  # cursor/erase ANSI sequences present
    assert any("done 1/2" in line and "in flight 1" in line for line in plain)
    assert any("✓ LIKELY src/routes/projects.py:592" in line for line in plain)
    closing = plain[-1]
    assert "    [ai] groups validated: 1/2" in closing


def test_live_mode_lines_truncated_to_terminal_width():
    stream = _FakeStream(isatty=True, columns=50)
    dash = _dashboard(stream, total=1)
    long_file = "very/long/path/" + "d" * 80 + ".py"
    with dash:
        dash.on_event(_started_event(1, 1, long_file, 10))
    lines = [_strip_ansi(line) for line in stream.lines() if line]
    assert all(len(line) <= 49 for line in lines)
    assert any(long_file[:40] in line for line in lines)


def test_broken_stream_silences_dashboard_without_raising():
    class _BrokenStream:
        def isatty(self):
            return True

        def write(self, _text):
            raise OSError("EPIPE")

        def flush(self):
            raise OSError("EPIPE")

    stream = _BrokenStream()
    dash = AIDashboard(2, stream=stream, terminal_width=80)
    with dash:  # must not raise
        dash.on_event(_started_event(1, 2))
        dash.on_event(_completed_event(1, 2))
    stream2 = _FakeStream(isatty=False)
    dash = AIDashboard(2, quiet=False, verbose=True, stream=stream2)
    dash._broken = True
    dash.on_event(_started_event(1, 2))
    assert stream2.buffer == ""


# ----------------------------------------------------------------------
# State snapshot semantics
# ----------------------------------------------------------------------


def test_snapshot_counts_and_recent_ring_order():
    stream = _FakeStream(isatty=False)
    dash = _dashboard(stream, total=6)
    with dash:
        for i in range(1, 5):
            dash.on_event(_started_event(i, 6, f"f{i}.py", i))
        for i in range(1, 4):
            dash.on_event(_completed_event(i, 6, "LIKELY", f"f{i}.py", i))
        dash.on_event(_completed_event(99, 6, status="", error="gone"))  # unknown index

    state = dash.snapshot()
    assert state.done == 4
    assert state.in_flight == 1
    assert state.pending == 1
    assert len(state.recent) == 4
    # recent is most-recent-first
    assert state.recent[0][2] == ""  # the error completion (renders UNPROCESSED)
    assert state.recent[0][0] == "src/a.py"  # its synthetic file placeholder is the default
    assert state.recent[1][2] == "LIKELY"


def test_recent_ring_capped_at_max_recent():
    stream = _FakeStream(isatty=False)
    dash = _dashboard(stream, total=8, verbose=True, max_recent=3)
    with dash:
        for i in range(1, 7):
            dash.on_event(_started_event(i, 8, f"f{i}.py", i))
            dash.on_event(_completed_event(i, 8, "LIKELY", f"f{i}.py", i))
    snapshot = dash.snapshot()
    assert len(snapshot.recent) == 3
    assert snapshot.recent[0][0] == "f6.py"


def test_in_flight_rows_capped_with_overflow_marker():
    stream = _FakeStream(isatty=True)
    dash = _dashboard(stream, total=6, max_running=2, verbose=True)
    with dash:
        for i in range(1, 5):
            dash.on_event(_started_event(i, 6, f"f{i}.py", i))
    lines = [_strip_ansi(line) for line in stream.lines()]
    assert any("▸ f2.py:2 " in line for line in lines)
    assert any("… +2 more in flight" in line for line in lines)


def test_live_elapsed_grows_between_redraws():
    class _ManualClock:
        def __init__(self):
            self.now = 100.0

        def __call__(self):
            return self.now

    clock = _ManualClock()
    stream = _FakeStream(isatty=True)
    dash = _dashboard(stream, total=2, clock=clock)
    with dash:
        clock.now += 1.0
        dash.on_event(_started_event(1, 2, "src/a.py", 5))
        clock.now += 70.0
        dash.on_event(_completed_event(1, 2, "LIKELY", "src/a.py", 5))

    state = dash.snapshot()
    assert state.elapsed == pytest.approx(71.0)
    assert state.recent[0][4] == pytest.approx(70.0)


def test_stop_joins_ticker_without_thread_leak():
    stream = _FakeStream(isatty=True)
    before = time.monotonic()
    dash = _dashboard(stream, total=1, refresh_seconds=0.1)
    with dash:
        dash.on_event(_started_event(1, 1))
        time.sleep(0.25)
    after = time.monotonic()
    assert dash._ticker is None
    assert after - before < 2.0  # join must not hang
    # no extra non-daemon dashboard threads remain
    live = [t for t in __import__("threading").enumerate() if t.name == "ai-dashboard"]
    assert live == [] or all(not t.is_alive() for t in live)


# ----------------------------------------------------------------------
# Settings: raised AI concurrency default
# ----------------------------------------------------------------------


def test_ai_concurrency_default_is_eight(monkeypatch):
    from core.settings import load_settings

    monkeypatch.delenv("AI_CONCURRENCY", raising=False)
    assert load_settings().ai_concurrency == 8

    monkeypatch.setenv("AI_CONCURRENCY", "12")  # env wins over the repo .env
    assert load_settings().ai_concurrency == 12

# ----------------------------------------------------------------------
# Cached (restored) verdicts and dedup progress events
# ----------------------------------------------------------------------


class _CountingValidator:
    def __init__(self, status=ValidationStatus.CONFIRMED):
        self.status = status
        self.found_ids = []

    def validate_group(self, finding, deadline=None):
        from ai.validator import ValidationResult as VR

        self.found_ids.append(finding["finding_id"])
        return VR(finding["finding_id"], self.status, confidence=0.9), None


class _CheckpointStub:
    """Minimal AICheckpoint duck type preloaded with one group verdict."""

    def __init__(self, entry):
        self.entry = entry
        self.recorded = []

    def preload(self):
        return {self.entry.finding_id: self.entry}

    def cached_group(self, group):
        from ai.checkpoint import CachedGroup

        rep = group.primary().finding_id[:8]
        if rep != self.entry.finding_id:
            return None
        return CachedGroup(
            finding_id=self.entry.finding_id,
            member_ids=[f.finding_id[:8] for f in group.findings],
            verdict=self.entry.verdict,
            error=self.entry.error,
        )

    def dedup_preload(self):
        return {}

    def record(self, group, result, error):
        self.recorded.append((group.primary().finding_id[:8], result.status.value, error))

    def record_dedup(self, members, links, error):
        pass

    def flush(self):
        pass


def _checkpoint_entry(short_id, verdict):
    from ai.checkpoint import CachedGroup

    return CachedGroup(finding_id=short_id, member_ids=[short_id], verdict=verdict, error=None)


def test_analyzer_skips_cached_groups_without_model_call():
    validator = _CountingValidator()
    cached_group_id = "f0001aa"
    checkpoint = _CheckpointStub(
        _checkpoint_entry(
            cached_group_id,
            {
                "status": "LIKELY",
                "confidence": 0.7,
                "reason": "restored",
                "ai_severity": "HIGH",
            },
        )
    )
    events: list = []
    analyzer = _analyzer(validator)
    analyzer.checkpoint = checkpoint
    groups = [_group_of(_finding_stub(i)) for i in range(1, 4)]
    results, links, errors = analyzer.analyze_groups(groups, on_event=events.append)

    assert errors == []
    assert validator.found_ids == ["f0002aa", "f0003aa"]  # cached group never re-asked
    restored = results[cached_group_id]
    assert restored.status == ValidationStatus.LIKELY
    assert restored.confidence == 0.7
    # 1 cached + 2 completed events, cached one tagged as such.
    kinds = [e.kind for e in events]
    assert kinds.count("cached") == 1
    assert kinds.count("completed") == 2
    cached_event = next(e for e in events if e.kind == "cached")
    assert cached_event.status == "LIKELY"
    assert cached_event.index == 1


def test_dashboard_counts_cached_events_as_done():
    dashboard = AIDashboard(3, enable_ansi=False, stream=_FakeStream(isatty=False))
    dashboard.start()
    dashboard.on_event(GroupEvent("cached", 1, 3, "src/a.py", 1, "LIKELY"))
    dashboard.on_event(GroupEvent("dedup", 1, 4, "dedup", 0))
    dashboard.on_event(GroupEvent("dedup", 4, 4, "dedup", 0))
    state = dashboard.snapshot()
    assert state.done == 1
    assert state.in_flight == 0
    assert state.dedup_done == 4
    assert state.dedup_total == 4
    dashboard.stop()
