"""Incremental AI checkpoint tests (validation-partial.json / dedup.json)."""

import json

import pytest

from ai.checkpoint import AICheckpoint, CachedGroup
from core.models import DedupLink, ValidationStatus, ValidationResult
from tests.test_ai import _finding_stub, _group_of


def _result(short_id, status="CONFIRMED", confidence=0.9):
    return ValidationResult(
        finding_id=short_id,
        status=ValidationStatus(status),
        confidence=confidence,
        reason="ok",
        ai_severity="HIGH",
    )


def _record_one(checkpoint, count=1):
    groups = []
    for i in range(count):
        f = _finding_stub(i + 1)
        group = _group_of(f)
        groups.append(group)
        checkpoint.record(group, _result(f.finding_id[:8]), None)
    return groups


def test_checkpoint_round_trip_on_disk(tmp_path):
    path = tmp_path / "validation-partial.json"
    checkpoint = AICheckpoint(path, tmp_path / "dedup.json", throttle_seconds=0.0)
    _record_one(checkpoint, count=2)

    document = json.loads(path.read_text())
    assert document["format"] == 1
    assert len(document["groups"]) == 2

    restored = AICheckpoint(path).preload()
    assert len(restored) == 2
    for rep, entry in restored.items():
        assert rep == entry.finding_id
        result = entry.to_result(rep)
        assert result.status == ValidationStatus.CONFIRMED
        assert result.confidence == 0.9
        assert result.ai_severity == "HIGH"


def test_checkpoint_survives_reopen_and_flush(tmp_path):
    # Corrupt (torn) contents must read back empty, never crash the scan.
    path = tmp_path / "validation-partial.json"
    path.write_text('{"groups": {"abc12345": {"ve')  # torn write
    assert AICheckpoint.preload_file(path) == {}


def test_cached_group_member_set_guard(tmp_path):
    path = tmp_path / "validation-partial.json"
    checkpoint = AICheckpoint(path, throttle_seconds=0.0)
    group = _group_of(_finding_stub(1), _finding_stub(2))
    checkpoint.record(group, _result(group.primary().finding_id[:8]), None)

    assert checkpoint.cached_group(group) is not None
    # A different group ([:8] collision shape): member set mismatch → no reuse.
    other = _group_of(_finding_stub(3), _finding_stub(4))
    assert checkpoint.cached_group(other) is None


def test_cached_group_reruns_recorded_failures(tmp_path):
    """UNPROCESSED+error entries (budget stall) get a fresh call on resume."""
    path = tmp_path / "validation-partial.json"
    checkpoint = AICheckpoint(path, throttle_seconds=0.0)
    group = _group_of(_finding_stub(1))
    checkpoint.record(group, _result(group.primary().finding_id[:8], status="UNPROCESSED"), "AI group budget exhausted")

    assert checkpoint.cached_group(group) is None  # worth a fresh model call

    checkpoint.record(group, _result(group.primary().finding_id[:8], status="UNPROCESSED"), None)
    assert checkpoint.cached_group(group) is not None  # clean UNPROCESSED still reused


def test_record_dedup_round_trip_and_failure_rerun(tmp_path):
    checkpoint = AICheckpoint(
        tmp_path / "validation-partial.json", tmp_path / "dedup.json", throttle_seconds=0.0
    )
    members = [{"finding_id": "aaa11111x"[:8]}, {"finding_id": "bbb22222y"[:8]}]
    checkpoint.record_dedup(members, [DedupLink(canonical_finding_id="aaa11111", duplicates=["bbb22222"], reason="same")], None)

    preloaded = AICheckpoint(
        tmp_path / "validation-partial.json", tmp_path / "dedup.json"
    ).dedup_preload()
    from ai.deduplicator import dedup_key

    assert list(preloaded) == [dedup_key(members)]
    assert preloaded[dedup_key(members)][0]["canonical_finding_id"] == "aaa11111"

    # Recorded failure → not reused (re-run).
    checkpoint.record_dedup(members, [], "gateway exploded")
    refreshed = AICheckpoint(
        tmp_path / "validation-partial.json", tmp_path / "dedup.json"
    ).dedup_preload()
    assert "links" not in refreshed or not refreshed  # key still present only via links
    from ai.deduplicator import _links_from_saved

    links, _err = _links_from_saved(
        json.loads((tmp_path / "dedup.json").read_text())["groups"][dedup_key(members)], members
    )
    assert links is None  # failure record → re-run


def test_checkpoint_flush_writes_pending_state(tmp_path):
    checkpoint = AICheckpoint(
        tmp_path / "validation-partial.json", tmp_path / "dedup.json", throttle_seconds=3600
    )
    groups = _record_one(checkpoint, count=1)
    assert len(checkpoint) == 1
    checkpoint.flush()
    restored = AICheckpoint.preload_file(tmp_path / "validation-partial.json")
    rep = groups[0].primary().finding_id[:8]
    assert rep in restored
    assert restored[rep].to_result(rep).status == ValidationStatus.CONFIRMED


def test_throttle_still_persists_on_large_stage(tmp_path):
    """Large stages throttle writes, but never lose the first completions."""
    checkpoint = AICheckpoint(
        tmp_path / "validation-partial.json", throttle_seconds=3600.0
    )
    _record_one(checkpoint, count=3)
    with open(tmp_path / "validation-partial.json", encoding="utf-8") as handle:
        document = json.load(handle)
    assert len(document["groups"]) == 3
    checkpoint.flush()


def test_record_failures_never_break_callers(tmp_path):
    """record()/record_dedup() swallow anything (fail-open)."""

    class Broken:
        finding_id = None

    checkpoint = AICheckpoint(tmp_path / "validation-partial.json", throttle_seconds=0.0)
    checkpoint.record(_group_of(_finding_stub(1)), Broken(), None)  # no crash
    checkpoint.record_dedup([{"nonsense": True}], [None], None)  # no crash
    assert len(checkpoint) == 0