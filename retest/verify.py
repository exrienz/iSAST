"""Evidence-cell parsing and code-presence verification for retest.

A canonical finding's evidence cell pins the finding to the source:

    Affected File: <path>
    Affected Line: <start> - <end>

    <snippet>

The snippet is the flagged line (stripped) followed by up to
``MAX_EVIDENCE_AFTER_LINES`` (core/scanner.py) lines of after-context with
original indentation. Verification is whitespace-insensitive and
case-sensitive, and tolerates line drift and small edits around the finding
(see the matching notes below). It proves the *code* is still present —
not that the finding is still exploitable (that requires the full scanner
path).

Matching is fail-closed on absence: a snippet that can no longer be located
means the finding is gone. Two-stage search:
  1. anchored — the first snippet line must fall within ±RETEST_LINE_WINDOW
     lines of the reported start line;
  2. whole-file fallback — only when the snippet is specific enough
    (≥2 non-empty lines, or one line ≥ RETEST_MIN_FALLBACK_CHARS chars), so
    trivial one-liners ("return {") are never matched away from the reported
    location. Known false-keep risk: the fallback can hit an identical
    construct elsewhere in the same file after a large reorganization
    (bounded by the specificity rule and in-order contiguity).
  Both stages fail-closed: a snippet that cannot be matched (e.g. a snippet
  that is a scanner *message*, not code, never appears in the file) removes
  the row — aggressive-cleanup semantics.

Matching details:
- Consecutive snippet lines map onto consecutive *non-empty* file lines,
  but up to RETEST_MAX_SKIP_LINES inserted non-blank lines are tolerated
  between them (an unrelated log line inside the flagged construct must not
  void the match). The chain backtracks, so an earlier pattern never
  starves a later contiguous occurrence.
- The file may have collapsed (a minified bundle): several consecutive
  snippet lines may live inside one file line.
- Clamped evidence (core/textclamp.py head+tail truncation) is split at the
  ``…[truncated +N chars]`` marker into sequential segments; only forward
  movement is allowed, and the skip guard applies *within* a segment —
  around markers the omitted middle may contain anything, including whole
  lines, so segments are not required to be adjacent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Drift (± lines) tolerated around the reported start line from edits above it.
RETEST_LINE_WINDOW = 10
# Non-blank lines tolerated between consecutive snippet lines (edits inside
# the flagged construct).
RETEST_MAX_SKIP_LINES = 3
# How many after-context lines the snippet may carry beyond the reported
# end line (mirrors MAX_EVIDENCE_AFTER_LINES in core/scanner.py; it only
# widens the scan bound — the anchor and contiguity guard do the gating).
RETEST_AFTER_CONTEXT_LINES = 15
# Single-line snippets shorter than this are too non-specific for the
# whole-file fallback (measured on the raw line, before normalization).
RETEST_MIN_FALLBACK_CHARS = 24

_FILE_HEADER = "Affected File: "
_LINE_HEADER_RE = re.compile(r"^Affected Line:\s*(\d+)(?:\s*-\s*(\d+))?\s*$")
_SEGMENT_MARKER_RE = re.compile(r"…\[truncated \+\d+ chars\]")


@dataclass(frozen=True)
class EvidenceRef:
    """Where a finding's evidence claims the flagged code lives."""

    file: str  # as written in the cell (source-root-relative or absolute POSIX)
    start_line: int  # 1-based; <=0 coerced to 1 by the parser
    end_line: int  # never < start_line
    snippet: str  # everything after the header blank line, verbatim


def parse_evidence(cell: str) -> Optional[EvidenceRef]:
    """Parse an evidence cell into its location reference; None if unparseable."""
    lines = (cell or "").replace("\r\n", "\n").split("\n")
    file_idx = next((i for i, line in enumerate(lines) if line.startswith(_FILE_HEADER)), None)
    if file_idx is None:
        return None
    file_path = lines[file_idx][len(_FILE_HEADER) :].strip()
    if not file_path:
        return None
    # Affected Line is expected immediately after the file header (blank
    # lines between the two still tolerated).
    line_match = None
    header_idx = file_idx
    for offset, candidate in enumerate(lines[file_idx + 1 : file_idx + 3], start=1):
        if candidate.strip():
            line_match = _LINE_HEADER_RE.match(candidate.strip())
            if line_match is not None:
                header_idx = file_idx + offset
            break
    if line_match is None:
        return None
    start = int(line_match.group(1)) or 1
    end = int(line_match.group(2) or 0) or start
    # Snippet follows the header's single blank separating line.
    rest = lines[header_idx + 1 :]
    if rest and not rest[0].strip():
        rest = rest[1:]
    return EvidenceRef(file=file_path, start_line=start, end_line=max(end, start), snippet="\n".join(rest))


def resolve_source_path(root: Path, file: str) -> Optional[Path]:
    """Map the evidence file path onto the retest source tree.

    Relative paths are joined with *root* and must not escape it (traversal
    guard); absolute paths are taken as-is but must also live under *root*,
    because a prior report's absolute paths belong to another machine.
    """
    candidate = Path(file)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve()
        if not resolved.is_relative_to(root.resolve()):
            return None
    except (OSError, ValueError):  # ValueError: NUL byte or other malformed path
        return None
    if not resolved.is_file():
        return None
    return resolved


def _norm(text: str) -> str:
    """Whitespace-insensitive normalization (indentation, tabs, spacing)."""
    return "".join(text.split())


def _match_segments(
    normed: List[str], segments: List[List[str]], lo: int, hi: int, anchor_hi: Optional[int]
) -> Tuple[bool, int]:
    """Match the segment patterns in order inside normed[lo..hi].

    Returns (ok, last_matched_index). The first pattern of the first segment
    anchors the match — it must fall within [lo, anchor_hi] (hi when
    *anchor_hi* is None, i.e. the whole-file fallback); every later pattern
    moves forward from the previous match. Each pattern line must appear
    within a file line; lines may collapse (the same file line can satisfy
    several consecutive patterns), and the contiguity guard tolerates up to
    RETEST_MAX_SKIP_LINES skipped non-blank file lines within a segment.
    Across a truncation marker the omitted middle may contain arbitrary
    code, so the guard does not apply at segment boundaries.
    """
    steps = [(pattern, pos > 0) for patterns in segments for pos, pattern in enumerate(patterns)]
    failed: set = set()

    def walk(i_step: int, j: int, last: int) -> Optional[int]:
        if i_step == len(steps):
            return last
        if (i_step, j) in failed:
            return None
        pattern, guarded = steps[i_step]
        limit = hi
        if i_step == 0 and anchor_hi is not None:
            limit = anchor_hi
        for i in range(j, limit + 1):
            if pattern not in normed[i]:
                continue
            if guarded and last >= 0 and i > last:
                skipped = sum(1 for k in range(last + 1, i) if normed[k])
                if skipped > RETEST_MAX_SKIP_LINES:
                    break  # skipped non-blank count only grows with i
            result = walk(i_step + 1, i, i)
            if result is not None:
                return result
        failed.add((i_step, j))
        return None

    result = walk(0, lo, -1)
    return (True, result) if result is not None else (False, -1)


def finding_exists(evidence: EvidenceRef, source_root: Path, cache: Dict[Path, List[str]]) -> bool:
    """True when the flagged snippet still matches the file under source_root.

    Never raises: unreadable/missing files count as "gone". *cache* (owned by
    the caller) avoids re-reading the same file for repeated findings.
    """
    resolved = resolve_source_path(source_root, evidence.file)
    if resolved is None:
        return False
    try:
        lines = cache.get(resolved)
        if lines is None:
            lines = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
            cache[resolved] = lines
    except OSError:
        return False
    normed = [_norm(line) for line in lines]

    segments = [
        [n for n in (_norm(line) for line in segment.split("\n")) if n]
        for segment in _SEGMENT_MARKER_RE.split(evidence.snippet)
    ]
    segments = [seg for seg in segments if seg]
    if not segments:
        # No code to compare: the row is a location in a real file — keep it
        # only while that location still exists.
        return 1 <= evidence.start_line <= len(lines)

    all_patterns = [pattern for seg in segments for pattern in seg]
    start_idx = evidence.start_line - 1
    span_end = evidence.end_line - 1
    lo = max(0, start_idx - RETEST_LINE_WINDOW)
    anchor_hi = min(len(normed) - 1, start_idx + RETEST_LINE_WINDOW)
    # The first pattern must anchor near the reported start line; the rest
    # follow contiguously, so an overall reach bound just limits the scan.
    hi = min(len(normed) - 1, max(span_end, anchor_hi) + len(all_patterns) + RETEST_AFTER_CONTEXT_LINES)

    ok, _ = _match_segments(normed, segments, lo, hi, anchor_hi)
    if ok:
        return True

    raw_lines = [line for line in evidence.snippet.split("\n") if line.strip()]
    specific = len(raw_lines) >= 2 or len(raw_lines[0]) >= RETEST_MIN_FALLBACK_CHARS
    if not specific:
        return False
    ok, _ = _match_segments(normed, segments, 0, len(normed) - 1, None)
    return ok