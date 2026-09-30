"""Text clamping for oversized source lines.

Minified bundles (single-line JS/CSS/HTML) can make one physical line
hundreds of kilobytes long. Anything derived from such a line — AI prompt
context, canonical-finding evidence, CSV cells — must be bounded so prompts
stay within token budget and CSV cells stay under spreadsheet/ingestion
limits (Excel, LibreOffice and Google Sheets all cap a cell at 32,767
characters). Head+tail truncation keeps the match start (where scanners
usually point) and the stream tail visible.
"""

from __future__ import annotations

from typing import Optional

TRUNCATION_MARK = "…[truncated +{} chars]"


def clamp_text(text: Optional[str], max_chars: int) -> str:
    """Clamp *text* to *max_chars*, keeping head+tail and an omission marker."""
    if not text or len(text) <= max_chars:
        return text or ""
    # First pass reserves the worst-case marker width, second pass reports
    # the exact omitted count — the result is always <= max_chars.
    mark = TRUNCATION_MARK.format(len(text))
    keep = max(0, max_chars - len(mark))
    mark = TRUNCATION_MARK.format(len(text) - keep)
    keep = max(0, max_chars - len(mark))
    head_len = keep - keep // 2
    tail_len = keep - head_len
    return text[:head_len] + mark + (text[-tail_len:] if tail_len else "")