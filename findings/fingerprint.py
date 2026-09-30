"""Deterministic finding fingerprints (blueprint section 20).

SHA256 of normalized path + rule id + line + code snippet. This is used for
cross-engine correlation only — it is NOT AI deduplication.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Optional


def normalize_path(path: str) -> str:
    """POSIX-style, ./-free path usable in fingerprints."""
    cleaned = Path(path.replace("\\", "/")).as_posix()
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned


def snippet_signature(path: Path, line: int, context_lines: int = 3) -> str:
    """Fold the code around the finding into a comparable signature."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    lines = text.splitlines()
    start = max(0, (line or 1) - 1 - context_lines)
    end = min(len(lines), (line or 1) - 1 + context_lines + 1)
    window = lines[start:end]
    compact = "\n".join(_strip_noise(text_line) for text_line in window)
    return hashlib.sha1(compact.encode("utf-8", "replace") + path.name.encode()).hexdigest()


def _strip_noise(text_line: str) -> str:
    """Remove whitespace + pure punctuation so moving braces don't matter."""
    return re.sub(r"\s+", "", text_line)


def fingerprint(finding: dict, source_root: Optional[Path] = None, context_lines: int = 3) -> str:
    """Correlation fingerprint for one normalized finding dict."""
    rule = str(finding.get("rule_id") or "")
    path_part = normalize_path(str(finding.get("file") or ""))
    line_part = str(int(finding.get("line") or 0))
    context = ""
    if source_root and finding.get("file"):
        context = snippet_signature(source_root / str(finding["file"]), int(finding.get("line") or 1), context_lines)
    payload = "|".join((path_part, rule, line_part, context))
    return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()