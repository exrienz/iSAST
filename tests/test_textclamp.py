"""clamp_text guarantees (head+tail bounds with omission marker)."""

from core.textclamp import clamp_text


def test_short_text_passthrough():
    assert clamp_text("hello", 100) == "hello"
    assert clamp_text("", 100) == ""
    assert clamp_text(None, 100) == ""


def test_long_text_bounded_with_marker():
    huge = "A" * 50000 + "TAIL" + "B" * 50000
    out = clamp_text(huge, 2000)
    assert len(out) <= 2000
    assert "truncated" in out
    assert out.startswith("A")  # head kept (matching region is at the start)
    assert out.endswith("B")  # tail kept


def test_exact_boundary_not_clamped():
    text = "x" * 2000
    assert clamp_text(text, 2000) == text


def test_marker_reports_omitted_chars():
    out = clamp_text("y" * 60000, 2000)
    assert "…[truncated +58" in out