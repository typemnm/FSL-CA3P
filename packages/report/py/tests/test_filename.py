import unicodedata

import pytest

from ca3p_report.hwpx.filename import normalize_filename

RUN = "run-20261020-xss"


@pytest.mark.parametrize(
    "proposed",
    ["../../etc/passwd", "..\\..\\windows\\system32", "/abs/path/report", "a/../b"],
)
def test_traversal_never_leaves_a_separator_or_dotdot(proposed):
    name = normalize_filename(proposed, RUN)
    assert "/" not in name and "\\" not in name and ".." not in name
    assert name.endswith(".hwpx")


def test_traversal_keeps_the_readable_part():
    assert normalize_filename("../../보고서", RUN) == "보고서.hwpx"


@pytest.mark.parametrize("proposed", ["CON", "con", "PRN.hwpx", "aux.txt", "NUL", "COM1", "lpt9"])
def test_windows_reserved_names_fall_back(proposed):
    assert normalize_filename(proposed, RUN) == f"{RUN}.hwpx"


def test_reserved_prefix_inside_longer_name_is_allowed():
    assert normalize_filename("CONSOLE 보고서", RUN) == "CONSOLE 보고서.hwpx"


def test_overlong_name_is_capped_at_120():
    name = normalize_filename("가" * 500, RUN)
    assert len(name) == 120
    assert name.endswith(".hwpx")


@pytest.mark.parametrize("proposed", [None, "", "   ", "..", "...", "/", "\x00\x1f", ".hwpx"])
def test_empty_or_invalid_falls_back_to_run_id(proposed):
    assert normalize_filename(proposed, RUN) == f"{RUN}.hwpx"


@pytest.mark.parametrize(
    ("proposed", "expected"),
    [
        ("저장형 XSS 보고서", "저장형 XSS 보고서.hwpx"),
        ("report.hwpx", "report.hwpx"),
        ("report.HWPX.hwpx", "report.hwpx"),
        ("report.pdf", "report.pdf.hwpx"),
        ("report.", "report.hwpx"),
    ],
)
def test_extension_is_forced_to_a_single_hwpx(proposed, expected):
    assert normalize_filename(proposed, RUN) == expected


def test_control_chars_are_removed_and_text_is_nfc():
    decomposed = unicodedata.normalize("NFD", "보고서")
    name = normalize_filename(f"{decomposed}\n\t\x7f", RUN)
    assert name == "보고서.hwpx"
    assert unicodedata.is_normalized("NFC", name)
