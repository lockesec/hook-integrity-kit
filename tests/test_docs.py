"""The documentation says what the code does: known gaps are listed in the limits doc, the
redirect and in-place spellings are named, and the control keys and tool scope are stated."""
from __future__ import annotations

from hook_integrity_kit import manifest as M


def _doc(name):
    import os
    return open(os.path.join(os.path.dirname(__file__), "..", name),
                encoding="utf-8").read()


def test_known_gaps_are_listed_in_the_limits_doc():
    import os
    text = open(os.path.join(os.path.dirname(__file__), "..", "docs", "limits.md"),
                encoding="utf-8").read()
    for gap in ("chroot", "tee >(sh)", "`sh -c", "abbreviat"):
        assert gap in text, gap


def test_docs_name_the_redirect_and_in_place_spellings():
    rules, limits = _doc("docs/rules.md"), _doc("docs/limits.md")
    for token in (">\\|", "&>", "--in-place", "perl -i"):
        assert token in rules, token
    for token in ("quoted", "joined", "backtick"):
        assert token in limits, token


def test_the_docs_name_the_control_keys_and_the_tool_scope():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    for key in M.HOOK_CONTROL_KEYS:
        assert key in (root / "docs" / "coverage.md").read_text(), key
    for name in ("README.md", "THREAT_MODEL.md", "docs/limits.md"):
        text = (root / name).read_text()
        assert "shell_tools" in text, name
    assert "disableAllHooks" in (root / "SECURITY.md").read_text()
    assert "disableAllHooks" in (root / "CHANGELOG.md").read_text()
