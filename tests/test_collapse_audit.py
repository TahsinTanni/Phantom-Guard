import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.evaluation.collapse_audit import diverge_at, excerpt, jaccard, masked_text, tokens


def test_diverge_at():
    assert diverge_at("abcdef", "abcxef") == 3
    assert diverge_at("abc", "abcdef") == 3
    assert diverge_at("same", "same") == 4


def test_excerpt_starts_at_text_start_for_early_divergence():
    text = "This package does something " * 10
    assert excerpt(text, 1).startswith("This package")
    assert excerpt(text, 28).startswith("This package")  # offset 28 is a repeat boundary
    assert len(excerpt("x" * 500, 200)) == 100


def test_excerpt_escapes_table_pipes():
    assert "\\|" in excerpt("a | b")


def test_tokens_and_jaccard():
    assert tokens("Steals AWS keys; steals") == {"steals", "aws", "keys"}
    assert jaccard({"a", "b"}, {"b", "c"}) == 1 / 3
    assert jaccard(set(), set()) == 1.0


def test_masked_text_strips_headers_and_masks_own_name():
    r = {"package_name": "evil-pkg",
         "description": "## Source: kam193 (" + "a" * 64 + ")\nevil-pkg steals keys"}
    assert masked_text(r) == "<PKG> steals keys"
