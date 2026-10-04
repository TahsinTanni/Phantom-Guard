import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.data.naming_grammar import (
    classify_naming_grammar,
    classify_batch,
    generate_typosquat_candidates,
    _levenshtein_distance,
)


def test_compound_suffix_match():
    result = classify_naming_grammar("pytest-mock-server")
    assert result.is_grammar_flagged
    assert "server" in result.matched_compound_suffixes
    assert result.matched_pattern_type == "compound"


def test_compound_prefix_match():
    result = classify_naming_grammar("react-cli")
    assert result.is_grammar_flagged
    assert "react" in result.matched_compound_prefixes


def test_trend_suffix_match():
    result = classify_naming_grammar("openai-turbo")
    assert result.is_grammar_flagged
    assert "turbo" in result.matched_trend_suffixes
    assert result.matched_pattern_type == "trend"


def test_both_pattern_types():
    result = classify_naming_grammar("react-pro-cli")
    assert result.matched_pattern_type == "both"
    assert "pro" in result.matched_trend_suffixes
    assert "cli" in result.matched_compound_suffixes


def test_no_match_on_unrelated_name():
    result = classify_naming_grammar("numpy")
    assert not result.is_grammar_flagged
    assert result.matched_pattern_type == "none"


def test_npm_scoped_package_normalized():
    # '@org/pkg-cli' should normalize to 'org-pkg-cli' and still match 'cli'
    result = classify_naming_grammar("@myorg/data-cli")
    assert result.is_grammar_flagged
    assert "cli" in result.matched_compound_suffixes


def test_classify_batch_matches_individual_calls():
    names = ["numpy", "react-turbo", "flask-utils"]
    batch_results = classify_batch(names)
    individual_results = [classify_naming_grammar(n) for n in names]
    assert [r.is_grammar_flagged for r in batch_results] == [
        r.is_grammar_flagged for r in individual_results
    ]


def test_grammar_classification_does_not_accept_label_input():
    """
    Guards the Phase 0 audit's circularity requirement: the function
    signature must take only a name, nothing derived from injection or
    malicious labels. This test exists so that if someone later 'helpfully'
    adds an optional label parameter, CI catches the signature change.
    """
    import inspect

    sig = inspect.signature(classify_naming_grammar)
    assert list(sig.parameters.keys()) == ["name"]


def test_levenshtein_distance_basic_cases():
    assert _levenshtein_distance("abc", "abc") == 0
    assert _levenshtein_distance("abc", "abd") == 1
    assert _levenshtein_distance("", "abc") == 3
    assert _levenshtein_distance("abc", "") == 3
    assert _levenshtein_distance("kitten", "sitting") == 3


def test_generate_typosquat_candidates_respects_real_set_exclusion():
    real_set = {"requests", "flask", "django"}
    candidates = generate_typosquat_candidates(
        "requests", real_set, n=5, seed=42
    )
    assert all(c not in real_set for c in candidates)
    assert len(candidates) <= 5


def test_generate_typosquat_candidates_is_deterministic_with_seed():
    real_set = {"flask"}
    c1 = generate_typosquat_candidates("flask", real_set, n=3, seed=42)
    c2 = generate_typosquat_candidates("flask", real_set, n=3, seed=42)
    assert c1 == c2


def test_generate_typosquat_candidates_edit_distance_bounded():
    real_set: set[str] = set()
    candidates = generate_typosquat_candidates("numpy", real_set, n=10, seed=1)
    for c in candidates:
        assert 1 <= _levenshtein_distance(c, "numpy") <= 2
