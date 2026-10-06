import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.statistics.misclassification import (
    corrected_table,
    odds_ratio,
    probabilistic_correction,
    simple_correction,
    woolf_ci,
)


def test_perfect_labeler_leaves_table_unchanged():
    t = [[46, 39], [123, 109]]
    assert corrected_table(t, 1.0, 0.0) == [[46, 39], [123, 109]]


def test_hand_computed_correction_and_no_text_exclusion():
    # flagged: 10 pos, 20 neg; unflagged: 30 pos, 40 neg, 10 of them no-text
    t = [[10, 20], [30, 40]]
    c = corrected_table(t, 0.9, 0.25, no_text_negatives=(0, 10))
    assert c[0] == pytest.approx([10 * 0.9 + 20 * 0.25, 30 - 14.0])   # [14, 16]
    assert c[1] == pytest.approx([30 * 0.9 + 30 * 0.25, 70 - 34.5])   # [34.5, 35.5]
    assert odds_ratio(c) == pytest.approx(14 * 35.5 / (16 * 34.5))
    with pytest.raises(ValueError):
        corrected_table(t, 0.9, 0.25, no_text_negatives=(21, 0))


def test_woolf_ci_matches_known_value_and_simple_wrapper():
    lo, hi = woolf_ci([[46, 39], [123, 109]])
    assert odds_ratio([[46, 39], [123, 109]]) == pytest.approx(46 * 109 / (39 * 123))
    assert lo < 1.0452 < hi
    out = simple_correction([[46, 39], [123, 109]], 0.917, 0.425)
    assert out["odds_ratio"] is not None and len(out["corrected_table"]) == 2


def test_probabilistic_correction_is_seeded_and_brackets_simple():
    t = [[46, 39], [123, 109]]
    a = probabilistic_correction(t, 55, 60, 17, 40, draws=2000)
    b = probabilistic_correction(t, 55, 60, 17, 40, draws=2000)
    assert a == b
    lo, hi = a["interval_95"]
    assert lo < simple_correction(t, 55 / 60, 17 / 40)["odds_ratio"] < hi
