import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.evaluation import labeler_spot_check as sc


def test_snippet_marks_span_collapses_whitespace_and_marks_cuts():
    text = "a" * 10 + " x\n\n y " + "MATCH" + " z " + "b" * 10
    s = text.index("MATCH")
    assert sc.snippet(text, (s, s + 5), context=4) == "…y ⟦MATCH⟧ z b…"
    assert sc.snippet("MATCH", (0, 5), context=100) == "⟦MATCH⟧"


def _frame(eco, n):
    return [{"ecosystem": eco, "package_name": f"{eco}{i:02d}"} for i in range(n)]


def test_draw_sample_census_when_n_equals_frame_and_is_deterministic():
    frame = {"npm": _frame("npm", 13), "pypi": _frame("pypi", 47)}
    a = sc.draw_sample(frame, {"npm": 13, "pypi": 17}, seed=42)
    b = sc.draw_sample(frame, {"npm": 13, "pypi": 17}, seed=42)
    assert a == b
    assert a["npm"] == frame["npm"]
    assert len(a["pypi"]) == 17 and len({c["package_name"] for c in a["pypi"]}) == 17
    assert a["pypi"] != sc.draw_sample(frame, {"npm": 13, "pypi": 17}, seed=43)["pypi"]


def test_draw_sample_rejects_n_larger_than_frame():
    with pytest.raises(ValueError, match="npm: asked for 15, frame has 13"):
        sc.draw_sample({"npm": _frame("npm", 13)}, {"npm": 15})


def test_spot_check_rows_on_frozen_snapshot():
    rows, meta = sc.build_rows(sc.load_joined())
    assert meta["n_campaigns"] == 106 and meta["n_dv_positive_campaigns"] == 62  # 5.13
    assert meta["frame_sizes"] == {"npm": 12, "pypi": 33}
    assert "levvleys" not in {r["package_name"] for r in rows}  # negated text, now DV-negative
    assert {r["package_name"]: r["campaign_size"] for r in rows[:21]}["licloud"] == 15
    assert len(rows) == 51
    assert [r["row"] for r in rows] == list(range(1, 52))
    assert [r["package_name"] for r in rows[:21]] == [n for _, n in sc.parse_osv_only_report()]
    # Part (a) matches agree with osv_only_positives.md (33 matches).
    assert sum(len(r["matches"]) for r in rows[:21]) == 33
    assert all(r["matches"] and "⟦" in r["matches"][0]["snippet"] for r in rows)
    assert len({r["package_name"] for r in rows}) == 51
