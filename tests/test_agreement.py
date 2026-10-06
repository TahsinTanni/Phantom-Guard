import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.evaluation.agreement import (
    PRECISION_LABELS,
    agreement,
    cohen_kappa,
    main,
    miss_rate,
    parse_sheet,
    precision,
    read_sheet,
    recall_estimate,
    wilson,
)

ROOT = Path(__file__).resolve().parents[1]


def _sheet(verdicts, notes=None):
    out = ["# Sheet", "", "---", ""]
    for i, v in enumerate(verdicts, 1):
        out += [f"## {i}. `pkg-{i}`", "", "```text", "Verdict: not this one (inside a snippet)", "```", "",
                f"Verdict: {v}", "", f"Note: {(notes or {}).get(i, '')}", "", "---", ""]
    return "\n".join(out)


def test_wilson_matches_v1_verdicts():
    lo, hi = wilson(44, 47)
    assert (round(lo, 4), round(hi, 4)) == (0.8284, 0.9781)
    lo, hi = wilson(44, 51)
    assert (round(lo, 4), round(hi, 4)) == (0.7428, 0.9319)
    assert wilson(0, 0) is None
    assert wilson(0, 4)[0] == 0.0


def test_cohen_kappa_textbook_and_edges():
    # 2x2 table [[20, 5], [10, 15]]: po = 0.70, pe = 0.50 -> kappa 0.40
    a = ["Y"] * 25 + ["N"] * 25
    b = ["Y"] * 20 + ["N"] * 5 + ["Y"] * 10 + ["N"] * 15
    assert cohen_kappa(a, b) == pytest.approx(0.4)
    assert cohen_kappa(["A", "B", "A"], ["A", "B", "A"]) == 1.0
    assert cohen_kappa(["A", "A"], ["A", "A"]) is None  # chance agreement 1
    assert cohen_kappa([], []) is None
    with pytest.raises(ValueError):
        cohen_kappa(["A"], [])


def test_parse_sheet_takes_the_row_verdict_not_snippet_text():
    rows = parse_sheet(_sheet(["real", "", "UNSURE"], {1: "steals keys"}), PRECISION_LABELS)
    assert [(r["row"], r["package"], r["verdict"]) for r in rows] == [
        (1, "pkg-1", "REAL"), (2, "pkg-2", None), (3, "pkg-3", "UNSURE")]
    assert rows[0]["note"] == "steals keys"
    with pytest.raises(ValueError):
        parse_sheet(_sheet(["MAYBE"]), PRECISION_LABELS)


def test_agreement_and_disagreement_list():
    a = parse_sheet(_sheet(["REAL", "REAL", "FALSE", "REAL", ""]))
    b = parse_sheet(_sheet(["REAL", "FALSE", "FALSE", "REAL", "REAL"], {2: "tag list only"}))
    out = agreement(a, b)
    assert out["n_rows"] == 5 and out["n_both_filled"] == 4
    assert out["percent_agreement"] == 0.75
    assert out["cohen_kappa"] == pytest.approx(0.5)
    assert out["disagreements"] == [{"row": 2, "package": "pkg-2", "annotator1": "REAL", "annotator2": "FALSE",
                                     "note1": "", "note2": "tag list only"}]
    with pytest.raises(ValueError):
        agreement(a, a[:-1])


def test_precision_miss_rate_and_recall():
    pr = precision(parse_sheet(_sheet(["REAL"] * 8 + ["FALSE"] * 2 + ["UNSURE"])))
    assert pr["excluding_unsure"]["p"] == 0.8 and pr["unsure_as_false"]["p"] == pytest.approx(8 / 11)
    mr = miss_rate(parse_sheet(_sheet(["PRESENT"] * 1 + ["ABSENT"] * 3)))
    assert mr["excluding_unsure"]["p"] == 0.25
    rec = recall_estimate(100, pr["excluding_unsure"], 50, mr["excluding_unsure"])
    assert rec["recall"] == pytest.approx(80 / (80 + 12.5))
    lo, hi = rec["interval"]
    assert lo < rec["recall"] < hi
    assert recall_estimate(100, {"p": None}, 50, mr["excluding_unsure"])["recall"] is None


def test_v1_sheet_parses_to_published_counts():
    rows = read_sheet(ROOT / "reports" / "labeler_spot_check.md", PRECISION_LABELS)
    assert len(rows) == 51
    pr = precision(rows)
    assert pr["counts"] == {"REAL": 44, "FALSE": 3, "UNSURE": 4}
    v1 = json.loads((ROOT / "results" / "spot_check_verdicts.json").read_text())
    assert [r["verdict"] for r in rows] == [r["verdict"] for r in v1["rows"]]


def _adj_sheet(rows):
    """rows: (verdict, adjudicated or None, adjudication note)."""
    out = ["# Sheet", ""]
    for i, (v, adj, note) in enumerate(rows, 1):
        out += [f"## {i}. `pkg-{i}`", "", f"Verdict: {v}", ""]
        if adj is not None:
            out += [f"Adjudicated: {adj}", "", f"Adjudication note: {note}", ""]
        out += ["Note: n", "", "---", ""]
    return "\n".join(out)


def test_parse_adjudicated_lines_and_final_verdict():
    from src.evaluation.agreement import final_verdict

    a = parse_sheet(_adj_sheet([("REAL", "FALSE", "tag list only"), ("REAL", None, ""), ("FALSE", None, "")]),
                    PRECISION_LABELS)
    b = parse_sheet(_adj_sheet([("FALSE", None, ""), ("REAL", None, ""), ("REAL", None, "")]), PRECISION_LABELS)
    assert a[0]["adjudicated"] == "FALSE" and a[0]["adjudication_note"] == "tag list only"
    assert a[1]["adjudicated"] is None
    assert final_verdict(a[0], b[0]) == ("FALSE", "adjudicated")
    assert final_verdict(a[1], b[1])[0] == "REAL"  # agreed first pass, no Adjudicated line
    assert final_verdict(a[2], b[2])[0] is None     # disagreement never adjudicated
    with pytest.raises(ValueError):
        parse_sheet(_adj_sheet([("REAL", "MAYBE", "")]), PRECISION_LABELS)


def test_in_tag_list_and_category_names():
    from src.evaluation.agreement import categories_named, in_tag_list

    text = "It steals keys.\nReasons (based on the campaign):\n - exfiltrates credentials\n---\nmore prose"
    assert not in_tag_list(text, text.index("steals"))
    assert in_tag_list(text, text.index("exfiltrates"))
    assert not in_tag_list(text, text.index("more prose"))
    assert categories_named("hidden_install_hook — setup.py", None, "agree") == ["hidden_install_hook"]


@pytest.mark.skipif(not (ROOT / "results" / "annotation_sample_v2.json").exists(), reason="sheets not built")
def test_cli_on_v2_sheets(tmp_path):
    out = main(["--out", str(tmp_path / "a.json"), "--labeler-out", str(tmp_path / "l.json")])
    assert out["agreement"]["precision_sheet"]["n_rows"] == 60
    assert out["agreement"]["recall_sheet"]["n_rows"] == 40


def test_confirmed_categories_counts_and_validation(tmp_path):
    from src.evaluation.agreement import confirmed_categories

    path = tmp_path / "c.json"
    path.write_text(json.dumps({"rows": [
        {"row": 1, "package": "a", "categories": ["hidden_install_hook", "remote_payload_retrieval"], "borderline": False},
        {"row": 4, "package": "b", "categories": ["hidden_install_hook"], "borderline": True},
    ]}))
    out = confirmed_categories(path, {1: "a", 4: "b"})
    assert out["per_category_miss_counts"]["hidden_install_hook"] == 2
    assert out["per_category_miss_counts_excluding_borderline"]["hidden_install_hook"] == 1
    assert out["borderline_rows"] == [4] and out["n_rows_with_k_categories"] == {1: 1, 2: 1}
    with pytest.raises(ValueError):
        confirmed_categories(path, {1: "a"})  # file lists a row that is not PRESENT
    path.write_text(json.dumps({"rows": [{"row": 1, "package": "a", "categories": ["phishing"], "borderline": False}]}))
    with pytest.raises(ValueError):
        confirmed_categories(path, {1: "a"})

