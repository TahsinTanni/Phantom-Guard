import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.data.seed_lists import parse_npm_high_impact_top
from src.evaluation import grammar_validation as gv

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "hallucinated_tiny.txt"


def test_load_hallucinated_parses_tsv_and_skips_blank_lines():
    rows = gv.load_hallucinated(FIXTURE)
    assert [(r["ecosystem"], r["name"], r["count"]) for r in rows] == [
        ("pypi", "aws-cdk", 429), ("pypi", "objc", 375), ("pypi", "turbo-pro-tools", 7),
        ("npm", "react-randomized", 5), ("npm", "@ember/service", 55)]


def test_load_hallucinated_rejects_malformed_line(tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_text("pypi\tonly-two-fields\n")
    with pytest.raises(ValueError, match="bad.txt:1"):
        gv.load_hallucinated(bad)


def test_load_or_fetch_names_caches_and_is_offline_on_rerun(tmp_path):
    calls = []

    def fetcher():
        calls.append(1)
        return ["boto3", "requests"]

    cache, meta = tmp_path / "benign.txt", tmp_path / "meta"
    kw = dict(source="test", source_version="v", metadata_dir=meta)
    assert gv.load_or_fetch_names(cache, fetcher, **kw) == ["boto3", "requests"]
    assert (meta / "benign.manifest.json").exists()
    assert gv.load_or_fetch_names(cache, lambda: pytest.fail("network used"), **kw) == ["boto3", "requests"]
    gv.load_or_fetch_names(cache, fetcher, refresh=True, **kw)
    assert len(calls) == 2


def test_load_or_fetch_names_refuses_empty_fetch(tmp_path):
    with pytest.raises(RuntimeError):
        gv.load_or_fetch_names(tmp_path / "x.txt", lambda: [], "s", "v", metadata_dir=None)
    assert not (tmp_path / "x.txt").exists()


def test_classify_unit_campaign_is_any_member_and_combines_pattern_types():
    u = gv.classify_unit(["numpy", "aws-thing", "fast-turbo"], "pypi")
    assert u["flagged"] is True
    assert u["pattern_type"] == "both"
    assert u["tokens"] == ["aws", "turbo"]
    assert gv.classify_unit(["numpy"], "pypi")["pattern_type"] == "none"


def test_summarize_units_counts_tokens_once_per_unit():
    units = [gv.classify_unit(["aws-aws-sdk"], "pypi"), gv.classify_unit(["aws-x"], "pypi"),
             gv.classify_unit(["numpy"], "pypi")]
    s = gv.summarize_units(units)
    assert (s["n"], s["flag_count"]) == (3, 2)
    assert s["flag_rate"] == pytest.approx(2 / 3)
    assert s["pattern_type_distribution"] == {"none": 1, "compound": 2, "trend": 0, "both": 0}
    assert s["top_flagging_tokens"][0] == ["aws", 2]


def test_build_report_on_tiny_fixture():
    report = gv.build_report(
        hallucinated=gv.load_hallucinated(FIXTURE),
        benign={"pypi": ["boto3", "azure-core"], "npm": ["semver", "react-dom"]},
        malware_campaigns=[{"ecosystem": "npm", "names": ["a", "b-tools"], "pipeline_flagged": True},
                           {"ecosystem": "pypi", "names": ["zzz"], "pipeline_flagged": False}],
        benign_sensitivity={"npm": ["react-x"]},
    )
    h = report["sets"]["hallucinated"]
    assert (h["pypi"]["flag_count"], h["pypi"]["n"]) == (2, 3)
    assert (h["npm"]["flag_count"], h["npm"]["n"]) == (1, 2)
    assert h["pypi"]["pattern_type_distribution"]["both"] == 1  # turbo-pro-tools
    assert report["sets"]["benign_top5000"]["all"]["flag_count"] == 2
    assert report["sets"]["malware_campaigns"]["all"]["flag_count"] == 1
    assert report["sets"]["benign_npm_search_api"]["npm"]["flag_rate"] == 1.0
    ex = report["hallucinated_examples"]
    assert [e["name"] for e in ex["flagged"]] == ["aws-cdk", "turbo-pro-tools", "react-randomized"]
    assert [e["name"] for e in ex["unflagged_top15_by_count"]] == ["objc", "@ember/service"]


def test_build_report_rejects_campaign_flag_that_disagrees_with_pipeline():
    with pytest.raises(AssertionError):
        gv.build_report([], {}, [{"ecosystem": "npm", "names": ["numpy"], "pipeline_flagged": True}])


def test_main_runs_offline_from_caches(tmp_path, monkeypatch):
    ext = tmp_path / "external"
    ext.mkdir()
    for key, src in gv.benign_sources().items():
        (ext / src["cache"]).write_text("numpy\naws-sdk\n")
    monkeypatch.setattr(gv, "EXTERNAL_DIR", ext)
    monkeypatch.setattr(gv, "HALLUCINATED_PATH", FIXTURE)
    monkeypatch.setattr(gv, "ROOT", Path(__file__).resolve().parent)
    monkeypatch.setattr(gv, "load_malware_campaign_names",
                        lambda: [{"ecosystem": "pypi", "names": ["py-x"], "pipeline_flagged": True}])
    monkeypatch.setattr("src.data.seed_lists.requests.get", lambda *a, **k: pytest.fail("network used"))
    out = tmp_path / "gv.json"
    report = gv.main(["--out", str(out)])
    assert out.exists()
    assert report["sets"]["benign_top5000"]["all"]["n"] == 4


def test_parse_npm_high_impact_top_keeps_order_and_scoped_names():
    src = "export const top = [\n  'semver',\n  '@babel/core',\n  \"debug\",\n]\n"
    assert parse_npm_high_impact_top(src) == ["semver", "@babel/core", "debug"]


@pytest.mark.skipif(not gv.HALLUCINATED_PATH.exists(), reason="hallucinated_names.txt not present")
def test_real_hallucinated_rates_section_5_11():
    report = gv.build_report(gv.load_hallucinated(), {}, [])
    h = report["sets"]["hallucinated"]
    assert (h["pypi"]["flag_count"], h["pypi"]["n"]) == (4, 121)
    assert (h["npm"]["flag_count"], h["npm"]["n"]) == (3, 18)
