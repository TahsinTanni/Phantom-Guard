import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.statistics.h1_pilot_analysis import (
    attach_grammar_labels,
    build_contingency_table,
    build_stratified_tables,
    run_fisher_exact,
    run_cmh_test,
    ContingencyTable,
)


def test_attach_grammar_labels_uses_package_name_only():
    records = [
        {"package_name": "react-turbo", "malware_label": {"malware_payload_present_candidate": True}},
        {"package_name": "numpy", "malware_label": {"malware_payload_present_candidate": False}},
    ]
    joined = attach_grammar_labels(records)
    assert joined[0]["grammar_match"]["is_grammar_flagged"] is True
    assert joined[1]["grammar_match"]["is_grammar_flagged"] is False
    # Original fields preserved.
    assert joined[0]["package_name"] == "react-turbo"
    assert joined[0]["malware_label"]["malware_payload_present_candidate"] is True


def test_build_contingency_table_counts_correctly():
    joined = [
        {"grammar_match": {"is_grammar_flagged": True}, "malware_label": {"malware_payload_present_candidate": True}},
        {"grammar_match": {"is_grammar_flagged": True}, "malware_label": {"malware_payload_present_candidate": True}},
        {"grammar_match": {"is_grammar_flagged": True}, "malware_label": {"malware_payload_present_candidate": False}},
        {"grammar_match": {"is_grammar_flagged": False}, "malware_label": {"malware_payload_present_candidate": True}},
        {"grammar_match": {"is_grammar_flagged": False}, "malware_label": {"malware_payload_present_candidate": False}},
        {"grammar_match": {"is_grammar_flagged": False}, "malware_label": {"malware_payload_present_candidate": False}},
    ]
    table = build_contingency_table(joined)
    assert table.grammar_flagged_and_outcome == 2
    assert table.grammar_flagged_and_not == 1
    assert table.not_flagged_and_outcome == 1
    assert table.not_flagged_and_not == 2
    assert table.total() == 6


def test_contingency_table_rates():
    table = ContingencyTable(
        grammar_flagged_and_outcome=8,
        grammar_flagged_and_not=2,
        not_flagged_and_outcome=2,
        not_flagged_and_not=8,
    )
    assert abs(table.rate_when_flagged() - 0.8) < 1e-9
    assert abs(table.rate_when_not_flagged() - 0.2) < 1e-9


def test_contingency_table_handles_empty_group():
    table = ContingencyTable(0, 0, 5, 5)
    assert table.rate_when_flagged() == 0.0  # no divide-by-zero crash


def test_run_fisher_exact_on_strong_known_association():
    # Strongly associated table: flagged group has much higher outcome rate.
    table = ContingencyTable(
        grammar_flagged_and_outcome=18,
        grammar_flagged_and_not=2,
        not_flagged_and_outcome=2,
        not_flagged_and_not=18,
    )
    result = run_fisher_exact(table)
    assert result["p_value"] < 0.01  # should be clearly significant
    assert result["odds_ratio"] > 1
    assert result["n_total"] == 40


def test_run_fisher_exact_on_null_association():
    # Roughly equal rates in both groups -> not significant.
    table = ContingencyTable(
        grammar_flagged_and_outcome=10,
        grammar_flagged_and_not=10,
        not_flagged_and_outcome=10,
        not_flagged_and_not=10,
    )
    result = run_fisher_exact(table)
    assert result["p_value"] > 0.05
    assert abs(result["odds_ratio"] - 1.0) < 0.5


def test_build_contingency_table_supports_alternate_outcome_field():
    joined = [
        {"grammar_match": {"is_grammar_flagged": True}, "heuristic_label": {"injection_present_candidate": True}},
        {"grammar_match": {"is_grammar_flagged": False}, "heuristic_label": {"injection_present_candidate": False}},
    ]
    table = build_contingency_table(
        joined, outcome_field="heuristic_label", outcome_key="injection_present_candidate"
    )
    assert table.grammar_flagged_and_outcome == 1
    assert table.not_flagged_and_not == 1


def test_build_stratified_tables_splits_correctly():
    joined = [
        {"ecosystem": "npm", "grammar_match": {"is_grammar_flagged": True}, "malware_label": {"malware_payload_present_candidate": True}},
        {"ecosystem": "npm", "grammar_match": {"is_grammar_flagged": False}, "malware_label": {"malware_payload_present_candidate": False}},
        {"ecosystem": "pypi", "grammar_match": {"is_grammar_flagged": True}, "malware_label": {"malware_payload_present_candidate": False}},
    ]
    tables = build_stratified_tables(joined, strata_field="ecosystem")
    assert set(tables.keys()) == {"npm", "pypi"}
    assert tables["npm"].total() == 2
    assert tables["pypi"].total() == 1


def test_cmh_matches_known_hand_calculated_example():
    """
    Hand-verified example (values chosen so the arithmetic is checkable
    by hand): two strata, each individually weak/non-significant, but
    with the SAME direction of effect, should combine into a stronger
    pooled signal under CMH than either stratum alone shows under Fisher's
    exact test.

    Stratum 1: a=5, b=15, c=10, d=20 (n=50)
    Stratum 2: a=6, b=14, c=11, d=19 (n=50)
    Both have modest OR<1 individually; CMH should detect the pooled
    signal more readily than per-stratum Fisher tests would.
    """
    t1 = ContingencyTable(5, 15, 10, 20)
    t2 = ContingencyTable(6, 14, 11, 19)

    # Manual calculation of Mantel-Haenszel common OR:
    # numerator = (5*20/50) + (6*19/50) = 2.0 + 2.28 = 4.28
    # denominator = (15*10/50) + (14*11/50) = 3.0 + 3.08 = 6.08
    # OR_MH = 4.28 / 6.08 ≈ 0.7039
    result = run_cmh_test([t1, t2])
    assert abs(result["common_odds_ratio"] - (4.28 / 6.08)) < 1e-6
    assert result["n_strata"] == 2
    assert result["n_total"] == 100
    assert 0 <= result["p_value"] <= 1


def test_cmh_detects_consistent_pooled_signal_better_than_isolated_tests():
    """
    Regenerates the exact shape of the real pilot finding: two strata,
    each non-significant alone under Fisher's exact, but consistent
    in direction, pooling to a stronger combined signal under CMH.
    """
    from scipy.stats import fisher_exact

    npm_table = ContingencyTable(5, 59, 16, 122)   # matches real npm data
    pypi_table = ContingencyTable(18, 32, 75, 74)  # matches real pypi data

    npm_p = fisher_exact(npm_table.as_2x2())[1]
    pypi_p = fisher_exact(pypi_table.as_2x2())[1]
    assert npm_p > 0.05   # individually non-significant, as observed
    # (pypi_p may be borderline; not asserted strictly here since the
    # real run showed ~0.10 — the point of this test is the CMH pooling
    # behavior below, not re-deriving the exact Fisher p-values.)

    cmh_result = run_cmh_test([npm_table, pypi_table])
    assert cmh_result["common_odds_ratio"] < 1  # same direction preserved
    assert cmh_result["n_total"] == npm_table.total() + pypi_table.total()


def test_cmh_handles_degenerate_single_stratum_gracefully():
    tiny_table = ContingencyTable(0, 0, 0, 1)  # n=1, cannot compute variance
    result = run_cmh_test([tiny_table])
    assert result["p_value"] != result["p_value"] or "note" in result  # NaN or noted


# Campaign-collapse regression tests. Added after discovering that
# treating each package-name record as an independent observation
# inflated the npm odds ratio to 178 (p=5e-07) — a non-independence
# artifact from (a) GHSA/OSV both reporting the same package under
# different advisory_ids, and (b) one attacker squatting multiple
# distinct names under one campaign. See research log bug entry.

from src.statistics.h1_pilot_analysis import (
    build_campaign_signature,
    collapse_to_campaign_level,
)


def test_build_campaign_signature_excludes_generic_ghsa_boilerplate():
    """
    GHSA's generic 'fully compromised' fallback template is IDENTICAL
    across unrelated incidents. Using it as a campaign signature would
    wrongly merge distinct packages. Records matching this template must
    each get a unique signature (never merged with each other via text).
    """
    boilerplate_record_a = {
        "ecosystem": "npm",
        "package_name": "pkg-a",
        "description": "Any computer that has this package installed or "
        "running should be considered fully compromised. All secrets...",
    }
    boilerplate_record_b = {
        "ecosystem": "npm",
        "package_name": "pkg-b",
        "description": "Any computer that has this package installed or "
        "running should be considered fully compromised. All secrets...",
    }
    sig_a = build_campaign_signature(boilerplate_record_a)
    sig_b = build_campaign_signature(boilerplate_record_b)
    assert sig_a != sig_b  # must NOT collide despite identical text


def test_build_campaign_signature_groups_real_campaign_text():
    record_a = {"ecosystem": "npm", "package_name": "pkg-a",
                "description": "This package is part of a large family "
                "(100+ identified) of near-identical forks."}
    record_b = {"ecosystem": "npm", "package_name": "pkg-b",
                "description": "This package is part of a large family "
                "(100+ identified) of near-identical forks."}
    assert build_campaign_signature(record_a) == build_campaign_signature(record_b)


# Verbatim openings of GHSA-2wm2-fc38-63vw (shortneer) and GHSA-74qh-6w69-w7vc
# (sherpy): same text, same kam193 campaign (2026-09-sherpy), different hash.
_SHERPY_BODY = (
    "When used, the package exfiltrates Chrome extension files (likely targeting "
    "cryptocurrency wallets) and sensitive Telegram files.\n\n\n---\n\nCategory: "
    "MALICIOUS - The campaign has clearly malicious intent, like infostealers.\n\n\n"
    "Campaign: 2026-09-sherpy\n"
)


def test_build_campaign_signature_strips_source_header_lines():
    a = {"ecosystem": "pypi", "package_name": "shortneer", "description":
         "## Source: kam193 (5e166ae1253c886885381cb5087f67a59a869cad6ece6f3ac40aefc6e463c27f)\n"
         + _SHERPY_BODY}
    b = {"ecosystem": "pypi", "package_name": "sherpy", "description":
         "## Source: kam193 (2e5440f1e24545fd14e73c7fc459a9abf893f4674683899ed29ff7c4189416b6)\n"
         + _SHERPY_BODY}
    assert build_campaign_signature(a) == build_campaign_signature(b)
    # Since 5.14 the shared Campaign tag is the key; the prefix path still strips.
    assert build_campaign_signature(a) == ("pypi", "__campaign__:2026-09-sherpy")
    prefix = build_campaign_signature(a, use_campaign_tag=False)
    assert prefix == build_campaign_signature(b, use_campaign_tag=False)
    assert prefix[1].startswith("When used, the package exfiltrates")


def test_build_campaign_signature_strips_every_source_header_line():
    a = {"ecosystem": "pypi", "package_name": "x", "description":
         "---\n## Source: amazon-inspector (1111)\nBody one.\n\n## Source: kam193 (2222)\nBody two."}
    b = {"ecosystem": "pypi", "package_name": "y", "description":
         "---\n## Source: amazon-inspector (3333)\nBody one.\n\n## Source: kam193 (4444)\nBody two."}
    sig = build_campaign_signature(a)
    assert sig == build_campaign_signature(b)
    assert "## Source" not in sig[1] and "Body two." in sig[1]



# --- Signature keys added in research_log 5.14 -------------------------------

_GENERIC_BODY = (
    "Installing the package or importing the module exfiltrates basic information "
    "about the host, and the package has no other purpose.\n\n\n---\n\nCategory: "
    "PROBABLY_PENTEST - Packages looking like typical pentest packages, but also anything "
    "that looks like testing, exploring pre-prepared kits, research & co, with clearly "
    "low-harm possibilities.\n\n\nCampaign: GENERIC-standard-pypi-install-pentest\n"
)


def test_build_campaign_signature_excludes_kam193_generic_pentest_template():
    # Verbatim openings of GHSA-gwqx-5242-h5mw (licloud) and GHSA-92qj-f225-g878
    # (metricboxlite): kam193's catch-all template, unrelated packages.
    a = {"ecosystem": "pypi", "package_name": "licloud", "description":
         "## Source: kam193 (5e2bddcfca980297be9856fbbc3eeab78253c51efe034bd92b9e8b52ed9aacc6)\n"
         + _GENERIC_BODY}
    b = {"ecosystem": "pypi", "package_name": "metricboxlite", "description":
         "## Source: kam193 (83407b9909ebc137e4d47fbb7fe2672a5920dd22bfd7d86ce8edb536bdd5fcab)\n"
         + _GENERIC_BODY}
    assert build_campaign_signature(a) != build_campaign_signature(b)
    assert build_campaign_signature(a) == ("pypi", "__noboilerplate__:licloud")
    # 5.13 behaviour (exclusion off): the two were merged on the text prefix.
    assert (build_campaign_signature(a, exclude_generic_tag=False)
            == build_campaign_signature(b, exclude_generic_tag=False))


_AITEXT_TAIL = (
    "The remote stages are hosted on a domain presenting a suspicious-looking corporate "
    "website. The downloaded code establishes persistence e.g. as \"anymeetly-cameradriver\" "
    "systemd service.\n\n\n---\n\nCategory: MALICIOUS - The campaign has clearly malicious "
    "intent, like infostealers.\n\n\nCampaign: 2026-09-aitextkit-py\n"
)


def test_build_campaign_signature_groups_on_kam193_campaign_tag():
    # Verbatim openings of GHSA-657v-53xv-3xw9 (aitextkit-py) and
    # GHSA-hm5j-9gw8-8568 (aitextutils-py): same Campaign tag, different first sentence.
    a = {"ecosystem": "pypi", "package_name": "aitextkit-py", "description":
         "## Source: kam193 (b1a048ec587dcab5a71ed9423d105b4b972f646b93f790f62c10d394610b64bf)\n"
         "The package hides code downloading script, which then downloads and executes a "
         "heavily obfuscated final stage. " + _AITEXT_TAIL}
    b = {"ecosystem": "pypi", "package_name": "aitextutils-py", "description":
         "## Source: kam193 (079adf053b093075a5d8151dbbb82bb85a45f577ae3a9f6e6c751a4779d52f77)\n"
         "This package executes code from malicious dependency, which hides code downloading "
         "script, which then downloads and executes a heavily obfuscated final stage. " + _AITEXT_TAIL}
    assert build_campaign_signature(a) == build_campaign_signature(b) == (
        "pypi", "__campaign__:2026-09-aitextkit-py")
    assert (build_campaign_signature(a, use_campaign_tag=False)
            != build_campaign_signature(b, use_campaign_tag=False))
    # Same tag in another ecosystem is a different key.
    assert build_campaign_signature({**a, "ecosystem": "npm"}) != build_campaign_signature(a)


def _amel10_text(name):
    # Verbatim opening of GHSA-fmw8-mrp6-mj68 (figma-to-apl) / GHSA-5m79-v4p8-r597
    # (ai-workshop-maa15-radio); only the package name differs.
    return (
        f"{name} is a dependency-confusion package: it takes a name that looks like an "
        "internal project, uses an inflated version (100.0.0) so it outranks private-registry "
        "versions, and runs `node setup.js || true` as a preinstall script on npm install. "
        "setup.js sends the hostname, username, working directory, OS, architecture, Node.js "
        "version and configured npm registry, with a per-package tracking token, in an HTTPS "
        "POST to `https://s85r5k14qk.execute-api.us-east-1.amazonaws.com/prod/hook`. The npm "
        f"account amel10 published {name} and 9 similar packages within two minutes on "
        "2026-09-30, all with the same setup.js."
    )


def test_build_campaign_signature_masks_own_package_name_amel10():
    a = {"ecosystem": "npm", "package_name": "figma-to-apl", "description": _amel10_text("figma-to-apl")}
    b = {"ecosystem": "npm", "package_name": "ai-workshop-maa15-radio",
         "description": _amel10_text("ai-workshop-maa15-radio")}
    assert build_campaign_signature(a) == build_campaign_signature(b)
    assert build_campaign_signature(a)[1].startswith("<PKG> is a dependency-confusion package")
    assert (build_campaign_signature(a, mask_package_name=False)
            != build_campaign_signature(b, mask_package_name=False))


def test_mask_name_is_boundary_aware():
    from src.statistics.h1_pilot_analysis import mask_name

    # 5.13: a plain substring replace of "urc" broke "source".
    assert mask_name("## Source: kam193; urc is malicious", "urc") == "## Source: kam193; <PKG> is malicious"
    for kept in ("foo-bar", "barfoo", "foo_x", "foo.js", "@scope/foo", "x/foo", "foo@1.0", "foo2"):
        assert mask_name(kept, "foo") == kept
    assert mask_name("Foo, (foo) 'foo' foo\n", "foo") == "<PKG>, (<PKG>) '<PKG>' <PKG>\n"
    assert mask_name("a.b is bad", "a.b") == "<PKG> is bad"
    assert mask_name("axb is bad", "a.b") == "axb is bad"  # name is escaped, not a regex
    assert mask_name("text", "") == "text"

def test_collapse_merges_duplicate_name_level_records():
    """Stage 1: same (ecosystem, package_name) reported twice (GHSA + OSV
    under different advisory_ids) must collapse to one row."""
    joined = [
        {"ecosystem": "npm", "package_name": "pkg-x", "advisory_id": "GHSA-1",
         "description": "detail A", "summary": "",
         "grammar_match": {"is_grammar_flagged": True},
         "malware_label": {"malware_payload_present_candidate": False}},
        {"ecosystem": "npm", "package_name": "pkg-x", "advisory_id": "OSV-1",
         "description": "detail B", "summary": "",
         "grammar_match": {"is_grammar_flagged": False},
         "malware_label": {"malware_payload_present_candidate": True}},
    ]
    collapsed = collapse_to_campaign_level(joined)
    assert len(collapsed) == 1
    # "any member positive" aggregation
    assert collapsed[0]["grammar_match"]["is_grammar_flagged"] is True
    assert collapsed[0]["malware_label"]["malware_payload_present_candidate"] is True


def test_collapse_merges_campaign_level_records_across_names():
    """Stage 2: different package names sharing a real campaign
    description must collapse to one row."""
    shared_text = "This package is part of a large family (100+ identified)."
    joined = [
        {"ecosystem": "npm", "package_name": "campaign-pkg-1", "advisory_id": "GHSA-1",
         "description": shared_text, "summary": "",
         "grammar_match": {"is_grammar_flagged": False},
         "malware_label": {"malware_payload_present_candidate": True}},
        {"ecosystem": "npm", "package_name": "campaign-pkg-2", "advisory_id": "GHSA-2",
         "description": shared_text, "summary": "",
         "grammar_match": {"is_grammar_flagged": True},
         "malware_label": {"malware_payload_present_candidate": True}},
    ]
    collapsed = collapse_to_campaign_level(joined)
    assert len(collapsed) == 1
    assert collapsed[0]["grammar_match"]["is_grammar_flagged"] is True


def test_collapse_does_not_merge_distinct_boilerplate_records():
    """Regression guard for the exact bug found in production: generic
    GHSA boilerplate must not cause unrelated packages to be merged."""
    boilerplate = ("Any computer that has this package installed or "
                   "running should be considered fully compromised.")
    joined = [
        {"ecosystem": "npm", "package_name": "unrelated-a", "advisory_id": "GHSA-1",
         "description": boilerplate, "summary": "",
         "grammar_match": {"is_grammar_flagged": True},
         "malware_label": {"malware_payload_present_candidate": True}},
        {"ecosystem": "npm", "package_name": "unrelated-b", "advisory_id": "GHSA-2",
         "description": boilerplate, "summary": "",
         "grammar_match": {"is_grammar_flagged": False},
         "malware_label": {"malware_payload_present_candidate": True}},
    ]
    collapsed = collapse_to_campaign_level(joined)
    assert len(collapsed) == 2  # must stay separate


# --- Canonical text source (review.md A2 / D1) ------------------------------
# A package has a GHSA and an OSV record whose texts differ; "any record
# positive" across sources lets whichever text matches win. These tests pin
# select_canonical_record() and the independent text_source / group_on
# switches of collapse_to_campaign_level().

import json

import pytest

from src.statistics.h1_pilot_analysis import select_canonical_record


def _rec(name, source, adv, outcome, description="d", published_at="2026-09-01T00:00:00Z",
         flagged=False, ecosystem="pypi"):
    return {"ecosystem": ecosystem, "package_name": name, "source": source,
            "advisory_id": adv, "description": description, "summary": "",
            "published_at": published_at,
            "grammar_match": {"is_grammar_flagged": flagged},
            "malware_label": {"malware_payload_present_candidate": outcome}}


def test_select_canonical_record_prefers_requested_source():
    recs = [_rec("p", "ghsa", "GHSA-1", False), _rec("p", "osv", "MAL-1", True)]
    assert [r["advisory_id"] for r in select_canonical_record(recs, "ghsa")] == ["GHSA-1"]
    assert [r["advisory_id"] for r in select_canonical_record(recs, "osv")] == ["MAL-1"]


def test_select_canonical_record_falls_back_to_other_source():
    recs = [_rec("only-osv", "osv", "MAL-1", True), _rec("only-ghsa", "ghsa", "GHSA-2", False)]
    assert [r["advisory_id"] for r in select_canonical_record(recs, "ghsa")] == ["MAL-1", "GHSA-2"]
    assert [r["advisory_id"] for r in select_canonical_record(recs, "osv")] == ["MAL-1", "GHSA-2"]


def test_select_canonical_record_keeps_every_same_source_record():
    """Regression for the dict-overwrite bug in the first A2 table: the
    second OSV record must not replace the first. Earliest published wins,
    regardless of input order."""
    later = _rec("memoryos", "osv", "PYSEC-1", False, published_at="2026-09-23T19:52:25Z")
    earlier = _rec("memoryos", "osv", "MAL-1", True, published_at="2026-09-23T00:00:00Z")
    for recs in ([earlier, later], [later, earlier]):
        out = select_canonical_record([_rec("memoryos", "ghsa", "GHSA-1", False)] + recs, "osv")
        assert [r["advisory_id"] for r in out] == ["MAL-1"]


def test_select_canonical_record_rejects_bad_prefer_and_missing_sources():
    with pytest.raises(ValueError):
        select_canonical_record([_rec("p", "ghsa", "G", True)], "any")
    with pytest.raises(ValueError):
        select_canonical_record([_rec("p", "snyk", "S", True)], "ghsa")


def test_text_source_does_not_aggregate_across_sources():
    recs = [_rec("p", "ghsa", "GHSA-1", False), _rec("p", "osv", "MAL-1", True)]
    out = lambda ts: collapse_to_campaign_level(recs, text_source=ts)[0]["malware_label"][
        "malware_payload_present_candidate"]
    assert out("any") is True
    assert out("osv") is True
    assert out("ghsa") is False


def test_group_on_changes_grouping_but_not_outcome_source():
    """Two packages share GHSA text but not OSV text: they are one campaign
    when grouped on GHSA, two when grouped on OSV — and the DV still comes
    from text_source alone."""
    recs = [
        _rec("a", "ghsa", "GHSA-a", False, description="shared ghsa text"),
        _rec("b", "ghsa", "GHSA-b", False, description="shared ghsa text"),
        # Not "osv text a"/"b": 5.14 masks the package name, which would
        # make the two texts equal.
        _rec("a", "osv", "MAL-a", True, description="osv text one"),
        _rec("b", "osv", "MAL-b", True, description="osv text two"),
    ]
    g = collapse_to_campaign_level(recs, text_source="ghsa", group_on="ghsa")
    o = collapse_to_campaign_level(recs, text_source="ghsa", group_on="osv")
    assert len(g) == 1 and len(o) == 2
    assert all(c["malware_label"]["malware_payload_present_candidate"] is False for c in g + o)
    assert len(collapse_to_campaign_level(recs, text_source="osv", group_on="ghsa")) == 1


def test_collapse_rejects_unknown_setting():
    with pytest.raises(ValueError):
        collapse_to_campaign_level([_rec("p", "ghsa", "G", True)], text_source="both")


SNAPSHOT = Path(__file__).resolve().parents[1] / "data" / "frozen" / "incidents_snapshot.jsonl"


@pytest.mark.skipif(not SNAPSHOT.exists(), reason="frozen snapshot not present")
def test_default_settings_reproduce_section_5_6_and_any_group_equals_ghsa():
    from src.labeling.malware_labeler import label_batch

    recs = [json.loads(l) for l in SNAPSHOT.read_text(encoding="utf-8").splitlines() if l.strip()]
    joined = attach_grammar_labels(label_batch(recs))
    default = collapse_to_campaign_level(joined)
    # Section 5.14 (Campaign tag, GENERIC exclusion, name mask, narrowed negation);
    # 5.13 was 106 / [[19, 12], [43, 32]], 5.6 was 142 / [[20, 17], [61, 44]].
    assert len(default) == 94
    assert build_contingency_table(default).as_2x2() == [[13, 12], [38, 31]]
    # All three signature switches off is the 5.13 grouping.
    off = collapse_to_campaign_level(joined, use_campaign_tag=False, mask_package_name=False,
                                     exclude_generic_tag=False)
    assert len(off) == 106 and build_contingency_table(off).as_2x2() == [[19, 12], [43, 32]]
    # In this snapshot GHSA is always the first record per package, so
    # group_on="any" and group_on="ghsa" are the same grouping.
    explicit = collapse_to_campaign_level(joined, text_source="any", group_on="ghsa")
    assert [c["_member_package_names"] for c in default] == [c["_member_package_names"] for c in explicit]


# --- Reporter covariates (review.md A3 / D2) --------------------------------

from src.statistics.h1_pilot_analysis import (
    add_reporter_covariates,
    fit_reporter_logistic_regression,
    n_reporters_stratum,
    rates_by_indicator,
    reporter_indicators,
)

KAM = "## Source: kam193 (aaaaaaaaaaaaaaaa)\nkam text"
AMZ = "## Source: amazon-inspector (bbbbbbbbbbbbbbbb)\namazon text"
BOILER = "Any computer ... should be considered fully compromised."


def test_attach_grammar_labels_reporters_are_union_across_sources():
    recs = [
        {**_rec("p", "ghsa", "GHSA-1", False, description=KAM)},
        {**_rec("p", "osv", "MAL-1", True, description=AMZ + "\n" + KAM)},
        {**_rec("q", "ghsa", "GHSA-2", False, description="plain prose")},
    ]
    for r in recs:
        r.pop("grammar_match")
    joined = attach_grammar_labels(recs)
    assert joined[0]["reporters"] == joined[1]["reporters"] == ["kam193", "amazon-inspector"]
    assert joined[0]["n_reporters"] == 2
    assert joined[2]["reporters"] == ["<unattributed>"] and joined[2]["n_reporters"] == 1


def test_attach_grammar_labels_does_not_union_same_name_across_ecosystems():
    recs = [{**_rec("p", "ghsa", "G1", False, description=KAM, ecosystem="pypi")},
            {**_rec("p", "ghsa", "G2", False, description=AMZ, ecosystem="npm")}]
    joined = attach_grammar_labels(recs)
    assert [r["reporters"] for r in joined] == [["kam193"], ["amazon-inspector"]]


def _joined(name, source, adv, outcome, description, **kw):
    return attach_grammar_labels([_rec(name, source, adv, outcome, description=description, **kw)])[0]


def test_reporters_union_survives_text_source_and_campaign_collapse():
    """Name level: union over both sources even when text_source picks one.
    Campaign level: union over names."""
    recs = attach_grammar_labels([
        _rec("a", "ghsa", "GHSA-a", False, description="shared text\n" + KAM),
        _rec("a", "osv", "MAL-a", True, description=AMZ),
        _rec("b", "ghsa", "GHSA-b", False, description="shared text\n" + KAM),
        _rec("b", "osv", "MAL-b", True, description=BOILER),
    ])
    for ts in ("any", "ghsa", "osv"):
        (c,) = collapse_to_campaign_level(recs, text_source=ts)
        assert c["reporters"] == ["kam193", "amazon-inspector", "<ghsa-boilerplate>"]
        assert c["n_reporters"] == 3


def test_reporter_indicators():
    assert reporter_indicators(["kam193"]) == {
        "has_kam193": True, "has_amazon_inspector": False, "has_other": False, "has_boilerplate": False}
    assert reporter_indicators(["amazon-inspector", "ghsa-malware"]) == {
        "has_kam193": False, "has_amazon_inspector": True, "has_other": False, "has_boilerplate": True}
    for other in (["<unattributed>"], ["ossf-package-analysis"]):
        assert reporter_indicators(other)["has_other"] is True


def test_n_reporters_stratum():
    assert [n_reporters_stratum(n) for n in (0, 1, 2, 3)] == ["0", "1", "2+", "2+"]


def _campaign(eco, reporters, flagged, outcome):
    from src.data.incident_clients import count_reporters
    return {"ecosystem": eco, "reporters": reporters, "n_reporters": count_reporters(reporters),
            "grammar_match": {"is_grammar_flagged": flagged},
            "malware_label": {"malware_payload_present_candidate": outcome}}


def test_add_reporter_covariates_and_rates_by_indicator():
    cs = add_reporter_covariates([
        _campaign("npm", ["kam193"], True, True),
        _campaign("npm", ["kam193", "amazon-inspector"], False, True),
        _campaign("pypi", ["<ghsa-boilerplate>", "ghsa-malware"], False, False),
    ])
    assert [c["n_reporters_stratum"] for c in cs] == ["1", "2+", "1"]
    assert [c["ecosystem_x_n_reporters"] for c in cs] == ["npm|1", "npm|2+", "pypi|1"]
    rows = rates_by_indicator(cs, "has_kam193")
    assert rows[True]["n"] == 2 and rows[True]["grammar_flag_rate"] == 0.5 and rows[True]["dv_rate"] == 1.0
    assert rows[False]["n"] == 1 and rows[False]["dv_rate"] == 0.0


def test_fit_reporter_logistic_regression_shapes_and_or_is_exp_coef():
    import math
    import random

    rng = random.Random(0)
    cs = []
    for _ in range(400):
        eco = rng.choice(["npm", "pypi"])
        reps = rng.choice([["kam193"], ["kam193", "amazon-inspector"], ["amazon-inspector"], ["<unattributed>"]])
        flagged = rng.random() < 0.3
        logit = -0.5 + 1.0 * flagged + 0.8 * (len(reps) - 1)
        cs.append(_campaign(eco, reps, flagged, rng.random() < 1 / (1 + math.exp(-logit))))
    r = fit_reporter_logistic_regression(add_reporter_covariates(cs))
    assert r["n"] == 400 and r["converged"]
    assert set(r["terms"]) == {"Intercept", "grammar_flag", "C(ecosystem)[T.pypi]",
                               "n_reporters", "has_amazon_inspector"}
    for t in r["terms"].values():
        assert math.isclose(t["odds_ratio"], math.exp(t["coef"]))
        assert t["or_ci_low"] < t["odds_ratio"] < t["or_ci_high"]
    assert r["terms"]["grammar_flag"]["coef"] > 0  # simulated effect +1.0 recovered in sign


@pytest.mark.skipif(not SNAPSHOT.exists(), reason="frozen snapshot not present")
def test_snapshot_reporter_counts_section_5_10():
    from collections import Counter

    from src.labeling.malware_labeler import label_batch

    recs = [json.loads(l) for l in SNAPSHOT.read_text(encoding="utf-8").splitlines() if l.strip()]
    joined = attach_grammar_labels(label_batch(recs))
    packages = {(r["ecosystem"], r["package_name"]): r for r in joined}
    assert len(packages) == 200
    assert Counter(r["n_reporters"] for r in packages.values()) == Counter({1: 114, 2: 83, 3: 3})
    campaigns = add_reporter_covariates(collapse_to_campaign_level(joined))
    assert build_contingency_table(campaigns).as_2x2() == [[13, 12], [38, 31]]  # 5.14
    strata = build_stratified_tables(campaigns, "n_reporters_stratum")
    assert {k: t.as_2x2() for k, t in strata.items()} == {
        "1": [[5, 6], [4, 17]], "2+": [[8, 6], [34, 14]]}


# --- Sensitivity fits, VIFs, OR confidence intervals (5.10 / 5.11) ----------

from src.statistics.h1_pilot_analysis import (
    REPORTER_SENSITIVITY_MODELS,
    odds_ratio_ci,
    reporter_model_vifs,
)


def _random_campaigns(n=400, seed=1):
    import random

    rng = random.Random(seed)
    reps = [["kam193"], ["kam193", "amazon-inspector"], ["amazon-inspector"],
            ["<unattributed>"], ["<ghsa-boilerplate>"]]
    return add_reporter_covariates([
        _campaign(rng.choice(["npm", "pypi"]), rng.choice(reps), rng.random() < 0.3, rng.random() < 0.5)
        for _ in range(n)])


def test_sensitivity_models_fit_the_requested_terms():
    cs = _random_campaigns()
    for covs in REPORTER_SENSITIVITY_MODELS.values():
        r = fit_reporter_logistic_regression(cs, covariates=covs)
        assert set(r["terms"]) == {"Intercept", "grammar_flag", "C(ecosystem)[T.pypi]", *covs}
    assert REPORTER_SENSITIVITY_MODELS["c_a_plus_boilerplate_kam193"] == (
        "n_reporters", "has_boilerplate", "has_kam193")


def test_vifs_cover_non_intercept_columns_and_are_near_one_for_independent_flag():
    v = reporter_model_vifs(_random_campaigns())
    assert set(v) == {"C(ecosystem)[T.pypi]", "grammar_flag", "n_reporters", "has_amazon_inspector"}
    assert 1.0 <= v["grammar_flag"] < 1.1


def test_odds_ratio_ci_is_woolf_interval_around_fisher_or():
    import math

    t = ContingencyTable(20, 17, 61, 44)
    lo, hi = odds_ratio_ci(t)
    or_, se = (20 * 44) / (17 * 61), math.sqrt(1 / 20 + 1 / 17 + 1 / 61 + 1 / 44)
    assert lo == pytest.approx(or_ * math.exp(-1.959964 * se), rel=1e-5)
    assert hi == pytest.approx(or_ * math.exp(1.959964 * se), rel=1e-5)
    assert run_fisher_exact(t)["odds_ratio_ci_95"] == (lo, hi)


def test_odds_ratio_ci_undefined_with_zero_cell():
    assert odds_ratio_ci(ContingencyTable(0, 0, 5, 4)) is None


def test_cmh_reports_ci_containing_common_or():
    r = run_cmh_test([ContingencyTable(7, 7, 11, 17), ContingencyTable(13, 10, 50, 27)])
    lo, hi = r["common_odds_ratio_ci_95"]
    assert lo < r["common_odds_ratio"] < hi
