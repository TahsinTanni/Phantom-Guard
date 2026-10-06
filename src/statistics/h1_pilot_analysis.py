"""
H1 pilot analysis: joins naming_grammar classification with malware
labeling on the confirmed-incident corpus, and runs a quick contingency
test.

Scope note
-----------
This is a PILOT-SCALE sanity check, not the primary analysis specified in
the full research plan (that's logistic regression with controls —
ecosystem, age, popularity, doc length — plus matched-sample design, per
the Phase 0 audit). Fisher's exact test here answers only "is there any
signal worth pursuing at all," on the raw unmatched/uncontrolled data.
Do not report this test's p-value as a final result in the paper — it's a
go/no-go signal for whether the full matched-control analysis is worth
building next.

Independence note
-------------------
`attach_grammar_labels` computes naming_grammar classification from
`package_name` and malware labeling was already computed independently
(malware_labeler.py never sees the name). This join happens AFTER both
labels exist, for analysis purposes only — it does not feed one label
into the other's computation, so H1's circularity requirement is not
violated by this step.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass

from src.data.incident_clients import (
    GHSA_BOILERPLATE_ALIASES,
    GHSA_BOILERPLATE_PHRASE,
    count_reporters,
    extract_reporters,
    is_inspector_template,
    is_no_text,
    union_reporters,
)
from src.data.naming_grammar import classify_naming_grammar


def _record_text(record: dict) -> str:
    return (record.get("description") or record.get("summary") or "").strip()


def attach_grammar_labels(labeled_incidents: list[dict]) -> list[dict]:
    """
    Adds a `grammar_match` block to each already-malware-labeled incident
    record, computed from `package_name` only.

    Also adds `reporters` and `n_reporters` (review.md A3 / D2). These are
    package-level: the union of extract_reporters() over ALL of the
    package's records, from both sources, so every record of a package
    carries the same value regardless of which text later supplies the DV.
    """
    by_package: dict[tuple[str, str], list[list[str]]] = {}
    for r in labeled_incidents:
        key = (r.get("ecosystem", ""), r["package_name"])
        by_package.setdefault(key, []).append(extract_reporters(_record_text(r)))
    package_reporters = {k: union_reporters(v) for k, v in by_package.items()}

    result = []
    for r in labeled_incidents:
        grammar = classify_naming_grammar(r["package_name"])
        reporters = package_reporters[(r.get("ecosystem", ""), r["package_name"])]
        result.append({
            **r,
            "grammar_match": grammar.to_dict(),
            "reporters": reporters,
            "n_reporters": count_reporters(reporters),
        })
    return result


def _with_reporter_union(merged: dict, members: list[dict]) -> dict:
    """Sets `reporters`/`n_reporters` on a collapsed record to the union over
    its members. No-op when members carry no `reporters` field."""
    if not any("reporters" in m for m in members):
        return merged
    reporters = union_reporters(m.get("reporters", []) for m in members)
    return {**merged, "reporters": reporters, "n_reporters": count_reporters(reporters)}


NAMED_REPORTERS = ("kam193", "amazon-inspector")
REPORTER_INDICATORS = ("has_kam193", "has_amazon_inspector", "has_other", "has_boilerplate")


def reporter_indicators(reporters: list[str]) -> dict[str, bool]:
    """has_other = any reporter that is neither a NAMED_REPORTER nor the GHSA
    boilerplate (e.g. <unattributed>, ossf-package-analysis)."""
    known = set(NAMED_REPORTERS) | GHSA_BOILERPLATE_ALIASES
    return {
        "has_kam193": "kam193" in reporters,
        "has_amazon_inspector": "amazon-inspector" in reporters,
        "has_other": any(r not in known for r in reporters),
        "has_boilerplate": any(r in GHSA_BOILERPLATE_ALIASES for r in reporters),
    }


def n_reporters_stratum(n: int) -> str:
    """'1' or '2+' (review D2 strata); '0' only for packages with no text."""
    return "2+" if n >= 2 else str(n)


def add_reporter_covariates(campaigns: list[dict]) -> list[dict]:
    """Adds the four reporter indicators, `n_reporters_stratum`,
    `ecosystem_x_n_reporters` (for the two-way CMH) and `no_text` (every
    member text is a no-text advisory, research_log 5.18) to each campaign."""
    out = []
    for c in campaigns:
        stratum = n_reporters_stratum(c["n_reporters"])
        out.append({
            **c,
            **reporter_indicators(c["reporters"]),
            "n_reporters_stratum": stratum,
            "ecosystem_x_n_reporters": f"{c['ecosystem']}|{stratum}",
            "no_text": bool(c.get("_no_text", False)),
        })
    return out


def rates_by_indicator(
    campaigns: list[dict],
    indicator: str,
    outcome_field: str = "malware_label",
    outcome_key: str = "malware_payload_present_candidate",
) -> dict[bool, dict]:
    """For indicator True and False: n, grammar-flag rate, DV rate."""
    rows = {}
    for value in (True, False):
        subset = [c for c in campaigns if bool(c[indicator]) is value]
        n = len(subset)
        flagged = sum(c["grammar_match"]["is_grammar_flagged"] for c in subset)
        outcome = sum(c[outcome_field][outcome_key] for c in subset)
        rows[value] = {
            "n": n,
            "n_grammar_flagged": flagged,
            "grammar_flag_rate": flagged / n if n else float("nan"),
            "n_outcome": outcome,
            "dv_rate": outcome / n if n else float("nan"),
        }
    return rows


REPORTER_MODEL_COVARIATES = ("n_reporters", "has_amazon_inspector")
# Section 5.10(d) sensitivity fits. Keys are the labels used in the log.
REPORTER_SENSITIVITY_MODELS = {
    "a_drop_amazon": ("n_reporters",),
    "b_drop_n_reporters": ("has_amazon_inspector",),
    "c_a_plus_boilerplate_kam193": ("n_reporters", "has_boilerplate", "has_kam193"),
}


def _reporter_design_frame(campaigns: list[dict], outcome_field: str, outcome_key: str):
    import pandas as pd

    return pd.DataFrame({
        "dv": [int(c[outcome_field][outcome_key]) for c in campaigns],
        "grammar_flag": [int(c["grammar_match"]["is_grammar_flagged"]) for c in campaigns],
        "ecosystem": [c["ecosystem"] for c in campaigns],
        "n_reporters": [c["n_reporters"] for c in campaigns],
        **{ind: [int(c[ind]) for c in campaigns] for ind in REPORTER_INDICATORS},
    })


def _reporter_formula(covariates) -> str:
    return " + ".join(["dv ~ grammar_flag", "C(ecosystem)", *covariates])


def fit_reporter_logistic_regression(
    campaigns: list[dict],
    covariates: tuple[str, ...] = REPORTER_MODEL_COVARIATES,
    outcome_field: str = "malware_label",
    outcome_key: str = "malware_payload_present_candidate",
) -> dict:
    """
    Logit: DV ~ grammar_flag + C(ecosystem) + <covariates>, one row per
    campaign. The default covariates give the Section 5.10(d) model
    (n_reporters as a count, has_amazon_inspector). `covariates` may name
    n_reporters or any of REPORTER_INDICATORS. Returns per-term coefficient,
    SE, z, p, OR and 95% Wald CI (on both scales), plus fit statistics.
    `campaigns` must already have add_reporter_covariates().
    """
    import numpy as np
    import statsmodels.formula.api as smf

    df = _reporter_design_frame(campaigns, outcome_field, outcome_key)
    formula = _reporter_formula(covariates)
    fit = smf.logit(formula, data=df).fit(disp=False)
    ci = fit.conf_int(alpha=0.05)
    terms = {}
    for name in fit.params.index:
        lo, hi = ci.loc[name]
        terms[name] = {
            "coef": float(fit.params[name]),
            "se": float(fit.bse[name]),
            "z": float(fit.tvalues[name]),
            "p_value": float(fit.pvalues[name]),
            "ci_low": float(lo),
            "ci_high": float(hi),
            "odds_ratio": float(np.exp(fit.params[name])),
            "or_ci_low": float(np.exp(lo)),
            "or_ci_high": float(np.exp(hi)),
        }
    return {
        "formula": formula,
        "n": int(fit.nobs),
        "converged": bool(fit.mle_retvals.get("converged", False)),
        "log_likelihood": float(fit.llf),
        "pseudo_r2": float(fit.prsquared),
        "llr_p_value": float(fit.llr_pvalue),
        "terms": terms,
    }


def reporter_model_vifs(
    campaigns: list[dict],
    covariates: tuple[str, ...] = REPORTER_MODEL_COVARIATES,
    outcome_field: str = "malware_label",
    outcome_key: str = "malware_payload_present_candidate",
) -> dict[str, float]:
    """Variance inflation factor of each non-intercept column of the model's
    design matrix (intercept kept in the matrix, as VIF requires)."""
    from patsy import dmatrix
    from statsmodels.stats.outliers_influence import variance_inflation_factor

    df = _reporter_design_frame(campaigns, outcome_field, outcome_key)
    X = dmatrix(_reporter_formula(covariates).split("~", 1)[1], df, return_type="dataframe")
    return {
        col: float(variance_inflation_factor(X.values, i))
        for i, col in enumerate(X.columns) if col != "Intercept"
    }


@dataclass
class ContingencyTable:
    grammar_flagged_and_outcome: int  # a
    grammar_flagged_and_not: int  # b
    not_flagged_and_outcome: int  # c
    not_flagged_and_not: int  # d

    def as_2x2(self) -> list[list[int]]:
        """scipy.stats.fisher_exact expects [[a, b], [c, d]]."""
        return [
            [self.grammar_flagged_and_outcome, self.grammar_flagged_and_not],
            [self.not_flagged_and_outcome, self.not_flagged_and_not],
        ]

    def total(self) -> int:
        return (
            self.grammar_flagged_and_outcome
            + self.grammar_flagged_and_not
            + self.not_flagged_and_outcome
            + self.not_flagged_and_not
        )

    def rate_when_flagged(self) -> float:
        denom = self.grammar_flagged_and_outcome + self.grammar_flagged_and_not
        return self.grammar_flagged_and_outcome / denom if denom > 0 else 0.0

    def rate_when_not_flagged(self) -> float:
        denom = self.not_flagged_and_outcome + self.not_flagged_and_not
        return self.not_flagged_and_outcome / denom if denom > 0 else 0.0


def build_contingency_table(
    joined_records: list[dict],
    outcome_field: str = "malware_label",
    outcome_key: str = "malware_payload_present_candidate",
) -> ContingencyTable:
    """
    Builds a 2x2 table of grammar_match.is_grammar_flagged x
    <outcome_field>.<outcome_key>. Defaults to the malware construct;
    pass outcome_field="heuristic_label",
    outcome_key="injection_present_candidate" to run the same analysis
    against the (reserved-for-skills) injection construct instead, once
    that corpus exists.
    """
    a = b = c = d = 0
    for r in joined_records:
        flagged = r["grammar_match"]["is_grammar_flagged"]
        outcome = r[outcome_field][outcome_key]
        if flagged and outcome:
            a += 1
        elif flagged and not outcome:
            b += 1
        elif not flagged and outcome:
            c += 1
        else:
            d += 1
    return ContingencyTable(a, b, c, d)


def odds_ratio_ci(table: ContingencyTable, alpha: float = 0.05) -> tuple[float, float] | None:
    """Woolf (log) 95% CI for the sample odds ratio ad/bc, via statsmodels
    Table2x2 — the same point estimate scipy's fisher_exact reports. None
    when any cell is zero (the CI is undefined without a continuity
    correction; none is applied)."""
    from statsmodels.stats.contingency_tables import Table2x2

    if 0 in (t for row in table.as_2x2() for t in row):
        return None
    lo, hi = Table2x2(table.as_2x2()).oddsratio_confint(alpha=alpha)
    return (float(lo), float(hi))


def run_fisher_exact(table: ContingencyTable) -> dict:
    """
    Two-sided Fisher's exact test on the 2x2 table. Returns odds ratio and
    p-value. Requires scipy (already a project dependency).

    Interpretation reminder: this is UNADJUSTED (no controls for
    ecosystem, age, popularity). A significant result here is grounds to
    proceed to the full logistic regression, not a substitute for it. A
    non-significant result at pilot scale may simply mean the sample is
    too small yet (check counts against src/statistics/power_analysis.py
    before concluding the effect isn't there).
    """
    from scipy.stats import fisher_exact

    odds_ratio, p_value = fisher_exact(table.as_2x2(), alternative="two-sided")
    return {
        "odds_ratio": odds_ratio,
        "odds_ratio_ci_95": odds_ratio_ci(table),
        "p_value": p_value,
        "n_total": table.total(),
        "rate_when_flagged": table.rate_when_flagged(),
        "rate_when_not_flagged": table.rate_when_not_flagged(),
        "table_2x2": table.as_2x2(),
    }


def build_stratified_tables(
    joined_records: list[dict],
    strata_field: str,
    outcome_field: str = "malware_label",
    outcome_key: str = "malware_payload_present_candidate",
) -> dict[str, ContingencyTable]:
    """
    Splits joined_records by `strata_field` (e.g., 'ecosystem') and builds
    a separate ContingencyTable per stratum. Used as input to
    run_cmh_test, which pools evidence across strata rather than testing
    each in isolation (isolated per-stratum tests lose power fast — see
    module-level note on run_cmh_test for why this matters).
    """
    strata_values = sorted({r[strata_field] for r in joined_records})
    tables = {}
    for value in strata_values:
        subset = [r for r in joined_records if r[strata_field] == value]
        tables[value] = build_contingency_table(subset, outcome_field, outcome_key)
    return tables


def run_cmh_test(tables: list[ContingencyTable]) -> dict:
    """
    Cochran-Mantel-Haenszel test across K 2x2 strata tables.

    WHY THIS EXISTS: splitting a sample into subgroups (e.g., by
    ecosystem) and running a separate Fisher's exact test on each throws
    away statistical power — you need enough EVENTS WITHIN EACH SUBGROUP
    to detect an effect there alone, which is a much higher bar than
    detecting the same effect pooled. CMH instead asks "controlling for
    stratum, is there an association overall," combining evidence across
    strata without requiring significance in any single one — this is the
    classical-statistics equivalent of logistic regression with a stratum
    covariate, appropriate when sample size doesn't yet support the full
    regression with all planned controls.

    Formulas (standard, e.g. Agresti, "Categorical Data Analysis"):
        Mantel-Haenszel common odds ratio:
            OR_MH = sum(a_i * d_i / n_i) / sum(b_i * c_i / n_i)
        CMH chi-square statistic (1 df):
            chi2 = (sum(a_i) - sum(E_i))^2 / sum(V_i)
            where E_i = (a_i+b_i)(a_i+c_i) / n_i
                  V_i = (a_i+b_i)(c_i+d_i)(a_i+c_i)(b_i+d_i) / (n_i^2 (n_i-1))

    Assumes a common odds ratio across strata (homogeneity) — reasonable
    when, as here, the direction of effect is consistent across strata
    even if individually non-significant. If strata show OPPOSITE
    directions, CMH's pooled estimate is not meaningful and that should be
    reported as effect-modification (interaction), not pooled.
    """
    from scipy.stats import chi2 as chi2_dist

    numerator_or = 0.0
    denominator_or = 0.0
    sum_a = 0.0
    sum_e = 0.0
    sum_v = 0.0

    for t in tables:
        a, b, c, d = (
            t.grammar_flagged_and_outcome,
            t.grammar_flagged_and_not,
            t.not_flagged_and_outcome,
            t.not_flagged_and_not,
        )
        n = a + b + c + d
        if n < 2:
            continue  # a stratum with <2 total observations contributes
            # no usable variance term (division by n-1); skip rather than
            # crash, since this can legitimately happen with sparse strata.

        numerator_or += (a * d) / n
        denominator_or += (b * c) / n

        e_i = (a + b) * (a + c) / n
        v_i = ((a + b) * (c + d) * (a + c) * (b + d)) / (n**2 * (n - 1))

        sum_a += a
        sum_e += e_i
        sum_v += v_i

    if denominator_or == 0 or sum_v == 0:
        return {
            "common_odds_ratio": float("inf") if numerator_or > 0 else float("nan"),
            "chi2_statistic": float("nan"),
            "p_value": float("nan"),
            "n_strata": len(tables),
            "note": "Degenerate input (zero denominator or variance) — "
            "check for empty/near-empty strata.",
        }

    common_or = numerator_or / denominator_or
    # Robins-Breslow-Greenland 95% CI for the MH common OR (statsmodels
    # StratifiedTable, the K-stratum counterpart of Table2x2). Same strata
    # as the statistic: those with n < 2 are dropped.
    from statsmodels.stats.contingency_tables import StratifiedTable

    usable = [t.as_2x2() for t in tables if t.total() >= 2]
    ci_lo, ci_hi = StratifiedTable(usable).oddsratio_pooled_confint(alpha=0.05)
    chi2_stat = ((sum_a - sum_e) ** 2) / sum_v
    p_value = chi2_dist.sf(chi2_stat, df=1)

    return {
        "common_odds_ratio": common_or,
        "common_odds_ratio_ci_95": (float(ci_lo), float(ci_hi)),
        "chi2_statistic": chi2_stat,
        "p_value": p_value,
        "n_strata": len(tables),
        "n_total": sum(t.total() for t in tables),
    }


def build_campaign_signature(
    record: dict,
    sig_len: int = 200,
    use_campaign_tag: bool = True,
    mask_package_name: bool = True,
    exclude_generic_tag: bool = True,
    strip_urls: bool = True,
    exclude_inspector_template: bool = True,
) -> tuple[str, str]:
    """
    Groups records likely belonging to the same attack campaign: GHSA and
    OSV frequently report multiple squatted package names under one
    campaign with near-identical description text (e.g. tea.xyz reward
    farming, canary-token recon droppers, explicitly-named package
    "families"). Treating each name as an independent observation in
    Fisher's/CMH tests violates the independence assumption.

    Keys, in order:
    1. GHSA's generic fallback template ("Any computer that has this
       package installed... should be considered fully compromised...")
       and kam193's catch-all "Campaign: GENERIC-standard-pypi-install-pentest"
       are IDENTICAL across unrelated incidents and must NOT be used as a
       campaign signature. A record carrying either, and no specific
       kam193 campaign tag, keeps its own package_name-keyed signature
       (the GENERIC part is `exclude_generic_tag`).
    2. A specific kam193 "Campaign: <id>" tag groups on (ecosystem, id)
       (`use_campaign_tag`).
    No-text advisories (only the OpenSSF credit link and the OSV separator,
    see is_no_text) and Amazon Inspector's one-line "was found to contain
    malicious code" verdict (see is_inspector_template;
    `exclude_inspector_template`) also keep their own package-keyed
    signature, like the GHSA boilerplate (research_log 5.18).
    3. Otherwise the first `sig_len` characters of the text, after
       "## Source: <reporter> (<hash>)" header lines are stripped (the hash
       is unique per report) and the record's own package name is replaced
       by PACKAGE_NAME_MASK (`mask_package_name`; texts that open with the
       package name would otherwise never match), and every URL is replaced
       by URL_MASK (`strip_urls`, research_log 5.18; OSV links carry the
       package name inside the path, where the name mask cannot reach). See
       signature_text().
    The defaults are the research_log 5.18 behaviour (105 v1 campaigns).
    exclude_inspector_template=False gives the intermediate 5.18 grouping
    (93); with strip_urls=False as well it gives 5.14 (94); all five
    switches off gives 5.13 (106). v1 has no no-text records, so that rule
    has no switch.
    """
    text = (record.get("description") or record.get("summary") or "").strip()
    ecosystem = record.get("ecosystem", "")
    tags = campaign_tags(text)
    specific = sorted(t for t in tags if t not in GENERIC_CAMPAIGN_TAGS)
    if use_campaign_tag and specific:
        return (ecosystem, "__campaign__:" + "|".join(specific))
    if (GHSA_BOILERPLATE_PHRASE in text or is_no_text(text)
            or (exclude_inspector_template and is_inspector_template(text))
            or (exclude_generic_tag and tags and not specific)):
        return (ecosystem, f"__noboilerplate__:{record['package_name']}")
    return (ecosystem, signature_text(record, mask_package_name, strip_urls)[:sig_len])


def signature_text(record: dict, mask_package_name: bool = True, strip_urls: bool = True) -> str:
    """The text whose prefix is a text-prefix campaign signature: headers
    stripped, own name masked, then URLs masked (in that order)."""
    text = (record.get("description") or record.get("summary") or "").strip()
    text = SOURCE_HEADER_LINE.sub("", text).strip()
    if mask_package_name:
        text = mask_name(text, record["package_name"])
    if strip_urls:
        text = URL_PATTERN.sub(URL_MASK, text)
    return text


SOURCE_HEADER_LINE = re.compile(r"^[ \t]*## Source:.*(?:\r?\n|$)", flags=re.MULTILINE)
# kam193's "Campaign: <id>" line (research_log 5.13: 87 distinct ids in the
# snapshot, never two different ids in one record).
CAMPAIGN_TAG_LINE = re.compile(r"^[ \t]*Campaign:[ \t]*(\S+)", flags=re.MULTILINE)
# kam193's catch-all template, shared by unrelated packages (5.13: one
# 15-name false merge).
GENERIC_CAMPAIGN_TAGS = frozenset({"GENERIC-standard-pypi-install-pentest"})
PACKAGE_NAME_MASK = "<PKG>"
# research_log 5.18: a URL runs to the next whitespace (markdown closing
# brackets included), so "([source](https://.../MAL-1.json))" -> "([source](<URL>".
URL_PATTERN = re.compile(r"https?://\S+")
URL_MASK = "<URL>"
# Characters that may be part of a package name or path; the name is only
# masked when neither neighbour is one of these ("urc" is not masked inside
# "source", "foo" not inside "foo-bar" or "@scope/foo").
_NAME_CHAR = r"[A-Za-z0-9_.@/-]"


def campaign_tags(text: str) -> set[str]:
    """kam193 campaign ids in `text` ("Campaign: <id>" lines)."""
    return set(CAMPAIGN_TAG_LINE.findall(text or ""))


def mask_name(text: str, package_name: str) -> str:
    """Replaces whole-name occurrences of `package_name` (case-insensitive)
    with PACKAGE_NAME_MASK; see _NAME_CHAR for the boundary rule."""
    if not package_name:
        return text
    pattern = rf"(?<!{_NAME_CHAR}){re.escape(package_name)}(?!{_NAME_CHAR})"
    return re.sub(pattern, PACKAGE_NAME_MASK, text, flags=re.IGNORECASE)


def _collapse_group(members: list[dict], outcome_field: str, outcome_key: str) -> dict:
    """Merges a group of duplicate records into one, using 'any member
    positive' for both the outcome and the grammar flag — avoids
    arbitrary tie-breaking (e.g. 'longest text') which has no principled
    connection to which record is more representative."""
    rep = members[0]
    # no_text: every member text is a no-text advisory (is_no_text).
    all_no_text = all(m.get("_no_text", is_no_text(m.get("description", ""))) for m in members)
    any_flagged = any(m["grammar_match"]["is_grammar_flagged"] for m in members)
    any_outcome = any(m[outcome_field][outcome_key] for m in members)
    merged = {
        **rep,
        "grammar_match": {**rep["grammar_match"], "is_grammar_flagged": any_flagged},
        outcome_field: {**rep[outcome_field], outcome_key: any_outcome},
        "_member_count": len(members),
        "_member_package_names": [m["package_name"] for m in members],
        "_no_text": all_no_text,
    }
    return _with_reporter_union(merged, members)


SOURCES = ("ghsa", "osv")
SOURCE_SETTINGS = ("any",) + SOURCES


def _group_by_source(records: list[dict]) -> dict[str, list[dict]]:
    """Records of ONE package, keyed by source. Values are lists: a package
    can have more than one record from the same source (e.g. an OSV MAL-
    entry and a PYSEC entry), so a dict-of-records would silently keep
    only the last one."""
    by_source: dict[str, list[dict]] = {}
    for r in records:
        by_source.setdefault(r.get("source", ""), []).append(r)
    return by_source


def _pick_canonical(by_source: dict[str, list[dict]], prefer: str) -> dict:
    """One record from one package's per-source lists: `prefer`'s records
    if any, else the other source's. Within a source, the earliest
    published record wins (stable on input order; missing dates sort last)
    — i.e. the original report, not a later re-publication."""
    if prefer not in SOURCES:
        raise ValueError(f"prefer must be one of {SOURCES}, got {prefer!r}")
    fallback = next(s for s in SOURCES if s != prefer)
    candidates = by_source.get(prefer) or by_source.get(fallback)
    if not candidates:
        raise ValueError(
            f"no {prefer!r} or {fallback!r} record; sources present: {sorted(by_source)}"
        )
    return min(candidates, key=lambda r: (r.get("published_at") is None, r.get("published_at") or ""))


def select_canonical_record(records: list[dict], prefer: str) -> list[dict]:
    """
    One record per (ecosystem, package_name), in first-seen order. Records
    are grouped per source as lists, then `prefer` ("ghsa" or "osv") is
    taken with fallback to the other source (see _pick_canonical for the
    within-source rule). Use this instead of "any record positive" when
    the question is "what does source X's text say" (review.md A2).
    """
    by_name: dict[tuple[str, str], list[dict]] = {}
    for r in records:
        by_name.setdefault((r["ecosystem"], r["package_name"]), []).append(r)
    return [_pick_canonical(_group_by_source(members), prefer) for members in by_name.values()]


def _name_level_record(
    members: list[dict],
    text_source: str,
    group_on: str,
    outcome_field: str,
    outcome_key: str,
) -> dict:
    """Stage-1 collapse of all records for one package under the two
    independent switches:
      text_source: which record(s) supply the outcome. "any" = any record,
        any source, positive (the Section 5.6 behaviour).
      group_on: which record's text builds the campaign signature. "any" =
        members[0] in input order (the Section 5.6 behaviour; in the frozen
        snapshot that is always the GHSA record).
    """
    for name, value in (("text_source", text_source), ("group_on", group_on)):
        if value not in SOURCE_SETTINGS:
            raise ValueError(f"{name} must be one of {SOURCE_SETTINGS}, got {value!r}")
    by_source = _group_by_source(members)
    text_members = members if text_source == "any" else [_pick_canonical(by_source, text_source)]
    rep = members[0] if group_on == "any" else _pick_canonical(by_source, group_on)
    merged = _collapse_group(text_members, outcome_field, outcome_key)
    # Reporters are a property of the package, not of the DV text: union over
    # ALL members whatever text_source is.
    return _with_reporter_union({
        **rep,
        "grammar_match": merged["grammar_match"],
        outcome_field: merged[outcome_field],
        "_member_count": len(members),
        "_member_package_names": [m["package_name"] for m in members],
        "_text_advisory_ids": [m.get("advisory_id") for m in text_members],
        # Like reporters, a property of the package: all of its texts.
        "_no_text": all(is_no_text(m.get("description", "")) for m in members),
        "_group_advisory_id": rep.get("advisory_id"),
    }, members)


def collapse_to_campaign_level(
    joined_records: list[dict],
    outcome_field: str = "malware_label",
    outcome_key: str = "malware_payload_present_candidate",
    text_source: str = "any",
    group_on: str = "any",
    **signature_options,
) -> list[dict]:
    """
    Two-stage collapse to independent observational units, required
    before any Fisher's/CMH test on this corpus:

    Stage 1 (name-level dedup): GHSA and OSV frequently both report the
    SAME package under DIFFERENT advisory_ids with slightly different
    wording, so deduplicate_incidents()'s advisory_id-based dedup doesn't
    catch them. Collapse by (ecosystem, package_name) first.

    Stage 2 (campaign-level dedup): separately, one attacker/campaign
    often squats MULTIPLE distinct package names with near-identical
    payload/description (e.g. tea.xyz reward-farming, canary-token
    droppers). Collapse by description-text signature second, over the
    stage-1 output.

    Both stages use 'any member positive' aggregation (see
    _collapse_group) rather than picking a single representative record,
    since different name variants in one campaign can carry different
    naming-grammar classifications even though they share one payload.

    `text_source` and `group_on` (each "any", "ghsa" or "osv") choose,
    independently, which advisory text supplies the outcome and which
    builds the campaign signature (review.md A2). Stage 1 with
    text_source != "any" does NOT aggregate across sources: it reads one
    canonical record. "Any member positive" is kept only across names
    within a campaign (stage 2). Defaults reproduce Section 5.14.
    `signature_options` are passed to build_campaign_signature().
    """
    by_name: dict[tuple[str, str], list[dict]] = {}
    for r in joined_records:
        key = (r["ecosystem"], r["package_name"])
        by_name.setdefault(key, []).append(r)
    name_level = [
        _name_level_record(members, text_source, group_on, outcome_field, outcome_key)
        for members in by_name.values()
    ]

    by_campaign: dict[tuple[str, str], list[dict]] = {}
    for r in name_level:
        sig = build_campaign_signature(r, **signature_options)
        by_campaign.setdefault(sig, []).append(r)
    campaign_level = [
        _collapse_group(members, outcome_field, outcome_key)
        for members in by_campaign.values()
    ]

    return campaign_level


def load_manual_merges(path) -> list[dict]:
    """The "merges" list of data/manual_merges.json: package sets judged one
    campaign on name evidence (research_log 5.18). Each entry has id,
    ecosystem, packages and reason."""
    import json

    with open(path, encoding="utf-8") as f:
        merges = json.load(f)["merges"]
    for m in merges:
        if not (m.get("id") and m.get("ecosystem") and m.get("packages") and m.get("reason")):
            raise ValueError(f"manual merge entry needs id, ecosystem, packages and reason: {m}")
    return merges


def apply_manual_merges(
    campaigns: list[dict],
    merges: list[dict],
    outcome_field: str = "malware_label",
    outcome_key: str = "malware_payload_present_candidate",
) -> tuple[list[dict], list[dict]]:
    """Merges, for each entry, every campaign of its ecosystem that contains
    one of its packages into one campaign ('any member positive', as in
    _collapse_group), placed where its first constituent was. Whole
    campaigns are merged, never split. Returns (campaigns, report); the
    report lists per entry the campaigns merged and any listed package
    absent from the corpus. Sensitivity analysis only: the main analysis
    runs without manual merges."""
    out = list(campaigns)
    report = []
    for m in merges:
        names = set(m["packages"])
        idx = [i for i, c in enumerate(out)
               if c["ecosystem"] == m["ecosystem"] and names & set(c["_member_package_names"])]
        present = {n for i in idx for n in out[i]["_member_package_names"]}
        report.append({"id": m["id"], "campaigns_merged": len(idx),
                       "packages_merged": len(present), "missing": sorted(names - present)})
        if len(idx) < 2:
            continue
        group = [out[i] for i in idx]
        merged = _collapse_group(group, outcome_field, outcome_key)
        merged["_member_package_names"] = [n for c in group for n in c["_member_package_names"]]
        merged["_member_count"] = len(merged["_member_package_names"])
        merged["_manual_merge"] = m["id"]
        out[idx[0]] = merged
        for i in reversed(idx[1:]):
            del out[i]
    return out, report


CAMPAIGN_CSV_COLUMNS = (
    "campaign_id", "ecosystem", "member_packages", "signature_type", "grammar_flag",
    "mechanism_label", "n_reporters", "kam193", "amazon_inspector", "boilerplate", "no_text",
)
MEMBER_SEPARATOR = ";"


def signature_type(campaign: dict, **signature_options) -> str:
    """Which build_campaign_signature() rule keyed this campaign:
    "campaign_tag" (kam193 Campaign id), "own_package" (GHSA boilerplate,
    the GENERIC tag, a no-text advisory or the Amazon Inspector one-liner,
    so never merged) or "text_prefix" (masked description
    prefix). A campaign record is its first member's record, so its
    signature is the key it was grouped on; `signature_options` must match
    the collapse."""
    _, key = build_campaign_signature(campaign, **signature_options)
    if key.startswith("__campaign__:"):
        return "campaign_tag"
    if key.startswith("__noboilerplate__:"):
        return "own_package"
    return "text_prefix"


def campaign_table_rows(
    campaigns: list[dict],
    outcome_field: str = "malware_label",
    outcome_key: str = "malware_payload_present_candidate",
    **signature_options,
) -> list[dict]:
    """One row per campaign, in collapse order, with CAMPAIGN_CSV_COLUMNS.
    Ids are C001.. in that order (stable for a fixed snapshot and settings);
    flags and indicators are 0/1."""
    rows = []
    for i, c in enumerate(campaigns, start=1):
        ind = reporter_indicators(c["reporters"])
        rows.append({
            "campaign_id": f"C{i:03d}",
            "ecosystem": c["ecosystem"],
            "member_packages": MEMBER_SEPARATOR.join(c["_member_package_names"]),
            "signature_type": signature_type(c, **signature_options),
            "grammar_flag": int(c["grammar_match"]["is_grammar_flagged"]),
            "mechanism_label": int(c[outcome_field][outcome_key]),
            "n_reporters": c["n_reporters"],
            "kam193": int(ind["has_kam193"]),
            "amazon_inspector": int(ind["has_amazon_inspector"]),
            "boilerplate": int(ind["has_boilerplate"]),
            "no_text": int(c.get("_no_text", False)),
        })
    return rows


def write_campaign_csv(campaigns: list[dict], path, **signature_options) -> list[dict]:
    """Writes campaign_table_rows() to `path` and returns the rows."""
    rows = campaign_table_rows(campaigns, **signature_options)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CAMPAIGN_CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    return rows
