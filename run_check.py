"""
Phantom Guard — one-shot verification + power analysis.

Run from the project_p0_edited folder:
    python run_check.py
    python run_check.py --text-source ghsa --group-on ghsa   # review.md A2/D1

--text-source picks the advisory text that supplies the DV, --group-on the
text that builds the campaign signature (each any|ghsa|osv). The defaults
(any/any) reproduce Section 5.18 exactly; other settings write to
results/power_campaign_level__text-<x>__group-<y>.json.

Also writes the per-campaign table results/campaigns.csv (non-default
settings: results/campaigns__text-<x>__group-<y>.csv).

--snapshot v1|v2 picks the frozen snapshot (default v1, the 401-record
file every Section 5.18 v1 number comes from). v2 (research_log 5.17) writes
its outputs with a "__v2" suffix, e.g. results/power_campaign_level__v2.json.

Reproduces research-log Section 5.18 (campaign-level Fisher / CMH; supersedes 5.14, 5.13 and
5.6: the 5.18 no-text, Amazon Inspector template and URL-strip rules give 105 campaigns, 5.14
had 94) from the
frozen 401-record snapshot, then runs the power analysis that Section 7
item 1 asks for. Writes results/power_campaign_level.json.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
os.chdir(HERE)
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from scipy.stats import norm  # noqa: E402

from src.labeling.malware_labeler import label_batch, summarize_labeling  # noqa: E402
from src.labeling.malware_taxonomy import TAXONOMY  # noqa: E402
from src.statistics.h1_pilot_analysis import (  # noqa: E402
    REPORTER_INDICATORS,
    REPORTER_SENSITIVITY_MODELS,
    add_reporter_covariates,
    attach_grammar_labels,
    fit_reporter_logistic_regression,
    rates_by_indicator,
    reporter_model_vifs,
    build_contingency_table,
    build_stratified_tables,
    SOURCE_SETTINGS,
    apply_manual_merges,
    collapse_to_campaign_level,
    load_manual_merges,
    run_cmh_test,
    run_fisher_exact,
    write_campaign_csv,
)
from src.statistics.power_analysis import logistic_regression_power  # noqa: E402

SNAPSHOTS = {
    "v1": HERE / "data" / "frozen" / "incidents_snapshot.jsonl",
    "v2": HERE / "data" / "frozen" / "incidents_snapshot_v2.jsonl",
}


def fmt_ci(ci) -> str:
    return "[undefined: zero cell]" if ci is None else f"[{ci[0]:.3f}, {ci[1]:.3f}]"


def banner(title: str) -> None:
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def achieved_power(n: int, p: float, prev: float, odds_ratio: float, alpha: float = 0.05) -> float:
    """Inverse of the Hsieh/Demidenko approximation used in
    power_analysis.logistic_regression_power():  power = Phi(sqrt(n*denom) - z_a/2)."""
    denom = p * (1 - p) * prev * (1 - prev) * math.log(odds_ratio) ** 2
    if denom <= 0:
        return float("nan")
    return float(norm.cdf(math.sqrt(n * denom) - norm.ppf(1 - alpha / 2)))


def power_block(label: str, table) -> dict:
    n = table.total()
    p_ctrl = table.rate_when_not_flagged()
    n_flagged = table.grammar_flagged_and_outcome + table.grammar_flagged_and_not
    prev = n_flagged / n if n else 0.0
    print(f"\n[{label}]  n={n}  p_control={p_ctrl:.3f}  flagged_prevalence={prev:.3f}")
    print(f"  {'OR':>5} {'n required (80%)':>18} {'power at n':>12}")
    rows = {}
    for or_ in (0.5, 0.67, 1.5, 2.0, 3.0):
        if 0 < p_ctrl < 1 and 0 < prev < 1:
            req = logistic_regression_power(p_control=p_ctrl, odds_ratio_to_detect=or_,
                                            exposure_prevalence=prev).n_total
            pw = achieved_power(n, p_ctrl, prev, or_)
        else:
            req, pw = float("inf"), float("nan")
        rows[str(or_)] = {"n_required_80pct": req, "achieved_power": pw}
        print(f"  {or_:>5} {req:>18} {pw:>12.2f}")
    return {"n": n, "p_control": p_ctrl, "exposure_prevalence": prev, "by_odds_ratio": rows}


def reporter_block(campaigns: list[dict]) -> dict:
    """review.md D2: n_reporters strata, CMH by reporter strata, reporter
    indicator rates, and the reporter-adjusted logistic regression."""
    campaigns = add_reporter_covariates(campaigns)
    out = {}

    print("\n(a) Fisher by n_reporters stratum")
    out["by_n_reporters"] = {}
    for s, t in build_stratified_tables(campaigns, "n_reporters_stratum").items():
        r = run_fisher_exact(t)
        out["by_n_reporters"][s] = r
        print(f"  n_reporters={s:3s} n={r['n_total']:3d}  table={r['table_2x2']}  "
              f"OR={r['odds_ratio']:.3f} {fmt_ci(r['odds_ratio_ci_95'])}  p={r['p_value']:.3f}")

    print("\n(b) CMH")
    out["cmh"] = {}
    for field in ("n_reporters_stratum", "ecosystem_x_n_reporters"):
        strata = build_stratified_tables(campaigns, field)
        r = run_cmh_test(list(strata.values()))
        out["cmh"][field] = {"result": r, "strata": {k: t.as_2x2() for k, t in strata.items()}}
        print(f"  by {field}: OR={r['common_odds_ratio']:.3f} {fmt_ci(r['common_odds_ratio_ci_95'])}  chi2={r['chi2_statistic']:.3f}  "
              f"p={r['p_value']:.3f}  strata={r['n_strata']}")
        for k, t in strata.items():
            print(f"      {k:10s} n={t.total():3d}  table={t.as_2x2()}")

    print("\n(c) Grammar-flag rate and DV rate by reporter indicator")
    print(f"  {'indicator':22s} {'value':>5} {'n':>4} {'flagged':>8} {'flag rate':>9} {'DV+':>4} {'DV rate':>7}")
    out["by_indicator"] = {}
    for ind in REPORTER_INDICATORS:
        rows = rates_by_indicator(campaigns, ind)
        out["by_indicator"][ind] = {str(k): v for k, v in rows.items()}
        for value, row in rows.items():
            print(f"  {ind:22s} {str(value):>5} {row['n']:4d} {row['n_grammar_flagged']:8d} "
                  f"{row['grammar_flag_rate']:9.3f} {row['n_outcome']:4d} {row['dv_rate']:7.3f}")

    print("\n(d) Logistic regression")
    lr = fit_reporter_logistic_regression(campaigns)
    out["logit"] = lr
    print(f"  {lr['formula']}   n={lr['n']}  converged={lr['converged']}  "
          f"pseudo-R2={lr['pseudo_r2']:.3f}  LLR p={lr['llr_p_value']:.4f}")
    print(f"  {'term':24s} {'coef':>7} {'SE':>6} {'z':>6} {'p':>6} {'OR':>7} {'OR 95% CI':>18}")
    for name, t in lr["terms"].items():
        print(f"  {name:24s} {t['coef']:7.3f} {t['se']:6.3f} {t['z']:6.2f} {t['p_value']:6.3f} "
              f"{t['odds_ratio']:7.3f}  [{t['or_ci_low']:6.3f}, {t['or_ci_high']:6.3f}]")

    print("\n(d) VIFs")
    out["logit_vif"] = reporter_model_vifs(campaigns)
    for name, v in out["logit_vif"].items():
        print(f"  {name:24s} {v:6.3f}")

    print("\n(e) Sensitivity fits (grammar_flag and reporter terms)")
    out["logit_sensitivity"] = {}
    for label, covs in REPORTER_SENSITIVITY_MODELS.items():
        r = fit_reporter_logistic_regression(campaigns, covariates=covs)
        out["logit_sensitivity"][label] = r
        print(f"  [{label}] {r['formula']}  converged={r['converged']}")
        for name in ("grammar_flag", *covs):
            t = r["terms"][name]
            print(f"    {name:22s} coef={t['coef']:7.3f} [{t['ci_low']:6.3f}, {t['ci_high']:6.3f}]  "
                  f"OR={t['odds_ratio']:7.3f} [{t['or_ci_low']:6.3f}, {t['or_ci_high']:7.3f}]  p={t['p_value']:.3f}")
    return out


MANUAL_MERGES = HERE / "data" / "manual_merges.json"


def sensitivity_row(label: str, campaigns: list[dict], base: list[dict]) -> dict:
    """Pooled Fisher, CMH by ecosystem and logit (d) on `campaigns`, with
    the campaign and package difference from `base` (the main analysis)."""
    fp = run_fisher_exact(build_contingency_table(campaigns))
    cmh = run_cmh_test(list(build_stratified_tables(campaigns, "ecosystem").values()))
    lr = fit_reporter_logistic_regression(add_reporter_covariates(campaigns))
    g = lr["terms"]["grammar_flag"]
    d_c = len(campaigns) - len(base)
    d_p = sum(c["_member_count"] for c in campaigns) - sum(c["_member_count"] for c in base)
    print(f"  [{label}]  campaigns {len(campaigns)} ({d_c:+d}), packages {d_p:+d}")
    print(f"    Pooled  table={fp['table_2x2']}  OR={fp['odds_ratio']:.3f} {fmt_ci(fp['odds_ratio_ci_95'])}  "
          f"p={fp['p_value']:.3f}")
    print(f"    CMH     OR={cmh['common_odds_ratio']:.3f} {fmt_ci(cmh['common_odds_ratio_ci_95'])}  p={cmh['p_value']:.3f}")
    print(f"    Logit (d) grammar_flag OR={g['odds_ratio']:.3f} [{g['or_ci_low']:.3f}, {g['or_ci_high']:.3f}]  "
          f"p={g['p_value']:.3f}  converged={lr['converged']}")
    return {"n_campaigns": len(campaigns), "delta_campaigns": d_c, "delta_packages": d_p,
            "pooled": fp, "cmh": cmh, "logit": lr}


def sensitivity_table(campaigns: list[dict]) -> dict:
    """research_log 5.18: (1) without no-text campaigns (only the OpenSSF
    credit link; never DV-positive); (2) with the manual merges of
    data/manual_merges.json (package sets judged one campaign on name
    evidence). The main analysis uses neither."""
    out = {}
    no_text = [c for c in add_reporter_covariates(campaigns) if not c["no_text"]]
    out["exclude_no_text"] = sensitivity_row("exclude no-text", no_text, campaigns)
    merged, report = apply_manual_merges(campaigns, load_manual_merges(MANUAL_MERGES))
    for r in report:
        print(f"  manual merge {r['id']}: {r['campaigns_merged']} campaigns, {r['packages_merged']} packages"
              + (f", missing {r['missing']}" if r["missing"] else ""))
    out["with_manual_merges"] = sensitivity_row("with manual merges", merged, campaigns)
    out["with_manual_merges"]["merges"] = report
    return out


def parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--text-source", choices=SOURCE_SETTINGS, default="any",
                    help="advisory text used for the DV (default: any record positive, Section 5.6)")
    ap.add_argument("--group-on", choices=SOURCE_SETTINGS, default="any",
                    help="advisory text used for the campaign signature (default: first record, Section 5.6)")
    ap.add_argument("--snapshot", choices=sorted(SNAPSHOTS), default="v1",
                    help="frozen snapshot (default v1, which reproduces Section 5.18)")
    return ap.parse_args(argv)


def main(argv=None) -> None:
    args = parse_args(argv)
    is_default = args.text_source == "any" and args.group_on == "any"
    snapshot = SNAPSHOTS[args.snapshot]
    suffix = "" if args.snapshot == "v1" else f"__{args.snapshot}"
    print(f"Settings: --snapshot {args.snapshot}  --text-source {args.text_source}  --group-on {args.group_on}"
          + ("" if is_default and not suffix else "   (non-default: 'log:' columns refer to v1 any/any)"))

    banner("0. Sanity: taxonomy pattern counts (npm patch present?)")
    for cat, d in TAXONOMY.items():
        print(f"  {cat.value:40s} {len(d.patterns):3d} patterns")

    banner("1. Load frozen snapshot")
    if not snapshot.exists():
        sys.exit(f"Snapshot not found at {snapshot} — put {snapshot.name} there.")
    with open(snapshot, encoding="utf-8") as f:
        records = [json.loads(line) for line in f if line.strip()]
    print(f"  records: {len(records)}   (research log: 401)")

    banner("2. Label (malware taxonomy) + naming grammar, record level")
    labeled = label_batch(records)
    for eco in sorted({r["ecosystem"] for r in labeled}):
        s = summarize_labeling([r for r in labeled if r["ecosystem"] == eco])
        print(f"  {eco:6s} flagged {s['flagged_candidates']}/{s['total_records']} "
              f"= {s['flagged_rate']:.1%}   <-- npm must NOT be 0%")
    joined = attach_grammar_labels(labeled)

    banner("3. Collapse to independent campaigns")
    campaigns = collapse_to_campaign_level(joined, text_source=args.text_source, group_on=args.group_on)
    print(f"  campaigns: {len(campaigns)}   (research log 5.18: 105; 5.14 was 94, 5.13 was 106, 5.6 was 142)")

    banner("4. Section 5.18 reproduction (campaign level; supersedes 5.14)")
    pooled = build_contingency_table(campaigns)
    fp = run_fisher_exact(pooled)
    print(f"  Pooled  n={fp['n_total']}  table={fp['table_2x2']}  "
          f"OR={fp['odds_ratio']:.3f} {fmt_ci(fp['odds_ratio_ci_95'])}  p={fp['p_value']:.3f}   (log 5.18: OR 0.812, p 0.668)")
    strata = build_stratified_tables(campaigns, "ecosystem")
    expected = {"npm": "OR 1.543, p 0.673", "pypi": "OR 0.673, p 0.587"}
    for eco, t in strata.items():
        r = run_fisher_exact(t)
        print(f"  {eco:6s} n={r['n_total']}  table={r['table_2x2']}  "
              f"OR={r['odds_ratio']:.3f} {fmt_ci(r['odds_ratio_ci_95'])}  p={r['p_value']:.3f}   (log 5.18: {expected.get(eco, '?')})")
    cmh = run_cmh_test(list(strata.values()))
    print(f"  CMH     OR={cmh['common_odds_ratio']:.3f} {fmt_ci(cmh['common_odds_ratio_ci_95'])}  p={cmh['p_value']:.3f}   (log 5.18: OR 0.851, p 0.723)")

    banner("5. Power analysis at the campaign-level n (Section 7, item 1)")
    out = {"settings": {"snapshot": args.snapshot, "text_source": args.text_source,
                        "group_on": args.group_on},
           "snapshot_records": len(records), "n_campaigns": len(campaigns),
           "section_5_6": {"pooled": fp, "by_ecosystem": {k: run_fisher_exact(v) for k, v in strata.items()},
                           "cmh": cmh},
           "power": {"pooled": power_block("pooled", pooled)}}
    for eco, t in strata.items():
        out["power"][eco] = power_block(eco, t)

    banner("6. Reporter analysis (review.md A3 / D2)")
    out["reporters_d2"] = reporter_block(campaigns)

    banner("7. Sensitivity table (research_log 5.18)")
    out["sensitivity"] = sensitivity_table(campaigns)

    Path("results").mkdir(exist_ok=True)
    out_path = Path("results") / ("power_campaign_level" + ("" if is_default else
                                  f"__text-{args.text_source}__group-{args.group_on}") + suffix + ".json")
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2, default=str)
    print(f"\nWritten: {out_path}")
    csv_path = Path("results") / ("campaigns" + ("" if is_default else
                                  f"__text-{args.text_source}__group-{args.group_on}") + suffix + ".csv")
    rows = write_campaign_csv(campaigns, csv_path)
    print(f"Written: {csv_path}  ({len(rows)} campaigns)")

    pw2 = out["power"]["pooled"]["by_odds_ratio"]["2.0"]["achieved_power"]
    banner("Verdict")
    if pw2 < 0.8:
        print(f"  Power to detect OR=2.0 at n={len(campaigns)} is {pw2:.2f} (< 0.80).")
        print("  The Section 5.7 null is UNDERPOWERED -> grow the corpus before further analysis.")
    else:
        print(f"  Power to detect OR=2.0 at n={len(campaigns)} is {pw2:.2f} (>= 0.80).")
        print("  The null is informative for large effects; only modest effects remain open.")


if __name__ == "__main__":
    main()
