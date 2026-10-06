"""
Figures for the analysis paper (paper/) and the data article (paper_dib/).

Run from the project_p0_edited folder, after run_check.py (default and
--text-source ghsa):
    python -m src.visualization.paper_figures

Everything is recomputed from data/frozen/incidents_snapshot.jsonl through
the same pipeline functions run_check.py uses; model estimates are read from
results/power_campaign_level*.json. Writes vector PDFs to paper/figures/ and
paper_dib/figures/.

    python -m src.visualization.paper_figures --snapshot v2

draws the full set from the v2 snapshot (research_log 5.19) into
results/figures/v2/, after run_check.py --snapshot v2 (default and
--text-source ghsa). The paper folders are not touched.
"""

from __future__ import annotations

import json
import math
from collections import Counter
from datetime import datetime
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import FixedLocator, NullLocator  # noqa: E402

from src.data.incident_clients import (  # noqa: E402
    GHSA_BOILERPLATE_ALIASES,
    GHSA_BOILERPLATE_MARKER,
    UNATTRIBUTED_MARKER,
    extract_reporters,
)
from src.labeling.malware_labeler import label_batch  # noqa: E402
from src.statistics.h1_pilot_analysis import (  # noqa: E402
    add_reporter_covariates,
    attach_grammar_labels,
    collapse_to_campaign_level,
)
from src.statistics.power_analysis import logistic_regression_power  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT = ROOT / "data" / "frozen" / "incidents_snapshot.jsonl"
RESULTS = ROOT / "results"
OUT_MAIN = ROOT / "paper" / "figures"
OUT_DIB = ROOT / "paper_dib" / "figures"

# Validated categorical slots (dataviz reference palette, light surface).
NPM = "#2a78d6"
PYPI = "#eb6834"
ACCENT = "#e34948"
INK = "#0b0b0b"
INK_2 = "#52514e"
MUTED = "#8a8985"
GRID = "#e4e3df"
ECO_COLOR = {"npm": NPM, "pypi": PYPI}
ECO_LABEL = {"npm": "npm", "pypi": "PyPI"}

COL_W = 3.5    # IEEE column width, inches
FULL_W = 7.16  # IEEE text width
DIB_TEXT_W = 5.5  # elsarticle preprint, 12pt, text width
DIB_SCALE = 1.45  # included width / drawn width

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Times", "STIXGeneral", "DejaVu Serif"],
    "mathtext.fontset": "stix",
    "font.size": 8,
    "axes.titlesize": 8,
    "axes.labelsize": 8,
    "xtick.labelsize": 7,
    "ytick.labelsize": 7,
    "legend.fontsize": 7,
    "axes.edgecolor": MUTED,
    "axes.labelcolor": INK,
    "axes.linewidth": 0.6,
    "xtick.color": INK_2,
    "ytick.color": INK_2,
    "xtick.major.width": 0.6,
    "ytick.major.width": 0.6,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "legend.frameon": False,
    "pdf.fonttype": 42,  # TrueType, not Type 3 (IEEE PDF eXpress)
    "ps.fonttype": 42,
    "savefig.bbox": "tight",
    "savefig.pad_inches": 0.02,
})


# --------------------------------------------------------------------------
# Data
# --------------------------------------------------------------------------

def wilson(k: int, n: int, z: float = 1.959964) -> tuple[float, float]:
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (c - h, c + h)


def load(snapshot: Path = SNAPSHOT):
    with open(snapshot, encoding="utf-8") as f:
        records = [json.loads(line) for line in f if line.strip()]
    joined = attach_grammar_labels(label_batch(records))
    campaigns = add_reporter_covariates(collapse_to_campaign_level(joined))
    return records, joined, campaigns


def package_categories(joined: list[dict]) -> dict[tuple[str, str], set[str]]:
    """Union of matched mechanism categories over a package's GHSA and OSV
    records (the 'any' text setting)."""
    out: dict[tuple[str, str], set[str]] = {}
    for r in joined:
        cats = r["malware_label"].get("matched_categories") or []
        out.setdefault((r["ecosystem"], r["package_name"]), set()).update(
            c.value if hasattr(c, "value") else str(c) for c in cats)
    return out


def package_reporters(records: list[dict]) -> dict[tuple[str, str], set[str]]:
    out: dict[tuple[str, str], set[str]] = {}
    for r in records:
        reps = {GHSA_BOILERPLATE_MARKER if x in GHSA_BOILERPLATE_ALIASES else x
                for x in extract_reporters(r.get("description", ""))}
        out.setdefault((r["ecosystem"], r["package_name"]), set()).update(reps)
    return out


def save(fig, name: str, *dirs: Path) -> None:
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
        fig.savefig(d / f"{name}.pdf")
    plt.close(fig)


def hgrid(ax):
    ax.grid(axis="x", color=GRID, linewidth=0.5)
    ax.set_axisbelow(True)


def vgrid(ax):
    ax.grid(axis="y", color=GRID, linewidth=0.5)
    ax.set_axisbelow(True)


# --------------------------------------------------------------------------
# Figures
# --------------------------------------------------------------------------

def fig_units(records, campaigns, width: float, height: float = 3.6):
    """(a) records -> packages -> campaigns by ecosystem; (b) campaign sizes."""
    counts = {}
    for eco in ("npm", "pypi"):
        recs = [r for r in records if r["ecosystem"] == eco]
        counts[eco] = (
            len(recs),
            len({r["package_name"] for r in recs}),
            sum(1 for c in campaigns if c["ecosystem"] == eco),
        )
    stages = ["Advisory records", "Packages", "Campaigns"]

    fig, (a, b) = plt.subplots(2, 1, figsize=(width, height),
                               gridspec_kw={"height_ratios": [1, 1.35], "hspace": 0.75})
    y = list(range(len(stages)))[::-1]
    for i, stage in enumerate(stages):
        left = 0
        for eco in ("pypi", "npm"):
            v = counts[eco][i]
            a.barh(y[i], v, left=left, height=0.62, color=ECO_COLOR[eco],
                   edgecolor="white", linewidth=1.0)
            if v >= 15:
                a.text(left + v / 2, y[i], str(v), ha="center", va="center",
                       color="white", fontsize=7, fontweight="bold")
            left += v
        a.text(left + 6, y[i], f"{left}", ha="left", va="center", color=INK, fontsize=7.5)
    a.set_yticks(y, stages)
    a.set_xlim(0, 440 if counts['npm'][0] + counts['pypi'][0] <= 401 else
               1.12 * (counts['npm'][0] + counts['pypi'][0]))
    a.set_xlabel("Count")
    a.tick_params(axis="y", length=0)
    hgrid(a)
    a.set_title("(a) Units of analysis after the two-stage collapse", loc="left")
    a.legend(handles=[plt.Rectangle((0, 0), 1, 1, color=ECO_COLOR[e]) for e in ("pypi", "npm")],
             labels=["PyPI", "npm"], loc="lower right", ncol=2)

    ranked = sorted(campaigns, key=lambda c: (-c["_member_count"], c["ecosystem"]))
    sizes = [c["_member_count"] for c in ranked]
    xs = range(1, len(ranked) + 1)
    b.bar(xs, sizes, width=0.8, color=[ECO_COLOR[c["ecosystem"]] for c in ranked], linewidth=0)
    for i, c in enumerate(ranked[:2]):
        b.text(i + 1.9, sizes[i], str(sizes[i]), ha="left", va="center", fontsize=6.5, color=INK)
    singles = sum(1 for s in sizes if s == 1)
    b.annotate(f"{singles} single-package campaigns", xy=(len(sizes) - singles / 2, 1),
               xytext=(len(sizes) - singles / 2, 14), ha="center", fontsize=7, color=INK_2,
               arrowprops={"arrowstyle": "-", "color": MUTED, "linewidth": 0.6})
    b.set_xlim(0, len(sizes) + 1)
    b.set_ylim(0, max(sizes) * 1.08)
    b.set_xlabel("Campaigns, ranked by size")
    b.set_ylabel("Member packages")
    vgrid(b)
    b.set_title("(b) Packages per campaign", loc="left")
    return fig


def fig_forest(width: float, main_json: Path = RESULTS / "power_campaign_level.json",
               ghsa_json: Path = RESULTS / "power_campaign_level__text-ghsa__group-any.json"):
    """Grammar OR across specifications (left) and reporter terms (right)."""
    d = json.load(open(main_json))
    g = json.load(open(ghsa_json))
    s56, rep = d["section_5_6"], d["reporters_d2"]

    def fisher(r):
        return (r["odds_ratio"], *r["odds_ratio_ci_95"])

    def cmh(r):
        return (r["common_odds_ratio"], *r["common_odds_ratio_ci_95"])

    def term(model, name):
        t = model["terms"][name]
        return (t["odds_ratio"], t["or_ci_low"], t["or_ci_high"])

    sens = rep["logit_sensitivity"]
    grammar_rows = [
        ("Pooled, Fisher", fisher(s56["pooled"]), "main"),
        (f"npm, Fisher (n = {s56['by_ecosystem']['npm']['n_total']})", fisher(s56["by_ecosystem"]["npm"]), "main"),
        (f"PyPI, Fisher (n = {s56['by_ecosystem']['pypi']['n_total']})", fisher(s56["by_ecosystem"]["pypi"]), "main"),
        ("CMH by ecosystem", cmh(s56["cmh"]), "main"),
        ("CMH by eco. × reporter count", cmh(rep["cmh"]["ecosystem_x_n_reporters"]["result"]), "main"),
        ("Logit (d)", term(rep["logit"], "grammar_flag"), "main"),
        ("Logit (a)", term(sens["a_drop_amazon"], "grammar_flag"), "main"),
        ("Logit (b)", term(sens["b_drop_n_reporters"], "grammar_flag"), "main"),
        ("Logit (c)", term(sens["c_a_plus_boilerplate_kam193"], "grammar_flag"), "main"),
        ("GHSA text only, Fisher", fisher(g["section_5_6"]["pooled"]), "sens"),
    ]
    reporter_rows = [
        ("Logit (d): reporter count", term(rep["logit"], "n_reporters")),
        ("Logit (d): Amazon Inspector", term(rep["logit"], "has_amazon_inspector")),
        ("Logit (a): reporter count", term(sens["a_drop_amazon"], "n_reporters")),
        ("Logit (b): Amazon Inspector", term(sens["b_drop_n_reporters"], "has_amazon_inspector")),
        ("Logit (c): reporter count", term(sens["c_a_plus_boilerplate_kam193"], "n_reporters")),
        ("Logit (c): boilerplate", term(sens["c_a_plus_boilerplate_kam193"], "has_boilerplate")),
        ("Logit (c): kam193", term(sens["c_a_plus_boilerplate_kam193"], "has_kam193")),
    ]

    fig, (a, b) = plt.subplots(1, 2, figsize=(width, 2.9),
                               gridspec_kw={"width_ratios": [1, 1], "wspace": 1.45})
    ticks = [0.1, 0.2, 0.5, 1, 2, 5, 10, 20, 50]

    def draw(ax, rows, color_of, xlim, title):
        n = len(rows)
        for i, row in enumerate(rows):
            label, (est, lo, hi) = row[0], row[1]
            yy = n - 1 - i
            col = color_of(row)
            lo_c, hi_c = max(lo, xlim[0]), min(hi, xlim[1])
            ax.plot([lo_c, hi_c], [yy, yy], color=col, linewidth=1.4, solid_capstyle="round")
            if hi > xlim[1]:
                ax.annotate("", xy=(xlim[1], yy), xytext=(xlim[1] / 1.25, yy),
                            arrowprops={"arrowstyle": "-|>", "color": col, "linewidth": 1.0,
                                        "mutation_scale": 6})
            ax.plot(est, yy, "o", color=col, markersize=4.5, markeredgecolor="white",
                    markeredgewidth=0.8, zorder=3)
            ax.text(xlim[1] * 1.15, yy, f"{est:.2f} [{lo:.2f}, {hi:.2f}]",
                    va="center", ha="left", fontsize=6.3, color=INK_2, clip_on=False)
        ax.axvline(1, color=INK_2, linewidth=0.7, linestyle=(0, (3, 2)), zorder=1)
        ax.set_xscale("log")
        ax.set_xlim(*xlim)
        ax.xaxis.set_major_locator(FixedLocator([t for t in ticks if xlim[0] <= t <= xlim[1]]))
        ax.xaxis.set_minor_locator(NullLocator())
        ax.xaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:g}"))
        ax.set_yticks(range(n), [r[0] for r in rows][::-1])
        ax.set_ylim(-0.7, n - 0.3)
        ax.tick_params(axis="y", length=0)
        ax.set_xlabel("Odds ratio, 95% CI (log scale)")
        hgrid(ax)
        ax.set_title(title, loc="left")

    draw(a, grammar_rows, lambda r: ACCENT if r[2] == "sens" else NPM, (0.2, 20),
         "(a) Grammar flag → described mechanism")
    a.axhline(0.5, color=GRID, linewidth=0.8)
    draw(b, reporter_rows, lambda r: INK_2, (0.02, 50), "(b) Reporter terms in the same models")
    return fig


def fig_dv_by_reporter(campaigns, width: float, row_h: float = 0.19, compact: bool = False):
    """DV rate (Wilson CI) by naming flag vs reporter-coverage splits.
    compact=True drops the group header rows and prefixes each row label
    with its (short) group name instead."""
    def rate(sel):
        k = sum(1 for c in sel if c["malware_label"]["malware_payload_present_candidate"])
        return k, len(sel)

    flagged = lambda c: c["grammar_match"]["is_grammar_flagged"]  # noqa: E731
    groups = [
        ("Naming grammar", [
            ("Flagged", [c for c in campaigns if flagged(c)]),
            ("Not flagged", [c for c in campaigns if not flagged(c)]),
        ]),
        ("Amazon Inspector", [
            ("Covered", [c for c in campaigns if c["has_amazon_inspector"]]),
            ("Not covered", [c for c in campaigns if not c["has_amazon_inspector"]]),
        ]),
        ("Reporter count", [
            ("2 or more", [c for c in campaigns if c["n_reporters"] >= 2]),
            ("1", [c for c in campaigns if c["n_reporters"] == 1]),
        ]),
        ("GHSA boilerplate", [
            ("Absent", [c for c in campaigns if not c["has_boilerplate"]]),
            ("Among reporters", [c for c in campaigns if c["has_boilerplate"]]),
            ("Sole reporter", [c for c in campaigns if c["has_boilerplate"] and c["n_reporters"] == 1]),
        ]),
    ]
    short = {"Naming grammar": "Grammar", "Amazon Inspector": "Amazon Insp.",
             "Reporter count": "Reporters", "GHSA boilerplate": "Boilerplate"}
    gap = 0.45
    n_rows = (sum(len(r) for _, r in groups) + gap * (len(groups) - 1) if compact
              else sum(len(r) + 1 for _, r in groups))
    fig, ax = plt.subplots(figsize=(width, row_h * n_rows + 0.55))
    yy, yticks, ylabels = 0, [], []
    for gi, (gname, rows) in enumerate(groups):
        col = NPM if gi == 0 else INK_2
        if compact:
            yy += gap if gi else 0
        else:
            yticks.append(-yy)
            ylabels.append(gname)
            yy += 1
        for label, sel in rows:
            if compact:
                label = f"{short[gname]}: {label.lower() if label != '1' else '1'}"
            k, n = rate(sel)
            lo, hi = wilson(k, n)
            ax.plot([lo, hi], [-yy, -yy], color=col, linewidth=1.4, solid_capstyle="round")
            ax.plot(k / n, -yy, "o", color=col, markersize=4.5, markeredgecolor="white",
                    markeredgewidth=0.8, zorder=3, clip_on=False)
            ax.text(1.02, -yy, f"{k}/{n}", va="center", ha="left", fontsize=6.5, color=INK_2,
                    transform=ax.get_yaxis_transform())
            yticks.append(-yy)
            ylabels.append(label)
            yy += 1
    ax.set_yticks(yticks, ylabels)
    headers = {g for g, _ in groups}
    for t in ax.get_yticklabels():
        if t.get_text() in headers:
            t.set_fontweight("bold")
            t.set_color(INK)
    ax.tick_params(axis="y", length=0, pad=2)
    ax.set_ylim(-(yy - 0.4), 0.6)
    ax.set_xlim(0, 1)
    ax.xaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0, decimals=0))
    ax.set_xlabel("Campaigns with a described mechanism (Wilson 95% CI)")
    hgrid(ax)
    return fig


def fig_grammar(campaigns, width: float):
    gv = json.load(open(RESULTS / "grammar_validation.json"))["sets"]
    rows = []
    for (key, sub), label in ((("hallucinated", "all"), "LLM-hallucinated names"),
                              (("benign_top5000", "pypi"), "Benign top-5,000 PyPI"),
                              (("benign_top5000", "npm"), "Benign top-5,000 npm")):
        s = gv[key][sub]
        rows.append((label, s["flag_count"], s["n"]))
    k = sum(1 for c in campaigns if c["grammar_match"]["is_grammar_flagged"])
    rows.append(("Malware campaigns", k, len(campaigns)))

    fig, ax = plt.subplots(figsize=(width, 1.55))
    n = len(rows)
    for i, (label, k, nn) in enumerate(rows):
        yy = n - 1 - i
        lo, hi = wilson(k, nn)
        col = ACCENT if i == 0 else (NPM if i == n - 1 else INK_2)
        ax.plot([lo, hi], [yy, yy], color=col, linewidth=1.4, solid_capstyle="round")
        ax.plot(k / nn, yy, "o", color=col, markersize=4.5, markeredgecolor="white",
                markeredgewidth=0.8, zorder=3)
        ax.text(1.02, yy, f"{k:,}/{nn:,}", va="center", ha="left", transform=ax.get_yaxis_transform(),
                fontsize=6.5, color=INK_2)
    ax.set_yticks(range(n), [r[0] for r in rows][::-1])
    ax.tick_params(axis="y", length=0)
    ax.set_xlim(0, 0.4)
    ax.set_ylim(-0.6, n - 0.4)
    ax.xaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0, decimals=0))
    ax.set_xticks([0, 0.1, 0.2, 0.3, 0.4])
    ax.set_xlabel("Names flagged by the naming grammar (Wilson 95% CI)")
    hgrid(ax)
    return fig


def fig_power(width: float, main_json: Path = RESULTS / "power_campaign_level.json"):
    d = json.load(open(main_json))["power"]["pooled"]
    p0, prev, n_now = d["p_control"], d["exposure_prevalence"], d["n"]

    def power(n, or_):
        denom = p0 * (1 - p0) * prev * (1 - prev) * math.log(or_) ** 2
        from scipy.stats import norm
        return norm.cdf(math.sqrt(n * denom) - norm.ppf(0.975))

    fig, ax = plt.subplots(figsize=(width, 2.1))
    ns = list(range(10, 701, 5))
    styles = [(1.5, MUTED, (0, (1, 1.5)), 560, -0.07), (2.0, NPM, "solid", 255, -0.09),
              (3.0, PYPI, (0, (4, 1.5)), 195, 0.0)]
    for or_, col, ls, lx, dy in styles:
        ys = [power(n, or_) for n in ns]
        ax.plot(ns, ys, color=col, linewidth=1.6, linestyle=ls)
        ax.text(lx, power(lx, or_) + dy, f"OR {or_:g}", va="top", ha="left", fontsize=7, color=INK)
    ax.axhline(0.8, color=INK_2, linewidth=0.7, linestyle=(0, (3, 2)))
    ax.text(12, 0.815, "80% power", fontsize=6.5, color=INK_2, va="bottom")
    ax.axvline(n_now, color=INK_2, linewidth=0.7)
    ax.text(n_now + 6, 0.02, f"this study, n = {n_now}", fontsize=6.5, color=INK_2, va="bottom")
    for or_, col, *_ in styles[1:]:
        pw = power(n_now, or_)
        ax.plot(n_now, pw, "o", color=col, markersize=4.5, markeredgecolor="white",
                markeredgewidth=0.8, zorder=4)
        ax.text(n_now - 8, pw, f"{pw:.2f}", ha="right", va="center", fontsize=6.5, color=INK)
    n_req = logistic_regression_power(p_control=p0, odds_ratio_to_detect=2.0,
                                      exposure_prevalence=prev).n_total
    ax.plot(n_req, 0.8, "o", color=NPM, markersize=4.5, markeredgecolor="white",
            markeredgewidth=0.8, zorder=4)
    ax.annotate(f"n ≈ {n_req}", xy=(n_req, 0.8), xytext=(n_req + 25, 0.62), fontsize=6.5,
                color=INK, arrowprops={"arrowstyle": "-", "color": MUTED, "linewidth": 0.6})
    ax.set_xlim(0, 700)
    ax.set_ylim(0, 1)
    ax.set_xlabel("Independent campaigns")
    ax.set_ylabel("Power (α = 0.05)")
    vgrid(ax)
    return fig


def fig_timeline(records, width: float, start: datetime = datetime(2026, 9, 1)):
    """Records published per day by ecosystem, from `start`."""
    days: dict[str, Counter] = {"npm": Counter(), "pypi": Counter()}
    early = Counter()
    last = start
    for r in records:
        t = datetime.fromisoformat(r["published_at"].replace("Z", "+00:00")).replace(tzinfo=None)
        if t < start:
            early[r["ecosystem"]] += 1
            continue
        k = (t.date() - start.date()).days
        days[r["ecosystem"]][k] += 1
        last = max(last, t)
    span = (last.date() - start.date()).days + 1
    fig, ax = plt.subplots(figsize=(width, 2.0))
    bottom = [0] * span
    for eco in ("pypi", "npm"):
        vals = [days[eco][i] for i in range(span)]
        ax.bar(range(span), vals, bottom=bottom, width=0.8, color=ECO_COLOR[eco],
               edgecolor="white", linewidth=0.5, label=ECO_LABEL[eco])
        bottom = [b + v for b, v in zip(bottom, vals)]
    from datetime import timedelta
    step = 7 if span <= 40 else 14
    labels = {k: f"{(start + timedelta(days=k)).day} {(start + timedelta(days=k)):%b}"
              for k in range(0, span - 2, step)}
    ax.set_xticks(list(labels), list(labels.values()))
    ax.set_xlim(-0.8, span - 0.2)
    ax.set_ylabel("Records published per day")
    vgrid(ax)
    ax.legend(loc="upper left", ncol=2)
    n_early = sum(early.values())
    earliest = min(datetime.fromisoformat(r["published_at"].replace("Z", "+00:00")) for r in records)
    ax.text(0.01, 0.80,
            f"Not shown: {n_early} records published before {start.day} {start:%b %Y}\n"
            f"(PyPI {early['pypi']}, npm {early['npm']}; earliest {earliest.day} {earliest:%b %Y})",
            transform=ax.transAxes, ha="left", va="top", fontsize=6.5, color=INK_2)
    return fig


CATEGORY_LABEL = {
    "obfuscated_payload_execution": "Obfuscated payload execution",
    "hidden_install_hook": "Hidden install hook",
    "credential_or_wallet_exfiltration": "Credential / wallet exfiltration",
    "remote_backdoor_access": "Remote backdoor access",
    "remote_payload_retrieval": "Remote payload retrieval",
    "brand_impersonation_narrative": "Brand-impersonation narrative",
}


def fig_mechanisms(joined, campaigns, width: float):
    cats = package_categories(joined)
    per_eco = {"npm": Counter(), "pypi": Counter()}
    for c in campaigns:
        u = set()
        for name in c["_member_package_names"]:
            u |= cats.get((c["ecosystem"], name), set())
        per_eco[c["ecosystem"]].update(u)
    keys = sorted({k for e in per_eco.values() for k in e} | set(CATEGORY_LABEL),
                  key=lambda k: -(per_eco["npm"][k] + per_eco["pypi"][k]))
    keys = [k for k in keys if k in CATEGORY_LABEL or per_eco["npm"][k] + per_eco["pypi"][k]]
    n_c = {e: sum(1 for c in campaigns if c["ecosystem"] == e) for e in ("npm", "pypi")}
    fig, ax = plt.subplots(figsize=(width, 2.3))
    h = 0.36
    for i, k in enumerate(keys):
        yy = len(keys) - 1 - i
        for j, eco in enumerate(("pypi", "npm")):
            v = per_eco[eco][k]
            off = h / 2 + 0.02 if j == 0 else -(h / 2 + 0.02)
            ax.barh(yy + off, v, height=h, color=ECO_COLOR[eco], linewidth=0,
                    label=f"{ECO_LABEL[eco]} ({n_c[eco]} campaigns)" if i == 0 else None)
            ax.text(v + 0.6, yy + off, str(v), va="center", fontsize=6.5, color=INK_2)
    ax.set_yticks(range(len(keys)), [CATEGORY_LABEL.get(k, k) for k in keys][::-1])
    ax.tick_params(axis="y", length=0)
    ax.set_xlabel("Campaigns whose advisory text describes the mechanism")
    hgrid(ax)
    ax.legend(loc="lower right")
    return fig, per_eco


def fig_reporters(records, width: float):
    reps = package_reporters(records)

    def combo(s):
        names = []
        if "kam193" in s:
            names.append("kam193")
        if "amazon-inspector" in s:
            names.append("Amazon Inspector")
        if GHSA_BOILERPLATE_MARKER in s:
            names.append("GHSA boilerplate")
        others = s - {"kam193", "amazon-inspector", GHSA_BOILERPLATE_MARKER, UNATTRIBUTED_MARKER}
        if others:
            names.append("other reporter")
        if UNATTRIBUTED_MARKER in s and not names:
            return "Unattributed only"
        if UNATTRIBUTED_MARKER in s:
            names.append("unattributed")
        return " + ".join(names) if names else "none"

    per_eco = {"npm": Counter(), "pypi": Counter()}
    for (eco, _), s in reps.items():
        per_eco[eco][combo(s)] += 1
    keys = sorted(set(per_eco["npm"]) | set(per_eco["pypi"]),
                  key=lambda k: -(per_eco["npm"][k] + per_eco["pypi"][k]))
    fig, ax = plt.subplots(figsize=(width, 0.32 * len(keys) + 0.7))
    for i, k in enumerate(keys):
        yy = len(keys) - 1 - i
        left = 0
        for eco in ("pypi", "npm"):
            v = per_eco[eco][k]
            ax.barh(yy, v, left=left, height=0.62, color=ECO_COLOR[eco], edgecolor="white",
                    linewidth=1.0, label=ECO_LABEL[eco] if i == 0 else None)
            if v >= 6:
                ax.text(left + v / 2, yy, str(v), ha="center", va="center", color="white",
                        fontsize=6.5, fontweight="bold")
            left += v
        ax.text(left + 1, yy, str(left), va="center", fontsize=6.5, color=INK)
    def wrap(k):
        head, sep, tail = k.rpartition(" + ")
        return f"{head}\n+ {tail}" if sep and len(k) > 30 else k

    ax.set_yticks(range(len(keys)), [wrap(k) for k in keys][::-1])
    ax.tick_params(axis="y", length=0)
    ax.set_xlabel("Packages (GHSA and OSV texts combined)")
    hgrid(ax)
    ax.legend(loc="lower right")
    return fig, per_eco


def main_v2(out: Path = RESULTS / "figures" / "v2") -> None:
    """Every figure from the v2 snapshot, at the analysis paper's sizes
    (column width; the forest plot full width)."""
    snap = ROOT / "data" / "frozen" / "incidents_snapshot_v2.jsonl"
    main_json = RESULTS / "power_campaign_level__v2.json"
    ghsa_json = RESULTS / "power_campaign_level__text-ghsa__group-any__v2.json"
    records, joined, campaigns = load(snap)
    print(f"v2: records={len(records)} campaigns={len(campaigns)}")
    first_ghsa = min(datetime.fromisoformat(r["published_at"].replace("Z", "+00:00")).replace(tzinfo=None)
                     for r in records if r["source"] == "ghsa")
    save(fig_units(records, campaigns, COL_W), "fig_units", out)
    save(fig_dv_by_reporter(campaigns, COL_W), "fig_dv_by_reporter", out)
    save(fig_grammar(campaigns, COL_W), "fig_grammar", out)
    save(fig_forest(FULL_W, main_json, ghsa_json), "fig_forest", out)
    save(fig_power(COL_W, main_json), "fig_power", out)
    save(fig_timeline(records, FULL_W, start=datetime(first_ghsa.year, first_ghsa.month, first_ghsa.day)),
         "fig_timeline", out)
    fig, mech = fig_mechanisms(joined, campaigns, COL_W * 1.3)
    save(fig, "fig_mechanisms", out)
    fig, rep_ = fig_reporters(records, COL_W * 1.4)
    save(fig, "fig_reporters", out)
    print(f"Written: {out}")


def main() -> None:
    records, joined, campaigns = load()
    print(f"records={len(records)} campaigns={len(campaigns)}")

    # Analysis paper: one column-width figure, compact for the 4-page body.
    save(fig_dv_by_reporter(campaigns, COL_W, row_h=0.15, compact=True), "fig_dv_by_reporter", OUT_MAIN)

    # Data in Brief: drawn at DIB_SCALE of the included width so that the
    # 7-8 pt figure text reads at about 10 pt next to the 12 pt body.
    dib = lambda frac: DIB_TEXT_W * frac / DIB_SCALE  # noqa: E731
    save(fig_timeline(records, dib(1.0)), "fig_timeline", OUT_DIB)
    save(fig_units(records, campaigns, dib(0.85)), "fig_units", OUT_DIB)
    fig, mech = fig_mechanisms(joined, campaigns, dib(0.9))
    save(fig, "fig_mechanisms", OUT_DIB)
    print("mechanisms:", {e: dict(v) for e, v in mech.items()})
    fig, rep = fig_reporters(records, dib(0.95))
    save(fig, "fig_reporters", OUT_DIB)
    print("reporter combos:", {e: dict(v) for e, v in rep.items()})
    save(fig_dv_by_reporter(campaigns, dib(0.8)), "fig_dv_by_reporter", OUT_DIB)
    save(fig_grammar(campaigns, dib(0.8)), "fig_grammar", OUT_DIB)
    print(f"Written: {OUT_MAIN}, {OUT_DIB}")


if __name__ == "__main__":
    import sys

    main_v2() if sys.argv[1:] == ["--snapshot", "v2"] else main()
