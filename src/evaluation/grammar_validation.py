"""
IV validation (review.md A1 / B2 / D3): how often does the naming grammar
flag real LLM-hallucinated package names, popular benign names, and the
malware campaigns of the H1 analysis?

Run from the project root:
    python -m src.evaluation.grammar_validation            # offline after first run
    python -m src.evaluation.grammar_validation --refresh  # re-fetch benign lists

Sets
----
- hallucinated: data/external/hallucinated_names.txt (ecosystem, name,
  count; tab-separated). Provenance in hallucinated_names_SOURCES.md.
- benign_top5000: top-5000 PyPI (hugovk top-pypi-packages) and top-5000 npm
  (npm-high-impact, download-ranked) names, via src/data/seed_lists.py.
- benign_npm_search_api (sensitivity only): fetch_seed_npm_names(), the
  original notebook's npm control source. It is selected by search terms
  that are themselves grammar tokens, so its flag rate is biased upward.
- malware_campaigns: the 142 campaigns of Section 5.6 (default collapse of
  the frozen snapshot). A campaign is flagged if any member name is
  flagged, as in collapse_to_campaign_level().

Benign lists are cached to data/external/ with a manifest in data/metadata/
on first fetch; later runs read the cache and need no network.

Output: results/grammar_validation.json with, per set and per ecosystem,
n, flag count, flag rate, pattern_type distribution and the top-15
flagging tokens (counted once per unit). naming_grammar.py is used as is.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Callable

from src.data.naming_grammar import classify_naming_grammar

ROOT = Path(__file__).resolve().parents[2]
EXTERNAL_DIR = ROOT / "data" / "external"
METADATA_DIR = ROOT / "data" / "metadata"
HALLUCINATED_PATH = EXTERNAL_DIR / "hallucinated_names.txt"
SNAPSHOT_PATH = ROOT / "data" / "frozen" / "incidents_snapshot.jsonl"
OUT_PATH = ROOT / "results" / "grammar_validation.json"

TOP_N = 5000
TOP_TOKENS = 15
ECOSYSTEMS = ("pypi", "npm")
PATTERN_TYPES = ("none", "compound", "trend", "both")


# --- Loading -----------------------------------------------------------------

def load_hallucinated(path: Path = HALLUCINATED_PATH) -> list[dict]:
    """Rows of `ecosystem<TAB>name<TAB>count`; blank lines skipped."""
    rows = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 3:
            raise ValueError(f"{path}:{lineno}: expected 3 tab-separated fields, got {len(parts)}")
        ecosystem, name, count = parts
        rows.append({"ecosystem": ecosystem.strip().lower(), "name": name.strip(), "count": int(count)})
    return rows


def load_or_fetch_names(
    cache_path: Path,
    fetcher: Callable[[], list[str]],
    source: str,
    source_version: str,
    refresh: bool = False,
    metadata_dir: Path | None = METADATA_DIR,
) -> list[str]:
    """Names from `cache_path` (one per line) if it exists and not
    `refresh`; otherwise calls `fetcher()`, writes the cache and, if
    `metadata_dir` is set, a dataset manifest next to the other manifests."""
    if cache_path.exists() and not refresh:
        return [l for l in cache_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    names = fetcher()
    if not names:
        raise RuntimeError(f"fetch for {cache_path.name} returned no names")
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text("\n".join(names) + "\n", encoding="utf-8")
    if metadata_dir is not None:
        from src.utils.manifest import build_dataset_manifest

        build_dataset_manifest(
            dataset_name=cache_path.stem,
            source=source,
            source_version=source_version,
            data_file=cache_path,
            record_count=len(names),
            license_="not specified",
            data_generating_process="real_world_observed",
            extra={"role": "benign comparison set for grammar validation (review.md D3)"},
        ).save(metadata_dir)
    return names


def benign_sources(top_n: int = TOP_N) -> dict[str, dict]:
    """Cache file name, fetcher and provenance for each benign list."""
    from src.data import seed_lists

    return {
        "pypi": {
            "cache": f"benign_top{top_n}_pypi.txt",
            "fetcher": lambda: seed_lists.fetch_seed_pypi_names(top_n),
            "source": seed_lists.TOP_PYPI_URL,
            "source_version": "latest at fetch time (see download_timestamp)",
        },
        "npm": {
            "cache": f"benign_top{top_n}_npm.txt",
            "fetcher": lambda: seed_lists.fetch_top_npm_names(top_n),
            "source": seed_lists.NPM_HIGH_IMPACT_URL,
            "source_version": f"npm-high-impact@{seed_lists.NPM_HIGH_IMPACT_VERSION}",
        },
        "npm_search_api": {
            "cache": "benign_npm_search_api.txt",
            "fetcher": lambda: sorted(seed_lists.fetch_seed_npm_names(top_n)),
            "source": "https://registry.npmjs.org/-/v1/search "
                      f"(terms: {', '.join(seed_lists.NPM_FALLBACK_SEARCH_TERMS)})",
            "source_version": "live search at fetch time; failed terms are skipped",
        },
    }


def load_malware_campaign_names(snapshot_path: Path = SNAPSHOT_PATH) -> list[dict]:
    """The 142 Section 5.6 campaigns as {ecosystem, names}, plus the
    pipeline's own campaign flag for a consistency check."""
    from src.labeling.malware_labeler import label_batch
    from src.statistics.h1_pilot_analysis import attach_grammar_labels, collapse_to_campaign_level

    with open(snapshot_path, encoding="utf-8") as f:
        records = [json.loads(line) for line in f if line.strip()]
    campaigns = collapse_to_campaign_level(attach_grammar_labels(label_batch(records)))
    return [
        {
            "ecosystem": c["ecosystem"],
            "names": c["_member_package_names"],
            "pipeline_flagged": c["grammar_match"]["is_grammar_flagged"],
        }
        for c in campaigns
    ]


# --- Classification and summary ----------------------------------------------

def classify_unit(names: list[str], ecosystem: str) -> dict:
    """One unit (a name, or a campaign's names). Flagged if any name is;
    pattern_type combines compound/trend across names; tokens are the
    distinct matched grammar tokens, in first-match order."""
    has_compound = has_trend = False
    tokens: dict[str, None] = {}
    for name in names:
        g = classify_naming_grammar(name)
        has_compound |= bool(g.matched_compound_prefixes or g.matched_compound_suffixes)
        has_trend |= bool(g.matched_trend_suffixes)
        for t in g.matched_compound_prefixes + g.matched_compound_suffixes + g.matched_trend_suffixes:
            tokens.setdefault(t, None)
    pattern_type = {(True, True): "both", (True, False): "compound",
                    (False, True): "trend", (False, False): "none"}[(has_compound, has_trend)]
    return {
        "ecosystem": ecosystem,
        "names": list(names),
        "flagged": has_compound or has_trend,
        "pattern_type": pattern_type,
        "tokens": list(tokens),
    }


def summarize_units(units: list[dict], top_tokens: int = TOP_TOKENS) -> dict:
    n = len(units)
    flagged = sum(u["flagged"] for u in units)
    patterns = Counter(u["pattern_type"] for u in units)
    tokens = Counter(t for u in units for t in u["tokens"])
    return {
        "n": n,
        "flag_count": flagged,
        "flag_rate": flagged / n if n else None,
        "pattern_type_distribution": {p: patterns.get(p, 0) for p in PATTERN_TYPES},
        "top_flagging_tokens": [[t, c] for t, c in tokens.most_common(top_tokens)],
    }


def summarize_by_ecosystem(units: list[dict]) -> dict:
    out = {"all": summarize_units(units)}
    for eco in sorted({u["ecosystem"] for u in units}):
        out[eco] = summarize_units([u for u in units if u["ecosystem"] == eco])
    return out


def build_report(
    hallucinated: list[dict],
    benign: dict[str, list[str]],
    malware_campaigns: list[dict],
    benign_sensitivity: dict[str, list[str]] | None = None,
) -> dict:
    """`benign` and `benign_sensitivity` map ecosystem -> names."""
    h_units = []
    for row in hallucinated:
        u = classify_unit([row["name"]], row["ecosystem"])
        h_units.append({**u, "count": row["count"]})
    b_units = [classify_unit([n], eco) for eco, names in benign.items() for n in names]
    m_units = [classify_unit(c["names"], c["ecosystem"]) for c in malware_campaigns]

    mismatched = [
        c["names"][:3] for c, u in zip(malware_campaigns, m_units)
        if "pipeline_flagged" in c and c["pipeline_flagged"] != u["flagged"]
    ]
    if mismatched:
        raise AssertionError(f"campaign flag differs from the H1 pipeline for {mismatched}")

    report = {
        "sets": {
            "hallucinated": summarize_by_ecosystem(h_units),
            "benign_top5000": summarize_by_ecosystem(b_units),
            "malware_campaigns": summarize_by_ecosystem(m_units),
        },
        "hallucinated_examples": {
            "flagged": [
                {k: u[k] for k in ("ecosystem", "count", "pattern_type", "tokens")} | {"name": u["names"][0]}
                for u in h_units if u["flagged"]
            ],
            "unflagged_top15_by_count": [
                {"ecosystem": u["ecosystem"], "name": u["names"][0], "count": u["count"]}
                for u in sorted((u for u in h_units if not u["flagged"]), key=lambda u: -u["count"])[:15]
            ],
        },
    }
    if benign_sensitivity:
        s_units = [classify_unit([n], eco) for eco, names in benign_sensitivity.items() for n in names]
        report["sets"]["benign_npm_search_api"] = summarize_by_ecosystem(s_units)
    return report


# --- CLI ---------------------------------------------------------------------

def _display_path(path: Path) -> str:
    return str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)


def main(argv=None) -> dict:
    ap = argparse.ArgumentParser(description="Naming-grammar validation (review.md D3)")
    ap.add_argument("--refresh", action="store_true", help="re-fetch benign lists and overwrite the caches")
    ap.add_argument("--out", type=Path, default=OUT_PATH)
    args = ap.parse_args(argv)

    sources = benign_sources()
    lists = {
        key: load_or_fetch_names(EXTERNAL_DIR / src["cache"], src["fetcher"], src["source"],
                                 src["source_version"], refresh=args.refresh)
        for key, src in sources.items()
    }
    report = build_report(
        hallucinated=load_hallucinated(),
        benign={"pypi": lists["pypi"], "npm": lists["npm"]},
        malware_campaigns=load_malware_campaign_names(),
        benign_sensitivity={"npm": lists["npm_search_api"]},
    )
    report["inputs"] = {
        "hallucinated": _display_path(HALLUCINATED_PATH),
        "snapshot": _display_path(SNAPSHOT_PATH),
        **{f"benign_{k}": {"cache": f"data/external/{s['cache']}", "source": s["source"],
                           "source_version": s["source_version"]} for k, s in sources.items()},
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(f"{'set':24s} {'eco':5s} {'n':>5} {'flagged':>8} {'rate':>7}")
    for set_name, by_eco in report["sets"].items():
        for eco, s in by_eco.items():
            print(f"{set_name:24s} {eco:5s} {s['n']:5d} {s['flag_count']:8d} {s['flag_rate']:7.3f}")
    print(f"Written: {args.out}")
    return report


if __name__ == "__main__":
    main()
