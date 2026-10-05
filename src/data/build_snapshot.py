"""
Build a new frozen incident snapshot (research_log 5.17).

    GITHUB_TOKEN=... python -m src.data.build_snapshot \
        --out data/frozen/incidents_snapshot_v2.jsonl --per-ecosystem 250

Fetches GHSA malware advisories newest first (Link-cursor pagination)
until each ecosystem has --per-ecosystem package-level GHSA records or the
API runs out, queries OSV for every package found, deduplicates with
deduplicate_incidents() exactly as for v1, and writes the snapshot plus a
manifest in data/metadata/. Refuses to overwrite an existing snapshot:
frozen files are never modified.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

from src.data.incident_clients import (
    IncidentFetchConfig,
    deduplicate_incidents,
    fetch_ghsa_advisories,
    fetch_osv_advisories_for_package,
)
from src.utils.manifest import build_dataset_manifest

ROOT = Path(__file__).resolve().parents[2]


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--per-ecosystem", type=int, default=250,
                    help="stop each ecosystem once it has this many GHSA package records")
    ap.add_argument("--max-pages", type=int, default=100)
    args = ap.parse_args(argv)

    out = args.out if args.out.is_absolute() else ROOT / args.out
    if out.exists():
        sys.exit(f"Refusing to overwrite existing snapshot {out}")
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        sys.exit("GITHUB_TOKEN is not set (unauthenticated GHSA limit is 60/hr).")

    config = IncidentFetchConfig(github_token=token, per_page=50, max_retries=6, request_delay_seconds=0.2)
    ghsa = fetch_ghsa_advisories(config, ecosystems=("pip", "npm"), max_pages=args.max_pages,
                                 max_records_per_ecosystem=args.per_ecosystem)
    print(f"GHSA: {len(ghsa)} package records  {dict(Counter(r['ecosystem'] for r in ghsa))}")

    candidates = sorted({(r["package_name"], r["ecosystem"]) for r in ghsa})
    osv: list[dict] = []
    for i, (name, eco) in enumerate(candidates, 1):
        osv.extend(fetch_osv_advisories_for_package(name, eco, config))
        if i % 100 == 0:
            print(f"  OSV {i}/{len(candidates)} packages, {len(osv)} records")
    print(f"OSV: {len(osv)} records for {len(candidates)} packages")

    records = deduplicate_incidents(ghsa + osv)
    print(f"After deduplication: {len(records)} records (from {len(ghsa) + len(osv)} raw)")

    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    published = sorted(r["published_at"] for r in records if r.get("published_at"))
    fetched = sorted(r["fetched_at"] for r in records)
    manifest = build_dataset_manifest(
        dataset_name=out.stem,
        source="GitHub Security Advisories REST API (api.github.com/advisories, type=malware, "
               "ecosystems pip/npm, Link-cursor pagination) + OSV.dev v1 query API (per-package)",
        source_version="live API pull; see extra.fetched_at_min/max",
        data_file=out,
        record_count=len(records),
        license_="GHSA records: CC-BY-4.0; OSV records: per upstream source "
                 "(OpenSSF malicious-packages: Apache-2.0)",
        data_generating_process="real_world_observed",
        preprocessing_version="v2-cursor",
        extra={
            "ecosystem_counts": dict(Counter(r["ecosystem"] for r in records)),
            "source_counts": dict(Counter(r["source"] for r in records)),
            "unique_packages": len({(r["ecosystem"], r["package_name"]) for r in records}),
            "ghsa_records_per_ecosystem_target": args.per_ecosystem,
            "n_ghsa_raw": len(ghsa),
            "n_osv_raw": len(osv),
            "published_at_min": published[0] if published else None,
            "published_at_max": published[-1] if published else None,
            "fetched_at_min": fetched[0],
            "fetched_at_max": fetched[-1],
        },
    )
    manifest_dir = ROOT / "data" / "metadata"
    path = manifest.save(manifest_dir)
    print(f"Written: {out}\nManifest: {path}")


if __name__ == "__main__":
    main()
