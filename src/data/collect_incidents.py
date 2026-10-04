"""
Confirmed-incident collection orchestration.

Pipeline: GHSA (bulk, paginated) -> candidate package list -> OSV
cross-check per package (checkpointed, since OSV is a per-package call and
can be interrupted mid-run same as registry_clients.py's fetches).

Output is two JSONL files:
    - {operation_name}_ghsa.jsonl   (raw GHSA records)
    - {operation_name}_osv.jsonl    (raw OSV records, keyed by GHSA candidates)
plus a deduplicated combined file and a manifest.

This intentionally mirrors collect_packages.py's structure (same
CheckpointManager/manifest pattern) so the two collectors are easy to
reason about side by side.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from src.data.incident_clients import (
    IncidentFetchConfig,
    deduplicate_incidents,
    fetch_ghsa_advisories,
    fetch_osv_advisories_for_package,
)
from src.utils.checkpointing import CheckpointManager
from src.utils.manifest import build_dataset_manifest


def collect_incidents(
    output_dir: Path,
    checkpoint_dir: Path,
    operation_name: str = "collect_incidents",
    ecosystems: tuple[str, ...] = ("pip", "npm"),
    max_ghsa_pages: int = 5,
    fetch_config: Optional[IncidentFetchConfig] = None,
    manifest_dir: Optional[Path] = None,
    cross_check_osv: bool = True,
) -> Path:
    """
    Synchronous entry point. Returns path to the deduplicated combined
    JSONL output.

    Set `cross_check_osv=False` for a fast first pass (GHSA only) if you
    just want to see candidate volume before committing to the slower
    per-package OSV cross-check.
    """
    config = fetch_config or IncidentFetchConfig()
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Fetching GHSA advisories for ecosystems={ecosystems} "
          f"(max {max_ghsa_pages} pages each)...")
    ghsa_records = fetch_ghsa_advisories(
        config, ecosystems=ecosystems, max_pages=max_ghsa_pages
    )
    print(f"  GHSA: {len(ghsa_records)} package-level advisory records")

    ghsa_path = output_dir / f"{operation_name}_ghsa.jsonl"
    with open(ghsa_path, "w") as f:
        for r in ghsa_records:
            f.write(json.dumps(r) + "\n")

    all_records = list(ghsa_records)

    if cross_check_osv and ghsa_records:
        candidates = {
            (r["package_name"], r["ecosystem"]) for r in ghsa_records
        }
        print(f"Cross-checking {len(candidates)} unique packages against OSV...")

        ckpt = CheckpointManager(checkpoint_dir, f"{operation_name}_osv")
        osv_path = output_dir / f"{operation_name}_osv.jsonl"
        osv_records: list[dict] = []

        with open(osv_path, "a") as out_f:
            for name, ecosystem in candidates:
                item_id = f"{ecosystem}:{name}"
                if ckpt.is_done(item_id):
                    continue
                recs = fetch_osv_advisories_for_package(name, ecosystem, config)
                for r in recs:
                    out_f.write(json.dumps(r) + "\n")
                    out_f.flush()
                osv_records.extend(recs)
                ckpt.mark_done(item_id)

        print(f"  OSV: {len(osv_records)} additional/corroborating records")
        all_records.extend(osv_records)

    deduped = deduplicate_incidents(all_records)
    print(f"After deduplication: {len(deduped)} unique incident records "
          f"(from {len(all_records)} raw)")

    combined_path = output_dir / f"{operation_name}_combined.jsonl"
    with open(combined_path, "w") as f:
        for r in deduped:
            f.write(json.dumps(r) + "\n")

    if manifest_dir is not None:
        manifest = build_dataset_manifest(
            dataset_name=f"{operation_name}_combined",
            source="GHSA (api.github.com/advisories) + OSV.dev",
            source_version="live",
            data_file=combined_path,
            record_count=len(deduped),
            license_="not specified (see GHSA/OSV terms of use)",
            data_generating_process="real_world_observed",
            preprocessing_version="v0",
            extra={
                "ecosystems": list(ecosystems),
                "n_ghsa_raw": len(ghsa_records),
                "n_after_dedup": len(deduped),
                "osv_cross_checked": cross_check_osv,
            },
        )
        manifest_path = manifest.save(manifest_dir)
        print(f"Manifest written: {manifest_path}")

    return combined_path
