"""
Package collection orchestration.

This is the piece that didn't exist in the original notebook as reusable
infrastructure — the notebook's Cell 11 checkpointing was a bespoke
JSON-dict-per-operation pattern, duplicated with small variations across
Cells 11, 19, 23, 25b. This module unifies all of that onto the Phase 0
`CheckpointManager` (one mechanism, one ledger format, project-wide),
while reusing the actual tested fetch logic from registry_clients.py
unchanged.

What this produces
-------------------
A checkpointed, resumable collection run over a list of (name, ecosystem)
pairs, writing:
    - one JSONL record per successfully-fetched artifact (unified schema
      from registry_clients.py, PLUS a `grammar_match` block from
      naming_grammar.py computed at write time)
    - a dataset manifest (Phase 0's manifest.py) once the run completes

This module does NOT decide which names to collect — that's the caller's
job (seed_lists.py for the control sample; a separate incident-corpus
loader, not yet built, for confirmed-malicious names). Keeping collection
mechanics separate from name-source selection means the same resumable
pipeline serves both the control sample and, later, the incident corpus.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from src.data.naming_grammar import classify_naming_grammar
from src.data.registry_clients import RegistryFetchConfig, fetch_metadata
from src.utils.checkpointing import CheckpointManager
from src.utils.manifest import build_dataset_manifest

try:
    import aiohttp
except ImportError:  # pragma: no cover
    aiohttp = None  # type: ignore[assignment]


@dataclass
class CollectionTarget:
    name: str
    ecosystem: str  # 'pypi' | 'npm'


def _item_id(target: CollectionTarget) -> str:
    return f"{target.ecosystem}:{target.name}"


def _output_path(output_dir: Path, operation_name: str) -> Path:
    return output_dir / f"{operation_name}.jsonl"


async def _collect_async(
    targets: list[CollectionTarget],
    output_dir: Path,
    operation_name: str,
    checkpoint_dir: Path,
    fetch_config: RegistryFetchConfig,
    progress_every: int = 200,
) -> tuple[int, int]:
    """
    Core async collection loop. Resumable: on rerun with the same
    `checkpoint_dir`/`operation_name`, already-completed targets are
    skipped and NOT re-appended to the output file (append-only output +
    checkpoint ledger must stay in sync — see note in mark_done below).
    """
    ckpt = CheckpointManager(checkpoint_dir, operation_name)
    out_path = _output_path(output_dir, operation_name)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    remaining = [t for t in targets if not ckpt.is_done(_item_id(t))]
    already_done = len(targets) - len(remaining)
    newly_processed = 0

    connector = aiohttp.TCPConnector(limit=fetch_config.concurrency_limit)
    async with aiohttp.ClientSession(connector=connector) as session:
        # Open in append mode: since we've already filtered out completed
        # items above, every write here is for a genuinely new record —
        # no risk of duplicating a prior run's output.
        with open(out_path, "a") as out_f:
            for target in remaining:
                record = await fetch_metadata(
                    session, target.name, target.ecosystem, fetch_config
                )
                grammar = classify_naming_grammar(target.name)
                record["grammar_match"] = grammar.to_dict()

                out_f.write(json.dumps(record) + "\n")
                out_f.flush()  # ensure the record is durable before we mark
                # the checkpoint done, so a crash between write and mark
                # can only ever cause a harmless re-fetch, never data loss.

                ckpt.mark_done(_item_id(target))
                newly_processed += 1

                if newly_processed % progress_every == 0:
                    print(
                        f"  progress: {newly_processed}/{len(remaining)} "
                        f"new ({already_done} already done from prior run)"
                    )

    return newly_processed, already_done


def collect_packages(
    targets: list[CollectionTarget],
    output_dir: Path,
    checkpoint_dir: Path,
    operation_name: str = "collect_packages",
    fetch_config: Optional[RegistryFetchConfig] = None,
    manifest_dir: Optional[Path] = None,
    dataset_name: str = "package_collection",
    data_generating_process: str = "real_world_observed",
    license_: str = "not specified",
) -> Path:
    """
    Synchronous entry point (wraps the async loop) — this is what
    notebooks/scripts should call. Matches the calling convention of the
    original notebook's `asyncio.run(fetch_all(...))` cells.

    Returns the path to the output JSONL file. If `manifest_dir` is given,
    also writes a dataset manifest there (Phase 0 requirement: every
    dataset write gets a manifest).
    """
    config = fetch_config or RegistryFetchConfig()
    newly, already = asyncio.run(
        _collect_async(
            targets, output_dir, operation_name, checkpoint_dir, config
        )
    )
    out_path = _output_path(output_dir, operation_name)

    print(
        f"Collection complete: {newly} newly fetched, {already} resumed "
        f"from checkpoint. Output: {out_path}"
    )

    if manifest_dir is not None and out_path.exists():
        record_count = sum(1 for _ in open(out_path))
        manifest = build_dataset_manifest(
            dataset_name=dataset_name,
            source="pypi+npm registries (see registry_clients.py)",
            source_version="live",
            data_file=out_path,
            record_count=record_count,
            license_=license_,
            data_generating_process=data_generating_process,
            preprocessing_version="v0",
            extra={
                "operation_name": operation_name,
                "n_targets_requested": len(targets),
                "n_newly_fetched_this_run": newly,
                "n_resumed_from_checkpoint": already,
            },
        )
        manifest_path = manifest.save(manifest_dir)
        print(f"Manifest written: {manifest_path}")

    return out_path


def targets_from_names(names: list[str], ecosystem: str) -> list[CollectionTarget]:
    """Convenience: wrap a flat name list (e.g., from seed_lists.py) into
    CollectionTarget objects for a single ecosystem."""
    return [CollectionTarget(name=n, ecosystem=ecosystem) for n in names]
