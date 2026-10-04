"""
Checkpointing for restart-safe long-running operations.

Purpose
-------
Kaggle sessions can disconnect mid-run. Every expensive operation (downloads,
feature extraction, embedding caching, training, inference, evaluation) must
be resumable: rerunning after a disconnect should pick up where it left off,
not restart from zero and not silently redo (and waste GPU-hours on)
already-completed work.

Mechanism
---------
A `CheckpointManager` tracks, per named operation, which item IDs have
completed successfully, using an atomically-written JSONL ledger. "Atomic"
here means: write to a temp file in the same directory, then os.replace()
into place, so a crash mid-write never leaves a corrupt ledger.

This is intentionally simple (no external job queue, no database) because
the operations in this project are batch-oriented and single-process.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Callable, Iterable, Iterator, TypeVar

T = TypeVar("T")


class CheckpointManager:
    def __init__(self, checkpoint_dir: Path, operation_name: str):
        self.checkpoint_dir = Path(checkpoint_dir)
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self.operation_name = operation_name
        self.ledger_path = self.checkpoint_dir / f"{operation_name}.ledger.jsonl"
        self._completed_ids: set[str] = self._load_completed()

    def _load_completed(self) -> set[str]:
        if not self.ledger_path.exists():
            return set()
        completed = set()
        with open(self.ledger_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    if record.get("status") == "done":
                        completed.add(record["item_id"])
                except json.JSONDecodeError:
                    # A truncated final line from a crash mid-write is
                    # expected and should not corrupt the whole ledger.
                    continue
        return completed

    def is_done(self, item_id: str) -> bool:
        return item_id in self._completed_ids

    def mark_done(self, item_id: str, extra: dict | None = None) -> None:
        """Append-only write. JSONL append is not fully atomic against a
        crash mid-line, which is why _load_completed() tolerates a
        truncated final line."""
        record = {"item_id": item_id, "status": "done"}
        if extra:
            record["extra"] = extra
        with open(self.ledger_path, "a") as f:
            f.write(json.dumps(record) + "\n")
        self._completed_ids.add(item_id)

    def remaining(self, all_ids: Iterable[str]) -> list[str]:
        return [i for i in all_ids if i not in self._completed_ids]

    def progress(self, total: int) -> tuple[int, int]:
        return len(self._completed_ids), total

    def reset(self) -> None:
        """Explicit, deliberate wipe. Never called implicitly — a resumed
        run should never silently lose completed work."""
        if self.ledger_path.exists():
            self.ledger_path.unlink()
        self._completed_ids = set()


def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write-to-temp-then-replace so a killed process never leaves a
    half-written file at `path`."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, prefix=".tmp_")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp_path, path)
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def checkpointed_map(
    items: list[T],
    item_id_fn: Callable[[T], str],
    process_fn: Callable[[T], dict],
    checkpoint_dir: Path,
    operation_name: str,
    on_result: Callable[[T, dict], None],
) -> tuple[int, int]:
    """
    Generic restart-safe batch processor.

    Parameters
    ----------
    items: full list of work items (e.g., package names to fetch metadata for)
    item_id_fn: extracts a stable string ID from an item
    process_fn: does the actual (expensive) work, returns a result dict
    checkpoint_dir / operation_name: where the ledger lives
    on_result: side effect for a freshly-computed result (e.g., append to
        an output Parquet buffer). NOT called for items already marked done
        in a prior run — the caller is responsible for having already
        persisted those results in a previous session.

    Returns
    -------
    (newly_processed_count, already_done_count)
    """
    ckpt = CheckpointManager(checkpoint_dir, operation_name)
    remaining_ids = {item_id_fn(it): it for it in items}
    already_done = 0
    newly_processed = 0

    for item_id, item in remaining_ids.items():
        if ckpt.is_done(item_id):
            already_done += 1
            continue
        result = process_fn(item)
        on_result(item, result)
        ckpt.mark_done(item_id)
        newly_processed += 1

    return newly_processed, already_done


def iter_with_checkpoint(
    items: Iterable[T],
    item_id_fn: Callable[[T], str],
    checkpoint_dir: Path,
    operation_name: str,
) -> Iterator[T]:
    """
    Lower-level generator variant: yields only the items NOT yet marked
    done, in original order, and leaves marking-done to the caller (useful
    when the caller needs to mark done only after also confirming a
    downstream write succeeded).

    Usage:
        ckpt = CheckpointManager(dir, "fetch_npm_metadata")
        for item in iter_with_checkpoint(items, id_fn, dir, "fetch_npm_metadata"):
            result = fetch(item)
            write_result(result)
            ckpt.mark_done(id_fn(item))
    """
    ckpt = CheckpointManager(checkpoint_dir, operation_name)
    for item in items:
        if not ckpt.is_done(item_id_fn(item)):
            yield item
