"""
Manifest generation for datasets and experiments.

Every dataset write and every experiment run produces a manifest. This is
the mechanism that makes claims like "what was available at time T"
auditable rather than asserted, and it's what a skeptical reviewer would
ask for if they doubted your temporal-leakage controls.

Two manifest types:
    - DatasetManifest: attached to any data/raw or data/processed artifact.
    - ExperimentManifest: attached to any model training/evaluation run.

Design choices
--------------
- SHA256 over Parquet/JSONL bytes, not over in-memory objects, so the
  checksum verifies the actual file a future run will read.
- Manifests are JSON, human-diffable, and committed to git (small; the
  data itself is not).
- We do NOT use pickle for anything that touches externally-sourced data,
  per the project's explicit safety requirement.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    """Stream-hash a file. Never loads the whole file into memory, since
    some collected corpora (cached embeddings, bulk metadata) may be large
    even though individual text records are small."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def git_commit_hash() -> str:
    """Returns the current git commit hash, or 'no-git-repo' if unavailable.
    Never raises — reproducibility metadata should degrade gracefully, not
    crash a run."""
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL
        )
        return out.decode().strip()
    except Exception:
        return "no-git-repo"


def installed_package_versions(packages: list[str]) -> dict[str, str]:
    """Best-effort version lookup for the named packages. Missing packages
    are recorded as 'not-installed' rather than silently omitted, so a
    manifest diff shows exactly what changed in the environment."""
    versions: dict[str, str] = {}
    for pkg in packages:
        try:
            from importlib.metadata import version

            versions[pkg] = version(pkg)
        except Exception:
            versions[pkg] = "not-installed"
    return versions


CORE_PACKAGES = [
    "pandas",
    "numpy",
    "scipy",
    "scikit-learn",
    "statsmodels",
    "lifelines",
    "torch",
    "transformers",
    "datasets",
    "pyarrow",
    "lightgbm",
]


@dataclass
class DatasetManifest:
    dataset_name: str
    source: str
    source_version: str
    download_timestamp: str
    record_count: int
    checksum: str
    preprocessing_version: str
    code_version: str
    random_seed: int | None
    license: str
    exclusions: list[str] = field(default_factory=list)
    missing_value_policy: str = "not specified"
    data_generating_process: str = "not specified"  # see Phase 0 audit §2:
    # 'real_world_observed' | 'red_team_synthetic' | 'red_team_wild_subset'
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, manifest_dir: Path) -> Path:
        manifest_dir.mkdir(parents=True, exist_ok=True)
        out_path = manifest_dir / f"{self.dataset_name}.manifest.json"
        with open(out_path, "w") as f:
            json.dump(self.to_dict(), f, indent=2, sort_keys=True)
        return out_path


def build_dataset_manifest(
    dataset_name: str,
    source: str,
    source_version: str,
    data_file: Path,
    record_count: int,
    license_: str,
    data_generating_process: str,
    preprocessing_version: str = "v0",
    random_seed: int | None = None,
    exclusions: list[str] | None = None,
    missing_value_policy: str = "not specified",
    extra: dict | None = None,
) -> DatasetManifest:
    """Convenience constructor that computes the checksum for you.
    ``data_file`` must already exist on disk (Parquet/JSONL, never pickle)."""
    if not data_file.exists():
        raise FileNotFoundError(
            f"Cannot build manifest for nonexistent file: {data_file}"
        )
    return DatasetManifest(
        dataset_name=dataset_name,
        source=source,
        source_version=source_version,
        download_timestamp=datetime.now(timezone.utc).isoformat(),
        record_count=record_count,
        checksum=sha256_file(data_file),
        preprocessing_version=preprocessing_version,
        code_version=git_commit_hash(),
        random_seed=random_seed,
        license=license_,
        exclusions=exclusions or [],
        missing_value_policy=missing_value_policy,
        data_generating_process=data_generating_process,
        extra=extra or {},
    )


@dataclass
class ExperimentManifest:
    experiment_id: str
    dataset_version: str
    dataset_hash: str
    config_hash: str
    git_commit: str
    random_seed: int
    model_name: str
    model_version: str
    python_version: str
    package_versions: dict[str, str]
    device: str
    timestamp: str
    training_params: dict[str, Any] = field(default_factory=dict)
    evaluation_params: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, experiment_dir: Path) -> Path:
        experiment_dir.mkdir(parents=True, exist_ok=True)
        out_path = experiment_dir / "manifest.json"
        with open(out_path, "w") as f:
            json.dump(self.to_dict(), f, indent=2, sort_keys=True)
        return out_path


def config_hash(config: dict) -> str:
    """Deterministic hash of a config dict, independent of key order."""
    canonical = json.dumps(config, sort_keys=True).encode()
    return hashlib.sha256(canonical).hexdigest()[:16]


def build_experiment_manifest(
    experiment_id: str,
    dataset_version: str,
    dataset_hash: str,
    config: dict,
    random_seed: int,
    model_name: str,
    model_version: str,
    device: str,
    training_params: dict | None = None,
    evaluation_params: dict | None = None,
) -> ExperimentManifest:
    return ExperimentManifest(
        experiment_id=experiment_id,
        dataset_version=dataset_version,
        dataset_hash=dataset_hash,
        config_hash=config_hash(config),
        git_commit=git_commit_hash(),
        random_seed=random_seed,
        model_name=model_name,
        model_version=model_version,
        python_version=sys.version.split()[0],
        package_versions=installed_package_versions(CORE_PACKAGES),
        device=device,
        timestamp=datetime.now(timezone.utc).isoformat(),
        training_params=training_params or {},
        evaluation_params=evaluation_params or {},
    )
