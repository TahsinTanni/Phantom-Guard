"""
Environment detection and path resolution.

Purpose
-------
Notebooks and scripts must never hardcode paths. Every module that reads or
writes data calls `get_paths()` and receives environment-correct locations.
This is what lets the same code run unmodified on Kaggle, on a local
MacBook, or (optionally) on Colab.

Design note
-----------
Data COLLECTION (crawling GHSA/OSV/npm/PyPI, which needs long-running,
resumable, rate-limited network access) is intentionally NOT assumed to run
on Kaggle. Kaggle sessions are ephemeral and have no persistent background
jobs. The collection environment produces versioned, checksummed Parquet
snapshots (see manifest.py) which are then attached to Kaggle as a Dataset
input. Kaggle code should treat data/raw as READ-ONLY input, never as a
place it writes fresh crawl results to.
"""

from __future__ import annotations

import os
import platform
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class EnvironmentPaths:
    """Resolved paths for the current execution environment."""

    env_name: str
    project_root: Path
    data_raw: Path
    data_interim: Path
    data_processed: Path
    data_external: Path
    data_metadata: Path
    experiments: Path
    results: Path
    reports: Path
    is_kaggle: bool = False
    is_colab: bool = False
    extra: dict = field(default_factory=dict)


def detect_environment() -> str:
    """
    Returns one of: 'kaggle', 'colab', 'local'.

    Detection is deliberately simple and inspects environment variables /
    filesystem markers rather than trying to be clever. If detection is
    ambiguous, it fails toward 'local' rather than silently guessing wrong,
    because a wrong guess here corrupts every downstream path.
    """
    if os.environ.get("KAGGLE_KERNEL_RUN_TYPE") is not None or Path("/kaggle").exists():
        return "kaggle"
    if "google.colab" in sys.modules or Path("/content").exists():
        return "colab"
    return "local"


def get_paths(
    project_root: Path | None = None, force_env: str | None = None
) -> EnvironmentPaths:
    """
    Resolve all data/experiment/results paths for the current environment.

    Parameters
    ----------
    project_root:
        Override for local development. Ignored on Kaggle (Kaggle paths are
        fixed by the platform) and on Colab if a Drive mount is detected.
    force_env:
        Explicit override for `detect_environment()`'s result — one of
        'kaggle', 'colab', 'local'. Exists ONLY for testing: filesystem-
        marker-based detection (e.g. `Path("/kaggle").exists()`) correctly
        identifies a genuine Kaggle host, which means a test asserting
        "local" path behavior fails when the test SUITE ITSELF happens to
        run inside a Kaggle container — not a bug in detection, but a gap
        in a test that assumed it would run somewhere non-Kaggle. Do not
        use `force_env` in production code paths; only in tests.

    On Kaggle:
        input datasets  -> /kaggle/input/<dataset-name>/...   (read-only)
        working/output  -> /kaggle/working/...                (read-write,
                            wiped between sessions unless committed as
                            output)
    """
    env = force_env if force_env is not None else detect_environment()

    if env == "kaggle":
        # /kaggle/input is read-only and dataset-name-specific; callers that
        # need the actual attached-dataset subdirectory should pass it via
        # config, not hardcode it here, since dataset slugs vary per run.
        kaggle_input = Path("/kaggle/input")
        kaggle_working = Path("/kaggle/working")
        return EnvironmentPaths(
            env_name="kaggle",
            project_root=kaggle_working,
            data_raw=kaggle_input,  # read-only, see docstring
            data_interim=kaggle_working / "data" / "interim",
            data_processed=kaggle_working / "data" / "processed",
            data_external=kaggle_input,
            data_metadata=kaggle_working / "data" / "metadata",
            experiments=kaggle_working / "experiments",
            results=kaggle_working / "results",
            reports=kaggle_working / "reports",
            is_kaggle=True,
        )

    if env == "colab":
        root = Path("/content/project")
        return EnvironmentPaths(
            env_name="colab",
            project_root=root,
            data_raw=root / "data" / "raw",
            data_interim=root / "data" / "interim",
            data_processed=root / "data" / "processed",
            data_external=root / "data" / "external",
            data_metadata=root / "data" / "metadata",
            experiments=root / "experiments",
            results=root / "results",
            reports=root / "reports",
            is_colab=True,
        )

    # local
    root = project_root or Path(__file__).resolve().parents[2]
    return EnvironmentPaths(
        env_name="local",
        project_root=root,
        data_raw=root / "data" / "raw",
        data_interim=root / "data" / "interim",
        data_processed=root / "data" / "processed",
        data_external=root / "data" / "external",
        data_metadata=root / "data" / "metadata",
        experiments=root / "experiments",
        results=root / "results",
        reports=root / "reports",
    )


def ensure_dirs(paths: EnvironmentPaths) -> None:
    """Create all writable directories if they don't exist. Never creates
    data_raw on Kaggle (read-only input)."""
    writable = [
        paths.data_interim,
        paths.data_processed,
        paths.data_metadata,
        paths.experiments,
        paths.results,
        paths.reports,
    ]
    if not paths.is_kaggle:
        writable.append(paths.data_raw)
        writable.append(paths.data_external)
    for d in writable:
        d.mkdir(parents=True, exist_ok=True)


def print_environment_banner() -> EnvironmentPaths:
    """
    Call this at the top of every notebook / script. Prints the
    reproducibility-relevant environment facts required by the project spec
    (experiment ID is NOT printed here — that's per-experiment, see
    training/manifest logic).
    """
    paths = get_paths()
    ensure_dirs(paths)

    print("=" * 60)
    print("ENVIRONMENT")
    print("=" * 60)
    print(f"env_name        : {paths.env_name}")
    print(f"project_root    : {paths.project_root}")
    print(f"python_version  : {sys.version.split()[0]}")
    print(f"platform        : {platform.platform()}")

    try:
        import torch

        print(f"torch_version   : {torch.__version__}")
        print(f"cuda_available  : {torch.cuda.is_available()}")
        if torch.cuda.is_available():
            print(f"gpu_name        : {torch.cuda.get_device_name(0)}")
    except ImportError:
        print("torch_version   : (not installed)")

    print("=" * 60)
    return paths


if __name__ == "__main__":
    print_environment_banner()
