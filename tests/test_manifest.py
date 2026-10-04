import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.utils.manifest import (
    sha256_file,
    build_dataset_manifest,
    config_hash,
    build_experiment_manifest,
)


def test_sha256_file_is_deterministic(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_text("hello world")
    h1 = sha256_file(f)
    h2 = sha256_file(f)
    assert h1 == h2
    assert len(h1) == 64


def test_sha256_file_changes_with_content(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_text("version 1")
    h1 = sha256_file(f)
    f.write_text("version 2")
    h2 = sha256_file(f)
    assert h1 != h2


def test_build_dataset_manifest_roundtrip(tmp_path):
    data_file = tmp_path / "data.jsonl"
    data_file.write_text('{"a": 1}\n{"a": 2}\n')

    manifest = build_dataset_manifest(
        dataset_name="test_dataset",
        source="unit_test",
        source_version="v1",
        data_file=data_file,
        record_count=2,
        license_="MIT",
        data_generating_process="real_world_observed",
    )
    assert manifest.checksum == sha256_file(data_file)
    assert manifest.record_count == 2

    manifest_dir = tmp_path / "manifests"
    out_path = manifest.save(manifest_dir)
    assert out_path.exists()

    with open(out_path) as f:
        loaded = json.load(f)
    assert loaded["dataset_name"] == "test_dataset"
    assert loaded["data_generating_process"] == "real_world_observed"


def test_build_dataset_manifest_missing_file_raises(tmp_path):
    missing = tmp_path / "does_not_exist.jsonl"
    try:
        build_dataset_manifest(
            dataset_name="x",
            source="x",
            source_version="x",
            data_file=missing,
            record_count=0,
            license_="MIT",
            data_generating_process="real_world_observed",
        )
        assert False, "should have raised FileNotFoundError"
    except FileNotFoundError:
        pass


def test_config_hash_order_independent():
    h1 = config_hash({"a": 1, "b": 2})
    h2 = config_hash({"b": 2, "a": 1})
    assert h1 == h2


def test_config_hash_changes_with_content():
    h1 = config_hash({"a": 1})
    h2 = config_hash({"a": 2})
    assert h1 != h2


def test_build_experiment_manifest_roundtrip(tmp_path):
    manifest = build_experiment_manifest(
        experiment_id="exp_0001",
        dataset_version="v0",
        dataset_hash="deadbeef",
        config={"lr": 1e-5, "seed": 42},
        random_seed=42,
        model_name="deberta-v3-small",
        model_version="v1",
        device="cpu",
    )
    out_path = manifest.save(tmp_path / "exp_0001")
    assert out_path.exists()
    with open(out_path) as f:
        loaded = json.load(f)
    assert loaded["experiment_id"] == "exp_0001"
    assert loaded["random_seed"] == 42
    assert "python_version" in loaded
