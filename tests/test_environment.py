import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.utils.environment import detect_environment, get_paths, EnvironmentPaths


def test_detect_environment_returns_valid_value():
    env = detect_environment()
    assert env in {"kaggle", "colab", "local"}


def test_get_paths_local_returns_project_relative_paths(tmp_path):
    # force_env="local" makes this test host-independent: it must pass
    # identically whether pytest runs on a laptop, CI, OR inside an actual
    # Kaggle container (where Path("/kaggle").exists() is genuinely True
    # and auto-detection would correctly, but unhelpfully for this test,
    # return "kaggle").
    paths = get_paths(project_root=tmp_path, force_env="local")
    assert isinstance(paths, EnvironmentPaths)
    assert paths.data_raw == tmp_path / "data" / "raw"
    assert paths.data_processed == tmp_path / "data" / "processed"
    assert paths.is_kaggle is False


def test_get_paths_kaggle_ignores_project_root_override(tmp_path):
    # Explicitly documents the by-design behavior: on Kaggle, project_root
    # is ignored because Kaggle's paths are fixed by the platform, not
    # configurable per-project.
    paths = get_paths(project_root=tmp_path, force_env="kaggle")
    assert paths.is_kaggle is True
    assert paths.data_raw == Path("/kaggle/input")
    assert paths.project_root == Path("/kaggle/working")


def test_paths_are_distinct():
    paths = get_paths()
    values = [
        paths.data_raw, paths.data_interim, paths.data_processed,
        paths.data_metadata, paths.experiments, paths.results, paths.reports,
    ]
    # data_external may legitimately equal data_raw on Kaggle (both point at
    # /kaggle/input), so it's excluded from the strict-distinctness check.
    assert len(set(map(str, values))) == len(values)
