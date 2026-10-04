"""
Tests for registry_clients.py using a fake aiohttp ClientSession — no live
network calls, so these run identically in CI, on Kaggle, or locally.

Requires aiohttp to be installed (it's needed by the module under test
regardless). If aiohttp isn't available, these tests are skipped rather
than failed, since aiohttp absence is an environment issue, not a code
defect — `pytest.importorskip` makes that explicit.
"""

import sys
from pathlib import Path

import pytest

aiohttp = pytest.importorskip("aiohttp")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.data.registry_clients import (
    RegistryFetchConfig,
    fetch_pypi_metadata,
    fetch_npm_metadata,
    UNIFIED_SCHEMA_FIELDS,
)


class FakeResponse:
    def __init__(self, status: int, json_data: dict | None):
        self.status = status
        self._json_data = json_data

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def json(self):
        return self._json_data


class FakeSession:
    """Maps URL -> (status, json_data). Records every URL requested so
    tests can assert on call patterns if needed."""

    def __init__(self, responses: dict[str, tuple[int, dict | None]]):
        self.responses = responses
        self.requested_urls: list[str] = []

    def get(self, url: str, timeout=None):
        self.requested_urls.append(url)
        status, data = self.responses.get(url, (404, None))
        return FakeResponse(status, data)


PYPI_SAMPLE_RESPONSE = {
    "info": {
        "version": "1.2.3",
        "summary": "A fake package for testing.",
        "description": "# Fake Package\n\nSome README content here.",
        "author": "Test Author",
        "project_urls": {"Homepage": "https://github.com/test/fake-package"},
    },
    "releases": {
        "1.0.0": [{"upload_time_iso_8601": "2024-01-01T00:00:00.000000Z"}],
        "1.2.3": [{"upload_time_iso_8601": "2024-06-01T00:00:00.000000Z"}],
    },
}

NPM_SAMPLE_RESPONSE = {
    "dist-tags": {"latest": "2.0.0"},
    "description": "A fake npm package.",
    "readme": "# Fake NPM Package\n\nReadme body.",
    "time": {"created": "2023-05-01T00:00:00.000Z"},
    "repository": {"url": "git+https://github.com/test/fake-npm.git"},
    "versions": {"1.0.0": {}, "2.0.0": {}},
}


@pytest.mark.asyncio
async def test_fetch_pypi_metadata_parses_full_readme():
    session = FakeSession(
        {"https://pypi.org/pypi/fake-package/json": (200, PYPI_SAMPLE_RESPONSE)}
    )
    config = RegistryFetchConfig()
    result = await fetch_pypi_metadata(session, "fake-package", config)

    assert result["exists_in_registry"] is True
    assert result["readme_text"] == "# Fake Package\n\nSome README content here."
    assert result["first_published_at"] == "2024-01-01T00:00:00.000000Z"
    assert result["has_github"] is True
    assert result["release_count"] == 2
    assert set(result.keys()) == set(UNIFIED_SCHEMA_FIELDS)


@pytest.mark.asyncio
async def test_fetch_pypi_metadata_handles_404():
    session = FakeSession({})  # no matching URL -> defaults to (404, None)
    config = RegistryFetchConfig()
    result = await fetch_pypi_metadata(session, "does-not-exist", config)

    assert result["exists_in_registry"] is False
    assert result["readme_text"] == ""
    assert result["first_published_at"] is None


@pytest.mark.asyncio
async def test_fetch_npm_metadata_parses_readme_and_timestamp():
    session = FakeSession(
        {"https://registry.npmjs.org/fake-npm-package": (200, NPM_SAMPLE_RESPONSE)}
    )
    config = RegistryFetchConfig()
    result = await fetch_npm_metadata(session, "fake-npm-package", config)

    assert result["exists_in_registry"] is True
    assert result["readme_text"] == "# Fake NPM Package\n\nReadme body."
    assert result["first_published_at"] == "2023-05-01T00:00:00.000Z"
    assert result["has_github"] is True
    assert result["release_count"] == 2


@pytest.mark.asyncio
async def test_readme_truncation_respects_max_chars():
    long_readme = "x" * 50_000
    response = dict(PYPI_SAMPLE_RESPONSE)
    response["info"] = dict(response["info"])
    response["info"]["description"] = long_readme

    session = FakeSession(
        {"https://pypi.org/pypi/big-package/json": (200, response)}
    )
    config = RegistryFetchConfig(max_readme_chars=1000)
    result = await fetch_pypi_metadata(session, "big-package", config)

    assert len(result["readme_text"]) == 1000


@pytest.mark.asyncio
async def test_no_age_days_field_present():
    """Regression guard for the deliberate schema change: age_days must
    NOT appear anywhere in the unified schema — only first_published_at.
    This test exists specifically because it's easy to accidentally
    reintroduce age_days by copy-pasting from the original notebook."""
    session = FakeSession(
        {"https://pypi.org/pypi/fake-package/json": (200, PYPI_SAMPLE_RESPONSE)}
    )
    result = await fetch_pypi_metadata(session, "fake-package", RegistryFetchConfig())
    assert "age_days" not in result
    assert "first_published_at" in result
