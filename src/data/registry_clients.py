"""
PyPI / npm registry metadata clients.

Provenance
----------
Ported from the prior notebook's `fetch_pypi_meta`/`fetch_npm_meta`
(cells 11, 23, 25b) and `fetch_with_retry`. The retry/backoff/timeout
logic is unchanged — it was already tested against live registries across
~14,000 fetches in the prior run and there's no reason to redesign working
network code.

What changed from the original, and why
-----------------------------------------
1. FULL DOCUMENTATION TEXT IS NOW CAPTURED.
   The original only stored `summary`/short `description`. The new
   research question is about injection payloads IN DOCUMENTATION, and
   payloads don't live in one-line summaries. PyPI's `info.description`
   field (full rendered README) and npm's `readme` field are now captured.
   Known limitation, stated up front rather than discovered later: npm
   strips `readme` from the abbreviated registry response for some
   packages, and PyPI's `description` is sometimes empty even for real
   packages (this is exactly what the original notebook's Cell 23 was
   investigating for the *existence* classifier — expect the same gap
   here, just now relevant to injection-text availability too).

2. RAW TIMESTAMPS ARE STORED, NOT AGE-AT-FETCH-TIME.
   The original computed `age_days` at fetch time, which decays silently
   on rerun. This module stores `first_published_at` (ISO 8601) instead;
   age is derived downstream (features.py, added later) against a fixed
   reference date, so re-running collection doesn't change historical
   feature values out from under you — this is a direct requirement of
   the Phase 0 temporal-leakage checks.

3. Return schema is unified across ecosystems into one dict shape, so
   downstream code (naming_grammar.py, feature builders) doesn't need
   per-ecosystem branching.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

try:
    import aiohttp
except ImportError:  # pragma: no cover - exercised only when aiohttp absent
    aiohttp = None  # type: ignore[assignment]


@dataclass
class RegistryFetchConfig:
    max_retries: int = 3
    timeout_seconds: float = 10.0
    max_readme_chars: int = 20_000  # cap; injection payloads are typically
    # in the first few KB, and unbounded README text bloats storage/tokens
    # for no benefit — revisit if Phase 2 labeling finds payloads buried
    # deeper than this cap in practice.
    concurrency_limit: int = 15  # matches the prior notebook's TCPConnector
    # limit, which was already tuned against registry rate limits.


UNIFIED_SCHEMA_FIELDS = (
    "name",
    "ecosystem",
    "version",
    "summary",
    "readme_text",
    "author",
    "release_count",
    "first_published_at",  # ISO 8601 string or None; NOT age_days
    "has_github",
    "exists_in_registry",
    "fetched_at",  # ISO 8601 string; when THIS record was collected
)


async def fetch_with_retry(
    session: "aiohttp.ClientSession",
    url: str,
    config: RegistryFetchConfig,
) -> Optional[dict]:
    """
    Ported unchanged in behavior from the prior notebook's
    `fetch_with_retry`: exponential backoff on 429, immediate None on 404,
    retry on timeout/connection error. Only the config is now parameterized
    instead of hardcoded.
    """
    for attempt in range(config.max_retries):
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=config.timeout_seconds)
            ) as r:
                if r.status == 200:
                    return await r.json()
                if r.status == 429:
                    await asyncio.sleep(2**attempt)
                    continue
                if r.status == 404:
                    return None
                return None
        except (asyncio.TimeoutError, aiohttp.ClientError):
            await asyncio.sleep(1)
    return None


def _truncate_readme(text: str, config: RegistryFetchConfig) -> str:
    if text is None:
        return ""
    return text[: config.max_readme_chars]


async def fetch_pypi_metadata(
    session: "aiohttp.ClientSession",
    name: str,
    config: RegistryFetchConfig,
) -> Optional[dict]:
    """
    Extended version of the prior notebook's `fetch_pypi_meta`.

    Key differences from the original:
        - captures `info["description"]` (full README) as `readme_text`
        - stores `first_published_at` as a raw ISO date, not `age_days`
    """
    data = await fetch_with_retry(
        session, f"https://pypi.org/pypi/{name}/json", config
    )
    if not data:
        return {
            "name": name,
            "ecosystem": "pypi",
            "version": "",
            "summary": "",
            "readme_text": "",
            "author": "",
            "release_count": 0,
            "first_published_at": None,
            "has_github": False,
            "exists_in_registry": False,
            "fetched_at": _now_iso(),
        }

    info = data["info"]
    releases = data.get("releases", {})
    upload_times = [
        v[0]["upload_time_iso_8601"] for v in releases.values() if v
    ]
    first_upload = min(upload_times) if upload_times else None

    project_urls = info.get("project_urls") or {}
    has_github = any("github.com" in str(v).lower() for v in project_urls.values())

    return {
        "name": name,
        "ecosystem": "pypi",
        "version": info.get("version", "") or "",
        "summary": info.get("summary", "") or "",
        "readme_text": _truncate_readme(info.get("description", "") or "", config),
        "author": info.get("author", "") or "",
        "release_count": len(releases),
        "first_published_at": first_upload,
        "has_github": has_github,
        "exists_in_registry": True,
        "fetched_at": _now_iso(),
    }


async def fetch_npm_metadata(
    session: "aiohttp.ClientSession",
    name: str,
    config: RegistryFetchConfig,
) -> Optional[dict]:
    """
    Extended version of the prior notebook's `fetch_npm_meta`.

    Key differences from the original:
        - captures `readme` field as `readme_text` (may be absent for some
          large packages per npm's abbreviated-response behavior — this is
          a known, stated limitation, not a bug to silently work around)
        - stores `first_published_at` as a raw ISO date, not `age_days`
    """
    data = await fetch_with_retry(
        session, f"https://registry.npmjs.org/{name}", config
    )
    if not data:
        return {
            "name": name,
            "ecosystem": "npm",
            "version": "",
            "summary": "",
            "readme_text": "",
            "author": "",
            "release_count": 0,
            "first_published_at": None,
            "has_github": False,
            "exists_in_registry": False,
            "fetched_at": _now_iso(),
        }

    created = data.get("time", {}).get("created")
    repo = data.get("repository", {})
    repo_url = repo.get("url", "") if isinstance(repo, dict) else str(repo)
    has_github = "github.com" in repo_url.lower()

    readme_raw = data.get("readme", "") or ""

    return {
        "name": name,
        "ecosystem": "npm",
        "version": data.get("dist-tags", {}).get("latest", "") or "",
        "summary": data.get("description", "") or "",
        "readme_text": _truncate_readme(readme_raw, config),
        "author": "",
        "release_count": len(data.get("versions", {})),
        "first_published_at": created,
        "has_github": has_github,
        "exists_in_registry": True,
        "fetched_at": _now_iso(),
    }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def fetch_metadata(
    session: "aiohttp.ClientSession",
    name: str,
    ecosystem: str,
    config: RegistryFetchConfig,
) -> dict:
    """Single dispatch point used by the collector orchestration layer."""
    if ecosystem == "pypi":
        return await fetch_pypi_metadata(session, name, config)
    if ecosystem == "npm":
        return await fetch_npm_metadata(session, name, config)
    raise ValueError(f"Unknown ecosystem: {ecosystem!r} (expected 'pypi' or 'npm')")
