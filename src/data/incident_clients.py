"""
Confirmed-incident clients: GitHub Security Advisories (GHSA) and OSV.dev.

Scope note (important, do not extend without re-reading this)
---------------------------------------------------------------
These clients fetch and normalize ADVISORY METADATA ONLY: package name,
ecosystem, advisory ID, summary/description text, published/withdrawn
dates, and reference URLs. They do NOT determine whether an advisory
involves an injection payload — that is Phase 2's job (a separate,
explicitly human/LLM-reviewed labeling step). Do not add an
`injection_present` field here; computing it during collection would
skip the annotation-guideline/inter-annotator-agreement process the
Phase 0 audit requires, and would make any later H1 test unreviewable.

Sources
-------
- GHSA: https://api.github.com/advisories (public, no auth required for
  read access at low volume; a GITHUB_TOKEN raises rate limits
  substantially — pass one via `github_token` if you have it).
- OSV.dev: https://api.osv.dev (public, no auth).

Both APIs are paginated. Both clients here are synchronous (`requests`),
matching seed_lists.py's precedent — these are bulk/paginated listing
calls, not thousands of per-item calls, so async isn't needed the way it
was for registry_clients.py.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import requests

GHSA_API_URL = "https://api.github.com/advisories"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_ECOSYSTEMS_TO_ADVISORY_URL = "https://osv-vulnerabilities.storage.googleapis.com"

# GHSA/OSV ecosystem identifiers differ from each other; normalize both to
# your project's 'pypi' / 'npm' convention (matching registry_clients.py).
GHSA_ECOSYSTEM_MAP = {"pip": "pypi", "npm": "npm"}
OSV_ECOSYSTEM_MAP = {"PyPI": "pypi", "npm": "npm"}


@dataclass
class IncidentFetchConfig:
    max_retries: int = 3
    timeout_seconds: float = 15.0
    per_page: int = 100
    request_delay_seconds: float = 0.5  # GHSA unauthenticated rate limit is
    # low (60 req/hr) — a deliberate delay avoids burning through it during
    # a single pilot run. Raise `per_page` and lower/remove this delay if
    # you pass a `github_token`.
    github_token: Optional[str] = None


UNIFIED_INCIDENT_SCHEMA_FIELDS = (
    "advisory_id",
    "source",  # 'ghsa' | 'osv'
    "package_name",
    "ecosystem",
    "summary",
    "description",
    "published_at",
    "withdrawn_at",
    "severity",
    "reference_urls",
    "fetched_at",
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def fetch_ghsa_advisories(
    config: IncidentFetchConfig,
    ecosystems: tuple[str, ...] = ("pip", "npm"),
    max_pages: int = 5,
    max_records_per_ecosystem: Optional[int] = None,
) -> list[dict]:
    """
    Fetches GHSA advisories filtered to malware-relevant types, for the
    given GHSA ecosystem identifiers ('pip', 'npm'), newest first.

    `max_pages` bounds total volume for pilot runs — GHSA's advisory
    corpus is large; a pilot should NOT pull everything on first run.
    Each page is `config.per_page` records (GitHub's max is 100).
    `max_records_per_ecosystem` stops an ecosystem at the end of the page
    on which its distinct (advisory, package) count reaches that number.

    Pagination follows the `after=` cursor in the Link header. The
    advisories endpoint ignores `page=`: before research_log 5.17 this
    function sent page=1..N and got page 1 back N times, so the v1
    snapshot holds one page per ecosystem.
    """
    headers = {"Accept": "application/vnd.github+json"}
    if config.github_token:
        headers["Authorization"] = f"Bearer {config.github_token}"

    records: list[dict] = []

    for ecosystem in ecosystems:
        page = 1
        eco_keys: set[tuple[str, str]] = set()  # (advisory, package) seen
        url: Optional[str] = GHSA_API_URL
        params: Optional[dict] = {
            "ecosystem": ecosystem,
            "per_page": config.per_page,
            "type": "malware",  # GHSA supports filtering advisory type;
            # 'malware' is the category relevant to squatting/injection
            # incidents, as opposed to ordinary CVE-style vuln reports.
        }
        while page <= max_pages and url:
            resp = None
            for attempt in range(config.max_retries):
                try:
                    resp = requests.get(
                        url,
                        headers=headers,
                        params=params,
                        timeout=config.timeout_seconds,
                    )
                    if resp.status_code == 200:
                        break
                    if resp.status_code == 403:
                        # Likely rate-limited; back off and retry.
                        time.sleep(2**attempt * 2)
                        continue
                    break
                except requests.RequestException:
                    resp = None
                    time.sleep(2**attempt)
            if resp is None or resp.status_code != 200:
                print(
                    f"  GHSA fetch failed for ecosystem={ecosystem} page={page} "
                    f"(status={getattr(resp, 'status_code', 'no-response')})"
                )
                break

            batch = resp.json()
            if not batch:
                break  # no more pages

            for adv in batch:
                for vuln in adv.get("vulnerabilities", []) or [{}]:
                    pkg = (vuln.get("package") or {}).get("name")
                    if not pkg:
                        continue
                    records.append(
                        {
                            "advisory_id": adv.get("ghsa_id", ""),
                            "source": "ghsa",
                            "package_name": pkg,
                            "ecosystem": GHSA_ECOSYSTEM_MAP.get(ecosystem, ecosystem),
                            "summary": adv.get("summary", "") or "",
                            "description": adv.get("description", "") or "",
                            "published_at": adv.get("published_at"),
                            "withdrawn_at": adv.get("withdrawn_at"),
                            "severity": adv.get("severity", "") or "",
                            # GHSA's 'references' field is a plain list of
                            # URL strings (e.g. ["https://...", ...]) — NOT
                            # a list of {"url": ...} objects like OSV uses.
                            # This was wrong in the initial version (an
                            # unverified assumption, not checked against a
                            # live response first) and is fixed here to
                            # handle both a bare string and, defensively,
                            # a dict shape in case GitHub's API ever
                            # changes it.
                            "reference_urls": [
                                (r if isinstance(r, str) else r.get("url", ""))
                                for r in (adv.get("references") or [])
                                if (isinstance(r, str) and r)
                                or (isinstance(r, dict) and r.get("url"))
                            ],
                            "fetched_at": _now_iso(),
                        }
                    )
                    eco_keys.add((adv.get("ghsa_id", ""), pkg))

            # An advisory can list one package once per affected version
            # range; the cap counts distinct (advisory, package) pairs.
            if max_records_per_ecosystem is not None and len(eco_keys) >= max_records_per_ecosystem:
                break
            links = getattr(resp, "links", None)
            url = (links.get("next") or {}).get("url") if isinstance(links, dict) else None
            params = None  # the cursor URL carries the query
            page += 1
            time.sleep(config.request_delay_seconds)

    return records


def fetch_osv_advisories_for_package(
    package_name: str,
    ecosystem: str,
    config: IncidentFetchConfig,
) -> list[dict]:
    """
    OSV's query API is per-package, not a bulk listing endpoint — you query
    "does this package have known vulnerabilities" rather than "list all
    vulnerabilities." This means OSV collection needs a candidate package
    list to query against (e.g., names surfaced from GHSA, or your own
    naming-grammar-flagged names) rather than being a standalone bulk
    source. Use `fetch_ghsa_advisories` first to get candidate names, then
    cross-check each against OSV for corroborating/additional detail.
    """
    osv_ecosystem = {"pypi": "PyPI", "npm": "npm"}.get(ecosystem, ecosystem)
    payload = {
        "package": {"name": package_name, "ecosystem": osv_ecosystem}
    }

    for attempt in range(config.max_retries):
        try:
            resp = requests.post(
                OSV_QUERY_URL, json=payload, timeout=config.timeout_seconds
            )
            if resp.status_code == 200:
                break
            if resp.status_code == 429:
                time.sleep(2**attempt)
                continue
            return []
        except requests.RequestException:
            time.sleep(1)
    else:
        return []

    data = resp.json()
    vulns = data.get("vulns", [])
    records = []
    for v in vulns:
        records.append(
            {
                "advisory_id": v.get("id", ""),
                "source": "osv",
                "package_name": package_name,
                "ecosystem": ecosystem,
                "summary": v.get("summary", "") or "",
                "description": v.get("details", "") or "",
                "published_at": v.get("published"),
                "withdrawn_at": v.get("withdrawn"),
                "severity": _extract_osv_severity(v),
                "reference_urls": [
                    r.get("url", "") for r in (v.get("references") or []) if r.get("url")
                ],
                "fetched_at": _now_iso(),
            }
        )
    return records


def _extract_osv_severity(vuln: dict) -> str:
    severities = vuln.get("severity", [])
    if severities and isinstance(severities, list):
        return severities[0].get("score", "")
    return ""


def deduplicate_incidents(records: list[dict]) -> list[dict]:
    """
    Dedupes across GHSA/OSV on (ecosystem, package_name, advisory_id).
    When both sources report the SAME advisory_id (common, since OSV
    ingests GHSA), keeps the GHSA record (treated as primary) but does not
    silently drop OSV-only corroborating advisories for the same package
    under a DIFFERENT advisory_id — those are kept as separate records,
    since they may represent genuinely distinct incidents.
    """
    seen: dict[tuple, dict] = {}
    for r in records:
        key = (r["ecosystem"], r["package_name"], r["advisory_id"])
        if key not in seen:
            seen[key] = r
        elif r["source"] == "ghsa" and seen[key]["source"] != "ghsa":
            seen[key] = r  # prefer GHSA on exact-key collision
    return list(seen.values())


# ---------------------------------------------------------------------------
# Reporter extraction (review.md A3 / D2)
# ---------------------------------------------------------------------------
# Advisory descriptions concatenate one section per reporter, each opened by
# a "## Source: <name> (<sha256>)" header. OSV records often carry more
# sections than the GHSA record for the same package (research_log 5.9).

REPORTER_HEADER_RE = re.compile(r"^##\s*Source:\s*(.+?)\s*$", re.MULTILINE)
# The hex digest after the reporter name identifies the analysed artifact,
# not the reporter; strip it so "kam193 (e623...)" and "kam193 (5e16...)"
# are the same reporter.
_REPORTER_DIGEST_SUFFIX_RE = re.compile(r"\s*\([0-9a-fA-F]{16,}\)$")

GHSA_BOILERPLATE_PHRASE = "should be considered fully compromised"
GHSA_BOILERPLATE_MARKER = "<ghsa-boilerplate>"
# OSV's "## Source: ghsa-malware" section IS the GHSA boilerplate text, so
# the two strings name one reporter (see count_reporters).
GHSA_BOILERPLATE_ALIASES = frozenset({GHSA_BOILERPLATE_MARKER, "ghsa-malware"})
# Non-empty text with no "## Source:" header and no boilerplate. In the
# frozen snapshot these are mostly OpenSSF-credited prose.
UNATTRIBUTED_MARKER = "<unattributed>"


def extract_reporters(text: str) -> list[str]:
    """
    Every "## Source: <name>" header in `text`, in order (digest suffix
    stripped, repeats kept), followed by GHSA_BOILERPLATE_MARKER if the
    "fully compromised" template is present. Non-empty text with neither
    returns [UNATTRIBUTED_MARKER]; empty text returns [].
    """
    text = text or ""
    reporters = [
        _REPORTER_DIGEST_SUFFIX_RE.sub("", m.group(1)).strip()
        for m in REPORTER_HEADER_RE.finditer(text)
    ]
    if GHSA_BOILERPLATE_PHRASE in text:
        reporters.append(GHSA_BOILERPLATE_MARKER)
    if not reporters and text.strip():
        reporters.append(UNATTRIBUTED_MARKER)
    return reporters


def union_reporters(reporter_lists) -> list[str]:
    """Order-preserving union (first appearance wins) of reporter lists."""
    seen: dict[str, None] = {}
    for reporters in reporter_lists:
        for r in reporters:
            seen.setdefault(r, None)
    return list(seen)


def count_reporters(reporters: list[str]) -> int:
    """Number of distinct reporters, counting GHSA_BOILERPLATE_ALIASES as
    one (they are the same text under two labels)."""
    return len({GHSA_BOILERPLATE_MARKER if r in GHSA_BOILERPLATE_ALIASES else r for r in reporters})
