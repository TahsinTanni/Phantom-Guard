"""
Seed name-list fetchers for building the control (real, non-flagged)
package sample.

Provenance
----------
`fetch_seed_pypi_names` is ported from Cell 9 (hugovk's top-pypi-packages
JSON). `fetch_seed_npm_names` is ported from Cell 10's FALLBACK path only
— the notebook's own run showed the primary `npm-high-impact` source
failing (`Discovered files in npm-high-impact package: []`) and falling
back to the npm search API successfully, so this module starts from what
actually worked rather than re-porting the path that failed.

These are synchronous (plain `requests`), matching the original — no need
for async here since it's a handful of one-shot bulk-list fetches, not
thousands of per-package calls (that's registry_clients.py's job).
"""

from __future__ import annotations

import re
import time

import requests

TOP_PYPI_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"

# Download-ranked npm list (wooorm/npm-high-impact), pinned to one release
# so the benign set is reproducible. Read as a file from jsDelivr: the
# notebook's failure was in discovering files inside the installed
# package, not in the data itself.
NPM_HIGH_IMPACT_VERSION = "1.13.0"
NPM_HIGH_IMPACT_URL = (
    f"https://cdn.jsdelivr.net/npm/npm-high-impact@{NPM_HIGH_IMPACT_VERSION}/lib/top.js"
)
_JS_STRING_RE = re.compile(r"'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\"")

# Ported from Cell 10's fallback search terms.
NPM_FALLBACK_SEARCH_TERMS = [
    "react", "webpack", "babel", "eslint", "test", "server", "cli",
    "api", "util", "core", "plugin", "loader", "parser", "client",
]


def fetch_seed_pypi_names(n: int = 3000, timeout: float = 30.0) -> list[str]:
    """Ported from Cell 9. Returns the top-N PyPI package names by
    download count, per hugovk's periodically-updated public dataset."""
    resp = requests.get(TOP_PYPI_URL, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    top_packages = data["rows"]
    return [p["project"] for p in top_packages[:n]]


def fetch_seed_npm_names(
    n: int = 3000,
    search_terms: list[str] | None = None,
    size_per_term: int = 250,
    popularity: float = 1.0,
    request_delay_seconds: float = 0.0,
    timeout: float = 15.0,
) -> list[str]:
    """
    Ported from Cell 10's `fetch_npm_fallback`. Queries npm's search API
    across a fixed set of common terms and returns the deduplicated union
    of package names, popularity-sorted per term.

    Note the original notebook observed intermittent failures on some
    terms ("Expecting value: line 1 column 1 (char 0)" — an empty/non-JSON
    response, likely transient rate-limiting) and simply skipped those
    terms rather than retrying. Same behavior preserved here; if you need
    higher yield, add retry logic or `request_delay_seconds` > 0 between
    calls (not present in the original, added as an optional knob).
    """
    terms = search_terms or NPM_FALLBACK_SEARCH_TERMS
    names: set[str] = set()

    for term in terms:
        try:
            r = requests.get(
                "https://registry.npmjs.org/-/v1/search",
                params={"text": term, "size": size_per_term, "popularity": popularity},
                timeout=timeout,
            )
            data = r.json()
            for obj in data.get("objects", []):
                names.add(obj["package"]["name"])
        except Exception as e:
            print(f"  fallback query {term!r} failed: {e}")
        if request_delay_seconds:
            time.sleep(request_delay_seconds)

    return list(names)[:n]


def parse_npm_high_impact_top(js_source: str) -> list[str]:
    """Package names, in file (= download-rank) order, from npm-high-impact's
    `export const top = ['semver', 'minimatch', ...]` module."""
    start = js_source.index("[")
    end = js_source.rindex("]")
    return [a or b for a, b in _JS_STRING_RE.findall(js_source[start:end])]


def fetch_top_npm_names(n: int = 5000, timeout: float = 30.0) -> list[str]:
    """Top-N npm package names by download count (npm-high-impact,
    NPM_HIGH_IMPACT_VERSION). Unlike fetch_seed_npm_names, the set is not
    selected by search terms — several of NPM_FALLBACK_SEARCH_TERMS are
    naming-grammar tokens, which biases any grammar base rate computed on
    that set."""
    resp = requests.get(NPM_HIGH_IMPACT_URL, timeout=timeout)
    resp.raise_for_status()
    return parse_npm_high_impact_top(resp.text)[:n]
