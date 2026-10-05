import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.data.incident_clients import (
    IncidentFetchConfig,
    fetch_ghsa_advisories,
    fetch_osv_advisories_for_package,
    deduplicate_incidents,
    _extract_osv_severity,
)


GHSA_SAMPLE_PAGE = [
    {
        "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
        "summary": "Malicious package steals credentials",
        "description": "This package contains code that exfiltrates env vars.",
        "published_at": "2026-01-15T00:00:00Z",
        "withdrawn_at": None,
        "severity": "critical",
        "references": ["https://example.com/advisory"],
        "vulnerabilities": [
            {"package": {"name": "fake-malicious-pkg", "ecosystem": "pip"}}
        ],
    }
]


def _mock_response(status_code, json_data):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    return resp


def test_fetch_ghsa_advisories_parses_and_normalizes():
    call_count = {"n": 0}

    def fake_get(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _mock_response(200, GHSA_SAMPLE_PAGE)
        return _mock_response(200, [])  # second page empty -> stop

    with patch("src.data.incident_clients.requests.get", side_effect=fake_get):
        config = IncidentFetchConfig(request_delay_seconds=0)
        records = fetch_ghsa_advisories(config, ecosystems=("pip",), max_pages=5)

    assert len(records) == 1
    r = records[0]
    assert r["advisory_id"] == "GHSA-xxxx-yyyy-zzzz"
    assert r["source"] == "ghsa"
    assert r["package_name"] == "fake-malicious-pkg"
    assert r["ecosystem"] == "pypi"  # normalized from 'pip'
    assert "exfiltrates" in r["description"]


def test_fetch_ghsa_advisories_stops_on_empty_page():
    with patch(
        "src.data.incident_clients.requests.get",
        return_value=_mock_response(200, []),
    ) as mock_get:
        config = IncidentFetchConfig(request_delay_seconds=0)
        records = fetch_ghsa_advisories(config, ecosystems=("npm",), max_pages=5)

    assert records == []
    assert mock_get.call_count == 1  # stopped after first empty page


def test_fetch_ghsa_advisories_handles_persistent_failure():
    with patch(
        "src.data.incident_clients.requests.get",
        return_value=_mock_response(500, None),
    ):
        config = IncidentFetchConfig(request_delay_seconds=0, max_retries=1)
        records = fetch_ghsa_advisories(config, ecosystems=("pip",), max_pages=3)

    assert records == []  # fails gracefully, doesn't raise


OSV_SAMPLE_RESPONSE = {
    "vulns": [
        {
            "id": "OSV-2026-0001",
            "summary": "Injection payload in postinstall script",
            "details": "Full details here.",
            "published": "2026-02-01T00:00:00Z",
            "withdrawn": None,
            "severity": [{"type": "CVSS_V3", "score": "9.8"}],
            "references": [{"url": "https://osv.dev/OSV-2026-0001"}],
        }
    ]
}


def test_fetch_ghsa_advisories_handles_string_references():
    """
    Regression guard for the exact bug found running against live GHSA:
    'references' is a plain list of URL strings, NOT a list of {"url":...}
    dicts. This test exists because that wrong assumption shipped once
    already and broke on the very first live pilot run.
    """
    page = [
        {
            "ghsa_id": "GHSA-regression-test",
            "summary": "test",
            "description": "test",
            "published_at": "2026-01-01T00:00:00Z",
            "withdrawn_at": None,
            "severity": "high",
            "references": ["https://example.com/a", "https://example.com/b"],
            "vulnerabilities": [
                {"package": {"name": "some-pkg", "ecosystem": "npm"}}
            ],
        }
    ]

    call_count = {"n": 0}

    def fake_get(*args, **kwargs):
        call_count["n"] += 1
        return _mock_response(200, page if call_count["n"] == 1 else [])

    with patch("src.data.incident_clients.requests.get", side_effect=fake_get):
        config = IncidentFetchConfig(request_delay_seconds=0)
        records = fetch_ghsa_advisories(config, ecosystems=("npm",), max_pages=2)

    assert len(records) == 1
    assert records[0]["reference_urls"] == [
        "https://example.com/a",
        "https://example.com/b",
    ]


def test_fetch_ghsa_advisories_handles_empty_references():
    page = [
        {
            "ghsa_id": "GHSA-no-refs",
            "summary": "test",
            "description": "test",
            "published_at": "2026-01-01T00:00:00Z",
            "withdrawn_at": None,
            "severity": "low",
            "references": [],
            "vulnerabilities": [
                {"package": {"name": "another-pkg", "ecosystem": "pip"}}
            ],
        }
    ]
    call_count = {"n": 0}

    def fake_get(*args, **kwargs):
        call_count["n"] += 1
        return _mock_response(200, page if call_count["n"] == 1 else [])

    with patch("src.data.incident_clients.requests.get", side_effect=fake_get):
        config = IncidentFetchConfig(request_delay_seconds=0)
        records = fetch_ghsa_advisories(config, ecosystems=("pip",), max_pages=2)

    assert records[0]["reference_urls"] == []


def test_fetch_osv_advisories_for_package_parses_severity():
    with patch(
        "src.data.incident_clients.requests.post",
        return_value=_mock_response(200, OSV_SAMPLE_RESPONSE),
    ):
        config = IncidentFetchConfig()
        records = fetch_osv_advisories_for_package("fake-pkg", "pypi", config)

    assert len(records) == 1
    assert records[0]["advisory_id"] == "OSV-2026-0001"
    assert records[0]["source"] == "osv"
    assert records[0]["severity"] == "9.8"


def test_fetch_osv_advisories_returns_empty_on_no_vulns():
    with patch(
        "src.data.incident_clients.requests.post",
        return_value=_mock_response(200, {"vulns": []}),
    ):
        config = IncidentFetchConfig()
        records = fetch_osv_advisories_for_package("clean-pkg", "pypi", config)
    assert records == []


def test_extract_osv_severity_handles_missing_field():
    assert _extract_osv_severity({}) == ""
    assert _extract_osv_severity({"severity": []}) == ""


def test_deduplicate_incidents_prefers_ghsa_on_same_key():
    records = [
        {
            "ecosystem": "pypi",
            "package_name": "fake-pkg",
            "advisory_id": "GHSA-1",
            "source": "osv",
            "summary": "from osv",
        },
        {
            "ecosystem": "pypi",
            "package_name": "fake-pkg",
            "advisory_id": "GHSA-1",
            "source": "ghsa",
            "summary": "from ghsa",
        },
    ]
    deduped = deduplicate_incidents(records)
    assert len(deduped) == 1
    assert deduped[0]["source"] == "ghsa"


def test_deduplicate_incidents_keeps_distinct_advisory_ids():
    records = [
        {
            "ecosystem": "pypi",
            "package_name": "fake-pkg",
            "advisory_id": "GHSA-1",
            "source": "ghsa",
        },
        {
            "ecosystem": "pypi",
            "package_name": "fake-pkg",
            "advisory_id": "OSV-2",
            "source": "osv",
        },
    ]
    deduped = deduplicate_incidents(records)
    assert len(deduped) == 2


# --- Reporter extraction (review.md A3 / D2) --------------------------------

from src.data.incident_clients import (
    GHSA_BOILERPLATE_MARKER,
    UNATTRIBUTED_MARKER,
    count_reporters,
    extract_reporters,
    union_reporters,
)

# Shape of a real OSV MAL- description: preamble, then one section per reporter.
MULTI_REPORTER_TEXT = (
    "Malicious code in tsshare (PyPI)\n\n"
    "## Source: amazon-inspector (4d584c571cf5d112735aefd07c78bc19659af32f5950b1331a4970cba97c9707)\n"
    "The package POSTs to a hardcoded endpoint.\n\n"
    "## Source: kam193 (e15a50ec5b7be580dec5d1edefa80860b4c650d552f69a1a9ba3dc9bd8edbc9d)\n"
    "Reasons (based on the campaign): - Downloads and executes a remote executable.\n"
)


def test_extract_reporters_returns_all_headers_in_order_without_digest():
    """Not just the first header (the A3 table only read the first)."""
    assert extract_reporters(MULTI_REPORTER_TEXT) == ["amazon-inspector", "kam193"]


def test_extract_reporters_keeps_repeated_headers():
    text = "## Source: kam193 (aaaaaaaaaaaaaaaa)\nx\n## Source: kam193 (bbbbbbbbbbbbbbbb)\ny"
    assert extract_reporters(text) == ["kam193", "kam193"]


def test_extract_reporters_ignores_source_not_at_line_start():
    text = "See ## Source: kam193 in the upstream feed. Steals tokens."
    assert extract_reporters(text) == [UNATTRIBUTED_MARKER]


def test_extract_reporters_appends_boilerplate_marker():
    ghsa = ("Any computer that has this package installed or running should be "
            "considered fully compromised. All secrets and keys stored on that computer...")
    osv = ("## Source: ghsa-malware (cae53348f8261653938b39ae3cb79101baff666c4216ecaeb635e34b42ba8293)\n"
           + ghsa)
    assert extract_reporters(ghsa) == [GHSA_BOILERPLATE_MARKER]
    assert extract_reporters(osv) == ["ghsa-malware", GHSA_BOILERPLATE_MARKER]


def test_extract_reporters_headerless_and_empty_text():
    assert extract_reporters("websetup POSTs file contents to a Discord webhook.") == [UNATTRIBUTED_MARKER]
    assert extract_reporters("") == []
    assert extract_reporters(None) == []


def test_union_reporters_preserves_first_appearance_order():
    assert union_reporters([["kam193"], ["amazon-inspector", "kam193"], []]) == ["kam193", "amazon-inspector"]


def test_count_reporters_counts_ghsa_malware_and_boilerplate_once():
    assert count_reporters(["ghsa-malware", GHSA_BOILERPLATE_MARKER]) == 1
    assert count_reporters(["amazon-inspector", "ghsa-malware", GHSA_BOILERPLATE_MARKER]) == 2
    assert count_reporters(["amazon-inspector", "kam193"]) == 2
    assert count_reporters([]) == 0


def test_fetch_ghsa_advisories_follows_link_cursor():
    """The endpoint ignores page=; the next page comes from the Link header."""
    second = [dict(GHSA_SAMPLE_PAGE[0], ghsa_id="GHSA-2222-2222-2222")]
    calls = []

    def fake_get(url, *args, **kwargs):
        calls.append((url, kwargs.get("params")))
        if len(calls) == 1:
            resp = _mock_response(200, GHSA_SAMPLE_PAGE)
            resp.links = {"next": {"url": "https://api.github.com/advisories?after=CURSOR"}}
        else:
            resp = _mock_response(200, second)
            resp.links = {}
        return resp

    with patch("src.data.incident_clients.requests.get", side_effect=fake_get):
        config = IncidentFetchConfig(request_delay_seconds=0)
        records = fetch_ghsa_advisories(config, ecosystems=("pip",), max_pages=5)

    assert [r["advisory_id"] for r in records] == ["GHSA-xxxx-yyyy-zzzz", "GHSA-2222-2222-2222"]
    assert "page" not in (calls[0][1] or {})
    assert calls[1] == ("https://api.github.com/advisories?after=CURSOR", None)


def test_fetch_ghsa_advisories_stops_at_record_cap():
    n = {"i": 0}

    def fake_get(url, *args, **kwargs):
        n["i"] += 1
        adv = dict(GHSA_SAMPLE_PAGE[0], ghsa_id=f"GHSA-{n['i']}")
        # same package listed twice (two version ranges) counts once
        adv["vulnerabilities"] = adv["vulnerabilities"] * 2
        resp = _mock_response(200, [adv])
        resp.links = {"next": {"url": "https://api.github.com/advisories?after=X"}}
        return resp

    with patch("src.data.incident_clients.requests.get", side_effect=fake_get) as mock_get:
        config = IncidentFetchConfig(request_delay_seconds=0)
        records = fetch_ghsa_advisories(config, ecosystems=("npm",), max_pages=10,
                                        max_records_per_ecosystem=2)

    assert len({r["advisory_id"] for r in records}) == 2
    assert mock_get.call_count == 2
