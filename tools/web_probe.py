"""v10.4: Vault-driven web application probing battery.

Consumes technique specs distilled from the HTB-Academy vault
(knowledge/vault-*.md, ## TECH blocks) and executes every `class: auto`
technique against each enumerated web app / vhost. `class: manual` techniques
become ranked manual leads with the exact vault command, surfaced in the
report dashboard.

Design rules:
  - enum-safe ONLY: detection probes (error strings, canaries, benign reads).
    No exploitation, no data exfiltration, no payload delivery beyond a canary.
  - Everything Host-header aware so vhosts on a shared IP are probed as their
    own apps.
  - Time-boxed: per-app probe budget, no probe may hang the enumeration.

Probes implemented here mirror the vault notes:
  SQL Attacks/03+05 (error/union/boolean detection), SQL Map/* (manual leads)
  XSS/03+05 (reflected canary + input inventory)
  Command Injection/02+04 (operator canaries, filter detection)
  File Inclusion/02+04 (traversal + php://filter read)
  Web Attacks/01..03 (verb tampering, IDOR diff, XXE benign entity)
  Web Recon/08+09 (headers, robots/sitemap, JS/endpoint harvest)
  Common Applications/* (CMS-specific paths per fingerprint)
  Ffuf/06+07 (param/value fuzzing — wired as manual lead w/ exact syntax)
"""
from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import requests

requests.packages.urllib3.disable_warnings()

# ── Vault spec parsing ────────────────────────────────────────────────────

_TECH_RE = re.compile(r"^##\s+TECH:\s*(.+)$", re.M)


@dataclass
class Tech:
    name: str
    vault: str = ""
    cls: str = "manual"          # auto | manual
    when: str = ""
    probe: str = ""
    detect: str = ""
    sev: str = "med"
    requires: str = ""           # tech-fingerprint gate (e.g. 'wordpress')

    @property
    def is_auto(self) -> bool:
        return self.cls == "auto"


def parse_tech_specs(paths: Optional[List[str]] = None) -> List[Tech]:
    """Parse all knowledge/vault-*.md spec files into Tech objects."""
    if paths is None:
        kdir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "knowledge")
        try:
            paths = sorted(
                os.path.join(kdir, f) for f in os.listdir(kdir)
                if f.startswith("vault-") and f.endswith(".md"))
        except OSError:
            paths = []
    techs: List[Tech] = []
    for p in paths:
        try:
            text = open(p, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        parts = _TECH_RE.split(text)
        # split → [preamble, name1, body1, name2, body2, ...]: iterate PAIRS
        for name, block in zip(parts[1::2], parts[2::2]):
            if not name or not block:
                continue
            lines = [l.strip() for l in block.strip().splitlines() if l.strip()]
            if not lines:
                continue
            t = Tech(name=name.strip())
            for l in lines[1:]:
                m = re.match(r"-\s*([a-z_]+):\s*(.*)", l)
                if not m:
                    continue
                k, v = m.group(1), m.group(2).strip()
                if k == "class":
                    t.cls = v.lower()
                elif k in ("vault", "when", "probe", "detect", "sev", "requires"):
                    setattr(t, k, v)
            t.vault = t.vault or os.path.basename(p)
            techs.append(t)
    return techs


# ── Data structures ────────────────────────────────────────────────────────

@dataclass
class ProbeResult:
    tech: str
    target: str                 # app label (url or vhost:port label)
    finding: str
    evidence: str = ""          # matched signature / response snippet
    sev: str = "med"
    vault: str = ""


@dataclass
class ManualLead:
    tech: str
    target: str
    command: str                # exact vault command ({URL} substituted)
    why: str                    # trigger reason
    sev: str = "med"
    vault: str = ""


@dataclass
class AppSurface:
    """What we know about one web app (IP url or vhost) to probe."""
    url: str                    # base url over IP (http://ip:port)
    host_header: Optional[str]  # vhost name, None = default site
    label: str
    tech: List[str] = field(default_factory=list)
    params: List[str] = field(default_factory=list)
    forms: List[dict] = field(default_factory=list)
    paths: List[str] = field(default_factory=list)
    title: str = ""
    html: str = ""


def _sess() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": "StrikeARC-Enum/10.4"})
    s.verify = False
    return s


def _get(s, url, timeout=8, headers=None):
    h = {"Host": None} if False else None
    try:
        return s.get(url, timeout=timeout, allow_redirects=False, headers=headers)
    except requests.RequestException:
        return None


def _hh(app: AppSurface) -> Dict[str, str]:
    return {"Host": app.host_header} if app.host_header else {}


def _wildcard_baseline(s, app: AppSurface):
    """Fetch a random control path; returns (status, size) the server hands
    out for ANY path (wildcard default site), or None if not wildcarded."""
    r = _get(s, app.url + "strk-nonexist-" + str(int(time.time()) % 99991),
             headers=_hh(app))
    if not r:
        return None
    if r.status_code == 200:
        return (200, len(r.text or ""))
    return None


def _split_qs(url: str) -> Tuple[str, Dict[str, str]]:
    base, _, sep = url.partition("?")
    qs = {}
    for pair in sep.split("&"):
        if "=" in pair:
            k, _, v = pair.partition("=")
            qs[k] = v
    return base, qs


def _rebuild(base: str, qs: Dict[str, str]) -> str:
    return base + "?" + "&".join(f"{k}={v}" for k, v in qs.items())


# ── Detection signatures (DBMS errors per SQL Attacks/03) ─────────────────

SQL_ERRORS = [
    ("MySQL", r"SQL syntax.*?MySQL|Warning.*?mysql_[a-z]|MySQLSyntaxError"),
    ("PostgreSQL", r"PostgreSQL.*?ERROR|query failed:.*?pg_"),
    ("MSSQL", r"Microsoft SQL|OLE DB|SQL Server.*?(Native Client|error)"),
    ("Oracle", r"ORA-\d{5}|Oracle.*?error"),
    ("SQLite", r"SQLite3?::|SQLITE_[A-Z]+|\[SQLITE_"),
]

CMDI_UID = re.compile(r"uid=\d+\(\w+\)\s+gid=\d+")


# ── Auto probes (enum-safe detection) ─────────────────────────────────────

def probe_sqli_errors(s, app, out, stats):
    """Error-based SQLi detection (SQL Attacks/03): append quote payload to
    each param, scan response for DBMS error signatures."""
    if not app.params:
        return
    base, qs0 = _split_qs(app.url)
    for p in app.params[:6]:
        if p not in qs0:
            qs0[p] = "1"
        qs = dict(qs0)
        qs[p] = "'\"(" if qs[p] in ("1", "") else qs[p] + "'\"("
        r = _get(s, _rebuild(base, qs), headers=_hh(app))
        if not r:
            continue
        for dbms, sig in SQL_ERRORS:
            m = re.search(sig, r.text or "", re.I)
            if m:
                out.append(ProbeResult(
                    tech="sqli-error", target=app.label,
                    finding=f"{dbms} SQL error on param '{p}' — SQLi likely",
                    evidence=m.group(0)[:80], sev="high",
                    vault="SQL Attacks/03-SQLi-Fundamentals.md"))
                break


def probe_sqli_boolean(s, app, out, stats):
    """Boolean-based detection (SQL Attacks/04): compare TRUE vs FALSE
    payloads — size/status delta indicates subverted logic."""
    if not app.params:
        return
    base, qs0 = _split_qs(app.url)
    for p in app.params[:4]:
        if p not in qs0:
            continue
        true_qs = dict(qs0); true_qs[p] = f"{qs0[p]} AND 1=1"
        false_qs = dict(qs0); false_qs[p] = f"{qs0[p]} AND 1=2"
        r1 = _get(s, _rebuild(base, true_qs), headers=_hh(app))
        r2 = _get(s, _rebuild(base, false_qs), headers=_hh(app))
        if not (r1 and r2):
            continue
        if r1.status_code == r2.status_code and abs(
                len(r1.text or "") - len(r2.text or "")) > 60:
            out.append(ProbeResult(
                tech="sqli-boolean", target=app.label,
                finding=f"TRUE/FALSE differential on param '{p}' — boolean SQLi candidate",
                evidence=f"{len(r1.text or '')}b vs {len(r2.text or '')}b",
                sev="high", vault="SQL Attacks/04-Subverting-Query-Logic.md"))


def probe_cmdi(s, app, out, stats):
    """Command injection canary (Command Injection/02): ;id / newline / $()
    separators, look for uid= gid= echo. Benign."""
    if not app.params:
        return
    base, qs0 = _split_qs(app.url)
    for p in app.params[:4]:
        for canary in (";id", "%0aid", "$(id)", "|id"):
            qs = dict(qs0)
            if p not in qs:
                qs[p] = "1"
            qs[p] = f"{qs[p]}{canary}"
            r = _get(s, _rebuild(base, qs), headers=_hh(app))
            m = CMDI_UID.search(r.text or "") if r else None
            if m:
                out.append(ProbeResult(
                    tech="cmdi-canary", target=app.label,
                    finding=f"Command injection via '{canary}' on param '{p}'",
                    evidence=m.group(0), sev="high",
                    vault="Command Injection/02-Detection-and-Injection-Operators.md"))
                return


def probe_xss_reflected(s, app, out, stats):
    """Reflected-XSS canary (XSS/03+05): marker reflected unescaped."""
    if not app.params:
        return
    base, qs0 = _split_qs(app.url)
    marker = "strk7x"
    for p in app.params[:4]:
        qs = dict(qs0)
        if p not in qs:
            qs[p] = "1"
        qs[p] = f"<h1>{marker}</h1>"
        r = _get(s, _rebuild(base, qs), headers=_hh(app))
        if r and f"<h1>{marker}</h1>" in (r.text or ""):
            out.append(ProbeResult(
                tech="xss-reflected", target=app.label,
                finding=f"'{p}' reflects raw HTML — reflected XSS candidate",
                evidence=f"<h1>{marker}</h1> echoed", sev="med",
                vault="XSS/XSS-03-Reflected-XSS.md"))
            return


def probe_lfi(s, app, out, stats):
    """LFI detection (File Inclusion/02+03): traversal to /etc/passwd on
    path-like params; php://filter read of index page (04)."""
    if not app.params:
        return
    base, qs0 = _split_qs(app.url)
    pathish = [p for p in app.params
               if p.lower() in ("page", "file", "path", "doc", "cat", "include",
                                "view", "show", "template", "load", "lang")
               or any(k in p.lower() for k in ("file", "page", "path", "view"))]
    for p in pathish[:3]:
        for depth in ("", "../", "..%2f"):
            trav = (depth + "../" * 6) + "etc/passwd"
            qs = dict(qs0)
            qs[p] = trav
            r = _get(s, _rebuild(base, qs), headers=_hh(app))
            if r and re.search(r"root:x:0:0:", r.text or ""):
                out.append(ProbeResult(
                    tech="lfi-traversal", target=app.label,
                    finding=f"LFI: '{p}' reads /etc/passwd",
                    evidence="root:x:0:0: echoed", sev="high",
                    vault="File Inclusion/02-LFI-Basics.md"))
                break
        # php://filter — read page source without execution (04)
        if "php" in " ".join(app.tech).lower() or app.host_header is None:
            for page in ("index.php", "index"):
                qs = dict(qs0)
                qs[p] = (f"php://filter/convert.base64-encode/resource={page}")
                r = _get(s, _rebuild(base, qs), headers=_hh(app))
                if r and re.search(r"[A-Za-z0-9+/]{80,}={0,2}", r.text or "") \
                        and "passwd" not in (r.text or "")[:200]:
                    out.append(ProbeResult(
                        tech="lfi-php-filter", target=app.label,
                        finding=f"php://filter works on '{p}' — arbitrary source read",
                        sev="high",
                        vault="File Inclusion/04-PHP-Filters-and-Wrappers.md"))
                    break


def probe_verb_tampering(s, app, out, stats):
    """HTTP verb tampering (Web Attacks/01): OPTIONS body — methods beyond
    GET/HEAD/POST/OPTIONS on interesting endpoints."""
    for path in app.paths[:8]:
        if path.endswith((".php", ".aspx", ".jsp")) or path in ("/api", "/login"):
            r = _get(s, app.url + path if path.startswith("/") else app.url + "/" + path,
                     headers=_hh(app))
            if not r:
                continue
            allow = (r.headers.get("Allow") or "")
            extra = [m for m in re.split(r"[,\s]+", allow.upper())
                     if m and m not in ("GET", "HEAD", "POST", "OPTIONS")]
            if extra:
                out.append(ProbeResult(
                    tech="verb-tampering", target=app.label,
                    finding=f"{path}: Allow includes {','.join(extra)} — verb tampering target",
                    evidence=f"Allow: {allow}", sev="med",
                    vault="Web Attacks/01-HTTP-Verb-Tampering.md"))
                return


def probe_cors(s, app, out, stats):
    """CORS misconfig (Web Recon/08 header review): reflect Origin wildcard."""
    r = _get(s, app.url, headers={**_hh(app), "Origin": "https://evil.example"})
    if r:
        acao = r.headers.get("Access-Control-Allow-Origin") or ""
        acac = r.headers.get("Access-Control-Allow-Credentials") or ""
        if acao in ("*", "https://evil.example") or (
                acao and "evil.example" in acao):
            out.append(ProbeResult(
                tech="cors-misconfig", target=app.label,
                finding=f"CORS reflects arbitrary Origin ('{acao}'"
                        f"{' credentials=true' if acac == 'true' else ''})",
                evidence=f"ACAO={acao} ACAC={acac}", sev="med",
                vault="Web Recon/08-Fingerprinting.md"))


def probe_idor(s, app, out, stats):
    """IDOR detection (Web Attacks/02): sequential id swap diff on numeric
    params — different content for different ids (same length => fishy too)."""
    base, qs0 = _split_qs(app.url)
    for p, v in list(qs0.items())[:4]:
        if not re.fullmatch(r"\d{1,4}", v or ""):
            continue
        r_own = _get(s, _rebuild(base, qs0), headers=_hh(app))
        qs2 = dict(qs0)
        qs2[p] = str(int(v) + 1)
        r_other = _get(s, _rebuild(base, qs2), headers=_hh(app))
        if not (r_own and r_other):
            continue
        if r_own.status_code == 200 == r_other.status_code and \
                (r_own.text or "") != (r_other.text or ""):
            out.append(ProbeResult(
                tech="idor-candidate", target=app.label,
                finding=f"'{p}={v}+1' returns different data — IDOR candidate",
                evidence=f"{len(r_own.text or '')}b vs {len(r_other.text or '')}b",
                sev="med", vault="Web Attacks/02-IDOR.md"))
            return


def _is_real_hit(app: AppSurface, r) -> bool:
    """True if response r is NOT just the wildcard default page."""
    wc = app.__dict__.get("_wc") if hasattr(app, "__dict__") else None
    if not wc or not r:
        return True
    status, size = wc
    if r.status_code == status and abs(len(r.text or "") - size) < 30:
        return False   # identical to wildcard baseline — junk
    return True


def probe_robots_sitemap(s, app, out, stats):
    """robots.txt / sitemap.xml harvest (Web Recon/09)."""
    for f in ("robots.txt", "sitemap.xml"):
        r = _get(s, app.url + f, headers=_hh(app))
        if r and r.status_code == 200 and len(r.text or "") > 10:
            disallows = re.findall(r"(?:Disallow|Allow):\s*(\S+)", r.text or "", re.I)
            if disallows:
                out.append(ProbeResult(
                    tech="robots-harvest", target=app.label,
                    finding=f"{f}: {len(disallows)} entries",
                    evidence=", ".join(disallows[:8]), sev="low",
                    vault="Web Recon/09-Crawling.md"))


def probe_js_endpoints(s, app, out, stats):
    """JS endpoint harvest (Web Recon/09 crawling): api paths + secrets
    patterns in inline/linked JS."""
    html = app.html or ""
    if not html:
        r = _get(s, app.url, headers=_hh(app))
        html = (r.text or "") if r else ""
    eps = set()
    for m in re.finditer(r"""['"`](/(?:api|ajax|json|rest)[/\w.-]*)['"`]""", html):
        eps.add(m.group(1))
    if eps:
        out.append(ProbeResult(
            tech="js-endpoints", target=app.label,
            finding=f"{len(eps)} API endpoint(s) in page JS",
            evidence=", ".join(sorted(eps)[:8]), sev="low",
            vault="Web Recon/09-Crawling.md"))


def probe_cms_paths(s, app, out, stats):
    """CMS/app-specific path probing (Common Applications/*): probe the
    canonical enum paths for whatever the fingerprint says."""
    t = " ".join(app.tech).lower()
    checks: List[Tuple[str, str, str]] = []      # (path, finding, vault note)
    if "wordpress" in t:
        checks += [("/wp-links-opml.php", "WordPress version (wp-links-opml)", "Common Applications/02-WordPress.md"),
                   ("/xmlrpc.php", "xmlrpc interface exposed", "Common Applications/02-WordPress.md"),
                   ("/wp-login.php", "wp-login exposed", "Common Applications/02-WordPress.md"),
                   ("/wp-content/uploads/", "uploads dir listing", "Common Applications/02-WordPress.md")]
    if "drupal" in t:
        checks += [("/CHANGELOG.txt", "Drupal changelog (version)", "Common Applications/04-Drupal.md"),
                   ("/user/login", "Drupal login page", "Common Applications/04-Drupal.md"),
                   ("/sites/default/settings.php", "Drupal settings path", "Common Applications/04-Drupal.md")]
    if "joomla" in t:
        checks += [("/administrator/", "Joomla admin panel", "Common Applications/03-Joomla.md"),
                   ("/README.txt", "Joomla readme (version)", "Common Applications/03-Joomla.md")]
    if "tomcat" in t or "jsp" in t:
        checks += [("/manager/html", "Tomcat manager", "Common Applications/05-Tomcat.md"),
                   ("/host-manager/html", "Tomcat host-manager", "Common Applications/05-Tomcat.md")]
    if "jenkins" in t:
        checks += [("/script", "Jenkins script console", "Common Applications/06-Jenkins.md"),
                   ("/login", "Jenkins login", "Common Applications/06-Jenkins.md")]
    if "gitlab" in t or "gitlab" in app.label:
        checks += [("/users/sign_in", "GitLab sign-in", "Common Applications/10-GitLab.md"),
                   ("/help", "GitLab version page", "Common Applications/10-GitLab.md"),
                   ("/explore", "GitLab explore (public projects)", "Common Applications/10-GitLab.md")]
    if "splunk" in t:
        checks += [("/en-US/account/login", "Splunk login", "Common Applications/07-Splunk.md")]
    if "osticket" in t or "support" in t.lower():
        checks += [("/scp/", "osTicket staff panel", "Common Applications/09-osTicket.md"),
                   ("/open.php", "osTicket new ticket", "Common Applications/09-osTicket.md")]
    if "coldfusion" in t:
        checks += [("/CFIDE/administrator/", "ColdFusion admin", "Common Applications/13-ColdFusion.md")]
    if "phpmyadmin" in t or "adminer" in t:
        checks += [("/index.php", "DB admin panel", "Common Applications/01-Application-Discovery-Enumeration.md")]
    for path, finding, vault in checks[:10]:
        r = _get(s, app.url + path, headers=_hh(app))
        if r and r.status_code == 200 and len(r.text or "") > 50 and _is_real_hit(app, r):
            out.append(ProbeResult(
                tech="cms-path", target=app.label,
                finding=f"{finding}: {path} (200, {len(r.text or '')}b)",
                evidence=f"status={r.status_code}", sev="med", vault=vault))


def probe_git_exposure(s, app, out, stats):
    """.git exposure (Common Applications/01 + Web Recon): .git/HEAD readable
    → full source disclosure lead."""
    r = _get(s, app.url + ".git/HEAD", headers=_hh(app))
    if r and r.status_code == 200 and "ref:" in (r.text or ""):
        out.append(ProbeResult(
            tech="git-exposure", target=app.label,
            finding=".git/HEAD readable — source disclosure (manual: git-dumper)",
            evidence=(r.text or "").strip()[:40], sev="high",
            vault="Common Applications/01-Application-Discovery-Enumeration.md"))


def probe_backup_files(s, app, out, stats):
    """Common backup/config leftovers (File Inclusion/06 + Common Apps/01)."""
    for f in ("backup.zip", "www.zip", "site.zip", "backup.tar.gz",
              ".env", "web.config.bak", "index.php.bak", "index.php~"):
        r = _get(s, app.url + f, headers=_hh(app))
        if r and r.status_code == 200 and len(r.text or "") > 20 and _is_real_hit(app, r):
            out.append(ProbeResult(
                tech="backup-exposure", target=app.label,
                finding=f"{f} present (200, {len(r.text or '')}b)",
                sev="high" if f in (".env", "backup.zip", "www.zip") else "med",
                vault="Common Applications/01-Application-Discovery-Enumeration.md"))
            return


def probe_uploads_dir(s, app, out, stats):
    """Upload dir + upload forms (File Upload/01+02)."""
    for d in ("uploads/", "upload/", "files/", "upfiles/"):
        r = _get(s, app.url + d, headers=_hh(app))
        if r and r.status_code == 200 and "index" not in (r.text or "").lower()[:200] and _is_real_hit(app, r):
            if re.search(r"<a href=", r.text or ""):
                out.append(ProbeResult(
                    tech="uploads-listing", target=app.label,
                    finding=f"{d} directory listing enabled",
                    sev="med", vault="File Upload/02-Absent-Validation-and-Exploitation.md"))
                return
    if app.forms:
        for fm in app.forms:
            if str(fm.get("action", "")).lower().find("upload") >= 0 or \
                    any("file" in str(f).lower() for f in fm.get("fields", [])):
                out.append(ProbeResult(
                    tech="upload-form", target=app.label,
                    finding=f"upload form at {fm.get('action','?')} — test bypasses",
                    sev="med", vault="File Upload/04-Blacklist-Filters.md"))
                return


AUTO_PROBES = [
    ("sqli-errors", probe_sqli_errors),
    ("sqli-boolean", probe_sqli_boolean),
    ("cmdi", probe_cmdi),
    ("xss-reflected", probe_xss_reflected),
    ("lfi", probe_lfi),
    ("verb-tampering", probe_verb_tampering),
    ("cors", probe_cors),
    ("idor", probe_idor),
    ("robots", probe_robots_sitemap),
    ("js-endpoints", probe_js_endpoints),
    ("cms-paths", probe_cms_paths),
    ("git", probe_git_exposure),
    ("backups", probe_backup_files),
    ("uploads", probe_uploads_dir),
]


# ── Manual lead generation (exact vault commands) ─────────────────────────

def _substitute(cmd: str, app: AppSurface) -> str:
    cmd = cmd.replace("{TARGET}", app.host_header or app.url.split("//")[1].split("/")[0].split(":")[0])
    cmd = cmd.replace("{URL}", app.url.rstrip("/") + "/")
    return cmd


def manual_leads_for_app(app: AppSurface, techs: List[Tech],
                         auto_results: List[ProbeResult]) -> List[ManualLead]:
    """Match vault manual techniques against this app's surface."""
    leads: List[ManualLead] = []
    seen, uniq = set(), []
    t_all = " ".join(app.tech).lower()
    has_params = bool(app.params)
    has_forms = bool(app.forms)
    hit_techs = {r.tech for r in auto_results}

    for t in techs:
        if t.is_auto or not t.probe:
            continue
        if t.requires and t.requires.lower() not in t_all:
            continue
        when = (t.when or "").lower()
        triggered, why = False, ""
        if "param" in when and has_params:
            triggered, why = True, "URL parameters present"
        elif "form" in when and has_forms:
            triggered, why = True, "HTML forms present"
        elif "sqli" in when and ("sqli-error" in hit_techs or "sqli-boolean" in hit_techs):
            triggered, why = True, "SQLi detection confirmed"
        elif "xss" in when and ("xss-reflected" in hit_techs or has_params):
            triggered, why = True, "XSS candidate surface"
        elif "upload" in when and ("upload-form" in hit_techs or "uploads-listing" in hit_techs):
            triggered, why = True, "upload surface found"
        elif "wordpress" in when and "wordpress" in t_all:
            triggered, why = True, "WordPress fingerprint"
        elif any(k in when for k in ("drupal", "joomla", "tomcat", "jenkins", "gitlab", "splunk", "osticket")) \
                and any(k in t_all or k in app.label.lower() for k in
                        ("drupal", "joomla", "tomcat", "jenkins", "gitlab", "splunk", "osticket")):
            triggered, why = True, "app fingerprint match"
        elif when in ("", "any") or "always" in when:
            triggered, why = True, "applies to any web app"
        if not triggered:
            continue
        # dedup + noise control: max 6 manual leads per app, sev-ranked
        lead = ManualLead(
            tech=t.name, target=app.label,
            command=_substitute(t.probe, app), why=why,
            sev=t.sev, vault=t.vault)
        key = (lead.tech, lead.target)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(lead)
    sev_rank = {"high": 0, "med": 1, "low": 2}
    uniq.sort(key=lambda l: sev_rank.get(l.sev, 3))
    return uniq[:8]


# ── Orchestration ──────────────────────────────────────────────────────────

def harvest_params(s, app: AppSurface) -> None:
    """Populate app.params/forms from the live page: form fields (XSS/05
    input inventory) + links with query strings from landing + top paths."""
    try:
        from tools.web_enum import discover_forms
        app.forms = discover_forms(app.url, host_header=app.host_header) or []
        for fm in app.forms:
            for f in fm.get("fields", []) or []:
                if isinstance(f, str) and f and f not in app.params:
                    app.params.append(f)
    except Exception:
        pass
    pages = [app.url] + [app.url + p.lstrip("/") for p in app.paths[:6]
                         if isinstance(p, str) and p]
    for u in pages:
        r = _get(s, u, headers=_hh(app))
        if not r:
            continue
        if not app.html:
            app.html = r.text or ""
        for m in re.finditer(r'[?&]([a-z_][a-z0-9_]{1,20})=[^&#\s"\']', r.text or "", re.I):
            if m.group(1).lower() not in app.params:
                app.params.append(m.group(1).lower())


def probe_web_app(app: AppSurface, techs: Optional[List[Tech]] = None,
                  timeout_s: int = 90) -> Tuple[List[ProbeResult], List[ManualLead]]:
    """Run the full auto battery + generate manual leads for one app.
    Time-boxed: returns whatever completed within timeout_s."""
    if techs is None:
        techs = parse_tech_specs()
    s = _sess()
    out: List[ProbeResult] = []
    stats = {}
    deadline = time.time() + timeout_s

    harvest_params(s, app)
    started = time.time()
    # v10.4.1: calibrate wildcard once per app — all path probes compare
    # against it so a default-site-catches-all app can't fake 200s.
    wc = _wildcard_baseline(s, app)
    if wc:
        app.__dict__["_wc"] = wc
    for name, fn in AUTO_PROBES:
        if time.time() > deadline:
            out.append(ProbeResult(tech="budget", target=app.label,
                                   finding=f"probe budget hit after '{name}'",
                                   sev="low"))
            break
        try:
            fn(s, app, out, stats)
        except Exception as e:  # a probe may never break the battery
            out.append(ProbeResult(tech="probe-error", target=app.label,
                                   finding=f"{name}: {type(e).__name__}: {e}"[:120],
                                   sev="low"))
    leads = manual_leads_for_app(app, techs, out)
    return out, leads


def surfaces_from_host(host: dict, target: str) -> List[AppSurface]:
    """Build AppSurface list from a host state dict: IP web ports + vhosts."""
    surfaces: List[AppSurface] = []
    services = host.get("services") or {}

    def _web_ports():
        for port, svc in services.items():
            name = (svc.get("service") or "").lower()
            if _is_web(name, port):
                scheme = "https" if ("ssl" in name or int(port) in (443, 8443)) else "http"
                yield int(port), scheme

    def _is_web(name, port):
        web_ports = {80, 443, 8000, 8080, 8443, 5000, 3000, 8888}
        if int(port) in {993, 995, 465, 587}:
            return False
        return int(port) in web_ports or any(
            k in name for k in ("http", "www", "ssl/https", "https"))

    apps_by_url = {a.get("url", ""): a for a in host.get("web_apps", [])}
    for port, scheme in _web_ports():
        base = f"{scheme}://{target}:{port}/"
        wa = apps_by_url.get(base) or {}
        surfaces.append(AppSurface(
            url=base, host_header=None, label=f"{target}:{port}",
            tech=wa.get("technologies") or [],
            paths=[d.get("path", "") for d in (wa.get("directories") or [])
                   if isinstance(d, dict)],
            title=wa.get("title") or "", html=""))
    for vh in host.get("vhosts") or []:
        name = vh.get("name") if isinstance(vh, dict) else vh
        if not name:
            continue
        port = int(vh.get("port", 80)) if isinstance(vh, dict) else 80
        scheme = (vh.get("scheme", "http") if isinstance(vh, dict) else "http")
        vh_url = f"{scheme}://{name}:{port}/"
        ip_base = f"{scheme}://{target}:{port}/"
        wa = apps_by_url.get(vh_url) or {}
        surfaces.append(AppSurface(
            url=ip_base, host_header=name, label=f"{name}:{port}",
            tech=wa.get("technologies") or [],
            paths=[d.get("path", "") for d in (wa.get("directories") or [])
                   if isinstance(d, dict)],
            title=wa.get("title") or "", html=""))
    return surfaces
