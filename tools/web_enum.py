"""
StrikeARC — Web Application Enumeration
=======================================
Directory busting, form/API discovery, fingerprinting, config file detection.
NO exploitation — only passive and active enumeration.
"""

import re
import uuid
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

from utils import run_command, http_get, http_post, extract_emails, swallow


def directory_bust(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str = "php,html,txt,bak,old,json,xml,yml,yaml,env,git",
    timeout: int = 120,
) -> List[dict]:
    """Directory enumeration using gobuster.

    BUGFIX (run 11): added wildcard calibration. Hosts that return 200
    for EVERY path (soft-404 / wildcard vhosts, e.g. .60/.64:8000 in the
    Aug 28 run) previously poisoned state with ~98k "directories" per
    host (5.7 MB each). Now a random nonexistent path is baselined
    first; if it 200s, the service is marked wildcard and only paths
    whose size DIFFERS from the wildcard baseline are kept.
    """
    parsed = urlparse(url)
    host = parsed.hostname or url

    # ── wildcard calibration ────────────────────────────────────────
    wildcard = False
    baseline_size = -1
    try:
        import requests as _rq
        probe_url = f"{parsed.scheme}://{parsed.netloc}/{uuid.uuid4().hex}{uuid.uuid4().hex}"
        cal = _rq.get(probe_url, timeout=8, verify=False,
                      headers={"User-Agent": "StrikeARC"})
        if cal.status_code == 200:
            wildcard = True
            baseline_size = len(cal.text or "")
    except Exception:
        wildcard = False
    if wildcard:
        print(f"    [!] WILDCARD: {url} returns 200 for random paths "
              f"(baseline {baseline_size}b) — filtering to size-differential hits only")

    cmd = (
        f"gobuster dir -u '{url}' -w '{wordlist}' "
        f"-x '{extensions}' -t 30 -k --no-error "
        f"-b 404 -o /dev/stdout 2>/dev/null"
    )
    result = run_command(cmd, timeout=timeout)

    dirs = []
    if result["stdout"]:
        for line in result["stdout"].strip().split("\n"):
            # gobuster output: /path (Status: 200) [Size: 1234]
            m = re.match(r"^(.+?)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]", line.strip())
            if m:
                path = m.group(1).strip()
                status = int(m.group(2))
                size = int(m.group(3))
                # wildcard host: keep only responses that differ from the
                # soft-404 baseline (status differs OR size differs >5%)
                if wildcard:
                    if status == 200 and baseline_size > 0:
                        if abs(size - baseline_size) <= max(64, baseline_size * 0.05):
                            continue  # identical to soft-404 — skip
                dirs.append({"path": path, "status": status, "size": size})

    # hard cap: never store more than 500 paths per web app (state-size
    # hygiene — 98k-entry lists once crashed analysis context)
    if len(dirs) > 500:
        print(f"    [!] directory_bust: capping {len(dirs)} -> 500 results")
        dirs = dirs[:500]

    return dirs


def discover_forms(url: str) -> List[dict]:
    """Extract all HTML forms from a page."""
    resp = http_get(url)
    if not resp:
        return []

    forms = []
    form_pattern = re.compile(
        r"<form[^>]*action=[\"']?([^\"'>\s]*)[\"']?[^>]*method=[\"']?([^\"'>\s]*)[\"']?[^>]*>(.*?)</form>",
        re.DOTALL | re.IGNORECASE,
    )

    for m in form_pattern.finditer(resp.text):
        action = m.group(1) or url
        method = (m.group(2) or "GET").upper()
        inner = m.group(3)

        # Extract input fields
        inputs = []
        for inp in re.finditer(
            r"<input[^>]*name=[\"']?([^\"'>\s]*)[\"']?[^>]*type=[\"']?([^\"'>\s]*)[\"']?",
            inner, re.IGNORECASE,
        ):
            inputs.append({"name": inp.group(1), "type": inp.group(2)})
        for inp in re.finditer(
            r"<input[^>]*type=[\"']?([^\"'>\s]*)[\"']?[^>]*name=[\"']?([^\"'>\s]*)[\"']?",
            inner, re.IGNORECASE,
        ):
            inputs.append({"name": inp.group(2), "type": inp.group(1)})
        for sel in re.finditer(
            r"<(?:select|textarea)[^>]*name=[\"']?([^\"'>\s]*)[\"']?",
            inner, re.IGNORECASE,
        ):
            inputs.append({"name": sel.group(1), "type": "select/textarea"})

        full_action = urljoin(url, action)
        forms.append({
            "action": full_action,
            "method": method,
            "fields": list({f["name"] for f in inputs}),
            "raw_fields": inputs,
        })

    return forms


def api_enumerate(url: str) -> dict:
    """Discover API endpoints, swagger docs, GraphQL."""
    result = {"endpoints": [], "swagger": None, "graphql": False}

    # Check common API discovery paths
    api_paths = [
        "/api", "/api/v1", "/api/v2", "/api/users", "/api/status",
        "/swagger.json", "/swagger/v1/swagger.json", "/api-docs",
        "/openapi.json", "/openapi.yaml", "/graphql", "/graphiql",
        "/api/swagger.json", "/docs", "/redoc",
    ]

    for path in api_paths:
        test_url = urljoin(url, path)
        resp = http_get(test_url, timeout=5)
        if resp and resp.status_code == 200:
            content = resp.text[:500].lower()
            if "swagger" in path or "openapi" in path:
                result["swagger"] = test_url
            elif "graphql" in path:
                if "data" in content or "query" in content or "__schema" in content:
                    result["graphql"] = True
                    result["endpoints"].append({"url": test_url, "type": "graphql"})
            elif "/api" in path:
                result["endpoints"].append({
                    "url": test_url,
                    "status": resp.status_code,
                    "size": len(resp.text),
                    "auth": resp.headers.get("WWW-Authenticate") is not None,
                })

    return result


def fingerprint_tech(url: str) -> dict:
    """Detect web technologies, frameworks, and CMS."""
    resp = http_get(url)
    if not resp:
        return {}

    tech = []
    headers = dict(resp.headers)
    html = resp.text[:5000]
    html_lower = html.lower()

    # Server header
    server = headers.get("Server", "")
    if server:
        tech.append(f"Server: {server}")

    # X-Powered-By
    powered_by = headers.get("X-Powered-By", "")
    if powered_by:
        tech.append(f"Powered-By: {powered_by}")

    # Frameworks
    if "wordpress" in html_lower or "wp-content" in html_lower:
        tech.append("WordPress")
    if "joomla" in html_lower:
        tech.append("Joomla")
    if "drupal" in html_lower:
        tech.append("Drupal")
    if "laravel" in html_lower:
        tech.append("Laravel")
    if "symfony" in html_lower:
        tech.append("Symfony")
    if "django" in html_lower:
        tech.append("Django")
    if "flask" in html_lower:
        tech.append("Flask")
    if "express" in headers.get("X-Powered-By", "").lower():
        tech.append("Express.js")
    if "asp.net" in html_lower or "__viewstate" in html_lower:
        tech.append("ASP.NET")
    if "nextcloud" in html_lower:
        tech.append("Nextcloud")
    if "jenkins" in html_lower:
        tech.append("Jenkins")
    if "gitlab" in html_lower:
        tech.append("GitLab")
    if "grafana" in html_lower:
        tech.append("Grafana")

    # JS frameworks
    if "react" in html_lower or "react-dom" in html_lower:
        tech.append("React")
    if "vue" in html_lower or "vue.js" in html_lower:
        tech.append("Vue.js")
    if "angular" in html_lower:
        tech.append("Angular")
    if "jquery" in html_lower:
        m = re.search(r"jquery[.-](\d+\.\d+\.\d+)", html_lower)
        if m:
            tech.append(f"jQuery {m.group(1)}")
        else:
            tech.append("jQuery")

    # CSS frameworks
    if "bootstrap" in html_lower:
        tech.append("Bootstrap")
    if "tailwind" in html_lower:
        tech.append("Tailwind CSS")

    # PHP
    if headers.get("Set-Cookie", "").startswith("PHPSESSID"):
        tech.append("PHP")
    if ".php" in html_lower:
        tech.append("PHP")

    # Title
    title_match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    title = title_match.group(1).strip() if title_match else ""

    # Security headers
    security_headers = {}
    for h in ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
              "Strict-Transport-Security", "X-XSS-Protection"]:
        if h in headers:
            security_headers[h] = headers[h]

    return {
        "technologies": list(set(tech)),
        "title": title,
        "server": server,
        "security_headers": security_headers,
        "cookies": [c.split("=")[0] for c in headers.get("Set-Cookie", "").split(";")],
    }


def check_config_files(url: str) -> List[dict]:
    """Check for exposed configuration and backup files."""
    findings = []
    config_paths = [
        "/.env", "/config.php", "/configuration.php", "/wp-config.php",
        "/web.config", "/database.yml", "/config/database.yml",
        "/.git/config", "/.git/HEAD", "/backup.sql", "/dump.sql",
        "/composer.json", "/package.json", "/Gemfile.lock",
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        "/.well-known/security.txt", "/server-status",
        "/phpinfo.php", "/info.php", "/test.php",
        "/.htaccess", "/.htpasswd", "/id_rsa", "/id_dsa",
        "/debug", "/debug.log", "/error.log", "/access.log",
        "/api/config", "/system/info", "/actuator", "/actuator/env",
        "/actuator/health", "/metrics", "/health",
        "/backup/", "/backups/", "/old/", "/tmp/",
        "/.svn/entries", "/.svn/wc.db",
        "/WEB-INF/web.xml", "/META-INF/context.xml",
    ]

    for path in config_paths:
        test_url = urljoin(url, path)
        resp = http_get(test_url, timeout=5, allow_redirects=False)
        if resp and resp.status_code == 200 and len(resp.text) > 10:
            # Don't report empty or default pages
            content_preview = resp.text[:200].lower()
            if "<!doctype html" in content_preview and len(resp.text) < 500:
                continue  # Probably a redirect/default page

            severity = "info"
            content_type = resp.headers.get("Content-Type", "")

            # High-value findings
            if any(kw in path for kw in [".env", "config", "wp-config", ".git",
                                         "backup", "dump", "id_rsa", ".htpasswd"]):
                severity = "high"
            elif any(kw in path for kw in ["phpinfo", "info.php", "server-status",
                                           "actuator/env"]):
                severity = "high"
            elif any(kw in path for kw in ["robots", "sitemap", "composer",
                                           "package.json"]):
                severity = "info"

            # Check for secrets
            if any(kw in resp.text.lower() for kw in
                   ["password", "secret", "api_key", "apikey", "token",
                    "credential", "private_key"]):
                severity = "critical"

            findings.append({
                "path": path,
                "status": resp.status_code,
                "size": len(resp.text),
                "severity": severity,
                "content_type": content_type,
                "preview": resp.text[:100],
            })

    return findings


def check_sqli_point(url: str, forms: List[dict]) -> List[dict]:
    """PASSIVE SQLi detection — identify potential injection points only.
    Does NOT attempt injection. Identifies parameters that COULD be injectable."""
    findings = []

    # Check URL parameters
    parsed = urlparse(url)
    if parsed.query:
        params = parsed.query.split("&")
        for param in params:
            key = param.split("=")[0]
            # Heuristic: any parameter in URL is a potential injection point
            findings.append({
                "type": "url_param",
                "parameter": key,
                "url": url,
                "method": "GET",
                "note": "URL parameter — potential SQLi/LFI/SSRF target",
            })

    # Check form fields
    for form in forms:
        for field in form.get("fields", []):
            if any(kw in field.lower() for kw in
                   ["user", "name", "email", "search", "id", "page",
                    "query", "q", "sort", "filter", "redirect", "url",
                    "file", "path", "cmd", "debug"]):
                findings.append({
                    "type": "form_field",
                    "parameter": field,
                    "url": form["action"],
                    "method": form["method"],
                    "note": f"Form field '{field}' — potential injection target",
                })

    return findings


def extract_data_from_page(url: str) -> dict:
    """Extract emails, usernames, and interesting data from a page."""
    resp = http_get(url)
    if not resp:
        return {}

    data = {"emails": [], "usernames": [], "comments": [], "interesting": []}

    emails = extract_emails(resp.text)
    data["emails"] = emails

    # HTML comments (may contain developer notes, paths, credentials)
    comments = re.findall(r"<!--(.*?)-->", resp.text, re.DOTALL)
    interesting_comments = [
        c.strip() for c in comments
        if any(kw in c.lower() for kw in
               ["password", "secret", "todo", "fixme", "hack", "debug",
                "credential", "admin", "config", "api", "key", "token"])
    ]
    data["comments"] = interesting_comments

    # JavaScript file references
    js_files = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', resp.text)
    data["js_files"] = list(set(js_files))[:20]

    # Hidden inputs
    hidden = re.findall(
        r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']*)["\'][^>]*value=["\']([^"\']*)["\']',
        resp.text, re.IGNORECASE,
    )
    if hidden:
        data["hidden_fields"] = [{"name": h[0], "value": h[1]} for h in hidden]

    return data


def vhost_bruteforce(
    ip: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    max_time: int = 30,
    extra_domains: List[str] = None,
) -> List[str]:
    """Brute-force virtual hosts on the target IP.

    Uses common vhost prefixes combined with any domains discovered from SSL
    certs or DNS enumeration (``extra_domains``).  Runs in parallel with a
    hard ``max_time`` cap to prevent hangs.
    """
    import time
    from concurrent.futures import ThreadPoolExecutor, as_completed

    domains = set()

    # Cert-derived / discovered domains (high priority)
    if extra_domains:
        for d in extra_domains:
            domains.add(d)
            domains.add(f"www.{d}")

    # Build candidate domain list — include cert-derived domains as suffixes
    base_domains = ["htb", "local", "internal", "corp", "lab", "test"]
    # If we have cert domains, also use them as suffixes for common prefixes
    if extra_domains:
        for d in extra_domains:
            base_domains.append(d)

    try:
        with open(wordlist) as f:
            for i, line in enumerate(f):
                if i > 5000:
                    break
                word = line.strip()
                if word:
                    for suffix in base_domains:
                        domains.add(f"{word}.{suffix}")
    except FileNotFoundError:
        pass

    # Always check common vhosts
    common_vhosts = [
        "www", "admin", "mail", "dev", "test", "staging",
        "api", "vpn", "portal", "blog", "shop", "app",
    ]
    for prefix in common_vhosts:
        for suffix in base_domains:
            domains.add(f"{prefix}.{suffix}")

    # Also try SSL-cert-derived names if available (set by caller)
    candidates = sorted(domains)[:200]

    # Get baseline
    start_time = time.time()
    baseline = http_get(f"http://{ip}", timeout=5, allow_redirects=False)
    baseline_size = len(baseline.text) if baseline else 0
    baseline_status = baseline.status_code if baseline else 0

    discovered = []

    def _check_vhost(domain):
        """Check a single vhost. Returns (domain, status, size) or None."""
        elapsed = time.time() - start_time
        if elapsed > max_time:
            return None
        resp = http_get(
            f"http://{ip}", timeout=3, allow_redirects=False,
            headers={"Host": domain},
        )
        if resp and resp.status_code == 200:
            size = len(resp.text)
            if abs(size - baseline_size) > 100:
                return (domain, size)
        return None

    # Parallel with hard timeout
    try:
        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {pool.submit(_check_vhost, d): d for d in candidates}
            for future in as_completed(futures, timeout=max_time):
                try:
                    result = future.result(timeout=3)
                    if result:
                        domain, size = result
                        discovered.append(domain)
                        print(f"    [+] Vhost: {domain} ({size}b)")
                except Exception as e:
                    swallow(__name__ + ":444", e)
    except Exception:
        # Timeout — we have what we have
        pass

    return discovered


# ── Advanced Web Enumeration ───────────────────────────────────────────

def recursive_directory_bust(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    max_depth: int = 2,
    found_dirs: List[dict] = None,
    _depth: int = 0,
) -> List[dict]:
    """Recursively bust directories — finds /admin/config/ not just /admin/."""
    if _depth >= max_depth:
        return found_dirs or []

    if found_dirs is None:
        found_dirs = []

    dirs = directory_bust(url, wordlist=wordlist)

    for d in dirs:
        found_dirs.append(d)
        # Recurse into directories (not files)
        path = d["path"]
        if d["status"] in (200, 301, 302, 401, 403) and "." not in path.rsplit("/", 1)[-1]:
            subdir_url = f"{url}{path}" + ("" if path.endswith("/") else "/")
            if subdir_url not in str(found_dirs):  # avoid infinite loops
                recursive_directory_bust(
                    subdir_url, wordlist, max_depth, found_dirs, _depth + 1,
                )

    return found_dirs


def analyze_js_files(url: str, js_urls: List[str] = None) -> List[dict]:
    """Download and analyze JS files for API endpoints, secrets, and interesting patterns."""
    findings = []

    # If no JS URLs provided, extract from page
    if not js_urls:
        page_data = extract_data_from_page(url)
        js_urls = page_data.get("js_files", [])

    for js_url in js_urls[:15]:
        full_url = urljoin(url, js_url)
        resp = http_get(full_url, timeout=10)
        if not resp or len(resp.text) < 10:
            continue

        content = resp.text

        # API endpoints
        api_endpoints = set()
        for m in re.finditer(r'["\']/(api/[^"\'>\s]+)["\']', content):
            api_endpoints.add(m.group(1))
        for m in re.finditer(r'["\']/(v[12]/[^"\'>\s]+)["\']', content):
            api_endpoints.add(m.group(1))

        # AJAX URLs
        for m in re.finditer(r'(?:fetch|ajax|axios|\.get|\.post)\s*\(\s*["\']([^"\']+)["\']', content, re.IGNORECASE):
            path = m.group(1)
            if path.startswith("/") or path.startswith("http"):
                api_endpoints.add(path)

        if api_endpoints:
            findings.append({
                "type": "js_api_endpoints",
                "file": js_url,
                "endpoints": list(api_endpoints)[:20],
            })

        # Secrets/tokens
        secret_patterns = [
            (r'(?:api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "API Key"),
            (r'(?:secret|token|auth)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "Secret/Token"),
            (r'(?:password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\']{6,})["\']', "Password"),
            (r'(?:aws_access|aws_secret|stripe|github_token|ghp_)', "Cloud/Service Key"),
            (r'Bearer\s+([A-Za-z0-9_\-\.]{20,})', "JWT/Bearer Token"),
            (r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}', "JWT Token"),
        ]
        for pattern, secret_type in secret_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                findings.append({
                    "type": "js_secret",
                    "file": js_url,
                    "secret_type": secret_type,
                    "preview": str(matches[0])[:50],
                })

        # Source maps (can leak original source)
        if "sourceMappingURL" in content:
            findings.append({
                "type": "js_sourcemap",
                "file": js_url,
                "note": "Source map reference found — may leak original source code",
            })

    return findings


def check_http_methods(url: str) -> dict:
    """Check allowed HTTP methods and override headers."""
    result = {"methods": [], "put_test": None, "cors": None, "headers": {}}

    # OPTIONS method
    resp = http_get(url, timeout=5, allow_redirects=False)
    if resp:
        allow = resp.headers.get("Allow", "")
        if allow:
            result["methods"] = [m.strip() for m in allow.split(",")]

        # X-Powered-By, X-Forwarded-For trust, etc.
        for h in ["X-Powered-By", "X-AspNet-Version", "X-Generator",
                   "X-Runtime", "X-Version", "Via", "X-Cache"]:
            val = resp.headers.get(h)
            if val:
                result["headers"][h] = val

    # Test CORS
    cors_resp = http_get(
        url, timeout=5, allow_redirects=False,
        headers={"Origin": "https://evil.com"},
    )
    if cors_resp:
        acao = cors_resp.headers.get("Access-Control-Allow-Origin", "")
        acac = cors_resp.headers.get("Access-Control-Allow-Credentials", "")
        if acao:
            result["cors"] = {
                "origin": acao,
                "credentials": acac.lower() == "true",
                "reflects": acao == "https://evil.com",
            }

    # Test TRACE
    try:
        import requests as req
        trace_resp = req.request("TRACE", url, timeout=5, verify=False)
        if trace_resp.status_code == 200 and "TRACE" in trace_resp.text:
            result["methods"].append("TRACE (active)")
    except Exception as e:
        swallow(__name__ + ":591", e)

    # Test PUT
    try:
        import requests as req
        put_resp = req.request("PUT", url + "/test_reconarc.txt",
                               data="test", timeout=5, verify=False)
        if put_resp.status_code in (200, 201, 204):
            result["put_test"] = "PUT allowed — potential webshell upload"
    except Exception as e:
        swallow(__name__ + ":601", e)

    return result


def discover_params(url: str, wordlist: str = None) -> List[str]:
    """Discover URL parameters that elicit different responses."""
    common_params = [
        "id", "page", "file", "cmd", "exec", "query", "search", "q",
        "url", "redirect", "next", "target", "path", "template",
        "debug", "test", "admin", "user", "name", "email", "cat",
        "category", "item", "doc", "document", "lang", "load",
        "process", "step", "action", "module", "include", "require",
        "source", "dest", "destination", "callback", "return",
        "image", "img", "download", "view", "profile", "report",
        "token", "key", "auth", "session", "hash", "ref", "refid",
        "order", "sort", "filter", "type", "format", "output",
        "blog_id", "post", "p", "sub", "section", "topic", "forum",
    ]

    found = []
    baseline = http_get(url, timeout=5)
    baseline_size = len(baseline.text) if baseline else 0
    baseline_code = baseline.status_code if baseline else 0

    for param in common_params:
        test_url = f"{url}?{param}=testvalue123"
        resp = http_get(test_url, timeout=5)
        if not resp:
            continue
        # Different response = parameter has effect
        if resp.status_code != baseline_code or abs(len(resp.text) - baseline_size) > 100:
            found.append(param)

    return found


def check_backup_files(url: str, discovered_dirs: List[dict] = None) -> List[dict]:
    """Check for backup files of discovered paths and common source files."""
    findings = []

    # Common backup extensions
    backup_exts = [".bak", ".old", ".orig", ".save", ".swp", ".~",
                   ".copy", ".backup", ".tmp", ".dist", ".1", ".2"]

    # Files to check for backups
    base_files = [
        "index.php", "index.html", "config.php", "wp-config.php",
        "database.yml", "settings.py", ".env", "web.config",
        "application.properties", "appsettings.json",
    ]

    # Also check backups of discovered directories
    if discovered_dirs:
        for d in discovered_dirs[:20]:
            if "." not in d["path"].rsplit("/", 1)[-1]:
                base_files.append(d["path"].rstrip("/") + "/index.php")

    for base_file in base_files:
        for ext in backup_exts:
            test_url = urljoin(url, f"/{base_file}{ext}")
            resp = http_get(test_url, timeout=3, allow_redirects=False)
            if resp and resp.status_code == 200 and len(resp.text) > 10:
                findings.append({
                    "path": f"/{base_file}{ext}",
                    "status": resp.status_code,
                    "size": len(resp.text),
                    "preview": resp.text[:100],
                })

    # Check .git exposure more deeply
    git_files = ["/.git/HEAD", "/.git/config", "/.git/index",
                 "/.git/logs/HEAD", "/.git/refs/heads/master",
                 "/.git/refs/heads/main"]
    for gf in git_files:
        test_url = urljoin(url, gf)
        resp = http_get(test_url, timeout=3, allow_redirects=False)
        if resp and resp.status_code == 200 and len(resp.text) > 5:
            preview = resp.text[:200]
            # Verify it's actually git data
            if "ref:" in preview or "[core]" in preview or "commit" in preview:
                findings.append({
                    "path": gf,
                    "status": 200,
                    "size": len(resp.text),
                    "preview": preview[:100],
                    "type": "git_exposure",
                })

    return findings


def deep_link_crawl(url: str, max_pages: int = 10) -> List[dict]:
    """Crawl linked pages from the homepage to discover more content."""
    from collections import deque

    visited = set()
    queue = deque([(url, 0)])
    discovered = []
    max_depth = 2

    while queue and len(visited) < max_pages:
        current_url, depth = queue.popleft()
        if current_url in visited or depth > max_depth:
            continue
        visited.add(current_url)

        resp = http_get(current_url, timeout=5)
        if not resp or resp.status_code != 200:
            continue

        # Extract links
        links = re.findall(r'href=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
        for link in links:
            full_url = urljoin(current_url, link)
            # Same-origin only
            if urlparse(full_url).netloc == urlparse(url).netloc or full_url.startswith("/"):
                clean_url = urljoin(url, full_url)
                path = urlparse(clean_url).path
                if path not in [d["path"] for d in discovered] and path != "/":
                    discovered.append({
                        "path": path,
                        "found_on": urlparse(current_url).path,
                        "status": resp.status_code,
                    })
                    queue.append((clean_url, depth + 1))

    return discovered
