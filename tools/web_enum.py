"""
ReconARC — Web Application Enumeration
=======================================
Directory busting, form/API discovery, fingerprinting, config file detection.
NO exploitation — only passive and active enumeration.
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

from utils import run_command, http_get, http_post, extract_emails


def directory_bust(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str = "php,html,txt,bak,old,json,xml,yml,yaml,env,git",
    timeout: int = 120,
) -> List[dict]:
    """Directory enumeration using gobuster."""
    parsed = urlparse(url)
    host = parsed.hostname or url

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
                dirs.append({"path": path, "status": status, "size": size})

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
) -> List[str]:
    """Discover virtual hosts via Host header manipulation."""
    # Build a small domain wordlist
    domains = set()
    base_domains = ["htb", "local", "internal", "corp", "lab", "test"]

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

    discovered = []
    baseline = http_get(f"http://{ip}", timeout=5, allow_redirects=False)
    baseline_size = len(baseline.text) if baseline else 0

    for domain in sorted(domains)[:200]:  # Limit to 200
        resp = http_get(
            f"http://{ip}", timeout=5, allow_redirects=False,
            headers={"Host": domain},
        )
        if resp and resp.status_code == 200:
            size = len(resp.text)
            if abs(size - baseline_size) > 100:
                discovered.append(domain)
                print(f"    [+] Vhost: {domain} ({size}b)")

    return discovered
