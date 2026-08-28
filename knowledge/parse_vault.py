#!/usr/bin/env python3
"""Vault Parser — Obsidian vault → StrikeARC technique registry.

Parses the HTB Academy notes vault (~/Documents/Purple-Teaming) into a
structured technique registry consumed by knowledge/retrieval.py at
analyze/exploit time.

Registry schema (knowledge/registry.json):
{
  "generated": "<iso8601>",
  "vault_path": "...",
  "notes": <count>,
  "modules": { "<module>": <count> },
  "techniques": [
    {
      "id": "ad/10-living-off-the-land#kerbrute-user-enum",
      "module": "Active Directory",
      "note": "HTB-Academy/Pentester Path/Active Directory/10 - Living Off The Land.md",
      "title": "Attacking the Domain ... ",
      "tags": [...],                    # from frontmatter
      "headings": [...],                # H2/H3 chain (technique context)
      "trigger": {"services": [...], "keywords": [...], "cves": [...]},
      "commands": [{"lang": "bash", "text": "...", "binaries": [...]}],
      "wikilinks": [...],
      "requirements": ["kerbrute"],     # external binaries referenced
      "text_len": 1234
    }
  ]
}

Design notes:
- Zero LLM: deterministic parse, cheap, reproducible (build once, commit JSON).
- Trigger extraction is keyword-service based; retrieval.py does scoring.
- Vault is read-only; output goes to recon-arc/knowledge/.
"""
from __future__ import annotations

import datetime
import json
import os
import re
import sys
from collections import Counter

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
VAULT_ENV = "OBSIDIAN_VAULT_PATH"
DEFAULT_VAULT = os.path.expanduser("~/Documents/Purple-Teaming")
OUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "registry.json")

# Binaries the agent may be asked to run (superset check against code blocks)
KNOWN_BINARIES = {
    # recon / enum
    "nmap", "gobuster", "ffuf", "feroxbuster", "dirsearch", "nikto", "whatweb",
    "wafw00f", "searchsploit", "nuclei", "dig", "dnsenum", "dnsrecon", "whois",
    "smbclient", "smbmap", "rpcclient", "enum4linux", "enum4linux-ng", "nbtscan",
    "snmpwalk", "onesixtyone", "ldapsearch", "windapsearch", "adidnsdump",
    "showmount", "ftp", "nc", "ncat", "socat", "curl", "wget", "openssl",
    "mysql", "sqsh", "sqlplus", "redis-cli", "mongo", "mongosh", "snmpcheck",
    "crackmapexec", "netexec", "nxc", "proxychains",
    # AD attacks
    "GetUserSPNs.py", "GetNPUsers.py", "secretsdump.py", "ntlmrelayx.py",
    "psexec.py", "wmiexec.py", "smbexec.py", "atexec.py", "getST.py", "getTGT.py",
    "ticketer.py", "rbcd.py", "Get-GPPPassword.py", "findDelegation.py",
    "raiseChild.py", "mssqlclient.py", "goldenPac.py", "keylistattack.py",
    "kerbrute", "responder", "Responder", "certipy", "bloodhound-python",
    "bloodhound", "BloodHound", "SharpHound", "mimikatz", "mimikatz.exe",
    "Rubeus", "rubeus.exe", "pypykatz", "windapsearch",
    # privesc / post
    "linpeas", "winpeas", "linpeas.sh", "winpeas.exe", "peass",
    "GTFOBins", "sudo", "getcap", "setcap", "capsh", "pspy", "strace",
    "PrintSpoofer", "GodPotato", "JuicyPotato", "RoguePotato", "SharpUp",
    "Seatbelt", "PowerUp", "WinPEAS", "accesschk", "accesschk.exe", "icacls",
    "schtasks", "sc", "sc.exe", "reg", "reg.exe", "wmic", "net", "net.exe",
    "netstat", "ss", "lsof", "ps", "tasklist", "dir", "cd", "type", "findstr",
    # creds / cracking
    "hashcat", "john", "cewl", "cupp", "CUPP", "username-anarchy",
    "UsernameAnarchy", "laZagne", "LaZagne", "mimipenguin", "pcredz",
    "Pcredz", "snaffler", "Snaffler", "manspider", "MANSPIDER",
    "SessionGopher", "SharpChromium", "lakitu", "dpapi", "keytabextract",
    "KeyTabExtract",
    # tunnels / pivots
    "chisel", "ligolo-ng", "ligolo", "sshuttle", "plink", "ssh", "scp", "sftp",
    "dnscat2", "ptunnel-ng", "proxifier", "SocksOverRDP",
    # shells / msf
    "msfconsole", "msfvenom", "meterpreter", "msf6", "evil-winrm", "xfreerdp",
    "rdesktop", "powershell", "powershell.exe", "pwsh", "cmd", "cmd.exe",
    "iex", "IEX", "certutil", "bitsadmin", "mshta", "rundll32",
    # misc
    "python3", "python", "gcc", "make", "git", "unzip", "7z", "base64",
    "xxd", "strings", "file", "chmod", "mount", "umount", "tar", "zip",
    "impacket-smbserver", "uploadserver", "impacket-GetUserSPNs",
    "impacket-GetNPUsers", "impacket-secretsdump", "impacket-ntlmrelayx",
    "exploit", "locate", "which", "apt", "apt-get", "pip3", "pip",
    "sqlmap", "hydra", "medusa", "wfuzz", "wpscan", "droopescan",
    "joomscan", "wpscan", "searchsploit", "crackmapexec", "nbtscan",
    "gdb", "gdb-peda", "objdump", "readelf", "nmap", "redis-cli",
    "kubeletctl", "kubectl", "docker", "lxc", "lxd", "screen", "tmux",
    "logrotaten", "logrotate", "tcpdump", "wireshark", "tshark",
    "impacket-psexec", "impacket-wmiexec", "impacket-smbexec",
    "impacket-atexec", "impacket-getST", "impacket-getTGT",
}

# shell builtins — never counted as tool requirements
BUILTIN_TOKENS = {"cd", "ls", "echo", "pwd", "export", "source", "man", "history"}

# Commands never counted as tool requirements (noise)
NOISE_TOKENS = {
    "impacket", "www-data", "htb-student", "pwnbox", "target", "user", "admin",
    "password", "username", "server", "creds", "cred", "site", "search", "info",
    "attack", "exploit", "installed", "name", "windows", "web", "root",
    "get", "service", "workspace", "msfdb", "backup", "attack",
}

# service keyword → canonical service name for trigger matching
SERVICE_MAP = {
    "smb": "smb", "netbios": "smb", "445": "smb", "139": "smb",
    "ldap": "ldap", "ldaps": "ldap", "3268": "ldap", "3269": "ldap", "389": "ldap", "636": "ldap",
    "kerberos": "kerberos", "88": "kerberos", "464": "kerberos", "kdc": "kerberos",
    "winrm": "winrm", "5985": "winrm", "5986": "winrm", "psremoting": "winrm",
    "rdp": "rdp", "3389": "rdp", "freerdp": "rdp",
    "ssh": "ssh", "22": "ssh",
    "ftp": "ftp", "21": "ftp",
    "dns": "dns", "53": "dns", "dig": "dns", "zone transfer": "dns",
    "smtp": "smtp", "25": "smtp", "465": "smtp", "587": "smtp", "vrfy": "smtp",
    "snmp": "snmp", "161": "snmp", "udp/161": "snmp",
    "mssql": "mssql", "1433": "mssql", "sql server": "mssql",
    "mysql": "mysql", "3306": "mysql",
    "oracle": "oracle", "tns": "oracle", "1521": "oracle",
    "nfs": "nfs", "2049": "nfs", "showmount": "nfs",
    "redis": "redis", "6379": "redis",
    "mongodb": "mongodb", "27017": "mongodb", "mongo": "mongodb",
    "http": "http", "https": "http", "web": "http", "80": "http", "8080": "http",
    "443": "http", "8443": "http", "tomcat": "tomcat", "jenkins": "jenkins",
    "gitlab": "gitlab", "wordpress": "wordpress", "wp": "wordpress",
    "drupal": "drupal", "joomla": "joomla", "splunk": "splunk",
    "coldfusion": "coldfusion", "bind9": "dns", "api": "http", "ssl": "ssl",
    "tls": "ssl", "certificate": "ssl", "imaps": "mail", "pop3": "mail",
    "pop3s": "mail", "imap": "mail", "mail": "mail",
    "sip": "sip", "5060": "sip", "rpc": "rpc", "135": "rpc",
    "docker": "docker", "kubernetes": "kubernetes", "kubelet": "kubernetes",
    "elasticsearch": "elasticsearch", "9200": "elasticsearch",
    "ipp": "ipp", "cups": "ipp", "631": "ipp",
    "rsync": "rsync", "873": "rsync", "mqtt": "mqtt", "1883": "mqtt",
    "stomp": "stomp", "61616": "stomp", "git": "git", "9418": "git",
    "vnc": "vnc", "5900": "vnc", "xmpp": "xmpp", "5222": "xmpp",
    "ldap": "ldap", "iis": "iis", "webdav": "webdav",
    "caldav": "caldav", "radicale": "caldav",
}

# technique keywords (lowercase) → technique label
TECHNIQUE_MAP = {
    "kerberoast": "kerberoasting", "kerberoasting": "kerberoasting",
    "as-rep": "as-rep-roasting", "asrep": "as-rep-roasting",
    "dcsync": "dcsync", "dcshadow": "dcshadow",
    "golden ticket": "golden-ticket", "silver ticket": "silver-ticket",
    "diamond ticket": "diamond-ticket", "golden/silver": "ticket-forging",
    "pass-the-hash": "pass-the-hash", "pth": "pass-the-hash",
    "pass-the-ticket": "pass-the-ticket", "ptt": "pass-the-ticket",
    "pass-the-key": "pass-the-key", "overpass-the-hash": "pass-the-key",
    "ntlm relay": "ntlm-relay", "relay": "ntlm-relay", "responder": "llmnr-poisoning",
    "llmnr": "llmnr-poisoning", "nbt-ns": "llmnr-poisoning", "wpad": "wpad-abuse",
    "petitpotam": "petitpotam", "printnightmare": "printnightmare",
    "nopac": "nopac", "samaccountname spoofing": "nopac",
    "privexchange": "privexchange", "printer bug": "printer-bug",
    "coercion": "coerced-auth", "coerce": "coerced-auth",
    "dparcel": "dparcel", "dfscoerce": "dfscoerce",
    "shadow credentials": "shadow-credentials", "keycredentiallink": "shadow-credentials",
    "rbcd": "rbcd", "resource-based constrained": "rbcd",
    "unconstrained delegation": "unconstrained-delegation",
    "constrained delegation": "constrained-delegation",
    "s4u": "constrained-delegation", "s4u2self": "constrained-delegation",
    "s4u2proxy": "constrained-delegation", "gmsa": "gmsa",
    "laps": "laps", "gpp": "gpp-password", "cpassword": "gpp-password",
    "adcs": "adcs", "esc1": "adcs-esc1", "esc2": "adcs-esc2",
    "esc4": "adcs-esc4", "esc8": "adcs-esc8", "certificate template": "adcs",
    "ad recycle bin": "ad-recycle-bin", "group gmsa": "gmsa-password-read",
    "acl abuse": "acl-abuse", "genericall": "acl-abuse", "genericwrite": "acl-abuse",
    "forcechangepassword": "acl-abuse", "writeproperty": "acl-abuse",
    "dcsync right": "dcsync", "replication": "dcsync", "getchangesall": "dcsync",
    "trust": "trust-abuse", "extrasids": "extrasids", "sid history": "extrasids",
    "sqli": "sqli", "sql injection": "sqli", "union": "sqli-union",
    "blind sqli": "sqli-blind", "error-based": "sqli-error-based",
    "sqlmap": "sqli-sqlmap", "os-shell": "sqli-os-shell",
    "into outfile": "sqli-file-write", "load_file": "sqli-file-read",
    "lfi": "lfi", "local file inclusion": "lfi", "path traversal": "lfi",
    "php://": "lfi-wrappers", "php filter": "lfi-wrappers",
    "log poisoning": "lfi-log-poisoning", "session poisoning": "lfi-session-poisoning",
    "rfi": "rfi", "remote file inclusion": "rfi",
    "xxe": "xxe", "xml external": "xxe", "oob": "xxe-oob",
    "ssrf": "ssrf", "file upload": "file-upload", "upload bypass": "file-upload",
    "webshell": "webshell", "web shell": "webshell", "reverse shell": "reverse-shell",
    "bind shell": "bind-shell", "msfvenom": "msfvenom-payload",
    "xss": "xss", "dom xss": "xss-dom", "blind xss": "xss-blind",
    "idor": "idor", "command injection": "command-injection",
    "cmd injection": "command", "os command injection": "command-injection",
    "${ifs}": "command-injection-obfuscation", "ifs": "command-injection-obfuscation",
    "deserialization": "deserialization", "unserialize": "deserialization",
    "log4j": "log4j", "jndi": "log4j", "shellshock": "shellshock",
    "ghostcat": "ghostcat", "drupalgeddon": "drupalgeddon",
    "file transfer": "file-transfer", "lolbin": "lolbin", "lolbas": "lolbin",
    "certutil": "lolbin-certutil", "gtfobins": "gtfobins",
    "suid": "suid", "sgid": "suid", "sudo -l": "sudo-rules",
    "sudoers": "sudo-rules", "ld_preload": "ld_preload",
    "capabilities": "linux-capabilities", "cap_": "linux-capabilities",
    "cron": "cron-abuse", "wildcard": "wildcard-abuse",
    "docker": "docker-abuse", "docker socket": "docker-abuse",
    "kubernetes": "k8s-abuse", "kubeletctl": "k8s-abuse",
    "lxd": "lxd-abuse", "nfs": "nfs-abuse", "no_root_squash": "nfs-abuse",
    "seimpersonate": "seimpersonate", "potato": "potato-attacks",
    "sedebug": "sedebug", "setakeownership": "setakeownership",
    "dll hijack": "dll-hijacking", "unquoted service": "unquoted-service-path",
    "service perm": "weak-service-perms", "alwaysinstallelevated": "alwaysinstallelevated",
    "uac bypass": "uac-bypass", "credential hunting": "credential-hunting",
    "lsass": "lsass-dump", "mimikatz": "lsass-dump",
    "ntds": "ntds-dump", "sam database": "sam-dump", "sam hive": "sam-dump",
    "sam hashes": "sam-dump", "sam file": "sam-dump", "dpapi": "dpapi",
    "hashcat": "hash-cracking", "john": "hash-cracking",
    "password spray": "password-spraying", "spraying": "password-spraying",
    "credential stuffing": "credential-stuffing", "cewl": "custom-wordlists",
    "cupp": "custom-wordlists", "rainbow": "hash-cracking",
    "pivoting": "pivoting", "tunneling": "pivoting", "chisel": "chisel",
    "sshuttle": "sshuttle", "dnscat": "dnscat2", "icmp tunnel": "icmp-tunnel",
    "socks": "socks-proxy", "proxychains": "socks-proxy",
    "bloodhound": "bloodhound", "powerview": "powerview",
    "metasploit": "metasploit", "meterpreter": "meterpreter",
    "msfvenom ": "msfvenom-payload", "autoroute": "msf-autoroute",
    "port forward": "port-forwarding", "portfwd": "port-forwarding",
    "xfreerdp": "rdp", "wmi": "wmi", "psexec": "psexec", "winrm": "winrm",
    "evil-winrm": "winrm-evilwinrm", "dcom": "dcom",
    "zone transfer": "dns-zone-transfer", "axfr": "dns-zone-transfer",
    "subdomain": "subdomain-enum", "vhost": "vhost-enum",
    "google dork": "osint-dorking", "crt.sh": "osint-ct-logs",
    "ftp bounce": "ftp-bounce", "anonymous ftp": "ftp-anonymous",
    "snmp": "snmp-enum", "rdp session hijack": "rdp-hijack",
    "bitlocker": "bitlocker-crack", "keepass": "keepass",
    "autologon": "registry-autologon", "unattend": "unattend-files",
    "putty": "putty-creds", "winscp": "winscp-creds",
    "browser": "browser-creds", "chrome": "browser-creds",
    "git repo": "git-dump", ".git": "git-dump", "gitea/gitlab": "gitlab",
    "ldap injection": "ldap-injection", "nosql": "nosql",
    "iptables -": "firewall-tamper", "shell upgrade": "tty-upgrade",
    "tty": "tty-upgrade", "python -c": "tty-upgrade",
    "wpscan": "wpscan", "wp-config": "wp-config-hunt",
}

# module name → phase mapping (rough kill-chain placement)
MODULE_PHASE = {
    "NMAP": "recon", "Web Recon": "recon", "Footprint Services": "recon",
    "Ffuf": "recon", "Common Services": "enum", "Common Applications": "enum",
    "Active Directory": "ad", "Password Attacks": "creds",
    "Privesc - Windows": "privesc-win", "Privesc - Linux": "privesc-linux",
    "SQL Attacks": "web-exploit", "SQL Map": "web-exploit", "XSS": "web-exploit",
    "Command Injection": "web-exploit", "Web Attacks": "web-exploit",
    "File Inclusion": "web-exploit", "File Upload": "web-shells",
    "Shells": "shells", "Metasploit": "shells",
    "Pivoting, Tunneling, Port FWD": "pivoting",
    "File Transfers": "file-transfer",
}


def parse_frontmatter(text: str) -> dict:
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n?", text, re.S)
    if not m:
        return {}
    fm, tags = m.group(1), []
    # inline list  tags: [a, b]
    for tm in re.finditer(r"tags:\s*\[(.*?)\]", fm):
        tags += [t.strip().lower() for t in tm.group(1).split(",") if t.strip()]
    # block list  tags:\n  - a\n  - b
    bm = re.search(r"tags:\s*\n((?:\s*-\s+.+\n?)+)", fm)
    if bm:
        tags += [t.strip().lstrip("-").strip().lower() for t in bm.group(1).strip().splitlines()]
    module = None
    mm = re.search(r"^module:\s*(.+)$", fm, re.M)
    if mm:
        module = mm.group(1).strip().strip('"\'')
    return {"tags": tags, "module": module}


def strip_fm_and_code(text: str) -> str:
    text = re.sub(r"^---\s*\n.*?\n---\s*\n?", "", text, count=1, flags=re.S)
    text = re.sub(r"```.*?```", "", text, count=0, flags=re.S)
    return text


def parse_code_blocks(text: str) -> list:
    blocks = []
    for lang, body in re.findall(r"```(\w*)\n(.*?)```", text, re.S):
        body = body.rstrip("\n")
        if not body.strip():
            continue
        blocks.append({"lang": lang or "text", "text": body, "binaries": extract_binaries(body, lang)})
    return blocks


def extract_binaries(body: str, lang: str) -> list:
    found = set()
    shellish = lang.lower() in ("bash", "sh", "shell", "shell-session", "console", "powershell", "powershell-session", "cmd", "text", "plaintext", "")
    for raw in body.splitlines():
        line = raw.strip()
        line = re.sub(r"^(?:\[[^\]]*\][#$%]|PS>|PS\s+\w+>|[$#%>]\s*)", "", line)
        if line.startswith(("#", "//", "<", "Rem", "rem ")) or not line:
            continue
        if not shellish:
            continue
        m = re.match(r"^(?:sudo\s+|doas\s+)?([A-Za-z0-9_.\-]+)", line)
        token = m.group(1) if m else ""
        token_l = token.lower()
        if token_l in NOISE_TOKENS or token_l in BUILTIN_TOKENS:
            continue
        for known in KNOWN_BINARIES:
            if token_l == known.lower():
                found.add(known)
                break
        else:
            # impacket example-script style (foo.py invocations)
            if token.endswith(".py") and len(token) < 30:
                found.add(token)
    return sorted(found)


def extract_triggers(note_text_lower: str, headings: list) -> dict:
    services, techniques = set(), set()
    blob = " ".join(headings).lower() + " " + note_text_lower
    for kw, svc in SERVICE_MAP.items():
        if kw.isdigit():
            continue  # bare port numbers are too noisy as substrings
        if kw in blob:
            services.add(svc)
    for kw, tech in TECHNIQUE_MAP.items():
        if kw in blob:
            techniques.add(tech)
    cves = sorted(set(re.findall(r"cve-\d{4}-\d{4,7}", blob)))
    return {"services": sorted(services), "techniques": sorted(techniques), "cves": cves}


def parse_note(path: str, vault_root: str) -> dict | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return None
    rel = os.path.relpath(path, vault_root)
    fm = parse_frontmatter(text)
    module = fm.get("module") or (rel.split(os.sep)[2] if len(rel.split(os.sep)) > 3 else os.path.dirname(rel))
    title_m = re.match(r"^#\s+(.*)$", text, re.M)
    title = title_m.group(1).strip() if title_m else os.path.basename(path)
    headings = [m.group(2).strip() for m in re.finditer(r"^(#{2,3})\s+(.*)$", text, re.M)]
    code_blocks = parse_code_blocks(text)
    prose = strip_fm_and_code(text).lower()
    triggers = extract_triggers(prose, headings)
    wikilinks = sorted(set(re.findall(r"\[\[([^\]|#]+)", text)))
    requirements = sorted({b for blk in code_blocks for b in blk["binaries"]})
    return {
        "id": re.sub(r"\.md$", "", rel).replace(os.sep, "/").lower(),
        "module": module,
        "phase": MODULE_PHASE.get(module, "general"),
        "note": rel.replace(os.sep, "/"),
        "title": title,
        "tags": fm.get("tags", []),
        "headings": headings,
        "trigger": triggers,
        "commands": code_blocks,
        "wikilinks": wikilinks,
        "requirements": requirements,
        "text_len": len(text),
    }


def main() -> int:
    vault = os.environ.get(VAULT_ENV, DEFAULT_VAULT)
    if not os.path.isdir(vault):
        print(f"[!] vault not found: {vault}", file=sys.stderr)
        return 1
    techniques = []
    module_counts = Counter()
    for root, dirs, files in os.walk(vault):
        dirs[:] = [d for d in dirs if d != ".obsidian"]
        for f in sorted(files):
            if not f.endswith(".md"):
                continue
            parsed = parse_note(os.path.join(root, f), vault)
            if parsed:
                techniques.append(parsed)
                module_counts[parsed["module"]] += 1
    registry = {
        "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "vault_path": vault,
        "notes": len(techniques),
        "modules": dict(module_counts),
        "techniques": techniques,
    }
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as fh:
        json.dump(registry, fh, indent=1, ensure_ascii=False)
    total_cmds = sum(len(t["commands"]) for t in techniques)
    print(f"[+] parsed {len(techniques)} notes -> {OUT_PATH}")
    print(f"[+] {total_cmds} command blocks, {sum(len(t['trigger']['techniques']) for t in techniques)} technique tags, "
          f"{sum(len(t['trigger']['cves']) for t in techniques)} cve refs")
    print(f"[+] modules: {dict(module_counts)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
