"""
ReconARC — Reconnaissance Tools
================================
Network discovery, port scanning, service enumeration.
All functions are read-only (no exploitation).
"""

import re
from typing import Dict, List, Optional, Tuple

from utils import run_command, parse_nmap_output, infer_os


def network_sweep(
    subnet: str,
    exclude: List[str] = None,
) -> List[str]:
    """Discover live hosts in a subnet."""
    exclude_flag = f" --exclude {','.join(exclude)}" if exclude else ""
    cmd = (
        f"nmap -sn {subnet}{exclude_flag} --min-rate 10000 -oG - "
        f"2>/dev/null | grep 'Up' | awk '{{print $2}}'"
    )
    result = run_command(cmd, timeout=180)
    if result["stdout"]:
        hosts = [ip.strip() for ip in result["stdout"].split("\n") if ip.strip()]
        if exclude:
            hosts = [ip for ip in hosts if ip not in exclude]
        print(f"  [+] Discovered {len(hosts)} hosts in {subnet}")
        return hosts
    return []


def quick_scan(ip: str) -> Tuple[Dict[int, dict], str, str]:
    """Fast top-1000 port scan. Returns (services, os_hint, raw_output)."""
    cmd = (
        f"nmap {ip} --top-ports 1000 -sV --version-intensity 5 "
        f"-T4 --open --min-rate 5000 -oN - 2>/dev/null"
    )
    result = run_command(cmd, timeout=120)
    services = parse_nmap_output(result["stdout"])
    os_hint = infer_os(services, result["stdout"])
    return services, os_hint, result["stdout"]


def port_scan(
    target_ip: str,
    fast: bool = False,
) -> Tuple[Dict[int, dict], str, str]:
    """Full port scan with version detection."""
    if fast:
        cmd = (
            f"nmap {target_ip} --top-ports 1000 -sV --version-intensity 5 "
            f"-T4 --open --min-rate 5000 -oN - 2>/dev/null"
        )
    else:
        cmd = (
            f"nmap {target_ip} -p- -sV -sC --version-intensity 5 "
            f"-T4 --open --min-rate 5000 -oN - 2>/dev/null"
        )
    result = run_command(cmd, timeout=300)
    services = parse_nmap_output(result["stdout"])
    os_hint = infer_os(services, result["stdout"])
    return services, os_hint, result["stdout"]


def scan_all_services(
    target_ip: str,
    services: Dict[int, dict],
) -> Dict[int, dict]:
    """Deep enumeration of each service. Updates version/banner info."""
    updated = {}
    for port, svc in services.items():
        svc = dict(svc)
        svc_name = svc["service"].lower()

        if "ssh" in svc_name:
            result = run_command(
                f"nmap -p {port} -sV --script ssh2-enum-algos,ssh-hostkey "
                f"{target_ip} -oN - 2>/dev/null",
                timeout=30,
            )
            if result["stdout"]:
                if "ssh-rsa" in result["stdout"]:
                    svc["banner"] = "RSA key detected"
                svc["enumerated"] = True

        elif "http" in svc_name or "ssl" in svc_name or "https" in svc_name:
            # Leave web enumeration to the web_enum module
            svc["enumerated"] = True

        elif "smb" in svc_name or "microsoft-ds" in svc_name or port == 445:
            result = run_command(
                f"nmap -p {port} --script smb-os-discovery,smb-enum-shares,"
                f"smb-enum-users -oN - {target_ip} 2>/dev/null",
                timeout=30,
            )
            if result["stdout"]:
                svc["banner"] = result["stdout"][:500]
            svc["enumerated"] = True

        elif "ftp" in svc_name:
            result = run_command(
                f"nmap -p {port} --script ftp-anon,ftp-syst "
                f"{target_ip} -oN - 2>/dev/null",
                timeout=20,
            )
            svc["banner"] = result.get("stdout", "")[:500]
            svc["enumerated"] = True

        elif "rdp" in svc_name or "ms-wbt" in svc_name or port == 3389:
            result = run_command(
                f"nmap -p {port} --script rdp-enum-encryption,rdp-vuln-ms12-020 "
                f"{target_ip} -oN - 2>/dev/null",
                timeout=20,
            )
            svc["banner"] = result.get("stdout", "")[:500]
            svc["enumerated"] = True

        elif "ldap" in svc_name or port in (389, 636, 3268, 3269):
            result = run_command(
                f"nmap -p {port} --script ldap-rootdse,ldap-search "
                f"{target_ip} -oN - 2>/dev/null",
                timeout=20,
            )
            svc["banner"] = result.get("stdout", "")[:500]
            svc["enumerated"] = True

        elif "smtp" in svc_name:
            result = run_command(
                f"nmap -p {port} --script smtp-commands,smtp-enum-users "
                f"{target_ip} -oN - 2>/dev/null",
                timeout=20,
            )
            svc["banner"] = result.get("stdout", "")[:500]
            svc["enumerated"] = True

        elif "mssql" in svc_name or port == 1433:
            result = run_command(
                f"nmap -p {port} --script ms-sql-info "
                f"{target_ip} -oN - 2>/dev/null",
                timeout=15,
            )
            svc["banner"] = result.get("stdout", "")[:500]
            svc["enumerated"] = True

        elif "redis" in svc_name or port == 6379:
            result = run_command(
                f"nmap -p {port} --script redis-info "
                f"{target_ip} -oN - 2>/dev/null",
                timeout=15,
            )
            svc["banner"] = result.get("stdout", "")[:500]
            svc["enumerated"] = True

        elif "memcached" in svc_name or port == 11211:
            result = run_command(
                f"nmap -p {port} --script memcached-info "
                f"{target_ip} -oN - 2>/dev/null",
                timeout=15,
            )
            svc["banner"] = result.get("stdout", "")[:500]
            svc["enumerated"] = True

        else:
            svc["enumerated"] = True

        updated[port] = svc

    return updated


def searchsploit(query: str) -> List[dict]:
    """Search local exploitdb database for known exploits."""
    cmd = f"searchsploit --json '{query}' 2>/dev/null"
    result = run_command(cmd, timeout=15)
    if result["stdout"]:
        try:
            import json
            data = json.loads(result["stdout"])
            exploits = data.get("RESULTS_EXPLOIT", [])
            return [
                {
                    "title": e.get("Title", ""),
                    "type": e.get("Type", ""),
                    "path": e.get("Path", ""),
                }
                for e in exploits[:10]
            ]
        except (json.JSONDecodeError, KeyError):
            pass
    return []


def ssl_cert_info(host: str, port: int = 443) -> Optional[dict]:
    """Extract SSL certificate information for OS/domain intel."""
    cmd = (
        f"echo | openssl s_client -connect {host}:{port} "
        f"-servername {host} 2>/dev/null | openssl x509 -noout -text 2>/dev/null"
    )
    result = run_command(cmd, timeout=15)
    if not result["stdout"]:
        return None

    cert_text = result["stdout"]
    info = {}

    # Extract Subject Alternative Names
    sans = re.findall(r"DNS:([^\s,]+)", cert_text)
    if sans:
        info["sans"] = list(set(sans))

    # Extract organization
    org = re.search(r"O\s*=\s*([^\n,]+)", cert_text)
    if org:
        info["org"] = org.group(1).strip()

    # Extract issuer
    issuer = re.search(r"Issuer:.*?CN\s*=\s*([^\s,/]+)", cert_text, re.DOTALL)
    if issuer:
        info["issuer_cn"] = issuer.group(1).strip()

    return info or None
