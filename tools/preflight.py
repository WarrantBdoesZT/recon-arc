#!/usr/bin/env python3
"""Preflight — external tooling capability check for StrikeARC.

Run at agent startup (and on demand) to report which offensive tools are
actually invokable. Missing tools degrade silently elsewhere in the codebase
(only `nuclei` was historically which-checked) — this makes the capability
surface explicit before an engagement starts.

Usage:
    python3 tools/preflight.py            # human report
    from tools.preflight import preflight_report, missing_tools
    report = preflight_report()           # dict for agent state/logs

Tiers:
    core    — agent cannot function (nmap, curl)
    enum    — enumeration depth collapses without these
    attack  — exploitation/lateral techniques unavailable without these
    aux     — nice to have
"""
from __future__ import annotations

import os
import shutil

# tool -> (tier, purpose)
REQUIRED_TOOLS = {
    # core
    "nmap":        ("core", "port scanning / service enum"),
    "curl":        ("core", "HTTP requests"),
    # enum
    "gobuster":    ("enum", "directory busting"),
    "ffuf":        ("enum", "fuzzing (dirs, vhosts, params)"),
    "searchsploit": ("enum", "ExploitDB search"),
    "openssl":     ("enum", "SSL cert analysis"),
    "ldapsearch":  ("enum", "LDAP enumeration"),
    "rpcclient":   ("enum", "RPC/SMB null-session enumeration"),
    "smbclient":   ("enum", "SMB share enumeration"),
    "showmount":   ("enum", "NFS export enumeration"),
    "snmpwalk":    ("enum", "SNMP walking"),
    "onesixtyone": ("enum", "SNMP community brute"),
    "dig":         ("enum", "DNS enumeration"),
    "nikto":       ("enum", "web server scanner"),
    "wafw00f":     ("enum", "WAF detection"),
    "bloodhound-python": ("enum", "AD graph collection"),
    # attack
    "impacket-GetUserSPNs": ("attack", "Kerberoasting"),
    "impacket-GetNPUsers":  ("attack", "AS-REP roasting"),
    "impacket-secretsdump": ("attack", "DCSync / SAM-NTDS dumping"),
    "impacket-psexec":      ("attack", "SMB exec (psexec)"),
    "impacket-wmiexec":     ("attack", "WMI exec"),
    "impacket-ntlmrelayx":  ("attack", "NTLM relay"),
    "impacket-ticketer":    ("attack", "Golden/silver ticket forging"),
    "impacket-rbcd":        ("attack", "RBCD abuse"),
    "impacket-Get-GPPPassword": ("attack", "GPP cpassword decryption"),
    "impacket-mssqlclient": ("attack", "MSSQL interaction / xp_cmdshell"),
    "nxc":         ("attack", "NetExec (spray, PtH, share/AD enum)"),
    "certipy":     ("attack", "ADCS ESC1-13 abuse, shadow creds, cert auth"),
    "kerbrute":    ("attack", "Kerberos user enum / brute"),
    "responder":   ("attack", "LLMNR/NBT-NS poisoning"),
    "evil-winrm":  ("attack", "WinRM shell"),
    "hashcat":     ("attack", "hash cracking"),
    "john":        ("attack", "hash cracking"),
    "hydra":       ("attack", "online brute force"),
    "medusa":      ("attack", "online brute force"),
    "cewl":        ("attack", "custom wordlist generation"),
    "sqlmap":      ("attack", "SQLi automation"),
    "msfconsole":  ("attack", "Metasploit framework"),
    "msfvenom":    ("attack", "payload generation"),
    # pivoting
    "chisel":      ("attack", "SOCKS tunneling"),
    "sshuttle":    ("attack", "SSH pivoting"),
    "proxychains": ("attack", "socks proxying for scan tools"),
    "xfreerdp":    ("attack", "RDP client"),
    # aux
    "nuclei":      ("aux", "template vuln scanner"),
    "enum4linux":  ("aux", "SMB/RPC enum wrapper"),
    "wpscan":      ("aux", "WordPress scanner"),
}

TIER_ORDER = {"core": 0, "enum": 1, "attack": 2, "aux": 3}


def preflight_report(verbose: bool = True) -> dict:
    """Check every tool; return {"available": {name: path}, "missing": {name: tier}, ...}."""
    available, missing = {}, {}
    for tool, (tier, purpose) in REQUIRED_TOOLS.items():
        path = shutil.which(tool)
        if path:
            available[tool] = path
        else:
            missing[tool] = (tier, purpose)

    report = {
        "checked": len(REQUIRED_TOOLS),
        "available_count": len(available),
        "missing_count": len(missing),
        "available": available,
        "missing": {t: {"tier": tier, "purpose": purpose} for t, (tier, purpose) in missing.items()},
        "missing_by_tier": {
            tier: sorted(t for t, (tn, _) in missing.items() if tn == tier)
            for tier in ("core", "enum", "attack", "aux")
        },
    }

    if verbose:
        _print_report(report)
    return report


def missing_tools(tier: str | None = None) -> list:
    """Convenience: names of missing tools, optionally filtered by tier."""
    rep = preflight_report(verbose=False)
    if tier:
        return rep["missing_by_tier"].get(tier, [])
    return sorted(rep["missing"].keys())


def _print_report(report: dict) -> None:
    print("\n" + "=" * 62)
    print("  PREFLIGHT — external tooling capability check")
    print("=" * 62)
    print(f"  {report['available_count']}/{report['checked']} tools available")

    for tier in ("core", "enum", "attack", "aux"):
        miss = report["missing_by_tier"].get(tier, [])
        if miss:
            print(f"\n  [!] missing {tier}:")
            for t in miss:
                purpose = report["missing"][t]["purpose"]
                print(f"      ✗ {t:<28} {purpose}")
        else:
            have = sum(1 for t in report["available"] if REQUIRED_TOOLS[t][0] == tier)
            print(f"  [+] {tier}: all {have} present")

    if report["missing_by_tier"]["core"]:
        print("\n  [!!] CORE tools missing — agent cannot run scans. Fix first.")
    elif report["missing_by_tier"]["attack"]:
        print("\n  [i] Attack-tier gaps: corresponding techniques will be advisory-only.")
    print("=" * 62 + "\n")


if __name__ == "__main__":
    preflight_report()
