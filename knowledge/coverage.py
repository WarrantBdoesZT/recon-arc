#!/usr/bin/env python3
"""Coverage Engine — vault techniques × live hosts → enumeration checklist.

For every host service, expand ALL applicable HTB-Academy vault techniques into
a checklist. Techniques whose commands are enumeration-safe run automatically;
attack-class commands (brute force, sqlmap, responder, metasploit, hashcat…)
become MANUAL LEADS surfaced in the report with the exact commands from your
own notes — never auto-executed by the enum agent.

Usage (nodes/__init__.py):
    from knowledge.coverage import build_coverage, next_enum_batch

    state["coverage"] = build_coverage(state)          # after enum updates
    batch = next_enum_batch(state, limit=20)           # enum-safe commands to run
    record_run(state, tech_id, host, ok=True, note="3 users found")

Checklist item schema (state["coverage"]):
    {
      "tech": "htb-academy/.../nmap-service-enumeration-and-nse",
      "host": "10.10.10.5", "service": "http", "port": 80,
      "module": "Nmap", "title": "Nmap - Service Enumeration and NSE.md",
      "note_path": "HTB-Academy/Pentester Path/Nmap/....md",
      "phase": "enum",
      "status": "pending" | "done" | "skipped",   # skipped = binaries missing
      "classification": "enum-safe" | "manual-lead",
      "reason": "matched service=http", "runs": 0,
      "commands": [{"lang","text","binaries"}]
    }
"""
from __future__ import annotations

import difflib
import os
from datetime import datetime

from knowledge.retrieval import SERVICE_ALIASES, load_registry

# ---------------------------------------------------------------------------
# Command classification
# ---------------------------------------------------------------------------

# Attack-class binaries → technique becomes a manual lead, never auto-run
ATTACK_BINARIES = {
    "hydra", "medusa", "sqlmap", "responder", "hashcat", "john", "msfconsole",
    "msfvenom", "metasploit", "evil-winrm", "impacket-smbexec",
    "impacket-psexec", "impacket-wmiexec", "impacket-atexec", "impacket-secretsdump",
    "impacket-getST", "impacket-ticketer", "impacket-GetNPUsers", "impacket-GetUserSPNs",
    "getgpppassword", "cewl", "wfuzz", "patator", "crackmapexec", "netexec",
    "rpcdump", "kp3n", "kerbrute",  # kerbrute user-enum is fine but pwd-spray class is attack
    "mimikatz", "sharpHound", "sharphound", "bloodhound-python", "bloodhound",
    "powershell-empire", "starkiller", "ligolo", "chisel", "ssh -L", "plink",
    "searchsploit", "msconvert", "rdesktop", "xfreerdp",
}

# Even when a binary looks safe, these command-text patterns mark attacks
ATTACK_PATTERNS = (
    "sqlmap", "hydra", "hashcat", "responder", "mimikatz", "secretsdump",
    "GetUserSPNs", "GetNPUsers", "smbexec", "psexec", "wmiexec", "ticketer",
    "kerberoast", "as-rep", "password spray", "brute", "evil-winrm",
    "invoke-kerberoast", "nc -e", "bash -i", "mkfifo", "/dev/tcp",
    "base64 -d", "certutil -urlcache",
)

# Binaries that count as safe enumeration tools
SAFE_ENUM_BINARIES = {
    "nmap", "smbclient", "rpcclient", "enum4linux", "enum4linux-ng", "showmount",
    "dig", "nslookup", "host", "curl", "wget", "whatweb", "nikto", "gobuster",
    "ffuf", "feroxbuster", "dirb", "wfuzz-safe", "ldapsearch", "smbmap",
    "onesixtyone", "snmpwalk", "snmp-check", "redis-cli", "mysql", "mysqladmin",
    "sqsh", "tsql", "sqlcmd", "ftp", "tnscmd10g", "oscanner", "xfreerdp-info",
    "openssl", "nc", "ncat", "netcat", "telnet", "ssh-keyscan", "whois",
    "theHarvester", "amass", "sublist3r", "wafw00f", "wpscan-enum", "ping",
    "traceroute", "arp-scan", "netdiscover", "masscan", "rustscan", "udp-proto-scanner",
    "crackmapexec-enum", "netexec-enum", "impacket-GetNPUsers-enum",  # -enum suffixed = audit use
    "GetNPUsers",  # null-session user check is standard recon (no auth attempted)
}

# kerbrute special-case: user enumeration subcommands are recon; spray is attack
KERBRUTE_ENUM = ("userenum", "userenum --", "userenum -d")


def classify_command(cmd_text: str, binaries: list[str]) -> tuple[str, str]:
    """Return (classification, reason) for a single command."""
    text = (cmd_text or "").strip().lower()
    if not text:
        return "skip", "empty"
    for pat in ATTACK_PATTERNS:
        if pat in text:
            return "attack", f"pattern '{pat}'"
    for b in binaries or []:
        bl = (b or "").lower().strip()
        if not bl:
            continue
        if bl in ATTACK_BINARIES:
            # kerbrute userenum is enumeration despite binary being attack-class
            if bl == "kerbrute" and any(k in text for k in KERBRUTE_ENUM):
                continue
            if bl.endswith("-enum"):  # suffixed variants above
                continue
            return "attack", f"binary '{bl}'"
    return "enum-safe", ""


def classify_technique(tech: dict) -> tuple[str, str]:
    """Classify a whole technique from its commands."""
    cmds = tech.get("commands", [])
    if not cmds:
        return "no-commands", "note has no runnable commands (reference material)"
    worst = "enum-safe"
    reason = ""
    for c in cmds:
        cls, why = classify_command(c.get("text", ""), c.get("binaries", []))
        if cls == "attack":
            return "manual-lead", why
        if cls == "skip":
            continue
    return worst, reason


# ---------------------------------------------------------------------------
# Matching — service-based, same aliases as retrieval.py
# ---------------------------------------------------------------------------

def _host_services(host: dict) -> list[tuple[int, str, str]]:
    """[(port, service_name, version)] for a host state dict."""
    out = []
    for ps, svc in (host.get("services") or {}).items():
        name = (svc.get("service") or "").lower()
        ver = svc.get("version") or ""
        if name:
            out.append((svc.get("port") or int(ps), name, ver))
    return out


def _tech_service_tags(tech: dict) -> set[str]:
    trig = tech.get("trigger", {})
    return {s.lower() for s in (trig.get("services") or [])}


def _is_reference_note(tech: dict) -> bool:
    """Overview/Index/Mindset notes are study material, not runnable techniques."""
    title = (tech.get("title") or "").lower()
    ref_markers = ("overview", "index", "mindset", "hardening", "preparation",
                   "summary", "cheat sheet", "cheatsheet", "conclusion", "moc")
    return any(m in title for m in ref_markers)


def match_score(tech: dict, service: str, version: str, technologies: list[str]) -> float:
    """0..1 relevance of a technique to a concrete service instance.

    Primary match (service named in title/tags) scores full; a service that
    only appears in the greedy trigger list is diluted by the trigger breadth
    (a note triggering on 11 services is generic; one triggering on 1-2 is
    specifically about that service).
    """
    tags = _tech_service_tags(tech)
    aliases = SERVICE_ALIASES.get(service, {service})
    title_blob = " ".join([
        (tech.get("title") or ""),
        " ".join(tech.get("tags", [])),
        " ".join(tech.get("headings", [])[:2]),
    ]).lower()
    primary = any(a in title_blob for a in aliases)
    # service named in the note TITLE itself = the note is ABOUT this service
    in_title = any(a in (tech.get("title") or "").lower() for a in aliases)

    if tags & aliases:
        base = 0.65 if primary else 0.6 * min(1.0, 2.0 / max(1, len(tags)))
    else:
        # fuzzy fallback — only primary-sounding matches survive
        best = 0.0
        for t in tags:
            r = difflib.SequenceMatcher(None, t, service).ratio()
            best = max(best, r)
        if best < 0.75 or not primary:
            return 0.0
        base = 0.45
    # keyword/tech-name boosts
    blob = " ".join([
        " ".join(tech.get("tags", [])),
        (tech.get("title") or "").lower(),
        " ".join(tech.get("headings", [])),
        (version or "").lower(),
        " ".join((technologies or [])).lower(),
    ])
    vblob = (version or "").lower()
    boost = 0.0
    for kw, w in (("wordpress", .2), ("tomcat", .2), ("jenkins", .2),
                  ("joomla", .2), ("drupal", .2), ("gitlab", .2),
                  ("oracle", .15), ("mssql", .15), ("mysql", .1),
                  ("iis", .15), ("apache", .05), ("nginx", .05),
                  ("bind", .1), ("proftpd", .15), ("vsftpd", .1),
                  ("openvpn", .15), ("ssl", .05), ("tls", .05)):
        if kw in blob and (kw in vblob or kw in " ".join(technologies or []).lower()):
            boost = max(boost, w)
    return min(1.0, base + boost + (0.15 if in_title else 0.0))


# ---------------------------------------------------------------------------
# Checklist build
# ---------------------------------------------------------------------------

# Cap per host-service to keep the matrix sane; keep highest-scored
MAX_TECH_PER_SERVICE = 8
# Techniques with zero commands never enter the checklist (reference-only)


def build_coverage(state: dict) -> list[dict]:
    """Build (or rebuild) the coverage checklist from current host state."""
    reg = load_registry()
    if not reg:
        return []
    techs = reg.get("techniques", [])
    checklist: list[dict] = []
    for ip, host in (state.get("hosts") or {}).items():
        technologies = []
        for wa in (host.get("web_apps") or []):
            technologies += wa.get("technologies") or []
        seen_tech_ids: set[str] = set()
        for port, svc_name, version in _host_services(host):
            scored = []
            for tech in techs:
                s = match_score(tech, svc_name, version, technologies)
                if s > 0:
                    scored.append((s, tech))
            scored.sort(key=lambda x: (-x[0], x[1].get("id", "")))
            picked = 0
            for s, tech in scored:
                if tech["id"] in seen_tech_ids or _is_reference_note(tech):
                    continue
                cls, reason = classify_technique(tech)
                if cls == "no-commands":
                    continue
                checklist.append({
                    "tech": tech["id"],
                    "host": ip,
                    "service": svc_name,
                    "port": port,
                    "module": tech.get("module", ""),
                    "title": tech.get("title", ""),
                    "note_path": tech.get("note", ""),
                    "phase": tech.get("phase", ""),
                    "match": round(s, 2),
                    "classification": "enum-safe" if cls == "enum-safe" else "manual-lead",
                    "reason": reason,
                    "status": "pending",
                    "runs": 0,
                    "last_result": "",
                    "commands": tech.get("commands", []),
                })
                seen_tech_ids.add(tech["id"])
                picked += 1
                if picked >= MAX_TECH_PER_SERVICE:
                    break
    return checklist


# ---------------------------------------------------------------------------
# Progress helpers
# ---------------------------------------------------------------------------

# Vault notes paste terminal transcripts; these prefixes mark OUTPUT, not input
_TRANSCRIPT_PREFIXES = (
    "# ", "nmap scan report", "port ", "starting nmap", "220 ", "230 ",
    "name: ", "password: ", "ftp> ", "no platform", "no arch", "payload size",
    "final size", "total ", "drwx", "-rw-", "uid=", "gid=", "trying ",
    "connected to ", "login successful", "230 login", "msf6 >", "msf >",
    "[*] ", "[+] ", "[-] ", "reply:", "530 ", "331 ", "550 ",
)


def display_commands(item: dict, limit: int = 6) -> list[dict]:
    """Runnable-looking commands for display: drops transcript output blocks
    and transcript output LINES inside multi-line blocks."""
    out = []
    for c in item.get("commands", []):
        text = (c.get("text") or "").strip()
        if not text or c.get("lang") == "text":
            continue
        low = text.lower()
        if any(low.startswith(p) for p in _TRANSCRIPT_PREFIXES):
            continue
        # strip transcript output lines inside multi-line commands
        kept = []
        for line in text.splitlines():
            ll = line.strip().lower()
            if ll and any(ll.startswith(p) for p in _TRANSCRIPT_PREFIXES):
                continue
            kept.append(line)
        if not kept:
            continue
        out.append({**c, "text": "\n".join(kept)})
        if len(out) >= limit:
            break
    return out


def next_enum_batch(state: dict, limit: int = 20) -> list[dict]:
    """Pending enum-safe items, best match first, one per technique per host."""
    out = []
    for item in state.get("coverage", []):
        if item["status"] == "pending" and item["classification"] == "enum-safe":
            out.append(item)
    out.sort(key=lambda x: (-x.get("match", 0), x["host"], x["service"]))
    # dedupe same tech across ports of same host (keeps first/highest match)
    seen: set[tuple[str, str]] = set()
    batch = []
    for item in out:
        key = (item["tech"], item["host"])
        if key in seen:
            continue
        seen.add(key)
        batch.append(item)
        if len(batch) >= limit:
            break
    return batch


def record_run(checklist: list[dict], tech_id: str, host: str,
               ok: bool, note: str = "") -> None:
    """Update checklist items after a run (all matching items for tech+host)."""
    for item in checklist:
        if item["tech"] == tech_id and item["host"] == host:
            item["runs"] += 1
            item["status"] = "done" if ok else ("skipped" if note == "missing-binaries" else "pending")
            item["last_result"] = (note or ("ok" if ok else "failed"))[:200]
            item["last_run"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"


def coverage_stats(checklist: list[dict]) -> dict:
    total = len(checklist)
    done = sum(1 for i in checklist if i["status"] == "done")
    skipped = sum(1 for i in checklist if i["status"] == "skipped")
    manual = sum(1 for i in checklist if i["classification"] == "manual-lead")
    enum_safe = sum(1 for i in checklist if i["classification"] == "enum-safe")
    return {
        "total": total, "done": done, "skipped": skipped,
        "pending_enum": max(0, enum_safe - done - skipped),
        "manual_leads": manual, "enum_safe": enum_safe,
    }


def manual_leads(checklist: list[dict], limit: int | None = None) -> list[dict]:
    """Manual-lead items sorted by match score (report dashboard input)."""
    leads = [i for i in checklist if i["classification"] == "manual-lead"]
    leads.sort(key=lambda x: (-x.get("match", 0), x["host"]))
    return leads[:limit] if limit else leads
