#!/usr/bin/env python3
"""Vault Knowledge Retrieval — query the technique registry at analyze/exploit time.

Usage from the agent (nodes/__init__.py):
    from knowledge.retrieval import knowledge_pack

    pack = knowledge_pack(
        services={"smb": ..., "http": ...},          # nmap service names (keys only used)
        technologies=["Apache Tomcat 9.0.30", "WordPress 5.4"],
        vector_types={"ad_enum"},
        phase="ad",
        max_notes=12, max_chars=12000,
    )
    if pack:
        prompt_section = pack["text"]   # paste into analyze_node prompt
        state["knowledge_matches"] = pack["matches"]

Design: pure stdlib, zero deps, zero LLM. Loads knowledge/registry.json
(lazy, cached per process). Rebuild registry via knowledge/parse_vault.py.
"""
from __future__ import annotations

import difflib
import functools
import json
import os
import re

_REG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "registry.json")


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

@functools.lru_cache(maxsize=1)
def load_registry():
    if not os.path.exists(_REG_PATH):
        return None
    try:
        with open(_REG_PATH, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def registry_stats() -> dict:
    reg = load_registry()
    if not reg:
        return {"available": False}
    return {
        "available": True,
        "notes": reg.get("notes", 0),
        "generated": reg.get("generated", "?"),
        "modules": len(reg.get("modules", {})),
    }


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

# nmap service name -> vault trigger service tags
SERVICE_ALIASES = {
    "http": {"http"}, "https": {"http", "ssl"}, "ssl": {"http", "ssl"},
    "domain": {"dns"}, "dns": {"dns"},
    "kerberos": {"kerberos"},
    "ldap": {"ldap"}, "ldaps": {"ldap"}, "globalcatldap": {"ldap"},
    "smb": {"smb"}, "microsoft-ds": {"smb"}, "netbios-ssn": {"smb"},
    "winrm": {"winrm"}, "microsoft-httpapi": {"winrm", "http"},
    "rdp": {"rdp"}, "ms-wbt-server": {"rdp"},
    "ssh": {"ssh"}, "ftp": {"ftp"}, "smtp": {"smtp"},
    "pop3": {"mail"}, "pop3s": {"mail"}, "imap": {"mail"}, "imaps": {"mail"},
    "snmp": {"snmp"}, "mysql": {"mysql"}, "mariadb": {"mysql"},
    "ms-sql-s": {"mssql"}, "mssql": {"mssql"},
    "oracle": {"oracle"}, "oracle-tns": {"oracle"},
    "nfs": {"nfs"}, "nfs-or-iis": {"nfs"},
    "redis": {"redis"}, "mongodb": {"mongodb"},
    "elasticsearch": {"elasticsearch"},
    "tomcat": {"tomcat"}, "apache": {"http"}, "nginx": {"http"},
    "caldav": {"caldav"}, "webdav": {"webdav"}, "iis": {"iis"},
    "jenkins": {"jenkins"}, "gitlab": {"gitlab"},
    "wordpress": {"wordpress"}, "drupal": {"drupal"}, "joomla": {"joomla"},
    "rpc": {"rpc"}, "msrpc": {"rpc"}, "cups": {"ipp"}, "ipp": {"ipp"},
    "rsync": {"rsync"}, "vnc": {"vnc"}, "sip": {"sip"}, "mqtt": {"mqtt"},
    "git": {"git"}, "docker": {"docker"}, "kubernetes": {"kubernetes"},
    "coldfusion": {"coldfusion"}, "splunk": {"splunk"},
    "weblogic": {"http"}, "jboss": {"http"},
}


def _norm_service(name: str) -> set:
    n = (name or "").lower().strip().split("|")[0].strip()
    if not n:
        return set()
    if n in SERVICE_ALIASES:
        return set(SERVICE_ALIASES[n])
    best = difflib.get_close_matches(n, SERVICE_ALIASES.keys(), n=1, cutoff=0.75)
    if best:
        return set(SERVICE_ALIASES[best[0]])
    return set()


def _tech_tokens(tech_string: str) -> set:
    """'Apache Tomcat 9.0.30' -> {'apache', 'tomcat'}"""
    s = tech_string.lower()
    toks = set()
    for t in re.split(r"[\s/|,]+", s):
        t = t.strip("._-")
        if t and not t.isdigit() and len(t) > 2:
            toks.add(t)
    return toks


PHASE_BONUS = {"ad", "creds", "privesc-win", "privesc-linux", "pivoting"}


def _note_matches(note: dict, want_services: set, want_techs: set, want_cves: set,
                  phase: str) -> float:
    trig = note.get("trigger", {})
    t_services = set(trig.get("services", []))
    t_cves = set(trig.get("cves", []))
    t_phase = note.get("phase", "general")

    score = 0.0
    overlap = want_services & t_services
    if overlap:
        score += 4.0 * len(overlap)
    if want_cves & t_cves:
        score += 8.0 * len(want_cves & t_cves)
    if want_techs:
        blob = (note.get("title", "") + " " + note.get("module", "") + " " +
                " ".join(note.get("headings", [])[:20])).lower()
        for t in want_techs:
            if t in blob:
                score += 3.0 if len(t) > 6 else 2.0
    if phase and t_phase == phase:
        score += 1.5 if phase in PHASE_BONUS else 0.5
    return score


def knowledge_pack(services=None, technologies=None, vector_types=None,
                   phase="", max_notes=12, max_chars=12000):
    """Build a compact knowledge pack for the analyze/exploit prompt.

    services: iterable of nmap service names (dict keys or list)
    technologies: list of product strings ('Apache Tomcat 9.0.30')
    vector_types: iterable of vector type strings (scanned for CVE ids)
    """
    reg = load_registry()
    if not reg:
        return None

    want_services = set()
    for svc in (services or {}):
        if svc:
            want_services |= _norm_service(svc)
    if isinstance(services, (list, tuple, set)):
        # caller passed a plain list — cover dict-keys path above too
        pass
    want_techs = set()
    for t in (technologies or []):
        want_techs |= _tech_tokens(t)
    want_cves = set()
    for vt in (vector_types or ()):
        for cve in re.findall(r"cve-\d{4}-\d{4,7}", str(vt).lower()):
            want_cves.add(cve)

    scored = []
    for note in reg.get("techniques", []):
        s = _note_matches(note, want_services, want_techs, want_cves, phase)
        if s > 0:
            scored.append((s, note))
    if not scored:
        return None
    scored.sort(key=lambda x: (-x[0], x[1].get("id", "")))

    # dedup by (module, title)
    seen, picked = set(), []
    for s, note in scored:
        key = (note.get("module"), note.get("title"))
        if key in seen:
            continue
        seen.add(key)
        picked.append((s, note))
        if len(picked) >= max_notes:
            break

    lines, total = [], []
    used = 0
    for s, note in picked:
        entry = _format_note(note, want_services, want_techs)
        if used + len(entry) > max_chars:
            break
        lines.append(entry)
        used += len(entry)

    return {
        "text": "\n".join(lines),
        "matches": [
            {
                "note": note.get("note"),
                "module": note.get("module"),
                "title": note.get("title"),
                "score": round(s, 1),
            }
            for s, note in picked[:len(lines)]
        ],
    }


def _format_note(note: dict, want_services: set, want_techs: set) -> str:
    parts = [f"### {note.get('title', '?')}  [{note.get('module', '?')}]"]
    trig = note.get("trigger", {})
    if trig.get("techniques"):
        parts.append("Techniques: " + ", ".join(trig.get("techniques", [])[:8]))
    if trig.get("cves"):
        parts.append("CVEs: " + ", ".join(trig.get("cves", [])[:6]))
    cmds = note.get("commands", [])
    relevant = [c for c in cmds if _cmd_relevant(c, want_services, want_techs)]
    for c in (relevant or cmds)[:4]:
        snippet = c.get("text", "").strip()
        if len(snippet) > 400:
            snippet = snippet[:400] + " ..."
        parts.append("```" + c.get("lang", "") + "\n" + snippet + "\n```")
    parts.append("Source: ~/Documents/Purple-Teaming/" + note.get("note", ""))
    return "\n".join(parts)


def _cmd_relevant(cmd: dict, want_services: set, want_techs: set) -> bool:
    if set(cmd.get("binaries", [])) & want_services:
        return True
    blob = cmd.get("text", "").lower()
    return any(t in blob for t in want_techs)


# ---------------------------------------------------------------------------
# CLI (for testing / manual querying)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Query the vault technique registry")
    ap.add_argument("--services", default="", help="comma-separated nmap service names, e.g. http,smb,ms-sql-s")
    ap.add_argument("--techs", default="", help="comma-separated products, e.g. 'Apache Tomcat 9.0.30'")
    ap.add_argument("--phase", default="", help="ad|creds|privesc-win|privesc-linux|web-exploit|pivoting")
    ap.add_argument("--max-notes", type=int, default=12)
    args = ap.parse_args()
    svc_list = [s.strip() for s in args.services.split(",") if s.strip()]
    tech_list = [t.strip() for t in args.techs.split(",") if t.strip()]
    pack = knowledge_pack(svc_list, tech_list, set(), args.phase, max_notes=args.max_notes)
    if pack:
        print(pack["text"])
    else:
        print("[no matches]")
