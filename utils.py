"""
ReconARC — Utilities
=====================
Command execution (safe, no exploitation), network helpers, parsers.
"""

import json
import os
import re
import shlex
import signal
import socket
import subprocess
import time
from typing import Dict, List, Optional

import requests

requests.packages.urllib3.disable_warnings()


# ── Safety ────────────────────────────────────────────────────────────
# This is an enumeration-only tool. We block exploit execution commands.

DANGEROUS_PATTERNS = [
    "rm -rf /", "rm -rf /*", "mkfs", "dd if=/dev/zero",
    "dd if=/dev/urandom", ":(){:|:&};:", "shutdown", "reboot",
    "chmod -R 777 /", "halt", "init 0", "init 6",
]

# Commands that constitute exploitation (not enumeration)
EXPLOIT_PATTERNS = [
    "nc -e", "nc -l", "bash -i", "sh -i", "/dev/tcp/",
    "msfconsole", "msfvenom", "exploit/multi", "exploit/windows",
    "reverse", "shell.elf", "shell.exe", "payload.exe",
    "python -c 'import socket,*rm -rf",  # python reverse shells
    "perl -e", "ruby -e",  # language reverse shells
    "crackmapexec exec", "evil-winrm",  # exploitation tools
    "psexec", "wmiexec", "smbexec", "atexec",  # remote execution
    "sshpass",  # credential usage (not discovery)
    "hashcat", "john ",  # password cracking
    "mimikatz", "sekurlsa", "lsadump",  # credential extraction
    "net user.*add", "net localgroup",  # account creation
    "certutil.*decode", "certutil.*urlcache",  # file download
    "powershell.*-enc", "powershell.*hidden",  # obfuscated execution
    "wget http.*-O", "curl.*| bash", "curl.*| sh",  # download+execute
]


def is_safe_command(cmd: str) -> bool:
    """Check if a command is safe for an enumeration-only agent."""
    cmd_lower = cmd.lower()

    for pattern in DANGEROUS_PATTERNS:
        if pattern in cmd_lower:
            return False

    for pattern in EXPLOIT_PATTERNS:
        if re.search(pattern, cmd_lower):
            return False

    return True


# ── Command Execution ─────────────────────────────────────────────────

def run_command(cmd: str, timeout: int = 60) -> Dict:
    """
    Execute a shell command with process-group isolation.
    Returns {"stdout": str, "stderr": str, "returncode": int, "cmd": str}
    """
    if not is_safe_command(cmd):
        return {
            "stdout": "",
            "stderr": f"BLOCKED (exploitation command): {cmd}",
            "returncode": -1,
            "cmd": cmd,
        }

    proc = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return {
            "stdout": (stdout or "").strip(),
            "stderr": (stderr or "").strip(),
            "returncode": proc.returncode,
            "cmd": cmd,
        }
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = proc.communicate()
        return {
            "stdout": (stdout or "").strip(),
            "stderr": f"Command timed out after {timeout}s",
            "returncode": 124,
            "cmd": cmd,
        }
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1, "cmd": cmd}


# ── Network Helpers ───────────────────────────────────────────────────

def detect_listener_ip(interface: str = "tun0") -> str:
    """Detect VPN/listener IP from the specified interface."""
    try:
        result = run_command(
            f"ip -4 addr show {interface} 2>/dev/null | grep -oP 'inet \\K[\\d.]+'"
        )
        if result["stdout"]:
            return result["stdout"].split("\n")[0].strip()
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.10.10.10", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def parse_nmap_output(nmap_text: str) -> Dict[int, dict]:
    """Parse nmap output into a services dict."""
    services = {}
    for line in nmap_text.split("\n"):
        m = re.match(
            r"(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)(?:\s+(.*))?", line.strip()
        )
        if m:
            port = int(m.group(1))
            state = m.group(3)
            service = m.group(4)
            version = m.group(5) or ""
            if state == "open":
                services[port] = {
                    "port": port,
                    "protocol": m.group(2),
                    "service": service,
                    "version": version,
                    "banner": "",
                    "enumerated": False,
                }
    return services


def extract_emails(text: str) -> List[str]:
    return list(set(re.findall(r"[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}", text)))


def infer_os(services: Dict[int, dict], banner: str = "") -> str:
    all_text = banner + " " + " ".join(
        s.get("version", "") for s in services.values()
    )
    all_text = all_text.lower()
    if "windows" in all_text or "microsoft" in all_text or "iis" in all_text:
        return "windows"
    if "ubuntu" in all_text or "debian" in all_text or "linux" in all_text:
        return "linux"
    if any(p in services for p in [135, 139, 445, 3389, 5985, 5986]):
        return "windows"
    if 22 in services and not any(p in services for p in [135, 139, 445, 3389]):
        return "linux"
    return "unknown"


# ── HTTP Helpers ──────────────────────────────────────────────────────

def http_get(
    url: str, timeout: int = 10, verify_ssl: bool = False,
    allow_redirects: bool = True, headers: Optional[Dict] = None,
) -> Optional[requests.Response]:
    try:
        return requests.get(
            url, timeout=timeout, verify=verify_ssl,
            allow_redirects=allow_redirects, headers=headers,
        )
    except Exception:
        return None


def http_post(
    url: str, json_data: Optional[dict] = None, data: Optional[str] = None,
    timeout: int = 10, verify_ssl: bool = False,
    headers: Optional[Dict] = None,
) -> Optional[requests.Response]:
    try:
        return requests.post(
            url, json=json_data, data=data, timeout=timeout,
            verify=verify_ssl, headers=headers,
        )
    except Exception:
        return None
