"""
StrikeARC — Flag Hunter
========================
Systematically searches compromised hosts for flags.
Tracks all captured flags and reports on coverage.

In HTB environments, flags are typically:
  - user.txt / root.txt in user home directories
  - proof.txt / local.txt in certain directories
  - Flags in databases, config files, environment variables
  - Custom formats: HTB{...}, FLAG{...}, etc.
"""

from __future__ import annotations

import os
import re
import time
from typing import Dict, List, Optional

from utils import run_command


# ── Flag Locations ────────────────────────────────────────────────────

LINUX_FLAG_PATHS = [
    "/home/*/user.txt",
    "/home/*/root.txt",
    "/home/*/proof.txt",
    "/home/*/local.txt",
    "/home/*/flag.txt",
    "/home/*/flag",
    "/root/user.txt",
    "/root/root.txt",
    "/root/proof.txt",
    "/root/local.txt",
    "/root/flag.txt",
    "/root/flag",
    "/var/www/html/user.txt",
    "/var/www/html/flag.txt",
    "/var/www/flag.txt",
    "/tmp/flag.txt",
    "/tmp/flag",
    "/opt/flag.txt",
    "/opt/flag",
    "/var/flag.txt",
    "/etc/flag.txt",
    "/mnt/flag.txt",
    "/srv/flag.txt",
]

WINDOWS_FLAG_PATHS = [
    r"C:\\Users\\*\\Desktop\\user.txt",
    r"C:\\Users\\*\\Desktop\\root.txt",
    r"C:\\Users\\*\\Desktop\\proof.txt",
    r"C:\\Users\\*\\Desktop\\flag.txt",
    r"C:\\Users\\Administrator\\Desktop\\root.txt",
    r"C:\\Users\\Administrator\\Desktop\\proof.txt",
    r"C:\\inetpub\\wwwroot\\flag.txt",
    r"C:\\temp\\flag.txt",
    r"C:\\flag.txt",
]

# Regex patterns for flag formats
FLAG_PATTERNS = [
    r"HTB\{[^}]+\}",           # HTB standard
    r"FLAG\{[^}]+\}",          # Generic
    r"flag\{[^}]+\}",          # Generic lowercase
    r"CTF\{[^}]+\}",           # CTF format
    r"[a-f0-9]{32}",           # MD5 hash format (legacy HTB)
    r"[a-f0-9]{64}",           # SHA256 format
]

# Common flag-related filenames to search for
FLAG_FILENAMES = [
    "user.txt", "root.txt", "proof.txt", "local.txt",
    "flag.txt", "flag", ".flag", "secret.txt",
    "user_flag", "root_flag",
]


# ── Core Flag Hunting ─────────────────────────────────────────────────

def _execute(transport, cmd: str, timeout: int = 10) -> Dict:
    """Execute via transport or locally."""
    if transport:
        return transport.run(cmd)
    return run_command(cmd, timeout=timeout)


def hunt_linux_flags(transport=None) -> List[Dict]:
    """Search for flags on a Linux host.

    Checks known locations, searches filesystem, checks env vars,
    and scans common config files.
    """
    flags = []
    found_paths = set()

    print("  [FLAG] Hunting for Linux flags...")

    # Phase 1: Check known locations
    for pattern in LINUX_FLAG_PATHS:
        cmd = f"cat {pattern} 2>/dev/null"
        result = _execute(transport, cmd)

        if result.get("stdout", "").strip():
            content = result["stdout"].strip()
            # Handle multiple files (glob expansion)
            for line in content.split("\n"):
                line = line.strip()
                if line and len(line) < 256:
                    flags.append({
                        "flag_value": line,
                        "path": pattern,
                        "method": "known_location",
                    })
                    found_paths.add(pattern)
                    print(f"  [FLAG] ✓ Found at {pattern}: {line[:40]}...")

    # Phase 2: Find by filename
    find_cmd = "find / -maxdepth 4 \\( -name 'user.txt' -o -name 'root.txt' -o -name 'flag.txt' -o -name 'proof.txt' -o -name '.flag' \\) -readable 2>/dev/null"
    result = _execute(transport, find_cmd, timeout=15)

    if result.get("stdout", "").strip():
        for path in result["stdout"].strip().split("\n"):
            path = path.strip()
            if not path or path in found_paths:
                continue
            # Read the flag
            cat_result = _execute(transport, f"cat {path} 2>/dev/null")
            content = cat_result.get("stdout", "").strip()
            if content:
                flags.append({
                    "flag_value": content,
                    "path": path,
                    "method": "filesystem_search",
                })
                found_paths.add(path)
                print(f"  [FLAG] ✓ Found at {path}: {content[:40]}...")

    # Phase 3: Search for flag format patterns in accessible files
    grep_cmd = (
        "grep -rlE 'HTB\\{|FLAG\\{|flag\\{' /home/ /var/www/ /opt/ /tmp/ /srv/ "
        "--include='*.txt' --include='*.php' --include='*.conf' --include='*.env' "
        "--include='*.json' --include='*.yaml' --include='*.yml' 2>/dev/null"
    )
    result = _execute(transport, grep_cmd, timeout=15)

    if result.get("stdout", "").strip():
        for filepath in result["stdout"].strip().split("\n"):
            filepath = filepath.strip()
            if not filepath or filepath in found_paths:
                continue
            cat_result = _execute(transport, f"cat {filepath} 2>/dev/null")
            content = cat_result.get("stdout", "")
            for pattern in FLAG_PATTERNS:
                matches = re.findall(pattern, content)
                for match in matches:
                    flags.append({
                        "flag_value": match,
                        "path": filepath,
                        "method": "pattern_search",
                    })
                    print(f"  [FLAG] ✓ Pattern match in {filepath}: {match[:40]}...")

    # Phase 4: Check environment variables
    result = _execute(transport, "env 2>/dev/null")
    if result.get("stdout", ""):
        for line in result["stdout"].split("\n"):
            for pattern in FLAG_PATTERNS:
                matches = re.findall(pattern, line)
                for match in matches:
                    flags.append({
                        "flag_value": match,
                        "path": "env:" + line.split("=")[0] if "=" in line else "env",
                        "method": "environment",
                    })
                    print(f"  [FLAG] ✓ In env var: {match[:40]}...")

    # Phase 5: Check databases (MySQL/PostgreSQL)
    db_checks = [
        # MySQL
        ("mysql -u root -e 'SELECT * FROM flags' 2>/dev/null", "mysql_root"),
        ("mysql -u root -e 'SELECT * FROM users' 2>/dev/null", "mysql_users"),
        # Check for .flag files in home dirs
        ("ls -la /home/*/.flag /root/.flag 2>/dev/null", "hidden_flag"),
    ]
    for cmd, source in db_checks:
        result = _execute(transport, cmd)
        if result.get("stdout", "").strip():
            content = result["stdout"].strip()
            for pattern in FLAG_PATTERNS:
                matches = re.findall(pattern, content)
                for match in matches:
                    flags.append({
                        "flag_value": match,
                        "path": f"db:{source}",
                        "method": "database",
                    })

    # Deduplicate
    seen = set()
    unique_flags = []
    for f in flags:
        key = f["flag_value"]
        if key not in seen:
            seen.add(key)
            unique_flags.append(f)

    return unique_flags


def hunt_windows_flags(transport=None) -> List[Dict]:
    """Search for flags on a Windows host."""
    flags = []
    found_paths = set()

    print("  [FLAG] Hunting for Windows flags...")

    # Phase 1: Check known locations
    for pattern in WINDOWS_FLAG_PATHS:
        cmd = f"type {pattern} 2>nul"
        result = _execute(transport, cmd)

        if result.get("stdout", "").strip():
            content = result["stdout"].strip()
            flags.append({
                "flag_value": content,
                "path": pattern,
                "method": "known_location",
            })
            found_paths.add(pattern)
            print(f"  [FLAG] ✓ Found at {pattern}: {content[:40]}...")

    # Phase 2: Search filesystem
    find_cmd = (
        'dir /s /b C:\\\\Users\\\\*user.txt C:\\\\Users\\\\*root.txt '
        'C:\\\\Users\\\\*flag.txt C:\\\\Users\\\\*proof.txt 2>nul'
    )
    result = _execute(transport, find_cmd, timeout=15)

    if result.get("stdout", "").strip():
        for path in result["stdout"].strip().split("\n"):
            path = path.strip()
            if not path or path in found_paths:
                continue
            cat_result = _execute(transport, f"type \"{path}\" 2>nul")
            content = cat_result.get("stdout", "").strip()
            if content:
                flags.append({
                    "flag_value": content,
                    "path": path,
                    "method": "filesystem_search",
                })

    # Phase 3: Registry
    reg_cmd = 'reg query HKCU /f "HTB{" /s 2>nul'
    result = _execute(transport, reg_cmd, timeout=10)
    if result.get("stdout", ""):
        for pattern in FLAG_PATTERNS:
            matches = re.findall(pattern, result["stdout"])
            for match in matches:
                flags.append({
                    "flag_value": match,
                    "path": "registry:HKCU",
                    "method": "registry_search",
                })

    # Deduplicate
    seen = set()
    unique_flags = []
    for f in flags:
        key = f["flag_value"]
        if key not in seen:
            seen.add(key)
            unique_flags.append(f)

    return unique_flags


def hunt_flags(host_ip: str, os_type: str = "linux", transport=None) -> List[Dict]:
    """Master flag hunting function.

    Searches for flags on the given host using all available techniques.
    Works both locally and through transport abstraction.
    """
    print(f"\n  [FLAG] === Flag Hunt on {host_ip} ({os_type}) ===")

    if os_type == "windows":
        flags = hunt_windows_flags(transport)
    else:
        flags = hunt_linux_flags(transport)

    if flags:
        print(f"  [FLAG] === {len(flags)} flag(s) captured on {host_ip} ===")
        for f in flags:
            flag_type = _classify_flag(f)
            f["flag_type"] = flag_type
            f["host_ip"] = host_ip
            f["captured_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            print(f"  [FLAG] {flag_type.upper()}: {f['flag_value'][:50]} ({f['path']})")
    else:
        print(f"  [FLAG] No flags found on {host_ip}")

    return flags


def _classify_flag(flag_entry: Dict) -> str:
    """Classify a flag as user, root, or other based on path."""
    path = flag_entry.get("path", "").lower()

    if "root" in path or "administrator" in path:
        return "root"
    if "user" in path or "/home/" in path:
        return "user"
    if "proof" in path:
        return "proof"
    if "local" in path:
        return "local"

    # Try to determine from flag value patterns
    return "unknown"


def get_flag_summary(captured_flags: List[Dict]) -> str:
    """Generate a summary of all captured flags for reporting."""
    if not captured_flags:
        return "No flags captured yet."

    lines = [f"Flags Captured: {len(captured_flags)}"]

    # Group by host
    by_host: Dict[str, List[Dict]] = {}
    for f in captured_flags:
        host = f.get("host_ip", "unknown")
        by_host.setdefault(host, []).append(f)

    for host, flags in sorted(by_host.items()):
        user_flags = [f for f in flags if f.get("flag_type") == "user"]
        root_flags = [f for f in flags if f.get("flag_type") == "root"]
        other = [f for f in flags if f.get("flag_type") not in ("user", "root")]

        lines.append(f"\n  {host}:")
        if user_flags:
            lines.append(f"    👤 user.txt: {user_flags[0]['flag_value'][:50]}")
        if root_flags:
            lines.append(f"    👑 root.txt: {root_flags[0]['flag_value'][:50]}")
        for f in other:
            lines.append(f"    🔑 {f.get('flag_type', 'flag')}: {f['flag_value'][:50]}")

    return "\n".join(lines)
