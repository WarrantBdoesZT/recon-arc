"""
StrikeARC — Transport Abstraction Layer
=======================================
Routes command execution through different contexts: local subprocess, SSH,
webshell, SOCKS proxy, or chained proxies. This is the key abstraction that
makes post-exploitation enumeration transparent — callers invoke
``transport.run("ifconfig")`` and it works regardless of whether they are
running locally or on a compromised host reached via SSH/webshell/pivot.

Design notes
------------
* Every ``run()`` returns the same dict shape as ``utils.run_command()``:
  ``{"stdout": str, "stderr": str, "returncode": int, "cmd": str}``.
* The same safety filter (``utils.is_safe_command``) is applied on every
  transport so blocked commands cannot bypass it by switching context.
* ``paramiko`` and ``socks`` (PySocks) are imported *optionally* — missing
  libraries raise a clear ``ImportError`` only when the corresponding
  transport is instantiated, never at import time.
* This module contains NO exploitation code. It only transports commands
  that the caller (an authorized operator) chooses to run on a host they
  have already accessed through external means.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import time
from typing import Dict, List, Optional

from utils import is_safe_command, run_command

# ── Optional dependencies ─────────────────────────────────────────────
# Imported lazily/optionally so the module loads even when the heavy
# networking libraries are absent. Each transport that needs one raises a
# clear ImportError in its constructor if the library is missing.

try:
    import paramiko  # type: ignore
    _HAS_PARAMIKO = True
except ImportError:  # pragma: no cover - environment dependent
    paramiko = None  # type: ignore
    _HAS_PARAMIKO = False

try:
    import socks  # type: ignore  # PySocks
    _HAS_PYSOCKS = True
except ImportError:  # pragma: no cover - environment dependent
    socks = None  # type: ignore
    _HAS_PYSOCKS = False

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:  # pragma: no cover
    requests = None  # type: ignore
    _HAS_REQUESTS = False


# ── Helpers ───────────────────────────────────────────────────────────

def _empty_result(cmd: str, stderr: str, returncode: int = -1) -> Dict:
    """Build a standard result dict matching utils.run_command() output."""
    return {"stdout": "", "stderr": stderr, "returncode": returncode, "cmd": cmd}


def _check_safe(cmd: str) -> Optional[Dict]:
    """Return a BLOCKED result dict if the command fails the safety filter.

    Returns ``None`` when the command is safe to run. Centralizing this keeps
    the safety guarantee identical across every transport.
    """
    if not is_safe_command(cmd):
        return _empty_result(
            cmd, f"BLOCKED (destructive command): {cmd}", returncode=-1
        )
    return None


# ════════════════════════════════════════════════════════════════════════
# Base Transport
# ════════════════════════════════════════════════════════════════════════

class BaseTransport:
    """Abstract base class for all command-execution transports.

    Subclasses must implement ``run()``, ``is_alive()``, ``info()``, and
    ``close()``. ``run_background()``, ``upload()``, and ``download()`` have
    default implementations that may be overridden.
    """

    # Marker so subclasses can opt out of file transfer cleanly.
    supports_file_transfer: bool = True

    # ── Core execution ────────────────────────────────────────────────

    def run(self, cmd: str, timeout: int = 60) -> Dict:
        """Execute *cmd* and return {stdout, stderr, returncode, cmd}."""
        raise NotImplementedError

    def run_background(self, cmd: str) -> str:
        """Start *cmd* in the background and return a PID/handle string.

        Default implementation wraps the command in ``nohup … &`` through
        :meth:`run` and parses the PID from stdout. Transports that can do
        this natively (e.g. SSH exec with a detached channel) may override.
        """
        wrapped = f"nohup {cmd} >/dev/null 2>&1 & echo $!"
        result = self.run(wrapped, timeout=10)
        pid = (result.get("stdout") or "").strip().splitlines()
        return pid[0] if pid else ""

    # ── File transfer ─────────────────────────────────────────────────

    def upload(self, local_path: str, remote_path: str) -> bool:
        """Upload a local file to the remote endpoint. Return True on success."""
        raise NotImplementedError

    def download(self, remote_path: str, local_path: str) -> bool:
        """Download a remote file to a local path. Return True on success."""
        raise NotImplementedError

    # ── Lifecycle / introspection ─────────────────────────────────────

    def is_alive(self) -> bool:
        """Return True if the transport connection is currently usable."""
        raise NotImplementedError

    def info(self) -> Dict:
        """Return transport metadata: {type, host, user, credential_type, ...}."""
        raise NotImplementedError

    def close(self) -> None:
        """Release any underlying resources (connections, channels, etc.)."""
        pass

    # Context-manager support so transports can be used with ``with``.
    def __enter__(self) -> "BaseTransport":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


# ════════════════════════════════════════════════════════════════════════
# Local Transport
# ════════════════════════════════════════════════════════════════════════

class LocalTransport(BaseTransport):
    """Execute commands on the local machine via ``utils.run_command()``.

    This is the default transport and what StrikeARC has used implicitly up
    to now. It is a drop-in wrapper: the output shape is identical.
    """

    def __init__(self) -> None:
        self._type = "local"

    def run(self, cmd: str, timeout: int = 60) -> Dict:
        return run_command(cmd, timeout=timeout)

    def upload(self, local_path: str, remote_path: str) -> bool:
        # Locally, "upload" is just a copy.
        try:
            import shutil
            shutil.copy2(local_path, remote_path)
            return True
        except Exception:
            return False

    def download(self, remote_path: str, local_path: str) -> bool:
        try:
            import shutil
            shutil.copy2(remote_path, local_path)
            return True
        except Exception:
            return False

    def is_alive(self) -> bool:
        return True  # local subprocess is always available

    def info(self) -> Dict:
        return {
            "type": self._type,
            "host": "localhost",
            "user": os.environ.get("USER", "local"),
            "credential_type": "none",
        }

    def close(self) -> None:
        pass  # nothing to clean up


# ════════════════════════════════════════════════════════════════════════
# SSH Transport
# ════════════════════════════════════════════════════════════════════════

class SSHTransport(BaseTransport):
    """Execute commands on a remote host over SSH using ``paramiko``.

    Parameters
    ----------
    host : str
        Target host IP or hostname.
    port : int
        SSH TCP port (default 22).
    username : str
        SSH login username.
    credential : str
        Either a plaintext password or a filesystem path to a private key.
    credential_type : str
        ``"password"`` (default) or ``"key"``. If omitted, it is inferred
        from whether *credential* looks like an existing file path.
    timeout : float
        Connection timeout in seconds (default 10).

    Raises
    ------
    ImportError
        If ``paramiko`` is not installed.
    """

    def __init__(
        self,
        host: str,
        port: int = 22,
        username: str = "",
        credential: str = "",
        credential_type: str = "",
        timeout: float = 10.0,
    ) -> None:
        if not _HAS_PARAMIKO:
            raise ImportError(
                "SSHTransport requires the 'paramiko' package. "
                "Install it with: pip install paramiko"
            )

        self._host = host
        self._port = int(port)
        self._username = username
        self._credential = credential
        self._timeout = timeout

        # Infer credential type if not explicitly provided.
        if not credential_type:
            credential_type = "key" if (
                credential and os.path.isfile(os.path.expanduser(credential))
            ) else "password"
        self._credential_type = credential_type

        self._client: "Optional[paramiko.SSHClient]" = None
        self._sftp = None
        self._connect()

    # ── Connection management ─────────────────────────────────────────

    def _connect(self) -> None:
        """Establish the SSH client connection."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: Dict = dict(
            hostname=self._host,
            port=self._port,
            username=self._username,
            timeout=self._timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        if self._credential_type == "key":
            connect_kwargs["key_filename"] = os.path.expanduser(self._credential)
        else:
            connect_kwargs["password"] = self._credential

        client.connect(**connect_kwargs)
        self._client = client

    def _ensure_client(self) -> "paramiko.SSHClient":
        """Reconnect if the stored client is missing or dropped."""
        if self._client is None:
            self._connect()
        return self._client

    def _get_sftp(self):
        """Lazily open (and cache) an SFTP channel."""
        if self._sftp is None:
            client = self._ensure_client()
            self._sftp = client.open_sftp()
        return self._sftp

    # ── Core execution ────────────────────────────────────────────────

    def run(self, cmd: str, timeout: int = 60) -> Dict:
        blocked = _check_safe(cmd)
        if blocked:
            return blocked
        try:
            client = self._ensure_client()
            stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
            rc = stdout.channel.recv_exit_status()
            return {
                "stdout": out.strip(),
                "stderr": err.strip(),
                "returncode": rc,
                "cmd": cmd,
            }
        except Exception as e:
            return _empty_result(cmd, f"SSH run error: {e}")

    # ── File transfer ─────────────────────────────────────────────────

    def upload(self, local_path: str, remote_path: str) -> bool:
        try:
            self._get_sftp().put(local_path, remote_path)
            return True
        except Exception:
            return False

    def download(self, remote_path: str, local_path: str) -> bool:
        try:
            self._get_sftp().get(remote_path, local_path)
            return True
        except Exception:
            return False

    # ── Lifecycle / introspection ─────────────────────────────────────

    def is_alive(self) -> bool:
        try:
            client = self._client
            if client is None:
                return False
            transport = client.get_transport()
            return bool(transport and transport.is_active())
        except Exception:
            return False

    def info(self) -> Dict:
        return {
            "type": "ssh",
            "host": self._host,
            "port": self._port,
            "user": self._username,
            "credential_type": self._credential_type,
        }

    def close(self) -> None:
        for attr in ("_sftp", "_client"):
            obj = getattr(self, attr, None)
            if obj is not None:
                try:
                    obj.close()
                except Exception:
                    pass
                setattr(self, attr, None)


# ════════════════════════════════════════════════════════════════════════
# Webshell Transport
# ════════════════════════════════════════════════════════════════════════

class WebshellTransport(BaseTransport):
    """Execute commands through an HTTP webshell endpoint.

    The webshell is expected to echo command stdout directly in the HTTP
    response body (e.g. ``<?php system($_GET['cmd']); ?>``). This transport
    only carries text — file transfer is not supported.

    Parameters
    ----------
    webshell_url : str
        Full URL of the webshell (e.g. ``http://target/cmd.php``).
    parameter_name : str
        Query/form parameter that receives the command (default ``"cmd"``).
    method : str
        ``"GET"`` or ``"POST"`` (default ``"POST"``).
    auth_cookies : dict, optional
        Cookies required to reach an authenticated webshell.
    timeout : int
        Per-request timeout in seconds (default 30).
    marker : str, optional
        If set, the command is wrapped so that only text between the
        markers is captured as stdout (filters HTML noise). The marker is
        injected as ``echo {marker}; <cmd>; echo {marker}``.
    """

    supports_file_transfer = False

    def __init__(
        self,
        webshell_url: str,
        parameter_name: str = "cmd",
        method: str = "POST",
        auth_cookies: Optional[Dict] = None,
        timeout: int = 30,
        marker: Optional[str] = None,
    ) -> None:
        if not _HAS_REQUESTS:
            raise ImportError(
                "WebshellTransport requires the 'requests' package. "
                "Install it with: pip install requests"
            )

        self._url = webshell_url
        self._param = parameter_name
        self._method = method.upper()
        self._cookies = auth_cookies or {}
        self._timeout = timeout
        self._marker = marker
        if self._method not in ("GET", "POST"):
            raise ValueError(f"method must be 'GET' or 'POST', got {method!r}")

    # ── Internal HTTP dispatch ────────────────────────────────────────

    def _send(self, cmd: str) -> Optional[str]:
        """Send *cmd* to the webshell and return the response body text."""
        payload = {self._param: cmd}
        try:
            if self._method == "GET":
                resp = requests.get(
                    self._url, params=payload, cookies=self._cookies,
                    timeout=self._timeout, verify=False, allow_redirects=False,
                )
            else:
                resp = requests.post(
                    self._url, data=payload, cookies=self._cookies,
                    timeout=self._timeout, verify=False, allow_redirects=False,
                )
            return resp.text
        except Exception:
            return None

    def _extract(self, body: str) -> str:
        """Optionally strip everything outside the marker pair."""
        if not self._marker or body is None:
            return body or ""
        m_start = f"===BEGIN==={self._marker}==="
        m_end = f"===END==={self._marker}==="
        if m_start in body and m_end in body:
            return body.split(m_start, 1)[1].split(m_end, 1)[0]
        return body or ""

    # ── Core execution ────────────────────────────────────────────────

    def run(self, cmd: str, timeout: int = 60) -> Dict:
        blocked = _check_safe(cmd)
        if blocked:
            return blocked

        # Optionally wrap with markers to isolate stdout from page chrome.
        send_cmd = cmd
        if self._marker:
            send_cmd = f"echo '===BEGIN==={self._marker}==='; {cmd}; echo '===END==={self._marker}==='"

        body = self._send(send_cmd)
        if body is None:
            return _empty_result(cmd, "Webshell request failed (no response)")

        stdout = self._extract(body)
        # Webshells do not reliably report exit codes.
        return {
            "stdout": stdout.strip(),
            "stderr": "",
            "returncode": 0 if stdout else 1,
            "cmd": cmd,
        }

    # ── File transfer (unsupported) ───────────────────────────────────

    def upload(self, local_path: str, remote_path: str) -> bool:
        raise NotImplementedError(
            "WebshellTransport does not support file upload. "
            "Use SSHTransport or stage the file through the webshell manually."
        )

    def download(self, remote_path: str, local_path: str) -> bool:
        raise NotImplementedError(
            "WebshellTransport does not support file download. "
            "Use SSHTransport or read the file via run('cat <path>')."
        )

    # ── Lifecycle / introspection ─────────────────────────────────────

    def is_alive(self) -> bool:
        body = self._send("echo alive")
        return body is not None and "alive" in body

    def info(self) -> Dict:
        return {
            "type": "webshell",
            "host": self._url,
            "user": self._cookies.get("user", "webshell"),
            "credential_type": "cookie" if self._cookies else "none",
            "method": self._method,
            "parameter": self._param,
        }

    def close(self) -> None:
        pass  # HTTP is stateless; nothing to close


# ════════════════════════════════════════════════════════════════════════
# SOCKS Proxy Transport
# ════════════════════════════════════════════════════════════════════════

class SOCKSTransport(BaseTransport):
    """Route local-subprocess commands through a SOCKS proxy.

    This is used to scan/enumerate internal networks that are only reachable
    from a compromised host (e.g. via an SSH ``-D`` dynamic tunnel). Commands
    are executed locally but their network traffic egresses through the proxy.

    Two backends are supported, tried in order:

    1. **proxychains** (CLI) — if available, commands are prefixed with
       ``proxychains`` / ``proxychains4``. Simplest and works with any tool.
    2. **PySocks monkeypatch** — if proxychains is absent, the global
       ``socket`` module is monkeypatched so all subsequent socket traffic
       from the process flows through the SOCKS proxy.

    Parameters
    ----------
    proxy_host : str
        SOCKS proxy host (usually ``127.0.0.1`` for a local tunnel).
    proxy_port : int
        SOCKS proxy port.
    socks_version : int
        ``4`` or ``5`` (default 5).
    backend : str, optional
        ``"proxychains"`` or ``"pysocks"``. If omitted, auto-detect.
    """

    def __init__(
        self,
        proxy_host: str,
        proxy_port: int,
        socks_version: int = 5,
        backend: str = "",
    ) -> None:
        self._proxy_host = proxy_host
        self._proxy_port = int(proxy_port)
        self._socks_version = socks_version
        self._backend = ""
        self._patched = False
        self._proxychains_bin = ""

        if backend:
            self._backend = backend
        else:
            self._backend = self._detect_backend()

        if self._backend == "pysocks" and not _HAS_PYSOCKS:
            raise ImportError(
                "SOCKSTransport 'pysocks' backend requires the 'PySocks' "
                "package. Install it with: pip install PySocks"
            )
        if self._backend == "pysocks":
            self._apply_pysocks_patch()

    # ── Backend detection / setup ─────────────────────────────────────

    def _detect_backend(self) -> str:
        """Prefer proxychains if installed; fall back to PySocks."""
        for candidate in ("proxychains4", "proxychains"):
            path = self._which(candidate)
            if path:
                self._proxychains_bin = path
                return "proxychains"
        if _HAS_PYSOCKS:
            return "pysocks"
        raise ImportError(
            "SOCKSTransport needs either the 'proxychains' binary or the "
            "'PySocks' package. Install one of them."
        )

    @staticmethod
    def _which(binary: str) -> str:
        """Return the absolute path to *binary* on PATH, or ''."""
        for directory in os.environ.get("PATH", "").split(os.pathsep):
            candidate = os.path.join(directory.strip('"'), binary)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        return ""

    def _apply_pysocks_patch(self) -> None:
        """Monkeypatch ``socket`` so all traffic routes via the SOCKS proxy."""
        try:
            socks.set_default_proxy(
                socks.SOCKS5 if self._socks_version == 5 else socks.SOCKS4,
                self._proxy_host,
                self._proxy_port,
            )
            socks.wrap_module(socket)
            self._patched = True
        except Exception:
            self._patched = False

    # ── Core execution ────────────────────────────────────────────────

    def run(self, cmd: str, timeout: int = 60) -> Dict:
        blocked = _check_safe(cmd)
        if blocked:
            return blocked

        if self._backend == "proxychains":
            return self._run_proxychains(cmd, timeout)
        return self._run_pysocks(cmd, timeout)

    def _run_proxychains(self, cmd: str, timeout: int) -> Dict:
        """Prefix the command with proxychains and execute locally."""
        wrapped = (
            f"{self._proxychains_bin} -q -a {self._socks_version} "
            f"-f /dev/null "
            f"--host {self._proxy_host} --port {self._proxy_port} {cmd}"
        )
        # proxychains-ng supports inline proxy config via env/conf; fall back
        # to the simple prefix form that works with a default proxychains.conf.
        simple = f"{self._proxychains_bin} -q {shlex.quote(cmd)}"
        # Try the rich form first; if the binary rejects the flags, retry plain.
        result = run_command(wrapped, timeout=timeout)
        if result["returncode"] not in (127, 126):
            return result
        return run_command(simple, timeout=timeout)

    def _run_pysocks(self, cmd: str, timeout: int) -> Dict:
        """Execute locally with the global socket monkeypatch active."""
        if not self._patched:
            self._apply_pysocks_patch()
        return run_command(cmd, timeout=timeout)

    # ── File transfer (local semantics) ───────────────────────────────

    def upload(self, local_path: str, remote_path: str) -> bool:
        # Over a SOCKS proxy "remote" is still a URL/host reachable through
        # the proxy — generic file copy isn't meaningful. Treat as local copy.
        try:
            import shutil
            shutil.copy2(local_path, remote_path)
            return True
        except Exception:
            return False

    def download(self, remote_path: str, local_path: str) -> bool:
        try:
            import shutil
            shutil.copy2(remote_path, local_path)
            return True
        except Exception:
            return False

    # ── Lifecycle / introspection ─────────────────────────────────────

    def is_alive(self) -> bool:
        # A SOCKS proxy is "alive" if the local tunnel port is accepting
        # connections.
        try:
            import socket as _socket
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((self._proxy_host, self._proxy_port))
            s.close()
            return True
        except Exception:
            return False

    def info(self) -> Dict:
        return {
            "type": "socks",
            "host": self._proxy_host,
            "port": self._proxy_port,
            "user": "n/a",
            "credential_type": "none",
            "socks_version": self._socks_version,
            "backend": self._backend,
        }

    def close(self) -> None:
        # We cannot safely un-monkeypatch socket in-process; leave it.
        pass


# ════════════════════════════════════════════════════════════════════════
# Proxy Chain Transport
# ════════════════════════════════════════════════════════════════════════

class ProxyChainTransport(BaseTransport):
    """Chain multiple transports so a command traverses every hop.

    Example::

        chain = ProxyChainTransport([
            LocalTransport(),          # start locally
            SOCKSTransport("127.0.0.1", 1080),
            SSHTransport("10.0.0.5", username="user", credential="..."),
        ])

    Each ``run()`` is dispatched on the **last** transport in the chain
    (the final execution context). The preceding transports establish the
    routing path — e.g. a SOCKS tunnel that the SSH connection rides over.
    File-transfer and liveness checks aggregate across the chain.
    """

    def __init__(self, transports: List[BaseTransport]) -> None:
        if not transports:
            raise ValueError("ProxyChainTransport requires at least one transport")
        self._transports = list(transports)

    @property
    def transports(self) -> List[BaseTransport]:
        return self._transports

    # ── Core execution ────────────────────────────────────────────────

    def run(self, cmd: str, timeout: int = 60) -> Dict:
        blocked = _check_safe(cmd)
        if blocked:
            return blocked
        # The final transport is where the command actually executes.
        return self._transports[-1].run(cmd, timeout=timeout)

    def run_background(self, cmd: str) -> str:
        return self._transports[-1].run_background(cmd)

    # ── File transfer ─────────────────────────────────────────────────

    def upload(self, local_path: str, remote_path: str) -> bool:
        # Defer to the final hop's upload capability.
        return self._transports[-1].upload(local_path, remote_path)

    def download(self, remote_path: str, local_path: str) -> bool:
        return self._transports[-1].download(remote_path, local_path)

    # ── Lifecycle / introspection ─────────────────────────────────────

    def is_alive(self) -> bool:
        # Chain is alive only if *every* hop is alive.
        return all(t.is_alive() for t in self._transports)

    def info(self) -> Dict:
        return {
            "type": "proxychain",
            "host": " -> ".join(
                t.info().get("host", "?") for t in self._transports
            ),
            "user": self._transports[-1].info().get("user", "n/a"),
            "credential_type": "chained",
            "hops": [t.info() for t in self._transports],
        }

    def close(self) -> None:
        # Close in reverse order (innermost hop first).
        for t in reversed(self._transports):
            try:
                t.close()
            except Exception:
                pass


# ════════════════════════════════════════════════════════════════════════
# Transport Manager
# ════════════════════════════════════════════════════════════════════════

class TransportManager:
    """Registry and factory for active transports.

    Holds a pool of named transports, tracks which one is currently
    "active" (the default ``run()`` target), and can construct the correct
    transport subclass from a session-data dictionary (e.g. loaded from a
    saved engagement JSON).
    """

    def __init__(self) -> None:
        self._transports: Dict[str, BaseTransport] = {}
        self._active: Optional[str] = None

    # ── Registration ──────────────────────────────────────────────────

    def register_transport(self, name: str, transport: BaseTransport) -> None:
        """Register *transport* under *name*. First registration becomes active."""
        self._transports[name] = transport
        if self._active is None:
            self._active = name

    def get_transport(self, name: str) -> BaseTransport:
        """Return a previously registered transport. Raises KeyError if absent."""
        if name not in self._transports:
            raise KeyError(f"No transport named {name!r}. "
                           f"Known: {list(self._transports)}")
        return self._transports[name]

    def unregister_transport(self, name: str) -> None:
        """Remove a transport and close it. Clears active if it was selected."""
        transport = self._transports.pop(name, None)
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
        if self._active == name:
            self._active = next(iter(self._transports), None)

    # ── Active transport ──────────────────────────────────────────────

    def get_active_transport(self) -> BaseTransport:
        """Return the currently active transport.

        Falls back to a :class:`LocalTransport` if none has been set, so
        callers always get a usable transport.
        """
        if self._active is None or self._active not in self._transports:
            local = LocalTransport()
            self.register_transport("local", local)
            return local
        return self._transports[self._active]

    def set_active(self, name: str) -> None:
        """Switch the active transport to a registered *name*."""
        if name not in self._transports:
            raise KeyError(f"Cannot activate unknown transport {name!r}. "
                           f"Known: {list(self._transports)}")
        self._active = name

    def active_name(self) -> Optional[str]:
        """Return the name of the currently active transport (or None)."""
        return self._active

    # ── Introspection ─────────────────────────────────────────────────

    def list_transports(self) -> List[Dict]:
        """Return ``info()`` dicts for every registered transport."""
        return [
            {**t.info(), "name": name, "active": (name == self._active)}
            for name, t in self._transports.items()
        ]

    # ── Factory ───────────────────────────────────────────────────────

    @staticmethod
    def create_from_session(session_data: Dict) -> BaseTransport:
        """Build the correct transport from a session-data dictionary.

        Recognized ``type`` values: ``local``, ``ssh``, ``webshell``,
        ``socks``, ``proxychain``. Unrecognized types raise ``ValueError``.

        Example session_data::

            {"type": "ssh", "host": "10.0.0.5", "port": 22,
             "username": "root", "credential": "/path/to/id_rsa",
             "credential_type": "key"}
        """
        if not isinstance(session_data, dict) or "type" not in session_data:
            raise ValueError("session_data must be a dict with a 'type' key")

        stype = session_data["type"].lower()

        if stype == "local":
            return LocalTransport()

        if stype == "ssh":
            return SSHTransport(
                host=session_data["host"],
                port=int(session_data.get("port", 22)),
                username=session_data.get("username", ""),
                credential=session_data.get("credential", ""),
                credential_type=session_data.get("credential_type", ""),
                timeout=float(session_data.get("timeout", 10)),
            )

        if stype == "webshell":
            return WebshellTransport(
                webshell_url=session_data["webshell_url"],
                parameter_name=session_data.get("parameter_name", "cmd"),
                method=session_data.get("method", "POST"),
                auth_cookies=session_data.get("auth_cookies"),
                timeout=int(session_data.get("timeout", 30)),
                marker=session_data.get("marker"),
            )

        if stype == "socks":
            return SOCKSTransport(
                proxy_host=session_data["proxy_host"],
                proxy_port=int(session_data["proxy_port"]),
                socks_version=int(session_data.get("socks_version", 5)),
                backend=session_data.get("backend", ""),
            )

        if stype == "proxychain":
            hops = session_data.get("transports") or session_data.get("hops")
            if not hops:
                raise ValueError(
                    "proxychain session requires a 'transports' list of "
                    "session dicts"
                )
            chained = [
                TransportManager.create_from_session(h) for h in hops
            ]
            return ProxyChainTransport(chained)

        raise ValueError(f"Unknown transport type: {stype!r}")

    # ── Convenience: create-and-register in one call ──────────────────

    def add_from_session(self, name: str, session_data: Dict) -> BaseTransport:
        """Create a transport from session_data and register it under *name*."""
        transport = self.create_from_session(session_data)
        self.register_transport(name, transport)
        return transport

    # ── Failover ──────────────────────────────────────────────────────

    def failover(self) -> Optional[BaseTransport]:
        """If the active transport is dead, switch to the next alive one.

        Returns the new active transport, or ``None`` if no transport is
        alive.
        """
        active = self.get_active_transport()
        if active.is_alive():
            return active

        for name, transport in self._transports.items():
            if name == self._active:
                continue
            if transport.is_alive():
                self._active = name
                return transport
        return None

    # ── Cleanup ───────────────────────────────────────────────────────

    def close_all(self) -> None:
        """Close and drop every registered transport."""
        for transport in self._transports.values():
            try:
                transport.close()
            except Exception:
                pass
        self._transports.clear()
        self._active = None


# ════════════════════════════════════════════════════════════════════════
# Module-level convenience
# ════════════════════════════════════════════════════════════════════════

# A process-wide default manager so simple callers can do:
#     from transport import manager
#     manager.get_active_transport().run("id")
manager = TransportManager()
manager.register_transport("local", LocalTransport())


__all__ = [
    "BaseTransport",
    "LocalTransport",
    "SSHTransport",
    "WebshellTransport",
    "SOCKSTransport",
    "ProxyChainTransport",
    "TransportManager",
    "manager",
]
