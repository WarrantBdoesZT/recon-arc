#!/usr/bin/env python3
"""
extra_enum.py — Miscellaneous enumeration modules (NFS, SMTP, Database, CMS).

Part of the StrikeARC enumeration agent. Passive enumeration only — no exploits.
All functions handle failures gracefully and return structured data.
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urljoin

from utils import run_command, http_get, http_post, swallow


# ---------------------------------------------------------------------------
# NFS Enumeration
# ---------------------------------------------------------------------------

def nfs_enum(target_ip: str) -> List[dict]:
    """
    Enumerate NFS exports on a target.

    Runs `showmount -e` and parses the list of exported directories along with
    the hosts permitted to mount each one.

    Args:
        target_ip: IP address or hostname of the NFS server.

    Returns:
        List of dicts, each with keys 'directory' and 'hosts'.
    """
    print(f"    [+] ENUM: NFS exports on {target_ip}")
    result = run_command(f"showmount -e {target_ip} 2>/dev/null")
    exports: List[dict] = []

    stdout = result.get("stdout", "")
    if not stdout:
        return exports

    lines = stdout.splitlines()
    # First line is typically a header: "Export list for <ip>"
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        # Format: "/path   host1,host2" or "/path  everyone" or "/path (ro,...)"
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        directory = parts[0].strip()
        hosts = parts[1].strip()
        # Strip surrounding parentheses if present (e.g. options)
        hosts = hosts.strip("()")
        exports.append({"directory": directory, "hosts": hosts})

    if exports:
        print(f"    [+] ENUM: NFS found {len(exports)} exports")
    return exports


# ---------------------------------------------------------------------------
# SMTP Enumeration
# ---------------------------------------------------------------------------

# A small fallback wordlist if the metasploit file isn't available.
_FALLBACK_USERS = [
    "root", "admin", "administrator", "guest", "test", "user",
    "info", "support", "sales", "mail", "postmaster", "webmaster",
    "operator", "ftp", "nobody", "bin", "daemon", "sys", "lp",
]

_VRFY_USERLIST_PATH = "/usr/share/wordlists/metasploit/unix_users.txt"


def smtp_enum_users(target_ip: str, port: int = 25) -> List[str]:
    """
    Enumerate SMTP users via VRFY/EXPN.

    Prefers `smtp-user-enum` with the metasploit wordlist; falls back to a
    manual VRFY loop over nc using a small built-in userlist.

    Args:
        target_ip: Target host.
        port: SMTP port (default 25).

    Returns:
        List of discovered usernames.
    """
    print(f"    [+] ENUM: SMTP user enumeration on {target_ip}:{port}")
    discovered: List[str] = []

    # --- Primary: smtp-user-enum ---
    result = run_command(
        f"smtp-user-enum -M VRFY -U {_VRFY_USERLIST_PATH} -t {target_ip} "
        f"-p {port} 2>/dev/null"
    )
    stdout = result.get("stdout", "")
    rc = result.get("returncode", -1)

    if rc == 0 and stdout:
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # smtp-user-enum output: "root            <exists via VRFY: 250 2.1.5 root>"
            if "exists" in line.lower() or "250" in line:
                parts = line.split()
                if parts:
                    discovered.append(parts[0])
        if discovered:
            print(f"    [+] ENUM: SMTP found {len(discovered)} users via smtp-user-enum")
            return list(dict.fromkeys(discovered))  # dedupe preserving order

    # --- Fallback: manual VRFY via python socket ---
    print(f"    [+] ENUM: smtp-user-enum unavailable; trying manual VRFY")
    import socket

    users_to_try = _FALLBACK_USERS

    def _vrfy(sock: socket.socket, user: str) -> bool:
        try:
            sock.sendall(f"VRFY {user}\r\n".encode())
            resp = sock.recv(1024).decode(errors="ignore").strip()
            # 250 = exists, 252 = cannot verify but accepted, 251 = forwarded
            return any(resp.startswith(code) for code in ("250", "251", "252"))
        except (socket.timeout, OSError):
            return False

    try:
        with socket.create_connection((target_ip, port), timeout=10) as sock:
            sock.settimeout(5)
            # Read banner
            try:
                sock.recv(1024)
            except (socket.timeout, OSError):
                pass
            # EHLO
            try:
                sock.sendall(b"EHLO recon.local\r\n")
                sock.recv(2048)
            except (socket.timeout, OSError):
                pass

            for user in users_to_try:
                if _vrfy(sock, user):
                    discovered.append(user)

            # Try EXPN for a couple of common list addresses
            for alias in ("staff", "all", "everyone", "list"):
                try:
                    sock.sendall(f"EXPN {alias}\r\n".encode())
                    resp = sock.recv(2048).decode(errors="ignore").strip()
                    if resp.startswith("250") and resp.count("\n") >= 1:
                        for ln in resp.splitlines():
                            ln = ln.strip()
                            if ln and not ln.startswith("250 "):
                                discovered.append(ln)
                except (socket.timeout, OSError):
                    pass

            try:
                sock.sendall(b"QUIT\r\n")
            except (socket.timeout, OSError):
                pass
    except (socket.timeout, OSError, ConnectionRefusedError) as exc:
        print(f"    [+] ENUM: SMTP manual VRFY failed: {exc}")
        return []

    discovered = list(dict.fromkeys(discovered))
    if discovered:
        print(f"    [+] ENUM: SMTP found {len(discovered)} users via manual VRFY")
    return discovered


def smtp_check_commands(target_ip: str, port: int = 25) -> dict:
    """
    Probe an SMTP server's supported commands via EHLO.

    Args:
        target_ip: Target host.
        port: SMTP port (default 25).

    Returns:
        Dict with keys: 'banner', 'commands' (list), 'starttls' (bool),
        'auth' (list of supported auth mechanisms).
    """
    print(f"    [+] ENUM: SMTP EHLO command check on {target_ip}:{port}")
    import socket

    info: dict = {"banner": "", "commands": [], "starttls": False, "auth": []}

    try:
        with socket.create_connection((target_ip, port), timeout=10) as sock:
            sock.settimeout(5)
            try:
                info["banner"] = sock.recv(1024).decode(errors="ignore").strip()
            except (socket.timeout, OSError):
                pass

            sock.sendall(b"EHLO recon.local\r\n")
            try:
                resp = sock.recv(4096).decode(errors="ignore")
            except (socket.timeout, OSError):
                resp = ""

            for line in resp.splitlines():
                # EHLO lines look like: "250-SIZE 35882577" or "250 STARTTLS"
                m = re.match(r"^\d{3}[- ](.+)$", line.strip())
                if not m:
                    continue
                cmd_line = m.group(1).strip()
                cmd = cmd_line.split()[0].upper() if cmd_line.split() else ""
                if cmd:
                    info["commands"].append(cmd_line)
                if cmd == "STARTTLS":
                    info["starttls"] = True
                elif cmd == "AUTH":
                    # AUTH followed by mechanisms: "AUTH LOGIN PLAIN"
                    mechs = cmd_line.split()[1:]
                    info["auth"] = mechs

            try:
                sock.sendall(b"QUIT\r\n")
            except (socket.timeout, OSError):
                pass
    except (socket.timeout, OSError, ConnectionRefusedError) as exc:
        print(f"    [+] ENUM: SMTP EHLO failed: {exc}")
        return info

    print(f"    [+] ENUM: SMTP commands: {', '.join(info['commands']) or 'none'}")
    return info


# ---------------------------------------------------------------------------
# Database Enumeration (passive checks)
# ---------------------------------------------------------------------------

def check_mssql(target_ip: str, port: int = 1433) -> dict:
    """
    Passive MSSQL enumeration via nmap scripts.

    Runs ms-sql-info and ms-sql-empty-password (no exploit).

    Args:
        target_ip: Target host.
        port: MSSQL port (default 1433).

    Returns:
        Dict with keys: 'open' (bool), 'info' (raw nmap output),
        'empty_password' (bool).
    """
    print(f"    [+] ENUM: MSSQL check on {target_ip}:{port}")
    info: dict = {"open": False, "info": "", "empty_password": False}

    result = run_command(
        f"nmap -p {port} --script ms-sql-info,ms-sql-empty-password "
        f"{target_ip} 2>/dev/null"
    )
    stdout = result.get("stdout", "")
    info["info"] = stdout

    if "open" in stdout.lower() and str(port) in stdout:
        info["open"] = True

    if "empty password" in stdout.lower() or "Login Success" in stdout:
        info["empty_password"] = True
        print(f"    [+] ENUM: MSSQL empty-password login may succeed")

    if info["open"]:
        print(f"    [+] ENUM: MSSQL port {port} appears open")
    return info


def check_mongodb(target_ip: str, port: int = 27017) -> dict:
    """
    Check for unauthenticated MongoDB access.

    Tries the mongo shell first; falls back to an nmap script.

    Args:
        target_ip: Target host.
        port: MongoDB port (default 27017).

    Returns:
        Dict with keys: 'open' (bool), 'unauth' (bool), 'databases' (list),
        'raw' (str).
    """
    print(f"    [+] ENUM: MongoDB check on {target_ip}:{port}")
    info: dict = {"open": False, "unauth": False, "databases": [], "raw": ""}

    result = run_command(
        f"mongo --host {target_ip}:{port} "
        f"--eval 'db.adminCommand({{listDatabases:1}})' --quiet 2>/dev/null"
    )
    stdout = result.get("stdout", "")
    info["raw"] = stdout

    if stdout and ("db_name" in stdout or '"name"' in stdout or "totalSize" in stdout.lower()):
        info["open"] = True
        info["unauth"] = True
        # Try to extract database names from JSON-ish output
        for m in re.finditer(r'"name"\s*:\s*"([^"]+)"', stdout):
            info["databases"].append(m.group(1))
        print(f"    [+] ENUM: MongoDB UNAUTHENTICATED access; "
              f"dbs={info['databases']}")
        return info

    # Fallback: nmap script
    print(f"    [+] ENUM: mongo shell failed; trying nmap mongodb-info")
    nmap_res = run_command(
        f"nmap -p {port} --script mongodb-info {target_ip} 2>/dev/null"
    )
    nmap_out = nmap_res.get("stdout", "")
    info["raw"] = nmap_out or stdout
    if nmap_out and "open" in nmap_out.lower():
        info["open"] = True
    if "MongoDB" in nmap_out and ("version" in nmap_out.lower()):
        info["unauth"] = True
    if info["open"]:
        print(f"    [+] ENUM: MongoDB port {port} appears open")
    return info


def check_redis(target_ip: str, port: int = 6379) -> dict:
    """
    Check for unauthenticated Redis via redis-cli INFO.

    Args:
        target_ip: Target host.
        port: Redis port (default 6379).

    Returns:
        Dict with keys: 'open' (bool), 'unauth' (bool), 'version' (str),
        'os' (str), 'raw' (str).
    """
    print(f"    [+] ENUM: Redis check on {target_ip}:{port}")
    info: dict = {"open": False, "unauth": False, "version": "", "os": "", "raw": ""}

    result = run_command(
        f"redis-cli -h {target_ip} -p {port} INFO 2>/dev/null"
    )
    stdout = result.get("stdout", "")
    info["raw"] = stdout

    if stdout and "redis_version" in stdout:
        info["open"] = True
        info["unauth"] = True
        for line in stdout.splitlines():
            if line.startswith("redis_version:"):
                info["version"] = line.split(":", 1)[1].strip()
            elif line.startswith("os:"):
                info["os"] = line.split(":", 1)[1].strip()
        print(f"    [+] ENUM: Redis UNAUTHENTICATED; version={info['version']}")
    else:
        # Fallback: nmap
        nmap_res = run_command(
            f"nmap -p {port} --script redis-info {target_ip} 2>/dev/null"
        )
        nmap_out = nmap_res.get("stdout", "")
        info["raw"] = nmap_out or stdout
        if "open" in nmap_out.lower():
            info["open"] = True
        if "redis_version" in nmap_out:
            info["unauth"] = True
            m = re.search(r"redis_version[:=]\s*([\d.]+)", nmap_out)
            if m:
                info["version"] = m.group(1)
        if info["open"]:
            print(f"    [+] ENUM: Redis port {port} appears open")
    return info


def check_elasticsearch(target_ip: str, port: int = 9200) -> dict:
    """
    Check for open Elasticsearch via HTTP.

    Args:
        target_ip: Target host.
        port: Elasticsearch REST port (default 9200).

    Returns:
        Dict with keys: 'open' (bool), 'version' (str), 'cluster' (str),
        'raw' (str).
    """
    print(f"    [+] ENUM: Elasticsearch check on {target_ip}:{port}")
    info: dict = {"open": False, "version": "", "cluster": "", "raw": ""}

    resp = http_get(f"http://{target_ip}:{port}/")
    if resp is None:
        # http_get may return dict with error or None depending on impl
        print(f"    [+] ENUM: Elasticsearch {target_ip}:{port} not reachable")
        return info

    body = resp.get("body", "") if isinstance(resp, dict) else ""
    status = resp.get("status", 0) if isinstance(resp, dict) else 0
    info["raw"] = body or ""

    if status and status == 200 and body and "cluster_name" in body:
        info["open"] = True
        m = re.search(r'"number"\s*:\s*"([^"]+)"', body)
        if m:
            info["version"] = m.group(1)
        m = re.search(r'"cluster_name"\s*:\s*"([^"]+)"', body)
        if m:
            info["cluster"] = m.group(1)
        print(f"    [+] ENUM: Elasticsearch OPEN; version={info['version']} "
              f"cluster={info['cluster']}")
    elif body:
        info["open"] = True
        print(f"    [+] ENUM: Elasticsearch {target_ip}:{port} responded")
    return info


def check_ftp_content(target_ip: str, port: int = 21) -> dict:
    """
    Check for anonymous FTP access and list accessible files.

    Uses raw socket FTP with active mode (PORT command) to handle servers
    that advertise internal IPs in PASV mode (common in pivoting labs).

    Args:
        target_ip: Target host.
        port: FTP port (default 21).

    Returns:
        Dict with keys: 'anonymous' (bool), 'banner' (str), 'files' (list),
        'raw' (str), 'file_contents' (dict of filename → content).
    """
    print(f"    [+] ENUM: FTP anonymous check on {target_ip}:{port}")
    import socket as _sock
    import re as _re

    info: dict = {
        "anonymous": False, "banner": "", "files": [], "raw": "",
        "file_contents": {},
    }

    def _ftp_cmd(cmd, collect_data=False, listener_ip=""):
        """Send FTP command over raw socket with active mode data connection."""
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(8)
        s.connect((target_ip, port))
        s.recv(1024)  # banner
        s.sendall(b"USER anonymous\r\n")
        s.recv(1024)
        s.sendall(b"PASS anonymous@\r\n")
        auth = s.recv(1024)
        if b"230" not in auth:
            s.close()
            return None, "AUTH FAILED"

        if collect_data:
            # Set up active mode listener
            data_port = 55600
            while data_port < 55700:
                try:
                    s_data = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
                    s_data.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
                    s_data.bind((listener_ip, data_port))
                    s_data.listen(1)
                    s_data.settimeout(10)
                    break
                except OSError:
                    data_port += 1
                    s_data = None
            if not s_data:
                s.close()
                return None, "NO PORT AVAILABLE"

            p1, p2 = data_port // 256, data_port % 256
            ip_parts = listener_ip.split(".")
            s.sendall(f"PORT {ip_parts[0]},{ip_parts[1]},{ip_parts[2]},{ip_parts[3]},{p1},{p2}\r\n".encode())
            s.recv(1024)

            s.sendall(cmd.encode() + b"\r\n")
            s.recv(1024)

            try:
                conn, _ = s_data.accept()
                data = b""
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                conn.close()
            except _sock.timeout:
                data = b""
            s_data.close()
            s.close()
            return data.decode(errors="replace"), None
        else:
            s.sendall(cmd.encode() + b"\r\n")
            resp = s.recv(4096)
            s.close()
            return resp.decode(errors="replace"), None

    try:
        # Detect our listener IP from the route to the target (works for any
        # VPN interface — tun0/tap0/pwnbg — falls back to tun0 then default)
        import utils as _utils
        listener_ip = ""
        for detect_cmd in (
            f"ip -4 route get {target_ip} 2>/dev/null | grep -oP 'src \\K[\\d.]+'",
            "ip -4 addr show tun0 2>/dev/null | grep -oP 'inet \\K[\\d.]+'",
        ):
            try:
                det_result = _utils.run_command(detect_cmd, timeout=3)
                ip_cand = det_result.get("stdout", "").strip()
                if ip_cand:
                    listener_ip = ip_cand
                    break
            except Exception as e:
                swallow(__name__ + ":514", e)
        if not listener_ip:
            # never break the dict contract — keep old hardcoded-VPN behavior
            # minus the hardcoded value: mark anonymous check failed.
            info["raw"] = "could not determine listener IP (no route to target)"
            return info

        # Test anonymous login + get banner
        banner_sock = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        banner_sock.settimeout(5)
        banner_sock.connect((target_ip, port))
        banner = banner_sock.recv(1024).decode(errors="replace").strip()
        info["banner"] = banner
        banner_sock.sendall(b"USER anonymous\r\n")
        banner_sock.recv(1024)
        banner_sock.sendall(b"PASS anonymous@\r\n")
        auth_resp = banner_sock.recv(1024).decode(errors="replace")
        banner_sock.close()

        if "230" in auth_resp:
            info["anonymous"] = True
            print(f"    [+] ENUM: FTP ANONYMOUS login succeeded")

            # List root directory using active mode
            root_listing, err = _ftp_cmd("LIST", collect_data=True, listener_ip=listener_ip)
            if root_listing and root_listing != "AUTH FAILED":
                info["raw"] = root_listing
                for ln in root_listing.split("\n"):
                    parts = ln.split()
                    if len(parts) >= 9:
                        fname = " ".join(parts[8:])
                        if fname not in (".", ".."):
                            info["files"].append(fname)

                            # Download root text files (check for flags/creds)
                            if any(fname.endswith(ext) for ext in ['.txt', '.cfg', '.conf', '.md', '.json', '.csv']):
                                content, _ = _ftp_cmd(f"RETR {fname}", collect_data=True, listener_ip=listener_ip)
                                if content and "AUTH FAILED" not in content and len(content) < 10000:
                                    info["file_contents"][fname] = content

            # Explore common + Dante-specific directories
            extra_dirs = ["pub", "upload", "incoming", "share", "Transfer", "Transfer/Incoming", "Transfer/Outgoing"]
            for dirname in extra_dirs:
                listing, err = _ftp_cmd(f"LIST {dirname}", collect_data=True, listener_ip=listener_ip)
                if listing and "AUTH FAILED" not in listing and listing.strip():
                    for ln in listing.split("\n"):
                        parts = ln.split()
                        if len(parts) >= 9:
                            fname = " ".join(parts[8:])
                            if fname not in (".", ".."):
                                full_path = f"{dirname}/{fname}"
                                info["files"].append(full_path)

                                # Download text files (check for flags/creds)
                                if any(fname.endswith(ext) for ext in ['.txt', '.cfg', '.conf', '.md', '.json', '.csv']):
                                    content, _ = _ftp_cmd(f"RETR {dirname}/{fname}", collect_data=True, listener_ip=listener_ip)
                                    if content and len(content) < 10000:
                                        info["file_contents"][full_path] = content

            if info["files"]:
                print(f"    [+] ENUM: FTP listed {len(info['files'])} files")
                for fn in info["files"][:10]:
                    print(f"      → {fn}")

        else:
            print(f"    [+] ENUM: FTP anonymous login failed")
    except Exception as exc:
        print(f"    [+] ENUM: FTP check error: {exc}")

    return info


# ---------------------------------------------------------------------------
# CMS-Specific Enumeration
# ---------------------------------------------------------------------------

def wordpress_enum(url: str) -> dict:
    """
    Enumerate a WordPress site.

    Checks: REST API users/posts, xmlrpc.php methods, login pages,
    plugins/themes directories, and author archives.

    Args:
        url: Base URL of the WordPress site (e.g. http://target/).

    Returns:
        Dict with keys: 'users' (list), 'posts' (list), 'plugins' (list),
        'themes' (list), 'version' (str), 'xmlrpc_methods' (list).
    """
    print(f"    [+] ENUM: WordPress enumeration on {url}")
    info: dict = {
        "users": [],
        "posts": [],
        "plugins": [],
        "themes": [],
        "version": "",
        "xmlrpc_methods": [],
    }

    base = url.rstrip("/")

    # --- REST API: users ---
    resp = http_get(f"{base}/wp-json/wp/v2/users")
    if resp and isinstance(resp, dict):
        body = resp.get("body", "")
        if body and body.lstrip().startswith("["):
            try:
                import json
                users = json.loads(body)
                for u in users:
                    name = u.get("name") or u.get("slug")
                    if name:
                        info["users"].append(
                            {"name": name, "slug": u.get("slug"),
                             "id": u.get("id")}
                        )
            except (ValueError, TypeError):
                pass
    if info["users"]:
        print(f"    [+] ENUM: WP REST users: "
              f"{[u['name'] for u in info['users']]}")

    # --- REST API: posts (extract authors) ---
    resp = http_get(f"{base}/wp-json/wp/v2/posts")
    if resp and isinstance(resp, dict):
        body = resp.get("body", "")
        if body and body.lstrip().startswith("["):
            try:
                import json
                posts = json.loads(body)
                for p in posts[:10]:
                    title = p.get("title", {})
                    if isinstance(title, dict):
                        title = title.get("rendered", "")
                    info["posts"].append(
                        {"id": p.get("id"), "title": title,
                         "author": p.get("author")}
                    )
            except (ValueError, TypeError):
                pass

    # --- xmlrpc.php methods ---
    xmlrpc_body = (
        '<?xml version="1.0"?>'
        "<methodCall><methodName>system.listMethods</methodName>"
        "<params></params></methodCall>"
    )
    resp = http_post(f"{base}/xmlrpc.php", data=xmlrpc_body)
    if resp and isinstance(resp, dict):
        body = resp.get("body", "")
        if body and "<value><string>" in body:
            for m in re.finditer(r"<value><string>([^<]+)</string>", body):
                info["xmlrpc_methods"].append(m.group(1))
        if info["xmlrpc_methods"]:
            print(f"    [+] ENUM: WP xmlrpc.php exposed "
                  f"({len(info['xmlrpc_methods'])} methods)")

    # --- Author enumeration via ?author=N ---
    for i in range(1, 6):
        resp = http_get(f"{base}/?author={i}", allow_redirects=True)
        if resp and isinstance(resp, dict):
            final_url = resp.get("url", "") or ""
            body = resp.get("body", "") or ""
            # Redirect to /author/<slug>/ reveals username
            m = re.search(r"/author/([^/\"'?]+)/?", final_url)
            if m:
                slug = m.group(1)
                if slug not in [u.get("slug") for u in info["users"]]:
                    info["users"].append(
                        {"name": slug, "slug": slug, "id": i, "source": "author"}
                    )
            else:
                m = re.search(
                    r"author-([a-z0-9._-]+)", body, re.IGNORECASE
                )
                if m:
                    slug = m.group(1)
                    info["users"].append(
                        {"name": slug, "slug": slug, "id": i,
                         "source": "body_class"}
                    )

    # --- Version via generator meta tag ---
    resp = http_get(f"{base}/")
    if resp and isinstance(resp, dict):
        body = resp.get("body", "")
        m = re.search(
            r'name=["\']generator["\']\s+content=["\']WordPress\s+([\d.]+)["\']',
            body, re.IGNORECASE,
        )
        if m:
            info["version"] = m.group(1)
            print(f"    [+] ENUM: WP version {info['version']}")

    # --- Plugins (common ones) ---
    _COMMON_PLUGINS = [
        "akismet", "contact-form-7", "yoast", "wordfence", "elementor",
        "woocommerce", "jetpack", "wpforms-lite", "all-in-one-seo-pack",
        "duplicator", "wpdiscuz", "sitepress-multilingual-cms",
    ]
    for plugin in _COMMON_PLUGINS:
        # Check readme.txt which often exists even if plugin files are protected
        resp = http_get(
            f"{base}/wp-content/plugins/{plugin}/readme.txt"
        )
        if resp and isinstance(resp, dict):
            status = resp.get("status", 0)
            body = resp.get("body", "") or ""
            if status == 200 and ("===" in body or "Contributors" in body):
                info["plugins"].append(plugin)
    if info["plugins"]:
        print(f"    [+] ENUM: WP plugins: {info['plugins']}")

    # --- Themes (common ones) ---
    _COMMON_THEMES = [
        "twentytwentyfour", "twentytwentythree", "twentytwentytwo",
        "twentytwentyone", "twentytwenty", "twentynineteen",
        "astra", "oceanwp", "generatepress", "avada", "divi",
    ]
    for theme in _COMMON_THEMES:
        resp = http_get(
            f"{base}/wp-content/themes/{theme}/style.css"
        )
        if resp and isinstance(resp, dict):
            status = resp.get("status", 0)
            body = resp.get("body", "") or ""
            if status == 200 and "Theme Name:" in body:
                info["themes"].append(theme)
    if info["themes"]:
        print(f"    [+] ENUM: WP themes: {info['themes']}")

    return info


def joomla_enum(url: str) -> dict:
    """
    Enumerate a Joomla site.

    Checks: /administrator/, /components/, /modules/, /templates/,
    README.txt, /api/index.php, and version markers.

    Args:
        url: Base URL of the Joomla site.

    Returns:
        Dict with keys: 'admin' (bool), 'version' (str), 'components' (list),
        'templates' (list), 'raw' (str).
    """
    print(f"    [+] ENUM: Joomla enumeration on {url}")
    info: dict = {
        "admin": False,
        "version": "",
        "components": [],
        "templates": [],
        "api": False,
        "details": {},
    }

    base = url.rstrip("/")
    paths = {
        "admin": "/administrator/",
        "api": "/api/index.php",
        "readme": "/README.txt",
        "components": "/components/",
        "modules": "/modules/",
        "templates": "/templates/",
        "licenses": "/LICENSE.txt",
        "language": "/language/en-GB/en-GB.xml",
    }

    for label, path in paths.items():
        resp = http_get(f"{base}{path}")
        status = resp.get("status", 0) if isinstance(resp, dict) else 0
        body = resp.get("body", "") or "" if isinstance(resp, dict) else ""
        if status and status in (200, 301, 302, 401, 403):
            info["details"][label] = status
            if label == "admin" and status == 200:
                info["admin"] = True
                print(f"    [+] ENUM: Joomla /administrator/ accessible")
            if label == "api" and status == 200:
                info["api"] = True
                print(f"    [+] ENUM: Joomla API accessible")
            if label == "readme" and status == 200:
                m = re.search(
                    r"[Jj]oomla!?\s*(?:CMS\s*)?v?([\d.]+)", body
                )
                if m:
                    info["version"] = m.group(1)
                    print(f"    [+] ENUM: Joomla version {info['version']}")
            if label == "language" and status == 200:
                m = re.search(r"<version>([\d.]+)</version>", body)
                if m:
                    info["version"] = m.group(1)
                    print(f"    [+] ENUM: Joomla version {info['version']}")

    # Version via generator meta tag
    resp = http_get(f"{base}/")
    if resp and isinstance(resp, dict):
        body = resp.get("body", "") or ""
        if not info["version"]:
            m = re.search(
                r'name=["\']generator["\']\s+content=["\']Joomla!?\s*([\d.]+)',
                body, re.IGNORECASE,
            )
            if m:
                info["version"] = m.group(1)
                print(f"    [+] ENUM: Joomla version {info['version']}")

    return info


def drupal_enum(url: str) -> dict:
    """
    Enumerate a Drupal site.

    Checks: /user/login, /admin/, /sites/default/settings.php,
    CHANGELOG.txt, /?q=user, /node/1, and version markers.

    Args:
        url: Base URL of the Drupal site.

    Returns:
        Dict with keys: 'user_login' (bool), 'admin' (bool), 'version' (str),
        'settings_exposed' (bool), 'details' (dict).
    """
    print(f"    [+] ENUM: Drupal enumeration on {url}")
    info: dict = {
        "user_login": False,
        "admin": False,
        "version": "",
        "settings_exposed": False,
        "changelog": False,
        "node1": False,
        "details": {},
    }

    base = url.rstrip("/")
    paths = {
        "user_login": "/user/login",
        "user_login_alt": "/?q=user",
        "admin": "/admin/",
        "settings": "/sites/default/settings.php",
        "changelog": "/CHANGELOG.txt",
        "node1": "/node/1",
        "install_php": "/install.php",
        "authorize_php": "/authorize.php",
        "cron": "/cron.php",
    }

    for label, path in paths.items():
        resp = http_get(f"{base}{path}")
        status = resp.get("status", 0) if isinstance(resp, dict) else 0
        body = resp.get("body", "") or "" if isinstance(resp, dict) else ""
        if status and status in (200, 301, 302, 401, 403):
            info["details"][label] = status
            if label == "user_login" and status == 200:
                info["user_login"] = True
                print(f"    [+] ENUM: Drupal /user/login accessible")
            if label == "user_login_alt" and status == 200:
                info["user_login"] = True
            if label == "admin" and status in (200, 401, 403):
                info["admin"] = True
                print(f"    [+] ENUM: Drupal /admin/ present (status {status})")
            if label == "settings" and status == 200:
                # settings.php usually executes (empty body) but if it leaks
                info["settings_exposed"] = True
                print(f"    [+] ENUM: Drupal settings.php accessible!")
            if label == "changelog" and status == 200:
                info["changelog"] = True
                m = re.search(
                    r"Drupal\s+([\d.]+)", body
                )
                if m:
                    info["version"] = m.group(1)
                    print(f"    [+] ENUM: Drupal version {info['version']} "
                          f"(from CHANGELOG)")
            if label == "node1" and status == 200:
                info["node1"] = True

    # Version via generator meta tag
    if not info["version"]:
        resp = http_get(f"{base}/")
        if resp and isinstance(resp, dict):
            body = resp.get("body", "") or ""
            m = re.search(
                r'name=["\']generator["\']\s+content=["\']Drupal\s+([\d.]+)',
                body, re.IGNORECASE,
            )
            if m:
                info["version"] = m.group(1)
                print(f"    [+] ENUM: Drupal version {info['version']}")

    return info


# ---------------------------------------------------------------------------
# Convenience aggregator
# ---------------------------------------------------------------------------

def database_sweep(target_ip: str) -> dict:
    """
    Run all passive database checks against a target.

    Returns:
        Dict keyed by database type: 'mssql', 'mongodb', 'redis',
        'elasticsearch'.
    """
    print(f"    [+] ENUM: Database sweep on {target_ip}")
    return {
        "mssql": check_mssql(target_ip),
        "mongodb": check_mongodb(target_ip),
        "redis": check_redis(target_ip),
        "elasticsearch": check_elasticsearch(target_ip),
    }


if __name__ == "__main__":
    # Quick manual smoke test
    import sys

    if len(sys.argv) < 3:
        print("Usage: extra_enum.py <module> <target> [port]")
        print("Modules: nfs, smtp-users, smtp-ehlo, mssql, mongodb, redis, "
              "elastic, ftp, wp, joomla, drupal, dbsweep")
        sys.exit(1)

    mod = sys.argv[1]
    tgt = sys.argv[2]
    port = int(sys.argv[3]) if len(sys.argv) > 3 else None

    import json

    if mod == "nfs":
        print(json.dumps(nfs_enum(tgt), indent=2))
    elif mod == "smtp-users":
        print(json.dumps(smtp_enum_users(tgt, port or 25), indent=2))
    elif mod == "smtp-ehlo":
        print(json.dumps(smtp_check_commands(tgt, port or 25), indent=2))
    elif mod == "mssql":
        print(json.dumps(check_mssql(tgt, port or 1433), indent=2))
    elif mod == "mongodb":
        print(json.dumps(check_mongodb(tgt, port or 27017), indent=2))
    elif mod == "redis":
        print(json.dumps(check_redis(tgt, port or 6379), indent=2))
    elif mod == "elastic":
        print(json.dumps(check_elasticsearch(tgt, port or 9200), indent=2))
    elif mod == "ftp":
        print(json.dumps(check_ftp_content(tgt, port or 21), indent=2))
    elif mod == "wp":
        print(json.dumps(wordpress_enum(tgt), indent=2))
    elif mod == "joomla":
        print(json.dumps(joomla_enum(tgt), indent=2))
    elif mod == "drupal":
        print(json.dumps(drupal_enum(tgt), indent=2))
    elif mod == "dbsweep":
        print(json.dumps(database_sweep(tgt), indent=2))
    else:
        print(f"Unknown module: {mod}")
        sys.exit(1)
