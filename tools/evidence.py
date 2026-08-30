#!/usr/bin/env python3
"""Evidence Store — screenshots + text snapshots → /mnt/storage/strikearc/<session>/.

Two capture modes:
  1. Web screenshots  — headless Chrome (no X server required), PNG
  2. Text snapshots   — tool output, banners, credentials, findings (timestamped .txt)

Every artifact is recorded in manifest.json with sha256 + relative path, so the
report can link evidence and resume sessions keep working.

Layout:
  /mnt/storage/strikearc/<session>/
    manifest.json
    screenshots/   <host>_<port>_<slug>.png
    snapshots/     <kind>_<host>_<slug>_<HHMMSS>.txt

Public API (used by nodes/__init__.py):
    ev = EvidenceStore(session_id, base="/mnt/storage", enabled=True)
    path = ev.screenshot_url("10.10.10.5", 80, "http")           # blocking, Chrome headless
    path = ev.snapshot_text("ftp_banner", "10.10.10.5", "220 ProFTPD ...")
    ev.link(host, kind, path, note="anonymous FTP allowed")
    ev.summary()  -> {"screenshots": N, "snapshots": N, "dir": ...}
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time

DEFAULT_BASE = "/mnt/storage"
DEFAULT_ROOT = os.path.join(DEFAULT_BASE, "strikearc")

# Chrome flags for deterministic headless screenshots
_CHROME_FLAGS = [
    "--headless=new",
    "--no-sandbox",
    "--disable-gpu",
    "--disable-dev-shm-usage",
    "--hide-scrollbars",
    "--virtual-time-budget=8000",   # let JS render before shot
    "--window-size=1440,900",
    "--screenshot={path}",
    "--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36",
]


def _slug(text: str, maxlen: int = 40) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "_", text).strip("_")
    return s[:maxlen] or "x"


class EvidenceStore:
    def __init__(self, session_id: str, base: str = DEFAULT_BASE,
                 enabled: bool = True, chrome_bin: str | None = None):
        self.session_id = re.sub(r"[^a-zA-Z0-9._-]+", "_", session_id)[:80] or "session"
        self.base = base
        self.enabled = enabled
        self.chrome = chrome_bin or shutil.which("google-chrome") or shutil.which("chromium") \
            or shutil.which("chromium-browser")
        self.root = os.path.join(base, "strikearc", self.session_id)
        self.shot_dir = os.path.join(self.root, "screenshots")
        self.snap_dir = os.path.join(self.root, "snapshots")
        self.manifest_path = os.path.join(self.root, "manifest.json")
        self._manifest = None
        if self.enabled:
            os.makedirs(self.shot_dir, exist_ok=True)
            os.makedirs(self.snap_dir, exist_ok=True)
            self._load_manifest()

    # ------------------------------------------------------------------ manifest
    def _load_manifest(self):
        if os.path.exists(self.manifest_path):
            try:
                with open(self.manifest_path, encoding="utf-8") as fh:
                    self._manifest = json.load(fh)
            except (OSError, json.JSONDecodeError):
                self._manifest = None
        if self._manifest is None:
            self._manifest = {"session": self.session_id, "artifacts": []}

    def _flush(self):
        if not self.enabled:
            return
        tmp = self.manifest_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self._manifest, fh, indent=2)
        os.replace(tmp, self.manifest_path)

    def _record(self, kind: str, relpath: str, host: str, note: str = "",
                extra: dict | None = None):
        if self._manifest is None:  # store disabled — nothing to record into
            return None
        entry = {
            "kind": kind,
            "path": relpath,
            "host": host,
            "note": note,
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        if extra:
            entry.update(extra)
        self._manifest["artifacts"].append(entry)
        self._flush()
        return entry

    @staticmethod
    def _sha256(path: str) -> str:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except OSError:
            return ""

    # ------------------------------------------------------------------ capture
    def sweep_urls(self, urls: list[str], timeout: int = 600) -> list[dict]:
        """Batch web recon via aquatone (screenshots + headers + tech tags + HTML).

        One aquatone run per call — efficient for fleets. Artifacts land in
        <root>/aquatone/<runstamp>/ and are recorded in the manifest; parsed
        page records are returned for host-state enrichment:
          [{"url", "title", "tags": [...], "status", "screenshot": abs_path}]
        """
        if not self.enabled or not urls:
            return []
        aq = shutil.which("aquatone") or os.path.expanduser("~/tools/aquatone/aquatone")
        if not os.path.exists(aq):
            print("  [i] aquatone not found — falling back to single-shot Chrome")
            out = []
            for u in urls:
                m = re.match(r"(https?)://([^/:]+):?(\d+)?(.*)", u)
                if not m:
                    continue
                scheme, host, port, path = m.group(1), m.group(2), m.group(3), m.group(4)
                p = self.screenshot_url(host, int(port) if port else 80, scheme,
                                        path=path, note=u)
                if p:
                    out.append({"url": u, "title": "", "tags": [],
                                "status": "", "screenshot": p})
            return out
        runstamp = time.strftime("%Y%m%d_%H%M%S")
        out_dir = os.path.join(self.root, "aquatone", runstamp)
        os.makedirs(out_dir, exist_ok=True)
        wrapper = os.path.expanduser("~/tools/aquatone/aquatone-chrome")
        chrome_flag = ["-chrome-path", wrapper] if os.path.exists(wrapper) else []
        try:
            proc = subprocess.run(
                [aq, "-out", out_dir, "-scan-timeout", "2500",
                 "-screenshot-timeout", "60000", "-threads", "1",
                 *chrome_flag],
                input="\n".join(urls) + "\n", capture_output=True, text=True,
                timeout=timeout)
        except (subprocess.TimeoutExpired, OSError) as exc:
            print(f"  [!] aquatone failed: {exc}")
            return []
        sess = os.path.join(out_dir, "aquatone_session.json")
        if not os.path.exists(sess):
            return []
        try:
            with open(sess, encoding="utf-8") as fh:
                session = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return []
        pages = []
        for page in session.get("pages", {}).values():
            shot_rel = page.get("screenshotPath", "")
            shot_abs = os.path.join(out_dir, shot_rel) if shot_rel else None
            if shot_abs and not os.path.exists(shot_abs):
                shot_abs = None
            if shot_abs and os.path.getsize(shot_abs) < 4096:
                # <4KB at 1440x900 ≈ blank/killed-mid-render — drop it
                shot_abs = None
            rec = {
                "url": page.get("url", ""),
                "title": page.get("pageTitle", "") or "",
                "status": page.get("status", ""),
                "tags": [t.get("text", "") for t in page.get("tags", [])
                         if isinstance(t, dict)],
                "screenshot": shot_abs,
            }
            pages.append(rec)
            if shot_abs:
                self._record("screenshot",
                             os.path.relpath(shot_abs, self.root),
                             page.get("hostname", page.get("url", "")),
                             note=page.get("url", ""),
                             extra={"url": page.get("url", ""),
                                    "title": rec["title"],
                                    "sha256": self._sha256(shot_abs)})
        self._record("linked", f"aquatone/{runstamp}/aquatone_report.html",
                     "fleet", note=f"aquatone gallery ({len(pages)} pages)")
        stats = session.get("stats", {})
        print(f"  [AQ] aquatone: {stats.get('screenshotSuccessful', '?')} shots ok, "
              f"{stats.get('screenshotFailed', '?')} failed, gallery: aquatone/{runstamp}/")
        return pages

    def screenshot_url(self, host: str, port: int, scheme: str = "http",
                       path: str = "", note: str = "", timeout: int = 45) -> str | None:
        """Screenshot a URL with headless Chrome. Returns absolute path or None."""
        if not self.enabled:
            return None
        url = f"{scheme}://{host}:{port}{path if path.startswith('/') else ('/' + path if path else '')}"
        fname = f"{_slug(host)}_{port}{('_' + _slug(path, 24)) if path else ''}.png"
        dest = os.path.join(self.shot_dir, fname)
        # Same host+port+path re-shot: overwrite in place (keep newest frame)
        if not self.chrome:
            return None
        # Dedicated profile per store: first run builds it (slow); later runs are fast
        profile = os.path.join(self.root, "chrome-profile")
        os.makedirs(profile, exist_ok=True)
        flags = [f.format(path=dest) for f in _CHROME_FLAGS]
        flags += [f"--user-data-dir={profile}", "--no-first-run"]
        cmd = [self.chrome, *flags, url]
        for attempt in (1, 2):  # retry once — cold profile start can flake
            try:
                proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
            except (subprocess.TimeoutExpired, OSError):
                if attempt == 2:
                    return None
                continue
            if proc.returncode == 0 and os.path.exists(dest) and os.path.getsize(dest) >= 2048:
                break
            if attempt == 2:
                # Chrome writes to cwd on some versions — clean partial
                if os.path.exists(dest) and os.path.getsize(dest) < 2048:
                    os.unlink(dest)
                return None
        rel = os.path.relpath(dest, self.root)
        self._record("screenshot", rel, host,
                     note=note or f"{scheme}://{host}:{port}{path}",
                     extra={"url": url, "sha256": self._sha256(dest)})
        return dest

    def screenshot_vhost(self, vhostname: str, ip: str, port: int,
                         scheme: str = "http", note: str = "",
                         timeout: int = 45) -> str | None:
        """v10: screenshot a named vhost on a shared IP. Aquatone can't send
        Host headers, so single-shot Chrome maps the name to the IP via
        --host-resolver-rules, keeping TLS SNI correct too."""
        if not self.enabled or not self.chrome:
            return None
        url = f"{scheme}://{vhostname}:{port}/"
        fname = f"{_slug(vhostname)}_{port}.png"
        dest = os.path.join(self.shot_dir, fname)
        profile = os.path.join(self.root, "chrome-profile")
        os.makedirs(profile, exist_ok=True)
        flags = [f.format(path=dest) for f in _CHROME_FLAGS]
        flags += [
            f"--user-data-dir={profile}", "--no-first-run",
            f"--host-resolver-rules=MAP {vhostname} {ip}",
        ]
        cmd = [self.chrome, *flags, url]
        for attempt in (1, 2):
            try:
                proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
            except (subprocess.TimeoutExpired, OSError):
                if attempt == 2:
                    return None
                continue
            if proc.returncode == 0 and os.path.exists(dest) and os.path.getsize(dest) >= 2048:
                break
            if attempt == 2:
                if os.path.exists(dest) and os.path.getsize(dest) < 2048:
                    os.unlink(dest)
                return None
        rel = os.path.relpath(dest, self.root)
        self._record("screenshot", rel, vhostname,
                     note=note or f"{scheme}://{vhostname}:{port} (vhost on {ip})",
                     extra={"url": url, "vhost_of": ip, "sha256": self._sha256(dest)})
        return dest

    def snapshot_text(self, kind: str, host: str, content: str, note: str = "",
                      ext: str = "txt") -> str | None:
        """Persist a text artifact (banner, cred, tool output). Returns path."""
        if not self.enabled or not content or not content.strip():
            return None
        stamp = time.strftime("%H%M%S")
        fname = f"{_slug(kind)}_{_slug(host)}_{stamp}.{ext}"
        dest = os.path.join(self.snap_dir, fname)
        header = (f"# kind={kind} host={host} captured={time.strftime('%Y-%m-%d %H:%M:%S')}"
                  f"{' note=' + note if note else ''}\n")
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(header + content.rstrip() + "\n")
        rel = os.path.relpath(dest, self.root)
        self._record("snapshot", rel, host, note=note,
                     extra={"snap_kind": kind, "sha256": self._sha256(dest),
                            "bytes": len(content)})
        return dest

    def link(self, host: str, kind: str, path: str, note: str = ""):
        """Attach an externally-produced file (nmap XML, report, etc.)."""
        if not self.enabled or not path or not os.path.exists(path):
            return None
        dest_dir = os.path.join(self.root, "linked")
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, _slug(os.path.basename(path), 60))
        if os.path.abspath(path) != os.path.abspath(dest):
            shutil.copy2(path, dest)
        rel = os.path.relpath(dest, self.root)
        self._record("linked", rel, host, note=note or os.path.basename(path),
                     extra={"sha256": self._sha256(dest),
                            "bytes": os.path.getsize(dest)})
        return dest

    # ------------------------------------------------------------------ query
    def summary(self) -> dict:
        arts = self._manifest["artifacts"] if self._manifest else []
        return {
            "dir": self.root if self.enabled else None,
            "screenshots": sum(1 for a in arts if a["kind"] == "screenshot"),
            "snapshots": sum(1 for a in arts if a["kind"] == "snapshot"),
            "linked": sum(1 for a in arts if a["kind"] == "linked"),
            "enabled": self.enabled,
        }

    def for_host(self, host: str) -> list[dict]:
        if not self._manifest:
            return []
        return [a for a in self._manifest["artifacts"] if a.get("host") == host]

    def manifest(self) -> dict:
        return self._manifest or {"session": self.session_id, "artifacts": []}
