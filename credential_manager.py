"""
StrikeARC — Credential Manager
===============================
Tracks all discovered credentials, manages spray/test history, and
provides query interfaces for the scope/lateral/copilot nodes.

Ported from prolab-agent (battle-tested on Dante/Zephyr) and adapted
to StrikeARC's ReconState.Credential shape:
    id, username, password, hash, hash_type, key_path, source,
    source_host, validated, validated_against, notes

Key fixes inherited from prolab-agent v3 (commit e0eb551):
  - Spray targets are filtered to hosts with an authentication service
    (SSH/SMB/WinRM/RDP ports). Without this the agent loops forever
    spraying web-only hosts.
  - Deterministic credential IDs prevent duplicate entries.
"""

import hashlib
import time
from typing import Dict, List, Optional, Tuple

from state import Credential, ReconState

# Ports that expose an authentication service worth spraying
SPRAYABLE_PORTS = {22, 445, 5985, 5986, 3389}
SPRAYABLE_SERVICES = ("ssh", "microsoft-ds", "smb", "winrm", "rdp", "ms-wbt-server")


class CredentialManager:
    """Manages credentials across the engagement lifecycle."""

    def __init__(self, state: ReconState):
        self.state = state

    def _cred_id(self, username: str, password: str = "", hash_: str = "",
                 key_path: str = "") -> str:
        """Deterministic ID so the same secret is never stored twice."""
        material = f"{username}|{password}|{hash_}|{key_path}"
        short = hashlib.sha256(material.encode()).hexdigest()[:8]
        return f"cred_{username}_{short}"

    def add_credential(
        self,
        username: str,
        password: Optional[str] = None,
        hash_: Optional[str] = None,
        hash_type: Optional[str] = None,
        key_path: Optional[str] = None,
        source: str = "",
        source_host: str = "",
        notes: str = "",
    ) -> str:
        """
        Register a newly discovered credential.

        Returns the credential ID. If the credential already exists,
        merges source information instead of duplicating.
        """
        if not username:
            return ""
        if not any([password, hash_, key_path]):
            return ""  # nothing secret about it

        cred_id = self._cred_id(username, password or "", hash_ or "", key_path or "")
        existing = self.state.get("all_credentials", [])

        for c in existing:
            if c.get("id") == cred_id:
                # Merge: enrich source info, never downgrade validated
                if source_host and source_host not in (c.get("source_host") or ""):
                    c["source_host"] = f"{c.get('source_host') or ''}, {source_host}".strip(", ")
                if notes and notes not in (c.get("notes") or ""):
                    c["notes"] = f"{c.get('notes') or ''} {notes}".strip()
                return cred_id

        cred = Credential(
            id=cred_id,
            username=username,
            password=password,
            hash=hash_,
            hash_type=hash_type,
            key_path=key_path,
            source=source,
            source_host=source_host,
            validated=False,
            validated_against=None,
            notes=notes,
        )
        self.state["all_credentials"] = existing + [cred]
        kind = "password" if password else (hash_type or "key")
        print(f"  [+] New credential: {username} ({kind}) from {source_host or source}")
        return cred_id

    def record_test_result(
        self, cred_id: str, host_ip: str, success: bool, service: str = ""
    ) -> None:
        """Record the result of testing a credential against a host."""
        record = (
            f"[SPRAY] {cred_id} -> {host_ip}:{service} "
            f"{'SUCCESS' if success else 'FAILED'}"
        )
        self.state["findings"] = self.state.get("findings", []) + [record]

        for c in self.state.get("all_credentials", []):
            if c.get("id") != cred_id:
                continue
            if success:
                c["validated"] = True
                prior = c.get("validated_against") or ""
                if host_ip not in prior:
                    c["validated_against"] = f"{prior}, {host_ip}".strip(", ")
                print(f"  [!] Credential works: {c['username']} on {host_ip} ({service})")

    def tested_pairs(self) -> set:
        """(cred_id, host_ip) pairs already tried, from findings log."""
        pairs = set()
        for f in self.state.get("findings", []):
            if f.startswith("[SPRAY] ") and "->" in f:
                # [SPRAY] cred_x_ab12 -> 10.10.110.100:ssh SUCCESS
                try:
                    left, right = f[8:].split(" -> ")
                    host = right.split(":")[0].strip()
                    pairs.add((left.strip(), host))
                except ValueError:
                    continue
        # lateral attempts count as tests too
        for a in self.state.get("lateral_attempts", []):
            pairs.add((a.get("credential_id", ""), a.get("to_host", "")))
        return pairs

    def get_untested(self, target_ip: str, service: Optional[str] = None) -> List[Credential]:
        """Credentials not yet tried against a target host."""
        tried = {cid for cid, host in self.tested_pairs() if host == target_ip}
        results = []
        for c in self.state.get("all_credentials", []):
            if c.get("id") in tried:
                continue
            if service and not self._applies_to_service(c, service):
                continue
            results.append(c)
        return results

    @staticmethod
    def _applies_to_service(cred: Credential, service: str) -> bool:
        service = service.lower()
        if service in ("ssh",):
            return bool(cred.get("password") or cred.get("key_path"))
        if service in ("smb", "cifs", "microsoft-ds", "winrm", "rdp", "ms-wbt-server"):
            return bool(cred.get("password") or cred.get("hash"))
        if service in ("mssql", "mysql", "postgres", "ftp", "http", "https", "ldap"):
            return bool(cred.get("password"))
        return True  # unknown service — don't filter

    def get_validated(self) -> List[Credential]:
        """All credentials confirmed valid somewhere."""
        return [c for c in self.state.get("all_credentials", []) if c.get("validated")]

    def get_validated_for_host(self, host_ip: str) -> List[Credential]:
        """Credentials confirmed valid on a specific host."""
        return [
            c for c in self.state.get("all_credentials", [])
            if c.get("validated") and host_ip in (c.get("validated_against") or "")
        ]

    def get_spray_targets(self) -> List[Tuple[str, List[Credential], List[str]]]:
        """
        (host_ip, untested_creds, service_names) tuples for hosts that
        actually have an authentication service.

        CRITICAL (prolab lesson): only return hosts with a sprayable
        service. Without this filter the agent loops for 100+ iterations
        trying credentials against web-only hosts.
        """
        compromised = set(self.state.get("compromised_hosts", {}).keys())
        compromised |= {s["host_ip"] for s in self.state.get("sessions", [])}
        tried = self.tested_pairs()

        targets = []
        for ip, host in self.state.get("hosts", {}).items():
            if ip in compromised:
                continue

            services = host.get("services", {})
            svc_names = [
                (svc.get("service") or "").lower() for svc in services.values()
            ]
            has_sprayable_service = any(
                any(s in name for s in SPRAYABLE_SERVICES) for name in svc_names
            )
            has_sprayable_port = any(
                int(p) in SPRAYABLE_PORTS for p in services.keys()
            )
            if not (has_sprayable_service or has_sprayable_port):
                continue

            untested = [
                c for c in self.state.get("all_credentials", [])
                if (c.get("id"), ip) not in tried
            ]
            if untested:
                targets.append((ip, untested, svc_names))
        return targets

    def prioritize(self, creds: List[Credential]) -> List[Credential]:
        """Sort by likely value: validated > password-bearing > hash > key."""
        def score(c):
            s = 0
            if c.get("validated"):
                s += 100
            if c.get("password"):
                s += 20
            if c.get("hash"):
                s += 10
            if c.get("key_path"):
                s += 5
            return -s
        return sorted(creds, key=score)

    def summary(self) -> str:
        """One-screen credential database summary."""
        creds = self.state.get("all_credentials", [])
        if not creds:
            return "Credentials: none discovered yet."

        validated = [c for c in creds if c.get("validated")]
        lines = [f"Credentials: {len(creds)} total ({len(validated)} validated)"]

        by_kind: Dict[str, int] = {}
        for c in creds:
            kind = "password" if c.get("password") else (c.get("hash_type") or "key" if c.get("key_path") else "other")
            by_kind[kind] = by_kind.get(kind, 0) + 1
        lines.append(
            "  Kinds: " + ", ".join(f"{k}={n}" for k, n in sorted(by_kind.items()))
        )

        for c in creds[:30]:
            mark = "✓" if c.get("validated") else " "
            where = c.get("validated_against") or "untested"
            lines.append(
                f"  {mark} {c['username']:24s} {where[:40]}"
            )
        if len(creds) > 30:
            lines.append(f"  ... +{len(creds) - 30} more")
        return "\n".join(lines)
