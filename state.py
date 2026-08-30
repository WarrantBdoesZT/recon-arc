"""
StrikeARC — State Models
=======================
Core data structures for enumeration engagements.
Tracks hosts, services, attack vectors, findings, and active sessions.
Supports post-exploitation: compromised hosts, credentials, transport sessions,
and network topology graph for pivot operations.
"""

import json
import os
import operator
from datetime import datetime
from typing import Annotated, Dict, List, NotRequired, Optional, TypedDict


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from text."""
    import re as _re
    return _re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)


def _dedup_findings(a: list, b: list) -> list:
    """Merge findings lists, strip ANSI, dedup by content."""
    import re as _re
    seen = set()
    result = []
    for item in (a + b):
        clean = _re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', str(item)) if isinstance(item, str) else str(item)
        if clean not in seen:
            seen.add(clean)
            result.append(clean)
    return result[-500:]


# ── Dedup Reducers for LangGraph ──────────────────────────────────────

def _dedup_by_id(a: list, b: list) -> list:
    """Merge two lists, deduplicating by 'id' field. Last write wins."""
    seen = {}
    for item in (a + b):
        key = item.get("id", "") if isinstance(item, dict) else str(item)
        seen[key] = item
    return list(seen.values())[-500:]


def _dedup_by_value(a: list, b: list) -> list:
    """Merge two lists, deduplicating flags by 'flag_value' field."""
    seen = {}
    for item in (a + b):
        key = item.get("flag_value", "") if isinstance(item, dict) else str(item)
        seen[key] = item
    return list(seen.values())[-50:]


def _dedup_by_cred(a: list, b: list) -> list:
    """Merge credential lists, dedup by username:password hash:key_path."""
    seen = {}
    for item in (a + b):
        if isinstance(item, dict):
            key = f"{item.get('username','')}:{item.get('password','')}:{item.get('hash','')}:{item.get('key_path','')}"
        else:
            key = str(item)
        seen[key] = item
    return list(seen.values())[-200:]


def _dedup_by_target_vector(a: list, b: list) -> list:
    """Merge exploit_attempts, dedup by (target, vector_id) pair."""
    seen = {}
    for item in (a + b):
        if isinstance(item, dict):
            key = f"{item.get('target','')}:{item.get('vector_id','')}"
        else:
            key = str(item)
        seen[key] = item
    return list(seen.values())[-200:]


def _dedup_by_host_cred(a: list, b: list) -> list:
    """Merge lateral_attempts, dedup by (to_host, credential_id) pair."""
    seen = {}
    for item in (a + b):
        if isinstance(item, dict):
            key = f"{item.get('to_host','')}:{item.get('credential_id','')}"
        else:
            key = str(item)
        seen[key] = item
    return list(seen.values())[-100:]


def _dedup_users(a: list, b: list) -> list:
    """Merge user lists, dedup by name, cap length.

    CRITICAL: nodes return ``{**state, ...}`` (full state), so ``b`` already
    contains everything in ``a``. With plain ``operator.add`` the list DOUBLES
    on every node return (≈2× per iteration → 19 GB JSON, OOM SIGKILL on the
    mail-box run 2026-08-27). Dedup + cap makes this channel idempotent.
    """
    merged: dict = {}
    for item in (a + b):
        if isinstance(item, str):
            item = item.strip()
        if item:
            merged[item] = None
    return list(merged)[-500:]


class ServiceInfo(TypedDict):
    port: int
    protocol: str        # tcp, udp
    service: str         # ssh, http, smb, etc.
    version: str
    banner: str
    enumerated: bool     # has deep enum been run?


class WebAppInfo(TypedDict):
    url: str
    status_code: int
    title: str
    server: str
    technologies: List[str]      # detected frameworks/libs
    directories: List[dict]      # discovered paths
    forms: List[dict]            # forms found
    api_endpoints: List[dict]    # API endpoints
    interesting_findings: List[str]
    enumerated: bool


class ADInfo(TypedDict):
    domain_name: str
    dc_ip: str
    functional_level: str
    users: List[str]
    groups: List[str]
    computers: List[str]
    spns: List[str]
    trusts: List[str]
    ca_servers: List[str]        # ADCS certificate authorities
    enum_method: str             # ldap, rpcclient, null_session


class AttackVector(TypedDict):
    id: str
    target: str                  # host:port or URL
    category: str                # initial_access, privesc, lateral, ad_attack
    vector_type: str             # sqli, xss, rce, default_creds, etc.
    title: str
    description: str
    confidence: str              # high, medium, low
    score: int                   # 0-100 ranking
    evidence: List[str]          # supporting findings
    exploit_suggestions: List[str]  # suggested tools/techniques
    prerequisites: List[str]
    cves: List[str]
    references: List[str]


class HostFinding(TypedDict):
    id: str
    host_ip: str
    category: str               # recon, web, ad, vuln, cred_leak
    detail: str
    severity: str               # info, low, medium, high, critical
    raw_data: str


class NetworkHost(TypedDict):
    ip: str
    hostname: Optional[str]
    os: str
    os_version: str
    domain: Optional[str]
    services: Dict[int, ServiceInfo]
    web_apps: List[WebAppInfo]
    ad_info: Optional[ADInfo]
    findings: List[HostFinding]
    attack_vectors: List[AttackVector]
    enumerated: bool
    notes: str


# ── Post-Exploitation Types ────────────────────────────────────────────

class Credential(TypedDict):
    id: str
    username: str
    password: Optional[str]          # plaintext password (if found)
    hash: Optional[str]              # NTLM, shadow hash, etc.
    hash_type: Optional[str]         # ntlm, sha512, bcrypt, etc.
    key_path: Optional[str]          # SSH key file path
    source: str                      # where found: config_file, bash_history, etc.
    source_host: str                 # host IP where cred was found
    validated: bool                  # has this cred been tested and confirmed?
    validated_against: Optional[str] # service where cred was confirmed valid
    notes: str


class Session(TypedDict):
    """An active access session on a compromised host."""
    id: str                          # unique session ID
    host_ip: str                     # compromised host IP
    transport_type: str              # local, ssh, webshell, socks, proxychain
    transport_config: dict           # transport-specific config (host, port, user, etc.)
    username: Optional[str]          # user context (www-data, root, etc.)
    privilege: str                   # user, root, system, administrator
    established_at: str              # ISO timestamp
    interfaces: List[dict]           # network interfaces on the host
    discovered_subnets: List[str]    # internal subnets visible from this host
    notes: str


class NetworkEdge(TypedDict):
    """Edge in the topology graph — how two hosts connect."""
    from_host: str                   # source IP
    to_host: str                     # destination IP
    edge_type: str                   # direct, pivot, discovered, dns_resolved
    transport: str                   # vpn, ssh_tunnel, socks_proxy, webshell
    session_id: Optional[str]        # session enabling this edge
    notes: str


class CompromisedHost(TypedDict):
    """Tracks a compromised host and what we know from inside it."""
    ip: str
    hostname: Optional[str]
    sessions: List[str]              # session IDs active on this host
    local_users: List[str]           # users discovered
    local_services: List[dict]       # services running on the host
    interfaces: List[dict]           # network interfaces
    discovered_subnets: List[str]    # internal networks visible
    credentials_found: List[str]     # credential IDs found on this host
    privesc_vectors: List[AttackVector]  # local privesc opportunities
    files_of_interest: List[dict]    # interesting files found
    os_info: dict                    # full system info
    enumerated: bool                 # has post-exploit enum been run?
    notes: str


# ── Offensive Operations Types (v7) ───────────────────────────────────

class FlagEntry(TypedDict):
    """A captured flag on a host."""
    host_ip: str
    flag_type: str                   # user, root, service, custom
    flag_value: str                  # the flag content
    path: str                        # where it was found
    captured_at: str                 # ISO timestamp
    method: str                      # how it was obtained


class ExploitAttempt(TypedDict):
    """Record of an exploitation attempt."""
    id: str
    target: str                      # host:port or URL
    vector_id: str                   # the attack vector that was exploited
    technique: str                   # sqli_dump, rce, file_upload, webshell, etc.
    command: str                     # what was executed
    success: bool
    result: str                      # output or error
    timestamp: str
    session_id: Optional[str]        # session created if successful


class Tunnel(TypedDict):
    """An active network tunnel for pivoting."""
    id: str
    tunnel_type: str                 # chisel, ligolo, ssh_forward, socks
    local_port: int
    remote_host: str                 # target reachable through tunnel
    remote_port: int
    via_host: str                    # pivot host
    pid: Optional[int]               # process ID
    established_at: str
    status: str                      # active, dead, error


class PrivescResult(TypedDict):
    """Result of privilege escalation attempt on a host."""
    host_ip: str
    current_user: str
    technique: str                   # sudo, suid, cron, kernel, cap, path
    success: bool
    new_user: Optional[str]          # user escalated to (root, etc.)
    evidence: str
    timestamp: str


class LateralAttempt(TypedDict):
    """Record of lateral movement attempt."""
    id: str
    from_host: str
    to_host: str
    credential_id: str
    technique: str                   # smb, wmi, ssh, winrm, psexec
    success: bool
    session_id: Optional[str]
    timestamp: str


class ReconState(TypedDict):
    # Network topology
    hosts: Annotated[Dict[str, NetworkHost], lambda a, b: {**a, **b}]

    # All discovered attack vectors across all hosts
    attack_vectors: Annotated[List[AttackVector], _dedup_by_id]

    # Credentials found during enumeration (not exploited, just discovered)
    discovered_credentials: Annotated[List[dict], _dedup_by_cred]

    # Accessible networks
    accessible_subnets: List[str]
    scanned_subnets: List[str]
    out_of_scope: List[str]

    # AD domain info
    domain_info: Annotated[Optional[dict], lambda a, b: b if b else a]
    all_domains: List[dict]

    # Current operating context
    current_target: str
    current_phase: str           # discover, enumerate, analyze, post_exploit, pivot, report
    current_position: str

    # LLM context accumulation
    messages: Annotated[List[str], lambda a, b: (a + b)[-50:]]
    findings: Annotated[List[str], _dedup_findings]
    errors: Annotated[List[str], lambda a, b: (a + b)[-100:]]

    # Vault knowledge matches (knowledge/retrieval.py) — notes injected at analyze time
    knowledge_matches: List[dict]

    # Coverage engine (knowledge/coverage.py) — vault-technique checklist per
    # host×service; rebuilt after enumeration updates; drives enum batches
    coverage: List[dict]
    # Evidence store root for this session (/mnt/storage/strikearc/<session>)
    evidence_dir: NotRequired[str]
    # Aquatone/web evidence collected this session (summary dicts)
    evidence_web: NotRequired[List[dict]]
    web_probe_results: NotRequired[List[dict]]
    web_probe_leads: NotRequired[List[dict]]

    # Iteration control
    iteration: int
    max_iterations: int

    # Stall detection
    stall_count: int
    last_findings_len: int

    # Config
    initial_subnet: str
    vpn_interface: str
    listener_ip: str
    wordlist: str                # gobuster/ffuf wordlist path
    output_dir: str
    no_llm: bool                 # skip LLM calls (offline mode)

    # Feature flags (v3)
    quick_mode: bool             # --quick: skip deep enumeration
    test_creds: bool             # --test-creds: test default credentials
    cve_research: bool           # --cve-research: search NVD for CVEs

    # Internal tracking (not persisted)
    _cve_research_done: bool
    _cred_test_done: bool

    # Enumerated identities (SMTP VRFY, LDAP, enum4linux, etc.) — declared
    # so LangGraph checkpoints persist them across resume; attack_path
    # credential attacks (hydra -L fixup) consume them.
    # MUST use a dedup+cap reducer: operator.add doubles the list every node
    # return because nodes re-emit full state (run-10 OOM root cause).
    _domain_users: Annotated[List[str], _dedup_users]
    _analysis_done: bool

    # Post-exploitation state (v5)
    sessions: Annotated[List[Session], _dedup_by_id]
    compromised_hosts: Annotated[Dict[str, CompromisedHost], lambda a, b: {**a, **b}]
    topology_edges: Annotated[List[NetworkEdge], _dedup_by_id]
    all_credentials: Annotated[List[Credential], _dedup_by_cred]
    active_transport: str        # name of the active transport (for routing commands)
    pivot_depth: int             # how many hops from the VPN entry point
    session_file: str            # path to session config file for loading transports

    # Offensive operations state (v7)
    flags_captured: Annotated[List[FlagEntry], _dedup_by_value]
    exploit_attempts: Annotated[List[ExploitAttempt], _dedup_by_target_vector]
    playbook_runs: Annotated[List[Dict], _dedup_by_id]  # v9: playbook execution log
    active_tunnels: Annotated[List[Tunnel], _dedup_by_id]
    privesc_results: Annotated[Dict[str, PrivescResult], lambda a, b: {**a, **b}]
    lateral_attempts: Annotated[List[LateralAttempt], _dedup_by_host_cred]
    kill_chain_phase: str        # recon, exploit, privesc, lateral, pivot, flag_hunt
    exploit_threshold: int       # minimum score to auto-exploit (default 70)
    flags_found_count: int       # running total

    # Interactive copilot mode (v7.9)
    auto_approve: bool                    # auto-approve high-confidence hypotheses
    _copilot_skip_hosts: List[str]        # hosts the operator chose to skip

    # Session
    session_id: str
    save_path: str


def initial_state(
    initial_subnet: str,
    listener_ip: str = "",
    vpn_interface: str = "tun0",
    max_iterations: int = 50,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    output_dir: str = "",
    session_id: Optional[str] = None,
    out_of_scope: Optional[List[str]] = None,
    no_llm: bool = False,
) -> ReconState:
    """Create initial state for a new enumeration engagement."""
    if session_id is None:
        session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    if not output_dir:
        output_dir = os.path.expanduser(f"~/projects/recon-arc/output/{session_id}")

    return ReconState(
        hosts={},
        attack_vectors=[],
        discovered_credentials=[],
        accessible_subnets=[initial_subnet],
        scanned_subnets=[],
        out_of_scope=out_of_scope or [],
        domain_info=None,
        all_domains=[],
        current_target="",
        current_phase="discover",
        current_position=listener_ip,
        messages=[],
        findings=[],
        errors=[],
        knowledge_matches=[],
        coverage=[],
        iteration=0,
        max_iterations=max_iterations,
        stall_count=0,
        last_findings_len=-1,
        initial_subnet=initial_subnet,
        vpn_interface=vpn_interface,
        listener_ip=listener_ip,
        wordlist=wordlist,
        output_dir=output_dir,
        no_llm=no_llm,
        quick_mode=False,
        test_creds=False,
        cve_research=True,
        _cve_research_done=False,
        _cred_test_done=False,
        _analysis_done=False,
        sessions=[],
        compromised_hosts={},
        topology_edges=[],
        all_credentials=[],
        active_transport="local",
        pivot_depth=0,
        session_file="",
        flags_captured=[],
        exploit_attempts=[],
        active_tunnels=[],
        privesc_results={},
        lateral_attempts=[],
        kill_chain_phase="recon",
        exploit_threshold=70,
        flags_found_count=0,
        auto_approve=False,
        _copilot_skip_hosts=[],
        session_id=session_id,
        save_path=f"~/projects/recon-arc/saves/{session_id}.json",
    )


def save_state(state: ReconState, path: Optional[str] = None) -> str:
    """Persist enumeration state to JSON for resume."""
    if path is None:
        path = state.get("save_path", "~/projects/recon-arc/saves/session.json")
    path = os.path.expanduser(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)

    serializable = {}
    for k, v in state.items():
        try:
            json.dumps(v)
            serializable[k] = v
        except (TypeError, ValueError):
            serializable[k] = str(v)

    with open(path, "w") as f:
        json.dump(serializable, f, indent=2, default=str)
    return path


def load_state(path: str) -> ReconState:
    """Load saved enumeration state."""
    path = os.path.expanduser(path)
    with open(path) as f:
        data = json.load(f)
    # v8.2.2: save_state stringifies non-JSON values, so sets come back as
    # repr-strings ("{'a', 'b'}"). Restore _discovered_domains to a real set
    # — nodes call .add() on it, which would crash on a resumed save.
    dd = data.get("_discovered_domains")
    if isinstance(dd, str):
        import re as _re
        items = _re.findall(r"[A-Za-z0-9._-]+\.[A-Za-z]{2,}", dd)
        data["_discovered_domains"] = set(items)
    return ReconState(**data)


# ── Helper functions ──────────────────────────────────────────────────

def get_unenumerated_hosts(state: ReconState) -> Dict[str, NetworkHost]:
    return {
        ip: h for ip, h in state["hosts"].items()
        # v10.2: DNS-promoted hosts are born with services={} — include them
        # (h["services"]) so the walker port-scans and enumerates them.
        if not h["enumerated"] and (h["services"] or h.get("discovered_via", "").startswith("DNS:"))
    }


def get_enumerated_hosts(state: ReconState) -> Dict[str, NetworkHost]:
    return {ip: h for ip, h in state["hosts"].items() if h["enumerated"]}


def get_attack_vectors_by_confidence(state: ReconState) -> List[AttackVector]:
    """Return attack vectors sorted by score (highest first)."""
    vectors = sorted(state.get("attack_vectors", []),
                     key=lambda v: v.get("score", 0), reverse=True)
    return vectors


def get_vectors_by_category(state: ReconState, category: str) -> List[AttackVector]:
    return [v for v in state.get("attack_vectors", []) if v.get("category") == category]


def get_engagement_summary(state: ReconState) -> str:
    """Generate a compact text summary for LLM context."""
    lines = []
    total = len(state["hosts"])
    enumerated = len(get_enumerated_hosts(state))
    lines.append(f"Hosts discovered: {total} ({enumerated} fully enumerated)")

    for ip, host in sorted(state["hosts"].items()):
        services = ", ".join(
            f"{s['service']}/{p}" for p, s in sorted(host["services"].items())
        )[:80]
        web_count = len(host.get("web_apps", []))
        av_count = len(host.get("attack_vectors", []))
        lines.append(f"  {ip:16s} [{host.get('os', '?'):8s}] {services}")
        if web_count:
            lines.append(f"                   Web apps: {web_count}")
        if av_count:
            lines.append(f"                   Attack vectors: {av_count}")

    # Attack vector summary — dedup by ID
    all_vec_ids = set()
    all_vecs = []
    for v in state.get("attack_vectors", []):
        vid = v.get("id", "")
        if vid not in all_vec_ids:
            all_vec_ids.add(vid)
            all_vecs.append(v)
    for ip, h in state.get("hosts", {}).items():
        for v in h.get("attack_vectors", []):
            vid = v.get("id", "")
            if vid not in all_vec_ids:
                all_vec_ids.add(vid)
                all_vecs.append(v)
    if all_vecs:
        lines.append(f"\nAttack Vectors: {len(all_vecs)} total")
        by_cat = {}
        for v in all_vecs:
            by_cat.setdefault(v.get("category", "uncategorized"), []).append(v)
        for cat, vecs in sorted(by_cat.items()):
            high = sum(1 for v in vecs if v["confidence"] == "high")
            lines.append(f"  {cat}: {len(vecs)} ({high} high-confidence)")

    # Credentials discovered
    creds = state.get("discovered_credentials", [])
    if creds:
        lines.append(f"\nCredentials Found: {len(creds)}")
        for c in creds[:10]:
            lines.append(f"  {c.get('username', '?')}: {c.get('type', '?')}")

    # Domain info
    di = state.get("domain_info")
    if di:
        lines.append(f"\nDomain: {di.get('name', '?')} (DC: {di.get('dc_ip', '?')})")
        users = di.get("users", [])
        if users:
            lines.append(f"  Users: {len(users)} discovered")
            lines.append(f"  First 10: {', '.join(sorted(users)[:10])}")

    lines.append(f"\nAccessible networks: {', '.join(state['accessible_subnets'])}")
    lines.append(f"Iteration: {state['iteration']}/{state['max_iterations']}")

    # Post-exploitation state
    sessions = state.get("sessions", [])
    if sessions:
        lines.append(f"\nActive Sessions: {len(sessions)}")
        for s in sessions:
            lines.append(
                f"  {s['id']}: {s['host_ip']} ({s['transport_type']}/{s.get('privilege','?')}) "
                f"subnets: {', '.join(s.get('discovered_subnets', []))}"
            )

    compromised = state.get("compromised_hosts", {})
    if compromised:
        lines.append(f"\nCompromised Hosts: {len(compromised)}")
        for ip, ch in compromised.items():
            cred_count = len(ch.get("credentials_found", []))
            pe = "✓" if ch.get("enumerated") else "✗"
            lines.append(f"  {ip} [post-enum:{pe}] creds:{cred_count}")

    edges = state.get("topology_edges", [])
    if edges:
        lines.append(f"\nTopology: {len(edges)} edges")
        for e in edges[:5]:
            lines.append(f"  {e['from_host']} → {e['to_host']} ({e['edge_type']}/{e['transport']})")

    all_creds = state.get("all_credentials", [])
    if all_creds:
        validated = [c for c in all_creds if c.get("validated")]
        lines.append(f"\nCredentials: {len(all_creds)} total ({len(validated)} validated)")

    return "\n".join(lines)
