"""
ReconARC — State Models
=======================
Core data structures for enumeration-only engagements.
Tracks hosts, services, attack vectors, and findings.
NO exploitation state — this agent only observes and recommends.
"""

import json
import os
from datetime import datetime
from typing import Annotated, Dict, List, Optional, TypedDict


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


class ReconState(TypedDict):
    # Network topology
    hosts: Annotated[Dict[str, NetworkHost], lambda a, b: {**a, **b}]

    # All discovered attack vectors across all hosts
    attack_vectors: Annotated[List[AttackVector], lambda a, b: (a + b)[-500:]]

    # Credentials found during enumeration (not exploited, just discovered)
    discovered_credentials: Annotated[List[dict], lambda a, b: (a + b)[-200:]]

    # Accessible networks
    accessible_subnets: List[str]
    scanned_subnets: List[str]
    out_of_scope: List[str]

    # AD domain info
    domain_info: Annotated[Optional[dict], lambda a, b: b if b else a]
    all_domains: List[dict]

    # Current operating context
    current_target: str
    current_phase: str           # discover, enumerate, analyze, report
    current_position: str

    # LLM context accumulation
    messages: Annotated[List[str], lambda a, b: (a + b)[-50:]]
    findings: Annotated[List[str], lambda a, b: (a + b)[-500:]]
    errors: Annotated[List[str], lambda a, b: (a + b)[-100:]]

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
    return ReconState(**data)


# ── Helper functions ──────────────────────────────────────────────────

def get_unenumerated_hosts(state: ReconState) -> Dict[str, NetworkHost]:
    return {
        ip: h for ip, h in state["hosts"].items()
        if not h["enumerated"] and h["services"]
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
        lines.append(f"  {ip:16s} [{host['os']:8s}] {services}")
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
            by_cat.setdefault(v["category"], []).append(v)
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

    return "\n".join(lines)
