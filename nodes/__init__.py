"""
ReconARC — Graph Nodes
======================
LangGraph nodes for the enumeration pipeline:
  scope → discover → enumerate → analyze → report
The scope_node is the strategic hub that routes based on engagement state.
"""

import os
import time
from typing import Dict, List, Optional

from langchain_core.messages import SystemMessage, HumanMessage

from state import (
    ReconState, NetworkHost, ServiceInfo, WebAppInfo, ADInfo,
    AttackVector, HostFinding,
    get_unenumerated_hosts, get_enumerated_hosts,
    get_engagement_summary, save_state,
)
from llm import llm_invoke, parse_llm_json, print_llm_stats
from utils import run_command, detect_listener_ip, extract_emails, http_get

import tools.recon as recon
import tools.web_enum as web
import tools.ad_enum as ad
import tools.vuln_scan as vs


# ═══════════════════════════════════════════════════════════════════════
# DISCOVER NODE — Find new hosts and services
# ═══════════════════════════════════════════════════════════════════════

def discover_node(state: ReconState) -> ReconState:
    """Discover new hosts in accessible subnets."""
    print("\n" + "=" * 60)
    print("  PHASE: NETWORK DISCOVERY")
    print("=" * 60)

    new_findings = []
    new_hosts = {}

    for subnet in state["accessible_subnets"]:
        if subnet in state.get("scanned_subnets", []):
            continue

        print(f"  [>] Scanning {subnet}...")
        hosts = recon.network_sweep(subnet, exclude=state.get("out_of_scope", []))
        if not hosts:
            print(f"  [!] No hosts found in {subnet}")
            new_findings.append(f"[DISCOVER] Scanned: {subnet} (0 hosts)")
            continue

        for ip in hosts:
            if ip in state["hosts"]:
                continue

            print(f"  [>] Quick scan {ip}...")
            services, os_hint, raw = recon.quick_scan(ip)

            if services:
                host = NetworkHost(
                    ip=ip, hostname=None, os=os_hint, os_version="",
                    domain=None, services=services,
                    web_apps=[], ad_info=None,
                    findings=[], attack_vectors=[],
                    enumerated=False, notes="",
                )
                new_hosts[ip] = host
                svc_str = ", ".join(
                    f"{s['service']}/{p}" for p, s in sorted(services.items())
                )[:60]
                new_findings.append(
                    f"[DISCOVER] {ip}: {len(services)} services [{svc_str}] OS: {os_hint}"
                )
                print(f"  [+] {ip}: {svc_str}")

                # Check for AD indicators
                ad_ports = {88, 389, 464, 636, 3268, 3269}
                if ad_ports & set(services.keys()):
                    new_findings.append(f"[DISCOVER] {ip}: AD domain controller detected")
                    if not state.get("domain_info"):
                        print(f"  [>] Discovering AD domain on {ip}...")
                        domain = ad.discover_domain(ip)
                        if domain:
                            domain["dc_ip"] = ip
                            state["domain_info"] = domain
                            state.setdefault("all_domains", []).append(domain)
                            new_findings.append(
                                f"[DISCOVER] Domain: {domain.get('name', '?')} "
                                f"(DC: {ip})"
                            )

        new_findings.append(f"[DISCOVER] Scanned: {subnet}")

    # Mark subnets as scanned
    scanned = list(set(
        state.get("scanned_subnets", []) + state["accessible_subnets"]
    ))

    all_hosts = {**state["hosts"], **new_hosts}

    return {
        **state,
        "hosts": all_hosts,
        "scanned_subnets": scanned,
        "current_phase": "enumerate",
        "findings": _dedup(new_findings, state.get("findings", [])),
        "messages": [f"Discovery complete. {len(new_hosts)} new hosts found."],
        "iteration": state["iteration"] + 1,
    }


# ═══════════════════════════════════════════════════════════════════════
# ENUMERATE NODE — Deep dive on each host
# ═══════════════════════════════════════════════════════════════════════

def enumerate_node(state: ReconState) -> ReconState:
    """Deep enumeration of a single host."""
    target = state["current_target"]
    if not target or target not in state["hosts"]:
        return {**state, "current_phase": "scope"}

    host = state["hosts"][target]
    print("\n" + "=" * 60)
    print(f"  PHASE: ENUMERATION — {target} ({host['os']})")
    print("=" * 60)

    new_findings = []

    if host["enumerated"]:
        print(f"  [>] {target} already enumerated, skipping")
    else:
        _enumerate_host(state, host, target, new_findings)
        host["enumerated"] = True
        new_findings.append(f"[ENUM] {target}: enumeration complete")

    all_hosts = {**state["hosts"], target: host}

    return {
        **state,
        "hosts": all_hosts,
        "current_phase": "scope",
        "findings": _dedup(new_findings, state.get("findings", [])),
        "messages": [f"Enumeration of {target} complete."],
        "iteration": state["iteration"] + 1,
    }


def _enumerate_host(state, host, target, new_findings):
    """Full deep enumeration of a host: ports, services, web, AD."""
    # Full port scan if not done
    if len(host["services"]) < 5:
        print(f"  [>] Full port scan on {target}...")
        services, os_hint, raw = recon.port_scan(target, fast=False)
        host["services"] = services
        if os_hint != "unknown":
            host["os"] = os_hint
        new_findings.append(
            f"[ENUM] {target}: {len(services)} ports, OS: {os_hint}"
        )

    # Deep service enumeration
    print(f"  [>] Deep service enumeration on {target}...")
    host["services"] = recon.scan_all_services(target, host["services"])

    # searchsploit on all service versions
    for port, svc in host["services"].items():
        if svc.get("version"):
            exploits = recon.searchsploit(f"{svc['service']} {svc['version']}")
            if exploits:
                new_findings.append(
                    f"[VULN] {target}:{port} {svc['service']} {svc['version']}: "
                    f"{len(exploits)} exploits in ExploitDB"
                )
                for e in exploits[:3]:
                    new_findings.append(f"  → {e['title']} [{e['type']}]")

    # SSL certificate intel
    for port, svc in host["services"].items():
        if "ssl" in svc["service"].lower() or "https" in svc["service"].lower() or port == 443:
            cert = recon.ssl_cert_info(target, port)
            if cert:
                new_findings.append(f"[ENUM] {target}:{port} SSL cert: {cert}")
                sans = cert.get("sans", [])
                if sans:
                    new_findings.append(f"[ENUM] {target}: cert SANs: {', '.join(sans)}")

    # Web enumeration
    for port, svc in host["services"].items():
        svc_name = svc["service"].lower()
        if "http" in svc_name or "ssl" in svc_name or "https" in svc_name:
            _enumerate_web(state, host, target, port, svc, new_findings)

    # AD enumeration
    ad_ports = {88, 389, 464, 636, 3268, 3269}
    if ad_ports & set(host["services"].keys()):
        _enumerate_ad(state, host, target, new_findings)

    # SMB enumeration (even without full AD)
    if 445 in host["services"] or any(
        "smb" in s["service"].lower() or "microsoft-ds" in s["service"].lower()
        for s in host["services"].values()
    ):
        _enumerate_smb(state, host, target, new_findings)


def _enumerate_web(state, host, target, port, svc, new_findings):
    """Enumerate a web service."""
    svc_name = svc["service"].lower()
    scheme = "https" if ("ssl" in svc_name or "https" in svc_name or port == 443) else "http"
    url = f"{scheme}://{target}:{port}"

    print(f"  [>] Web enumeration: {url}")

    # Fingerprint
    tech = web.fingerprint_tech(url)
    if tech:
        new_findings.append(
            f"[ENUM] {url}: {', '.join(tech.get('technologies', []))}"
        )
        if tech.get("title"):
            new_findings.append(f"[ENUM] {url}: title='{tech['title']}'")

    # Directory bust
    print(f"  [>] Directory busting {url}...")
    dirs = web.directory_bust(url, wordlist=state.get("wordlist", ""))
    interesting_dirs = [
        d for d in dirs if d["status"] == 200 and d["size"] > 50
    ]
    if interesting_dirs:
        new_findings.append(
            f"[ENUM] {url}: {len(interesting_dirs)} accessible directories"
        )
        for d in interesting_dirs[:10]:
            new_findings.append(f"  → {d['path']} ({d['status']}, {d['size']}b)")

    # Config file check
    config_findings = web.check_config_files(url)
    for cf in config_findings:
        sev = cf["severity"].upper()
        new_findings.append(
            f"[{'!' if sev in ('HIGH', 'CRITICAL') else '*'}] {url}{cf['path']} "
            f"-> {cf['status']} ({cf['size']}b) [{sev}]"
        )

    # Forms
    forms = web.discover_forms(url)
    if forms:
        new_findings.append(f"[ENUM] {url}: {len(forms)} form(s) discovered")
        for f in forms[:5]:
            fields = ", ".join(f["fields"]) if isinstance(f.get("fields"), list) else str(f.get("fields", []))
            new_findings.append(f"  → {f['method']} {f['action']} fields=[{fields}]")

    # SQLi injection point identification (passive)
    sqli_points = web.check_sqli_point(url, forms)

    # API discovery
    api_result = web.api_enumerate(url)
    if api_result["endpoints"]:
        new_findings.append(
            f"[ENUM] {url}: {len(api_result['endpoints'])} API endpoint(s)"
        )
    if api_result.get("swagger"):
        new_findings.append(f"[ENUM] {url}: Swagger/OpenAPI at {api_result['swagger']}")

    # Data extraction
    page_data = web.extract_data_from_page(url)
    if page_data.get("emails"):
        new_findings.append(f"[ENUM] {url}: emails found: {', '.join(page_data['emails'])}")
        for email in page_data["emails"]:
            state.setdefault("_domain_users", []).append(email.split("@")[0])
    if page_data.get("comments"):
        for c in page_data["comments"][:3]:
            new_findings.append(f"[ENUM] {url}: HTML comment: {c[:80]}")

    # Store web app info
    web_app = WebAppInfo(
        url=url, status_code=tech.get("status_code", 0) if tech else 0,
        title=tech.get("title", "") if tech else "",
        server=tech.get("server", "") if tech else "",
        technologies=tech.get("technologies", []) if tech else [],
        directories=dirs, forms=forms,
        api_endpoints=api_result.get("endpoints", []),
        interesting_findings=[cf["path"] for cf in config_findings],
        enumerated=True,
    )
    host.setdefault("web_apps", []).append(web_app)

    # Generate attack vectors for this web app
    vectors = vs.vectors_for_web_app(
        url, tech or {}, config_findings, sqli_points, tech or {}
    )
    host.setdefault("attack_vectors", []).extend(vectors)

    # Also enumerate interesting subdirectories
    subdir_paths = [
        d["path"] for d in dirs
        if d["status"] in (200, 301, 302) and "." not in d["path"].rsplit("/", 1)[-1]
    ]
    for subpath in subdir_paths[:5]:
        subdir_url = f"{url}{subpath}" + ("" if subpath.endswith("/") else "/")
        sub_tech = web.fingerprint_tech(subdir_url)
        if sub_tech and sub_tech.get("technologies"):
            new_findings.append(
                f"[ENUM] {subdir_url}: {', '.join(sub_tech['technologies'])}"
            )

    return web_app


def _enumerate_ad(state, host, target, new_findings):
    """Enumerate AD domain via LDAP/RPC."""
    di = state.get("domain_info") or {}
    domain_name = di.get("name", "")
    dc_ip = di.get("dc_ip", target)

    print(f"  [>] AD enumeration on {target} (domain: {domain_name})...")

    # Domain users
    users = ad.enumerate_domain_users(dc_ip, domain_name)
    if users:
        new_findings.append(f"[ENUM] {target}: {len(users)} domain users")
        print(f"  [+] Users: {', '.join(sorted(users)[:10])}")
        state.setdefault("_domain_users", []).extend(users)
        di["users"] = users

    # Domain groups
    groups = ad.enumerate_domain_groups(dc_ip, domain_name)
    if groups:
        new_findings.append(f"[ENUM] {target}: {len(groups)} domain groups")
        di["groups"] = groups

    # Computers
    computers = ad.enumerate_computers(dc_ip, domain_name)
    if computers:
        new_findings.append(f"[ENUM] {target}: {len(computers)} domain computers")
        di["computers"] = computers

    # SPNs
    spns = ad.enumerate_spns(dc_ip, domain_name)
    if spns:
        new_findings.append(f"[ENUM] {target}: {len(spns)} SPNs discovered")
        di["spns"] = spns

    # ADCS
    cas = ad.enumerate_adcs(dc_ip, domain_name)
    if cas:
        new_findings.append(f"[ENUM] {target}: {len(cas)} ADCS CA(s) found")
        di["ca_servers"] = cas

    state["domain_info"] = di

    # Generate AD attack vectors
    ad_vectors = vs.vectors_for_ad(di, target)
    host.setdefault("attack_vectors", []).extend(ad_vectors)

    host["ad_info"] = ADInfo(
        domain_name=domain_name, dc_ip=dc_ip,
        functional_level=di.get("functional_level", ""),
        users=users, groups=groups, computers=computers,
        spns=spns, trusts=di.get("trusts", []),
        ca_servers=cas, enum_method="ldap/rpcclient",
    )


def _enumerate_smb(state, host, target, new_findings):
    """Enumerate SMB shares and info."""
    print(f"  [>] SMB enumeration on {target}...")

    shares = ad.enumerate_smb_shares(target)
    if shares:
        new_findings.append(f"[ENUM] {target}: {len(shares)} SMB share(s)")
        for s in shares[:10]:
            access = "✓" if s.get("accessible") else "✗"
            new_findings.append(
                f"  → {access} {s['name']} ({s.get('type', '?')}) {s.get('comment', '')}"
            )

    signing = ad.check_smb_signing(target)
    if signing is not None:
        status = "NOT REQUIRED" if signing else "required"
        new_findings.append(f"[ENUM] {target}: SMB signing {status}")


# ═══════════════════════════════════════════════════════════════════════
# ANALYZE NODE — LLM-powered attack path analysis and ranking
# ═══════════════════════════════════════════════════════════════════════

def analyze_node(state: ReconState) -> ReconState:
    """LLM-powered analysis of all findings to rank attack vectors."""
    print("\n" + "=" * 60)
    print("  PHASE: ATTACK PATH ANALYSIS")
    print("=" * 60)

    summary = get_engagement_summary(state)

    # Collect all findings for LLM context
    all_findings = state.get("findings", [])[-200:]
    findings_text = "\n".join(all_findings[-100:])

    # Collect all attack vectors
    all_vectors = []
    for ip, host in state["hosts"].items():
        all_vectors.extend(host.get("attack_vectors", []))
    all_vectors.extend(state.get("attack_vectors", []))

    vectors_text = "\n".join(
        f"- [{v['confidence']}/{v['score']}] {v['title']} "
        f"({v['category']}/{v['vector_type']}) → {v['target']}\n"
        f"  Suggest: {'; '.join(v.get('exploit_suggestions', [])[:2])}"
        for v in sorted(all_vectors, key=lambda x: x["score"], reverse=True)[:20]
    )

    if state.get("no_llm"):
        print("  [--no-llm] Skipping LLM analysis, using heuristic ranking")
        # Still update attack_vectors in state
        state["attack_vectors"] = all_vectors
        return {**state, "current_phase": "scope", "iteration": state["iteration"] + 1}

    prompt = f"""You are a senior penetration tester analyzing enumeration results.
Your task is to RANK attack vectors, identify the MOST LIKELY attack paths,
and suggest exploitation strategies.

## Current Engagement
{summary}

## Recent Findings (last 100)
{findings_text}

## Discovered Attack Vectors (heuristic-generated)
{vectors_text}

## Your Task
Analyze ALL the above data and provide:

1. **Top 5 Attack Paths** — ranked by likelihood of success
2. **Exploit Suggestions** for each path (specific commands/tools)
3. **Privilege Escalation** paths for each potential foothold
4. **Lateral Movement** opportunities
5. **Missing Intelligence** — what else should be enumerated?

Return JSON with this structure:
{{
  "top_attack_paths": [
    {{
      "rank": 1,
      "title": "Attack path name",
      "confidence": "high|medium|low",
      "target": "host:port or service",
      "steps": ["Step 1", "Step 2", ...],
      "tools": ["tool1", "tool2"],
      "privesc": ["privilege escalation suggestions"],
      "lateral": ["lateral movement opportunities"],
      "expected_result": "What we achieve"
    }}
  ],
  "additional_enum": ["Additional enumeration to perform"],
  "overall_assessment": "Summary of the engagement's attack surface"
}}"""

    print("  [>] Consulting LLM for strategic attack path analysis...")

    resp = llm_invoke(
        [SystemMessage(content="You are a senior offensive security consultant. Return JSON only."),
         HumanMessage(content=prompt)],
        fast_fail=True,
    )

    analysis = parse_llm_json(resp)

    if analysis:
        # Save LLM analysis to state
        state["_llm_analysis"] = analysis
        paths = analysis.get("top_attack_paths", [])
        print(f"\n  [+] LLM identified {len(paths)} attack paths:")
        for p in paths[:5]:
            print(f"    #{p.get('rank', '?')} [{p.get('confidence', '?')}] "
                  f"{p.get('title', '?')} → {p.get('target', '?')}")

        # Add LLM-suggested vectors to state
        for path in paths:
            vid = f"llm_path_{path.get('rank', 0)}"
            state.setdefault("attack_vectors", []).append(AttackVector(
                id=vid, target=path.get("target", ""),
                category="llm_analysis", vector_type="attack_path",
                title=path.get("title", "Unnamed path"),
                description=path.get("expected_result", ""),
                confidence=path.get("confidence", "medium"),
                score=90 - (int(path.get("rank", 5)) - 1) * 15,
                evidence=path.get("steps", []),
                exploit_suggestions=path.get("tools", []),
                prerequisites=[],
                cves=[], references=[],
            ))
    else:
        print("  [!] LLM analysis failed, using heuristic ranking only")

    # Merge all vectors into state
    state["attack_vectors"] = all_vectors + state.get("attack_vectors", [])[-10:]

    return {**state, "current_phase": "scope", "iteration": state["iteration"] + 1}


# ═══════════════════════════════════════════════════════════════════════
# SCOPE NODE — Strategic decision maker (the hub)
# ═══════════════════════════════════════════════════════════════════════

def scope_node(state: ReconState) -> ReconState:
    """Strategic brain — decides what to do next."""
    print("\n" + "=" * 60)
    print(f"  PHASE: SCOPE (iteration {state['iteration']}/{state['max_iterations']})")
    print("=" * 60)

    # Save state every iteration
    try:
        save_state(state)
    except Exception as e:
        print(f"  [!] Save failed: {e}")

    # Check termination
    if state["iteration"] >= state["max_iterations"]:
        print("  [*] Max iterations reached. Generating report.")
        return {**state, "current_phase": "report"}

    summary = get_engagement_summary(state)
    print(f"\n{summary}")

    # Priority 1: Discover new networks
    scanned = state.get("scanned_subnets", [])
    unscanned = [s for s in state["accessible_subnets"] if s not in scanned]
    if unscanned:
        print(f"\n  → ACTION: Discover hosts in {unscanned[0]}")
        return {**state, "current_phase": "discover"}

    # Priority 2: Enumerate unenumerated hosts
    unenum = get_unenumerated_hosts(state)
    if unenum:
        target_ip = _select_best_target(state, unenum)
        print(f"\n  → ACTION: Enumerate {target_ip}")
        return {**state, "current_target": target_ip, "current_phase": "enumerate"}

    # Priority 3: LLM analysis (after all hosts enumerated)
    all_enum = all(h["enumerated"] for h in state["hosts"].values() if h["services"])
    if all_enum and state["hosts"]:
        if not state.get("_analysis_done"):
            print(f"\n  → ACTION: Attack path analysis")
            state["_analysis_done"] = True
            return {**state, "current_phase": "analyze"}

    # Priority 4: Check stall condition
    findings_len = len(state["findings"])
    if state.get("last_findings_len") == findings_len:
        state["stall_count"] = state.get("stall_count", 0) + 1
    else:
        state["stall_count"] = 0
    state["last_findings_len"] = findings_len

    if state.get("stall_count", 0) >= 2:
        print("\n  [*] No new findings. Generating report.")
        return {**state, "current_phase": "report"}

    # Fallback to LLM for strategic direction
    if not state.get("no_llm"):
        print("\n  → ACTION: Consulting LLM for strategic direction...")
        next_action = _llm_strategic_plan(state)
        if next_action and "current_phase" in next_action:
            return {**state, **next_action}

    # Nothing left
    print("\n  [*] Enumeration complete. Generating report.")
    return {**state, "current_phase": "report"}


def _select_best_target(state: ReconState, candidates: dict) -> str:
    """Select the most promising target from unenumerated hosts."""
    best_ip = None
    best_score = -1

    for ip, host in candidates.items():
        score = 0
        for port, svc in host["services"].items():
            svc_name = svc["service"].lower()
            if "http" in svc_name or "ssl" in svc_name:
                score += 15
            if "smb" in svc_name or "microsoft-ds" in svc_name:
                score += 10
            if port in (5985, 3389):
                score += 12
            if "ftp" in svc_name:
                score += 8
            if port in (88, 389, 636, 464):
                score += 7
            if "ssh" in svc_name:
                score += 3
        if score > best_score:
            best_score = score
            best_ip = ip

    return best_ip or list(candidates.keys())[0]


def _llm_strategic_plan(state: ReconState) -> Optional[dict]:
    """Ask LLM for strategic direction when heuristics are exhausted."""
    summary = get_engagement_summary(state)
    all_hosts = state.get("hosts", {})
    domain_users = state.get("_domain_users", [])

    user_context = ""
    if domain_users:
        user_context = f"\n## Known Usernames\n{', '.join(sorted(set(domain_users))[:30])}\n"

    prompt = f"""You are the strategic planner for an enumeration engagement.

## Current State
{summary}{user_context}

## Available Actions
- discover: Scan for new hosts (if new subnets accessible)
- enumerate: Deep-dive on a host
- analyze: Re-analyze findings for attack paths
- report: Generate final report

Return JSON only:
{{"current_phase": "<action>", "current_target": "<ip or empty>"}}"""

    resp = llm_invoke(
        [SystemMessage(content="You are an enumeration strategic planner. Return JSON only."),
         HumanMessage(content=prompt)],
        fast_fail=True, use_planner_llm=True,
    )
    plan = parse_llm_json(resp)
    if plan and "current_phase" in plan:
        return plan
    return None


# ═══════════════════════════════════════════════════════════════════════
# REPORT NODE — Generate final engagement report
# ═══════════════════════════════════════════════════════════════════════

def report_node(state: ReconState) -> ReconState:
    """Generate the final enumeration report with attack path analysis."""
    print("\n" + "=" * 60)
    print("  PHASE: ENGAGEMENT REPORT")
    print("=" * 60)

    summary = get_engagement_summary(state)

    # Collect all attack vectors
    all_vectors = []
    for ip, host in state["hosts"].items():
        all_vectors.extend(host.get("attack_vectors", []))
    all_vectors.extend(state.get("attack_vectors", []))

    # Sort by score
    all_vectors = sorted(all_vectors, key=lambda v: v.get("score", 0), reverse=True)

    # Get LLM analysis if available
    llm_analysis = state.get("_llm_analysis", {})

    if state.get("no_llm"):
        report = _generate_heuristic_report(state, summary, all_vectors)
    else:
        vectors_text = "\n".join(
            f"- [{v['confidence']}/{v['score']}] {v['title']}\n"
            f"  Target: {v['target']}\n"
            f"  Category: {v['category']}/{v['vector_type']}\n"
            f"  Suggest: {'; '.join(v.get('exploit_suggestions', [])[:3])}\n"
            for v in all_vectors[:30]
        )

        report_prompt = f"""You are writing an enumeration report for a penetration test engagement.

## Engagement Data
{summary}

## All Findings
{chr(10).join(state['findings'][-100:])}

## Discovered Attack Vectors
{vectors_text}

Write a professional enumeration report with:
1. **Executive Summary** — overview of attack surface
2. **Attack Path Ranking** — top 10 most likely attack paths, ordered by probability of success
3. **Exploit Suggestions** — specific commands and tools for each path
4. **Privilege Escalation Paths** — for Linux and Windows hosts
5. **Lateral Movement Opportunities** — AD/domain attack chains
6. **Credential Discovery** — any found credentials or credential sources
7. **Missing Intelligence** — recommended additional enumeration
8. **Risk Matrix** — severity ratings for each finding

Format as Markdown with clear sections, tables where appropriate, and
actionable exploit suggestions."""

        report = llm_invoke(
            [SystemMessage(content="You are a professional penetration test report writer."),
             HumanMessage(content=report_prompt)],
            use_report_llm=True,
        )

        if not report or len(report.strip()) < 50:
            report = _generate_heuristic_report(state, summary, all_vectors)

    # Save report
    report_path = os.path.expanduser(
        f"~/projects/recon-arc/output/report_{state['session_id']}.md"
    )
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w") as f:
        f.write(report)
    print(f"\n  [+] Report saved to: {report_path}")

    # Print top 5 attack vectors
    print(f"\n  [+] Top Attack Vectors ({len(all_vectors)} total):")
    for i, v in enumerate(all_vectors[:5]):
        print(f"    #{i+1} [{v['confidence']}/{v['score']}] {v['title']}")
        print(f"        Target: {v['target']}")
        if v.get("exploit_suggestions"):
            print(f"        → {v['exploit_suggestions'][0]}")

    save_state(state)
    return {**state, "current_phase": "complete"}


def _generate_heuristic_report(state: ReconState, summary: str,
                                 vectors: List[AttackVector]) -> str:
    """Generate report without LLM (fallback)."""
    lines = [
        "# ReconARC Enumeration Report",
        f"\n**Session:** {state.get('session_id', 'unknown')}",
        f"**Iterations:** {state.get('iteration', 0)}/{state.get('max_iterations', 0)}",
        f"**Subnet:** {state.get('initial_subnet', 'N/A')}",
        f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"\n## Summary\n\n{summary}",
        "\n## Attack Vectors (Ranked)\n",
    ]

    for i, v in enumerate(vectors[:20]):
        lines.append(f"### #{i+1} [{v['confidence']}] {v['title']}")
        lines.append(f"- **Target:** {v['target']}")
        lines.append(f"- **Category:** {v['category']}")
        lines.append(f"- **Score:** {v['score']}/100")
        lines.append(f"- **Description:** {v['description']}")
        if v.get("cves"):
            lines.append(f"- **CVEs:** {', '.join(v['cves'])}")
        if v.get("exploit_suggestions"):
            lines.append(f"- **Exploit Suggestions:**")
            for s in v["exploit_suggestions"]:
                lines.append(f"  - `{s}`")
        if v.get("prerequisites"):
            lines.append(f"- **Prerequisites:** {', '.join(v['prerequisites'])}")
        lines.append("")

    # Host details
    lines.append("\n## Hosts\n")
    for ip, host in sorted(state.get("hosts", {}).items()):
        lines.append(f"### {ip} ({host.get('os', 'unknown')})")
        services = host.get("services", {})
        if services:
            svc_list = ", ".join(
                f"{s['service']}/{p}" for p, s in sorted(services.items())
            )
            lines.append(f"- **Services:** {svc_list}")
        web_apps = host.get("web_apps", [])
        if web_apps:
            lines.append(f"- **Web Apps:**")
            for wa in web_apps:
                lines.append(f"  - {wa['url']} ({', '.join(wa.get('technologies', []))})")
        lines.append("")

    # Findings
    findings = state.get("findings", [])
    if findings:
        unique = sorted(set(findings))
        lines.append(f"\n## Findings ({len(unique)} unique)\n")
        for f in unique[-50:]:
            lines.append(f"- {f}")

    return "\n".join(lines)


# ── Helpers ───────────────────────────────────────────────────────────

def _dedup(new_findings: List[str], existing: List[str]) -> List[str]:
    """Merge findings, removing duplicates."""
    combined = existing + new_findings
    seen = set()
    result = []
    for f in combined:
        if f not in seen:
            seen.add(f)
            result.append(f)
    return result[-500:]
