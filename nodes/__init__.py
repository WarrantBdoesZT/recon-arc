"""
StrikeARC — Graph Nodes
======================
LangGraph nodes for the enumeration pipeline:
  scope → discover → enumerate → analyze → report
The scope_node is the strategic hub that routes based on engagement state.
"""

import os
import re
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
from utils import run_command, detect_listener_ip, extract_emails, http_get, swallow

import tools.recon as recon
import tools.web_enum as web
import tools.ad_enum as ad
import tools.vuln_scan as vs

# Import optional modules (may not exist if subagents haven't finished)
try:
    import tools.dns_enum as dns
    _HAS_DNS = True
except ImportError:
    _HAS_DNS = False

try:
    import tools.snmp_enum as snmp
    _HAS_SNMP = True
except ImportError:
    _HAS_SNMP = False

try:
    import tools.extra_enum as extra
    _HAS_EXTRA = True
except ImportError:
    _HAS_EXTRA = False

try:
    import tools.cve_research as cve_res
    _HAS_CVE_RESEARCH = True
except ImportError:
    _HAS_CVE_RESEARCH = False

try:
    import tools.cred_test as cred
    _HAS_CRED_TEST = True
except ImportError:
    _HAS_CRED_TEST = False

try:
    import tools.sqli_probe as sqli_probe
    _HAS_SQLI_PROBE = True
except ImportError:
    _HAS_SQLI_PROBE = False

try:
    import tools.ssl_enum as ssl_enum
    _HAS_SSL_ENUM = True
except ImportError:
    _HAS_SSL_ENUM = False

try:
    import tools.caldav_enum as caldav
    _HAS_CALDAV = True
except ImportError:
    _HAS_CALDAV = False

try:
    import tools.lfi_probe as lfi_probe
    _HAS_LFI_PROBE = True
except ImportError:
    _HAS_LFI_PROBE = False

try:
    import tools.attack_chains as chain_mod
    _HAS_CHAINS = True
except ImportError:
    _HAS_CHAINS = False


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
    print(f"  PHASE: ENUMERATION — {target} ({host.get('os', '?')})")
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


_MAIL_TLS_PORTS = {993, 995, 465, 587}
_WEB_PORTS = {80, 443, 8000, 8080, 8443, 5000, 3000, 8888}


def _is_web_service(svc_name: str, port) -> bool:
    """v10: canonical web-service test. nmap labels imaps/pop3s/smtps as
    'ssl' — the old `ssl in name` match treated Dovecot 993/995 as web and
    gobuster'd/nuclei'd an IMAP server (~2min each, bogus XSS vectors)."""
    svc_name = (svc_name or "").lower()
    port = int(port)
    if port in _MAIL_TLS_PORTS:
        return False
    if "http" in svc_name or "https" in svc_name or "http-alt" in svc_name:
        return True
    if "ssl" in svc_name and port not in _MAIL_TLS_PORTS:
        return True
    return port in _WEB_PORTS


def _recursive_work_pending(state) -> bool:
    """v10.2: is there recursive enumeration work left? Used to override the
    stall-exit so discovered vhosts/promoted hosts actually get enumerated."""
    for ip, h in state.get("hosts", {}).items():
        if not isinstance(h, dict):
            continue
        # vhosts discovered but never deep-enumerated
        pending_vh = [vh for vh in (h.get("vhosts") or [])
                      if not (isinstance(vh, dict) and vh.get("deep_enum"))
                      and not (isinstance(vh, str) and h.get("vhost_enum_done"))]
        if pending_vh:
            return True
        # DNS-promoted hosts never picked up (created with services={})
        if h.get("discovered_via", "").startswith("DNS:") and not h.get("services"):
            return True
    return False


def _promote_dns_targets(state, dns_server, subs, new_findings):
    """v10: DNS-discovered hostnames often resolve to NEW IPs — promote them
    into scan scope so the walker enumerates them next iteration."""
    try:
        from tools.dns_enum import resolve_and_promote
        known = set(state.get("hosts", {}).keys())
        known.add(dns_server)
        for hit in resolve_and_promote(subs, dns_server, known)[:15]:
            ip, via = hit["ip"], hit["via"]
            if ip not in state.get("hosts", {}):
                state["hosts"][ip] = {
                    "ip": ip,
                    "alive": True,
                    "discovered_via": f"DNS: {via} (via {dns_server})",
                    "services": {},
                    "enum_depth": 0,
                    "enumerated": False,
                }
                state.setdefault("pending_targets", []).append(ip)
                new_findings.append(
                    f"[SCOPE+] {ip} — new target via DNS ({via}); queued for enumeration"
                )
    except Exception as e:
        from utils import swallow
        swallow(__name__ + ":promote_dns", e)


def _enumerate_host(state, host, target, new_findings):
    """Full deep enumeration of a host: ports, services, web, AD, DNS, SNMP."""
    quick_mode = state.get("quick_mode", False)

    if quick_mode:
        """Quick mode: nmap -sV top-1000 + web fingerprint + forms + SQLi probe + SSL cert.
        Still generates attack vectors — just skips UDP/deep web/vhost/AD/SNMP."""
        import requests as _requests

        # Fast nmap version scan (top-1000 ports with -sV)
        if len(host["services"]) < 3:
            print(f"  [QUICK] Fast service scan on {target}...")
            services, os_hint, _ = recon.quick_scan(target)
            host["services"] = services
            if os_hint != "unknown":
                host["os"] = os_hint

        # For each web service, do targeted enumeration
        for port, svc in host["services"].items():
            svc_name = svc.get("service", "").lower()
            if not _is_web_service(svc_name, port):
                continue

            scheme = "https" if ("ssl" in svc_name or port in (443, 8443)) else "http"
            url = f"{scheme}://{target}:{port}"

            # Title + fingerprint
            try:
                r = _requests.get(url, timeout=5, verify=False, allow_redirects=True)
                title_match = re.search(r"<title>(.*?)</title>", r.text, re.I)
                title = title_match.group(1).strip() if title_match else ""
                new_findings.append(
                    f"[QUICK-ENUM] {url}: title='{title}', status={r.status_code}, "
                    f"server={r.headers.get('Server', '?')}"
                )

                # Extract forms from page
                forms = web.discover_forms(url)
                if forms:
                    new_findings.append(f"[QUICK-ENUM] {url}: {len(forms)} form(s)")
                    for f in forms[:3]:
                        fields = ", ".join(f.get("fields", [])) if isinstance(f.get("fields"), list) else str(f.get("fields", []))
                        new_findings.append(f"  → {f['method']} {f['action']} fields=[{fields}]")

                # Active SQLi probe on forms
                for form in forms[:3]:
                    try:
                        results = sqli_probe.probe_form(url, form)
                        for vuln in results:
                            if vuln.get("is_vulnerable"):
                                new_findings.append(
                                    f"[!] SQLI CONFIRMED: {url} param '{vuln['parameter']}' "
                                    f"via {vuln['injection_type']} — {vuln.get('evidence', [''])[0][:60]}"
                                )
                                # Generate attack vector
                                vectors = sqli_probe.generate_sqli_vector(
                                    url, vuln["parameter"], vuln
                                )
                                host.setdefault("attack_vectors", []).extend(vectors)
                    except Exception as e:
                        swallow(__name__ + ":271", e)

            except Exception as e:
                swallow(__name__ + ":274", e)

            # SSL cert analysis for HTTPS
            if scheme == "https":
                try:
                    cert_info = ssl_enum.extract_cert(target, port)
                    if cert_info and cert_info.get("subject_cn"):
                        new_findings.append(
                            f"[CERT] {url}: CN={cert_info['subject_cn']}, "
                            f"ORG={cert_info.get('subject_org', '?')}, "
                            f"OU={cert_info.get('subject_ou', '?')}, "
                            f"ISSUER={cert_info.get('issuer_cn', '?')}"
                        )
                        if cert_info.get("san_list"):
                            new_findings.append(
                                f"[CERT] {url}: SANs={', '.join(cert_info['san_list'][:5])}"
                            )
                        if cert_info.get("is_self_signed"):
                            new_findings.append(f"[CERT] {url}: SELF-SIGNED certificate")
                        # Store for cross-host correlation
                        host.setdefault("cert_info", cert_info)
                except Exception as e:
                    swallow(__name__ + ":296", e)

        # Generate basic vectors from what we found
        vectors = vs.vectors_for_services(
            target,
            [{"port": p, "service": s.get("service", ""), "version": s.get("version", "")}
             for p, s in host["services"].items()],
        )
        host.setdefault("attack_vectors", []).extend(vectors)

        # Per-host CVE research in quick mode too
        if state.get("cve_research", True):
            _run_cve_research_host(state, host, target, new_findings)

        return

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

    # UDP scan (top 200 ports) — skip on clearly single-service web hosts
    tcp_ports = set(host["services"].keys())
    web_only = tcp_ports <= {80, 443, 8080, 8443}
    has_infra = bool(tcp_ports & {53, 88, 135, 139, 389, 445, 464, 636,
                                   1433, 2049, 3268, 3269, 3389})
    if web_only and len(tcp_ports) <= 2 and not has_infra:
        print(f"  [>] Skipping UDP scan on {target} (web-only host, unlikely to have useful UDP services)")
    else:
        print(f"  [>] UDP scan on {target}...")
        udp_services = recon.udp_scan(target)
        if udp_services:
            for port, svc in udp_services.items():
                if port not in host["services"]:
                    host["services"][port] = svc
                    new_findings.append(
                        f"[ENUM] {target}: UDP {port}/{svc['service']} discovered"
                    )

    # Deep service enumeration
    print(f"  [>] Deep service enumeration on {target}...")
    host["services"] = recon.scan_all_services(target, host["services"])

    # Nmap vuln scripts (safe category)
    print(f"  [>] Nmap vuln scripts on {target}...")
    vuln_findings = recon.nmap_vuln_scripts(target)
    for vf in vuln_findings:
        new_findings.append(
            f"[VULN] {target}: {vf['vulnerability']} — {vf['detail'][:80]}"
        )

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

    # SSL certificate intel — enhanced with ssl_enum module
    cert_domains = []  # Track domains discovered from SSL certs
    for port, svc in host["services"].items():
        if _is_web_service(svc["service"], port):
            if _HAS_SSL_ENUM:
                try:
                    cert_info = ssl_enum.extract_cert(target, port)
                    if cert_info and cert_info.get("subject_cn"):
                        new_findings.append(
                            f"[CERT] {target}:{port}: CN={cert_info['subject_cn']}, "
                            f"ORG={cert_info.get('subject_org', '?')}, "
                            f"OU={cert_info.get('subject_ou', '?')}, "
                            f"ISSUER={cert_info.get('issuer_cn', '?')}"
                        )
                        if cert_info.get("san_list"):
                            new_findings.append(
                                f"[CERT] {target}:{port}: SANs={', '.join(cert_info['san_list'][:5])}"
                            )
                        if cert_info.get("is_self_signed"):
                            new_findings.append(f"[CERT] {target}:{port}: SELF-SIGNED")
                        # Store for cross-host correlation
                        host["cert_info"] = cert_info

                        # ── Intel feedback loop ─────────────────────────────
                        # Extract domain names from cert CN and SAN list
                        for name_field in ["subject_cn"] + cert_info.get("san_list", []):
                            name = name_field.strip()
                            if name.startswith("*."):
                                name = name[2:]  # wildcard → base domain
                            if "." in name and "localhost" not in name and name not in cert_domains:
                                cert_domains.append(name)
                                state.setdefault("_discovered_domains", set()).add(name)

                        # ── Immediately use cert domains for DNS enum ──────
                        if cert_domains and (53 in host["services"] or _HAS_DNS):
                            for domain in cert_domains[:3]:
                                new_findings.append(
                                    f"[INTEL] {target}: SSL cert reveals domain '{domain}' — attempting DNS zone transfer"
                                )
                                try:
                                    zt = dns.zone_transfer(target, domain)
                                    if zt and zt.get("records"):
                                        new_findings.append(
                                            f"[!] DNS zone transfer SUCCESS on {target} for {domain}! "
                                            f"{len(zt['records'])} records"
                                        )
                                        for rec in zt["records"][:10]:
                                            new_findings.append(f"  → {rec}")
                                except Exception as e:
                                    swallow(__name__ + ":414", e)
                                # Subdomain brute using discovered domain
                                try:
                                    subs = dns.subdomain_bruteforce(target, domain)
                                    if subs:
                                        new_findings.append(
                                            f"[INTEL] {target}: Subdomains of {domain}: {', '.join(subs[:10])}"
                                        )
                                        for sub in subs[:5]:
                                            state.setdefault("_discovered_domains", set()).add(sub)
                                        # v10: resolve finds → promote new IPs into scope
                                        _promote_dns_targets(state, target, subs, new_findings)
                                except Exception as e:
                                    swallow(__name__ + ":425", e)
                except Exception as e:
                    swallow(__name__ + ":427", e)
            else:
                cert = recon.ssl_cert_info(target, port)
                if cert:
                    new_findings.append(f"[ENUM] {target}:{port} SSL cert: {cert}")
                    sans = cert.get("sans", [])
                    if sans:
                        new_findings.append(f"[ENUM] {target}: cert SANs: {', '.join(sans)}")

    # Store cert domains for vhost brute later
    if cert_domains:
        host["_cert_domains"] = cert_domains

    # Per-host CVE research during full enumeration too
    if state.get("cve_research", True):
        _run_cve_research_host(state, host, target, new_findings)

    # DNS enumeration (if DNS port detected)
    if 53 in host["services"] or _HAS_DNS:
        _enumerate_dns(state, host, target, new_findings)

    # SNMP enumeration (if SNMP port detected)
    if 161 in host["services"] and _HAS_SNMP:
        _enumerate_snmp(state, host, target, new_findings)

    # NFS enumeration (if NFS detected)
    if 2049 in host["services"] and _HAS_EXTRA:
        _enumerate_nfs(state, host, target, new_findings)

    # Web enumeration
    for port, svc in host["services"].items():
        svc_name = svc["service"].lower()
        if _is_web_service(svc_name, port):
            _enumerate_web(state, host, target, port, svc, new_findings)

    # Nuclei scan on web services
    for port, svc in host["services"].items():
        svc_name = svc["service"].lower()
        if _is_web_service(svc_name, port):
            scheme = "https" if ("ssl" in svc_name or "https" in svc_name or port == 443) else "http"
            use_ssl = scheme == "https"
            nuclei_results = recon.nuclei_scan(target, port, use_ssl=use_ssl)
            for nr in nuclei_results:
                new_findings.append(
                    f"[VULN] Nuclei: {nr['name']} [{nr['severity']}] at {nr['matched']}"
                )

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

    # Database/service checks
    if _HAS_EXTRA:
        _enumerate_extra_services(state, host, target, new_findings)

    # ── Coverage engine + evidence capture (aquatone sweep + snapshots) ─────
    _coverage_and_evidence(state, host, target, new_findings)


def _coverage_and_evidence(state, host, target, new_findings):
    """Post-enumeration hook: rebuild vault coverage checklist and capture
    web evidence (aquatone screenshots, titles, tech tags) for this host."""
    try:
        from knowledge.coverage import build_coverage, coverage_stats
        state["coverage"] = build_coverage(state)
        stats = coverage_stats(state["coverage"])
        print(f"  [COV] vault coverage: {stats['done']}/{stats['enum_safe']} enum-safe done, "
              f"{stats['manual_leads']} manual leads tracked")
    except Exception as exc:  # coverage must never break enumeration
        print(f"  [COV] coverage build failed (non-fatal): {exc}")

    # Aquatone sweep across every web service on this host
    web_urls = []
    for port, svc in (host.get("services") or {}).items():
        name = (svc.get("service") or "").lower()
        if _is_web_service(name, port):
            scheme = "https" if ("ssl" in name or int(port) in (443, 8443)) else "http"
            web_urls.append(f"{scheme}://{target}:{port}/")
    if not web_urls:
        return
    try:
        from tools.evidence import EvidenceStore
        ev = _get_evidence_store(state)
        pages = ev.sweep_urls(web_urls)
        state["evidence_web"] = state.get("evidence_web", []) + pages
        for page in pages:
            tags = ", ".join(page.get("tags", [])[:5]) or "no-tags"
            shot = "📷" if page.get("screenshot") else "·"
            new_findings.append(
                f"[ENUM] {page['url']} — '{page.get('title','?')}' [{page.get('status','?')}] "
                f"{shot} tech: {tags}")
            if page.get("tags"):
                # enrich web_apps tech lists via aquatone fingerprints
                for wa in host.get("web_apps", []):
                    if wa.get("url", "").rstrip("/") == page["url"].rstrip("/"):
                        merged = list(wa.get("technologies") or [])
                        for t in page["tags"]:
                            if t not in merged:
                                merged.append(t)
                        wa["technologies"] = merged

        # v10: vhost screenshots — aquatone can't send Host headers, so shoot
        # discovered vhosts individually with Chrome --host-resolver-rules
        _shoot_vhosts(state, host, target, ev, new_findings)
        # v10.4.5: persist final merged vhost list → /etc/hosts so every
        # named-URL consumer (probe battery, cred tests, recommended
        # sqlmap/wpscan commands, operator copy-paste) resolves
        _write_etc_hosts(state, host, target, new_findings)
    except Exception as exc:
        swallow(__name__ + ":_cov_ev", exc)

    # v10.4: vault-driven web probing battery on every web app + vhost
    try:
        from tools.web_probe import probe_web_app, surfaces_from_host
        surfaces = surfaces_from_host(host, target)
        if surfaces:
            print(f"  [PROBE] web-app battery: {len(surfaces)} surface(s) "
                  f"(vault-driven, enum-safe)")
            state["web_probe_results"] = state.get("web_probe_results", [])
            state["web_probe_leads"] = state.get("web_probe_leads", [])
            for surf in surfaces:
                results, leads = probe_web_app(surf)
                sev_rank = {"high": 0, "med": 1, "low": 2}
                results.sort(key=lambda r: sev_rank.get(r.sev, 3))
                for r in results:
                    state["web_probe_results"].append({
                        "tech": r.tech, "target": r.target, "finding": r.finding,
                        "evidence": r.evidence, "sev": r.sev, "vault": r.vault})
                    if r.sev in ("high", "med"):
                        marker = "[!]" if r.sev == "high" else "[*]"
                        new_findings.append(
                            f"{marker} {r.target}: {r.finding}"
                            + (f" ({r.evidence[:60]})" if r.evidence else ""))
                state["web_probe_leads"].extend(
                    [{"tech": l.tech, "target": l.target, "command": l.command,
                      "why": l.why, "sev": l.sev, "vault": l.vault}
                     for l in leads])
            hi = sum(1 for r in state["web_probe_results"] if r["sev"] == "high")
            med = sum(1 for r in state["web_probe_results"] if r["sev"] == "med")
            ml = len(state["web_probe_leads"])
            print(f"  [PROBE] done: {hi} high / {med} med findings, "
                  f"{ml} manual lead(s) from vault")
    except Exception as exc:
        swallow(__name__ + ":_probe", exc)


def _write_etc_hosts(state, host, target, new_findings):
    """v10.4.5: persist discovered vhosts to /etc/hosts in a managed block.

    Per-vhost enum and screenshots don't need this (Host-header override /
    Chrome --host-resolver-rules), but every consumer of the NAMED URLs
    stored in web_apps/findings does: cred-testing, authenticated scans,
    sqlmap/wpscan/nikto commands the report recommends, and the operator
    copy-pasting URLs. Without /etc/hosts those names resolve nowhere.

    Idempotent: one managed '# BEGIN/END StrikeARC vhosts' block; rewritten
    only when the name→IP set changes; names the operator already mapped
    to the same IP elsewhere in the file are left alone. Requires
    passwordless sudo (sudo -n); on failure it degrades to a findings note
    — never blocks the run.
    """
    import subprocess as _sp
    import tempfile as _tf
    import os as _os

    BEGIN, END = "# BEGIN StrikeARC vhosts", "# END StrikeARC vhosts"
    vhosts = host.get("vhosts") or []
    # name→target map; only dotted names (real FQDNs) belong in hosts(5)
    wanted = {}
    for vh in vhosts:
        name = vh["name"] if isinstance(vh, dict) else vh
        name = str(name).strip().lower().split("->")[0].strip()
        if name and "." in name:
            wanted[name] = target
    if not wanted:
        return

    try:
        current = open("/etc/hosts").read()
    except PermissionError:
        current = None
    if current is None:
        # can't even read it (unlikely) — nothing we can do safely
        return

    lines = current.splitlines()
    # Parse operator's own mappings: skip our managed block
    outside = []
    in_block = False
    block_names = {}
    for ln in lines:
        if ln.strip() == BEGIN:
            in_block = True
            continue
        if ln.strip() == END:
            in_block = False
            continue
        if in_block:
            parts = ln.split()
            if len(parts) >= 2:
                for nm in parts[1:]:
                    block_names[nm.lower()] = parts[0]
            continue
        outside.append(ln)
    # Operator already mapped a name to the same IP elsewhere? Keep theirs.
    for ln in outside:
        parts = ln.split()
        if len(parts) >= 2 and parts[0] == target:
            for nm in parts[1:]:
                nm = nm.lower()
                if nm in wanted:
                    del wanted[nm]

    # Names already correct inside our block? No rewrite needed.
    if all(block_names.get(n) == ip for n, ip in wanted.items()) and not (
            set(block_names) - set(wanted)):
        return

    # v10.4.5: multi-host engagements — keep OTHER hosts' entries from the
    # old block (host B's write must not drop host A's mappings); only
    # stale entries for THIS target's IP are replaced by `wanted`.
    for n, ip in block_names.items():
        if ip != target and n not in wanted:
            wanted[n] = ip

    entries = sorted(wanted.items())
    block = [BEGIN] + [f"{ip} {nm}" for nm, ip in entries] + [END]
    new_content = "\n".join(outside + block).rstrip("\n") + "\n"

    try:
        with _tf.NamedTemporaryFile("w", delete=False, dir="/tmp",
                                    prefix="starc_hosts_") as tf:
            tf.write(new_content)
            tmp = tf.name
        _os.chmod(tmp, 0o644)
        # Passwordless sudo only — never prompt mid-run
        proc = _sp.run(["sudo", "-n", "cp", tmp, "/etc/hosts"],
                       capture_output=True, timeout=10)
        _os.unlink(tmp)
        if proc.returncode != 0:
            new_findings.append(
                f"[ENUM] {target}: {len(entries)} vhost(s) NOT added to /etc/hosts "
                f"(sudo unavailable) — add manually for named-URL tooling"
            )
            return
        new_findings.append(
            f"[ENUM] {target}: {len(entries)} vhost(s) written to /etc/hosts "
            f"(managed block): {', '.join(n for n, _ in entries[:8])}"
            + (" …" if len(entries) > 8 else "")
        )
    except Exception as e:
        swallow(__name__ + ":etc_hosts", e)


def _shoot_vhosts(state, host, target, ev, new_findings):
    """Screenshot discovered vhosts via Chrome --host-resolver-rules mapping.
    v10.3: vhosts may be dicts {name, port, scheme} or legacy strings."""
    vhosts = host.get("vhosts") or []
    if not vhosts:
        return
    ports_by_scheme = [
        (p, "https" if ("ssl" in ((host["services"].get(p, {}) or {}).get("service", "") or "").lower() or int(p) in (443, 8443)) else "http")
        for p, s in (host.get("services") or {}).items()
        if _is_web_service((s.get("service") or "").lower(), p)
    ]
    for vh in vhosts[:10]:
        if isinstance(vh, dict):
            name = vh.get("name", "")
            # prefer the port/scheme the vhost was actually found on
            vh_port = vh.get("port")
            vh_scheme = vh.get("scheme", "http")
            if vh_port:
                shot = ev.screenshot_vhost(name, target, int(vh_port), scheme=vh_scheme)
                if shot:
                    new_findings.append(f"[ENUM] vhost 📷 {name}:{vh_port} → {shot}")
                    continue
        else:
            name = vh
        if not name or "." not in name:
            continue
        for p, scheme in ports_by_scheme[:2]:
            shot = ev.screenshot_vhost(name, target, int(p), scheme=scheme)
            if shot:
                new_findings.append(f"[ENUM] vhost 📷 {name}:{p} → {shot}")
                break


def _enumerate_vhost(state, host, target, port, scheme, vh, new_findings, depth=0):
    """v10.2/v10.3 RECURSIVE enumeration of one named vhost on a shared IP.

    Everything goes over the IP URL with an explicit Host header (no local
    DNS needed): fingerprint → forms → directory bust → config files →
    one-level subdirectory recursion. v10.3: accepts vh as dict (new
    vhost_bruteforce return) or str (legacy state); web_apps deduped by URL.
    """
    vh_name = vh["name"] if isinstance(vh, dict) else vh
    ip_url = f"{scheme}://{target}:{port}"
    label = f"vhost {vh_name}:{port}"
    vforms: List[dict] = []   # v10.4.3: collected by discover_forms below
    print(f"  [>] Recursive enum: {label}")
    r = None
    title = ""
    try:
        import requests as _rq
        r = _rq.get(ip_url + "/", timeout=8, verify=False,
                    headers={"Host": vh_name, "User-Agent": "StrikeARC"})
        _tm = re.search(r"<title>(.*?)</title>", r.text or "", re.I)
        title = _tm.group(1).strip() if _tm else ""
        new_findings.append(
            f"[ENUM] {label}: '{title[:60]}' status={r.status_code} size={len(r.text or '')}b"
        )
    except Exception as e:
        new_findings.append(f"[ENUM] {label}: unreachable ({type(e).__name__}) — skipped")
        if isinstance(vh, dict):
            vh["deep_enum"] = True   # don't retry dead vhosts forever
        return

    wl = state.get("wordlist", "") or "/usr/share/wordlists/dirb/common.txt"

    # v10.3: real tech fingerprint + forms for THIS vhost (Host-header aware)
    tech_tags = []
    try:
        ft = web.fingerprint_tech(ip_url, host_header=vh_name)
        if ft:
            tech_tags = ft.get("technologies", [])[:8]
            if tech_tags:
                new_findings.append(f"[ENUM] {label}: tech: {', '.join(tech_tags)}")
            if ft.get("title") and not title:
                title = ft["title"]
    except Exception as e:
        swallow(__name__ + ":vh_ft", e)
    try:
        vforms = web.discover_forms(ip_url, host_header=vh_name)
        if vforms:
            new_findings.append(f"[ENUM] {label}: {len(vforms)} form(s)")
            for fm in vforms[:3]:
                fields = fm.get("fields", [])
                flds = ", ".join(fields) if isinstance(fields, list) else str(fields)
                new_findings.append(f"  → {label} {fm.get('method','?')} {fm.get('action','?')} fields=[{flds}]")
    except Exception as e:
        swallow(__name__ + ":vh_forms", e)

    # Directory bust against the IP with Host override
    dirs = web.directory_bust(ip_url, wordlist=wl, host_header=vh_name)
    # v10.4.3: 301/401 are leads too (Drupal/WP redirect-storms were stored
    # as 0 dirs); filter junk by size floor only
    interesting = [d for d in dirs
                   if d["status"] in (200, 301, 401) and d["size"] > 50]
    if interesting:
        new_findings.append(f"[ENUM] {label}: {len(interesting)} accessible paths")
        for d in interesting[:10]:
            new_findings.append(f"  → {label} {d['path']} ({d['status']}, {d['size']}b)")

    # Config files (via IP + Host header)
    try:
        cfgs = web.check_config_files(ip_url, host_header=vh_name)
        for cf in cfgs:
            sev = cf["severity"].upper()
            new_findings.append(
                f"[{'!' if sev in ('HIGH', 'CRITICAL') else '*'}] {vh_name}{cf['path']} "
                f"-> {cf['status']} ({cf['size']}b) [{sev}]"
            )
    except TypeError:
        pass  # older signature without host_header
    except Exception as e:
        swallow(__name__ + ":vh_cfg", e)

    # Recurse into found directories (one level, cap 5 subdirs per vhost)
    if depth < 1 and interesting:
        dir_paths = [d["path"] for d in interesting
                     if "." not in d["path"].rsplit("/", 1)[-1]][:5]
        for dp in dir_paths:
            sub_url = f"{ip_url}{dp}" + ("" if dp.endswith("/") else "/")
            sub_dirs = web.directory_bust(sub_url, wordlist=wl, host_header=vh_name)
            for d in sub_dirs:
                if d["status"] == 200 and d["size"] > 50 and d["path"] != dp:
                    new_findings.append(
                        f"[ENUM] {label}: recursive → {d['path']} ({d['status']}, {d['size']}b)"
                    )

    # Record the vhost as a web_app — v10.3: dedup by URL (each vhost once)
    try:
        from state import WebAppInfo
        vh_url = f"{scheme}://{vh_name}:{port}/"
        apps = host.setdefault("web_apps", [])
        existing = next((a for a in apps if a.get("url") == vh_url), None)
        wa = WebAppInfo(
            url=vh_url,
            status_code=r.status_code,
            title=title[:80],
            server=r.headers.get("Server", ""),
            technologies=tech_tags,
            directories=interesting[:25],
            forms=vforms or [],   # v10.4.3: was discarded (forms=[]) — vpn's login form was lost
            api_endpoints=[],
            interesting_findings=[d["path"] for d in interesting[:10]],
            enumerated=True,
        )
        if existing:
            apps[apps.index(existing)] = wa  # refresh in place
        else:
            apps.append(wa)
    except Exception as e:
        swallow(__name__ + ":vh_wa", e)
    finally:
        if isinstance(vh, dict):
            vh["deep_enum"] = True   # v10.4.3: per-vhost mark replaces blunt gate


def _get_evidence_store(state):
    """Session-scoped EvidenceStore under /mnt/storage/strikearc/<session>/."""
    key = "_evidence_store"
    if key not in state:
        from tools.evidence import EvidenceStore
        session = state.get("session_id") or __import__("time").strftime("%Y%m%d_%H%M%S")
        state[key] = EvidenceStore(session, enabled=True)
        state["evidence_dir"] = state[key].root
    return state[key]


_DB_ERROR_PATTERNS = [
    ("mysql",      [r"mysql", r"mysqli?", r"sql syntax.*mysql", r"MySQLSyntaxErrorException", r"valid MySQL result"]),
    ("postgresql", [r"postgresql", r"pg_query", r"psql", r"unterminated quoted string.*postgres"]),
    ("mssql",      [r"microsoft sql server", r"sql server", r"\\[sql server\\]", r"odbc sql server", r"mssql_query"]),
    ("oracle",     [r"oracle", r"ora-\\d{5}", r"oci_parse"]),
    ("sqlite",     [r"sqlite", r"sqlite3", r"sqlitesyntaxexception"]),
]


def _fingerprint_db_from_evidence(evidence: List[str]) -> Optional[str]:
    """Extract database type from SQLi probe evidence strings."""
    combined = " ".join(evidence).lower()
    for db_name, patterns in _DB_ERROR_PATTERNS:
        for pat in patterns:
            if re.search(pat, combined):
                return db_name
    return None


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

    # ── robots.txt scan (flags + hidden paths) ──────────────────────
    try:
        import requests as _req
        robots_resp = _req.get(f"{url}/robots.txt", timeout=5, verify=False)
        if robots_resp.status_code == 200 and robots_resp.text.strip():
            robots_content = robots_resp.text
            new_findings.append(f"[ENUM] {url}/robots.txt found ({len(robots_content)}b)")

            # Search for flag patterns
            import re as _re
            flag_patterns = [r'DANTE\{[^}]+\}', r'FLAG\{[^}]+\}', r'HTB\{[^}]+\}', r'CTF\{[^}]+\}']
            existing_flags = {f.get("flag_value") for f in state.get("flags_captured", [])}
            for pattern in flag_patterns:
                flags_found = _re.findall(pattern, robots_content)
                for flag in flags_found:
                    if flag not in existing_flags:
                        new_findings.append(f"[FLAG] 🚩 {flag} (found in robots.txt)")
                        state["flags_captured"] = state.get("flags_captured", []) + [{
                            "host_ip": target,
                            "flag_type": "robots",
                            "flag_value": flag,
                            "path": f"{url}/robots.txt",
                            "captured_at": __import__("time").strftime("%Y-%m-%dT%H:%M:%S"),
                            "method": "robots.txt scan",
                        }]
                        state["flags_found_count"] = state.get("flags_found_count", 0) + 1
                        existing_flags.add(flag)

            # Extract Disallow paths for further enumeration
            disallowed = _re.findall(r'(?:Disallow|Allow):\s*(.+)', robots_content)
            for path in disallowed[:15]:
                path = path.strip()
                if path and path != '/':
                    new_findings.append(f"  → robots.txt path: {path}")
    except Exception as e:
        swallow(__name__ + ":562", e)

    # ── WordPress/CMS detection ─────────────────────────────────────
    wp_detected = False
    wp_paths = [
        f"{url}/wordpress/wp-login.php",
        f"{url}/wp-login.php",
        f"{url}/blog/wp-login.php",
    ]
    for wp_path in wp_paths:
        try:
            wp_resp = _req.get(wp_path, timeout=15, verify=False, allow_redirects=False)
            if wp_resp.status_code == 200 and ('wp-login' in wp_resp.text.lower() or 'wordpress' in wp_resp.text.lower()[:500]):
                wp_base = wp_path.rsplit('/wp-login.php', 1)[0]
                new_findings.append(f"[CMS] WordPress detected at {wp_base}")
                wp_detected = True

                # Extract WP version
                wp_ver_match = _re.search(r'generator.*?v=([0-9.]+)', wp_resp.text)
                if wp_ver_match:
                    wp_ver = wp_ver_match.group(1)
                    new_findings.append(f"[CMS] WordPress version: {wp_ver}")

                # Check for wp-config.php backup (swp, bak, ~)
                for ext in ['.swp', '.bak', '~', '.save', '.old']:
                    cfg_resp = _req.get(f"{wp_base}/.wp-config.php{ext}", timeout=3, verify=False)
                    if cfg_resp.status_code == 200 and len(cfg_resp.content) > 100:
                        new_findings.append(
                            f"[!] wp-config.php backup found: {wp_base}/.wp-config.php{ext} "
                            f"({len(cfg_resp.content)}b) [CRITICAL]"
                        )
                        # Extract DB credentials
                        cfg_text = cfg_resp.text if hasattr(cfg_resp, 'text') else cfg_resp.content.decode('utf-8', errors='replace')
                        # Handle vim swap files (binary)
                        import subprocess
                        try:
                            # Save and run strings on it
                            tmp_path = f"/tmp/wp_cfg_backup_{port}{ext}"
                            with open(tmp_path, 'wb') as f:
                                f.write(cfg_resp.content)
                            strings_result = subprocess.run(
                                ['strings', tmp_path],
                                capture_output=True, text=True, timeout=5
                            )
                            cfg_text = strings_result.stdout + cfg_text
                        except Exception as e:
                            swallow(__name__ + ":608", e)

                        db_user = _re.search(r"DB_USER['\"]*,\s*['\"]([^'\"]+)", cfg_text)
                        db_pass = _re.search(r"DB_PASSWORD['\"]*,\s*['\"]([^'\"]+)", cfg_text)
                        db_name = _re.search(r"DB_NAME['\"]*,\s*['\"]([^'\"]+)", cfg_text)
                        if db_user or db_pass:
                            cred_info = f"DB_USER={db_user.group(1) if db_user else '?'}, DB_PASSWORD={db_pass.group(1) if db_pass else '?'}"
                            new_findings.append(f"[!] WordPress DB credentials: {cred_info} [CRITICAL]")

                            # Add to state credentials
                            _db_user = db_user.group(1) if db_user else ""
                            _db_pass = db_pass.group(1) if db_pass else ""
                            state["all_credentials"] = state.get("all_credentials", []) + [{
                                "id": f"wp_db_cred_{target}_{port}",
                                "username": _db_user,
                                "password": _db_pass,
                                "service": "mysql",
                                "source": f"wp-config.php backup ({wp_base})",
                                "validated": False,
                                "validated_against": "",
                            }]

                            # Create high-priority attack vector for cred reuse
                            state["attack_vectors"] = state.get("attack_vectors", []) + [{
                                "id": f"wp_db_creds_{target}_{port}",
                                "title": f"WordPress DB credentials — potential SSH/WP reuse",
                                "description": cred_info,
                                "target": f"{target}:{port}",
                                "category": "initial_access",
                                "vector_type": "default_creds",
                                "confidence": "high",
                                "score": 85,
                                "evidence": [f"wp-config.php backup at {wp_base}/"],
                                "exploit_suggestion": f"Try {db_user.group(1) if db_user else ''}:{db_pass.group(1) if db_pass else ''} on SSH, WP login, MySQL",
                            }]

                # Check for debug.log (info leak)
                debug_resp = _req.get(f"{wp_base}/wp-content/debug.log", timeout=3, verify=False)
                if debug_resp.status_code == 200 and len(debug_resp.text) > 10:
                    new_findings.append(f"[!] WordPress debug.log exposed ({len(debug_resp.text)}b)")

                # Enumerate WP users via REST API and author archives
                try:
                    rest_resp = _req.get(f"{wp_base}/wp-json/wp/v2/users", timeout=8, verify=False)
                    wp_users = []
                    if rest_resp.status_code == 200:
                        import json as _json
                        users_data = _json.loads(rest_resp.text)
                        wp_users = [u.get("slug") or u.get("name", "") for u in users_data]
                    if not wp_users:
                        # Fallback: check author=1 redirect
                        for aid in range(1, 5):
                            author_resp = _req.get(
                                f"{wp_base}/?author={aid}",
                                timeout=5, verify=False, allow_redirects=False)
                            if author_resp.status_code in (301, 302):
                                loc = author_resp.headers.get("Location", "")
                                user_match = _re.search(r'/author/([^/]+)/', loc)
                                if user_match:
                                    wp_users.append(user_match.group(1))
                    if wp_users:
                        wp_users_str = ", ".join(wp_users)
                        new_findings.append(f"[CMS] WordPress users: {wp_users_str}")
                        # Store for exploit phase
                        for u in wp_users:
                            state["all_credentials"] = state.get("all_credentials", []) + [{
                                "username": u,
                                "password": None,
                                "service": "wordpress",
                                "source": f"WP REST API ({wp_base})",
                                "validated": False,
                                "validated_against": "",
                            }]
                except Exception as e:
                    swallow(__name__ + ":682", e)

                break
        except Exception as e:
            swallow(__name__ + ":686", e)

    # Directory bust
    print(f"  [>] Directory busting {url}...")
    dirs = web.directory_bust(url, wordlist=state.get("wordlist", ""))
    # v10: recurse one level into found directories — /admin/config/ not just
    # /admin/ (recursive_directory_bust existed but was never called)
    _wl = state.get("wordlist", "") or "/usr/share/wordlists/dirb/common.txt"
    try:
        deep_dirs = web.recursive_directory_bust(
            url, wordlist=_wl, max_depth=2, found_dirs=list(dirs), _depth=1,
        ) if dirs else dirs
    except TypeError:
        deep_dirs = dirs
    interesting_dirs = [
        d for d in (deep_dirs or dirs) if d["status"] == 200 and d["size"] > 50
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

    # Active SQLi probe — send actual payloads to confirm injection
    confirmed_sqli_params = set()
    if _HAS_SQLI_PROBE and forms:
        print(f"  [>] Active SQLi probe on {url}...")
        for form in forms[:5]:
            try:
                results = sqli_probe.probe_form(url, form)
                for vuln in results:
                    if vuln.get("is_vulnerable"):
                        param = vuln.get("parameter", "?")
                        confirmed_sqli_params.add(param)
                        # DB fingerprinting from error evidence
                        db_type = _fingerprint_db_from_evidence(vuln.get("evidence", []))
                        db_tag = f" [{db_type}]" if db_type else ""
                        new_findings.append(
                            f"[SQLI-CONFIRMED]{db_tag} {url} param '{param}' "
                            f"via {vuln['injection_type']} — "
                            f"{vuln.get('evidence', [''])[0][:80]}"
                        )
                        vectors = sqli_probe.generate_sqli_vector(
                            url, param, vuln
                        )
                        # Ensure confirmed vectors get high scores
                        for v in vectors:
                            v["score"] = max(v.get("score", 0), 85)
                            v["confidence"] = "high"
                            if db_type:
                                v["title"] = v.get("title", "") + f" ({db_type})"
                        host.setdefault("attack_vectors", []).extend(vectors)
                        print(f"    [+] SQLI CONFIRMED: {param} via {vuln['injection_type']}{db_tag}")
            except Exception as e:
                print(f"    [!] SQLi probe error on {url}: {e}")

    # Remove passive (low-score) SQLi vectors for params we confirmed actively
    if confirmed_sqli_params:
        host["attack_vectors"] = [
            v for v in host.get("attack_vectors", [])
            if not (
                v.get("vector_type") == "sqli"
                and v.get("score", 0) < 70
                and any(p in v.get("title", "").lower() for p in confirmed_sqli_params)
            )
        ]

    # Active LFI / path traversal probe — test parameters for file inclusion
    if _HAS_LFI_PROBE and forms:
        for form in forms[:3]:
            try:
                lfi_results = lfi_probe.probe_form(url, form)
                for vuln in lfi_results:
                    if vuln.get("is_vulnerable"):
                        new_findings.append(
                            f"[LFI-CONFIRMED] {url} param '{vuln['parameter']}' "
                            f"via {vuln.get('injection_type', 'LFI')} — "
                            f"{vuln.get('evidence', [''])[0][:80]}"
                        )
                        vector = lfi_probe.generate_lfi_vector(
                            url, vuln["parameter"], vuln
                        )
                        host.setdefault("attack_vectors", []).append(vector)
                        print(f"    [+] LFI CONFIRMED: {vuln['parameter']}")
            except Exception as e:
                print(f"    [!] LFI probe error: {e}")

    # Also probe URL query parameters for LFI
    if _HAS_LFI_PROBE:
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        if parsed.query:
            qs = parse_qs(parsed.query)
            for param_name, param_vals in qs.items():
                try:
                    lfi_result = lfi_probe.probe_param(url, "GET", param_name, param_vals[0] if param_vals else "test")
                    if lfi_result.get("is_vulnerable"):
                        new_findings.append(
                            f"[LFI-CONFIRMED] {url} param '{param_name}' "
                            f"via {lfi_result.get('injection_type', 'LFI')}"
                        )
                        vector = lfi_probe.generate_lfi_vector(url, param_name, lfi_result)
                        host.setdefault("attack_vectors", []).append(vector)
                        print(f"    [+] LFI CONFIRMED: {param_name}")
                except Exception as e:
                    swallow(__name__ + ":803", e)

    # CalDAV / Radicale enumeration for HTTPS or DAV-capable services
    if _HAS_CALDAV and (port == 443 or port == 80 or "caldav" in svc_name.lower()):
        try:
            caldav_result = caldav.run(url)
            if caldav_result.get("is_caldav"):
                new_findings.append(
                    f"[CALDAV] {url}: CalDAV server detected — "
                    f"DAV: {caldav_result.get('dav_header', '?')}"
                )
                if caldav_result.get("unauthenticated_access"):
                    new_findings.append(
                        f"[!] {url}: Unauthenticated CalDAV access — "
                        f"{len(caldav_result.get('calendars', []))} calendars"
                    )
                for cal_info in caldav_result.get("calendars", [])[:5]:
                    new_findings.append(
                        f"  → Calendar: {cal_info.get('url', '?')} "
                        f"({cal_info.get('displayname', '?')})"
                    )
                if caldav_result.get("default_creds_work"):
                    for dc in caldav_result["default_creds_work"]:
                        new_findings.append(
                            f"[CRED] {url}: CalDAV default cred {dc}"
                        )
                # Generate CalDAV attack vectors
                cal_vectors = caldav.generate_caldav_vectors(url, caldav_result)
                host.setdefault("attack_vectors", []).extend(cal_vectors)
        except Exception as e:
            swallow(__name__ + ":833", e)

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
            # v8.2.2: keep the DOMAIN half too — it feeds vhost bruteforce
            # and AXFR candidates (run-14 lesson: inlanefreight.local was
            # harvested then discarded → 9 vhosts invisible for 4 runs)
            mail_domain = email.split("@")[-1].lower().strip(".")
            if "." in mail_domain and mail_domain not in (
                "example.com", "localhost", "domain.com",
            ):
                state.setdefault("_discovered_domains", set()).add(mail_domain)
                host.setdefault("_cert_domains", []).append(mail_domain)
                # DNS enum ran BEFORE web enum on this host — retry AXFR
                # now that we have a domain, while we're here
                if _HAS_DNS and 53 in host.get("services", {}):
                    import tools.dns_enum as dns_mod
                    zt = dns_mod.zone_transfer(target, mail_domain)
                    if zt and zt.get("records"):
                        txt_vals = "; ".join(
                            r.get("value", "")[:120]
                            for r in zt["records"]
                            if r.get("type") == "TXT"
                        )[:300]
                        new_findings.append(
                            f"[!] AXFR success on {target} for {mail_domain}: "
                            f"{len(zt['records'])} records. TXT: {txt_vals}"
                        )
                        # v8.3.1: DNS TXT flags → flags_captured (run-15:
                        # HTB{DNs_ZOn3_Tr@nsf3r} sat in findings, never
                        # promoted — harvest→consumer gap, third instance)
                        import re as _re_flag
                        _existing = {f.get("flag_value") for f in state.get("flags_captured", []) if isinstance(f, dict)}
                        for _r in zt["records"]:
                            if _r.get("type") == "TXT":
                                for _m in _re_flag.findall(r"(?:HTB|FLAG|CTF|DANTE)\{[^}]+\}", str(_r.get("value", ""))):
                                    if _m not in _existing:
                                        new_findings.append(f"[FLAG] 🚩 {_m} (DNS TXT record, {mail_domain})")
                                        state["flags_captured"] = state.get("flags_captured", []) + [{
                                            "host_ip": target,
                                            "flag_type": "dns_txt",
                                            "flag_value": _m,
                                            "path": f"AXFR {mail_domain}",
                                            "captured_at": __import__("time").strftime("%Y-%m-%dT%H:%M:%S"),
                                            "method": "DNS zone transfer TXT record",
                                        }]
                                        state["flags_found_count"] = state.get("flags_found_count", 0) + 1
                                        _existing.add(_m)
                        for r in zt["records"]:
                            if r.get("type") == "A" and r.get("name"):
                                state.setdefault("_discovered_domains", set()).add(
                                    f"{r['name']}.{mail_domain}".lstrip(".")
                                )
                # v10: subdomain brute on email-derived domain + scope promotion
                if _HAS_DNS and 53 in host.get("services", {}):
                    import tools.dns_enum as dns_mod
                    subs = dns_mod.subdomain_bruteforce(target, mail_domain)
                    if subs:
                        new_findings.append(
                            f"[INTEL] {url}: {len(subs)} subdomains of {mail_domain} "
                            f"(first: {', '.join(subs[:5])})"
                        )
                        for sub in subs[:5]:
                            state.setdefault("_discovered_domains", set()).add(sub)
                        _promote_dns_targets(state, target, subs, new_findings)
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

    # Advanced web enumeration
    print(f"  [>] Advanced web enum on {url}...")

    # JS file analysis
    js_findings = web.analyze_js_files(url)
    for jf in js_findings:
        if jf["type"] == "js_secret":
            new_findings.append(
                f"[!] JS SECRET in {jf['file']}: {jf['secret_type']} — {jf.get('preview', '')[:50]}"
            )
        elif jf["type"] == "js_api_endpoints":
            new_findings.append(
                f"[ENUM] {url}: JS API endpoints in {jf['file']}: {', '.join(jf['endpoints'][:5])}"
            )

    # HTTP methods + CORS
    http_methods = web.check_http_methods(url)
    if http_methods.get("methods"):
        new_findings.append(
            f"[ENUM] {url}: HTTP methods: {', '.join(http_methods['methods'])}"
        )
    if http_methods.get("put_test"):
        new_findings.append(f"[!] {url}: {http_methods['put_test']}")
    cors = http_methods.get("cors")
    if cors and cors.get("reflects"):
        new_findings.append(
            f"[!] {url}: CORS reflects origin (creds={cors.get('credentials', False)})"
        )

    # Parameter discovery
    params = web.discover_params(url)
    if params:
        new_findings.append(f"[ENUM] {url}: Active parameters: {', '.join(params[:10])}")

    # Backup files
    backup_findings = web.check_backup_files(url, dirs)
    for bf in backup_findings:
        btype = bf.get("type", "backup")
        new_findings.append(
            f"[{'!' if btype == 'git_exposure' else '*'}] {url}{bf['path']} "
            f"({bf['status']}, {bf['size']}b) [{btype}]"
        )

    # Deep link crawling
    crawled = web.deep_link_crawl(url, max_pages=5)
    for cl in crawled[:10]:
        new_findings.append(f"[ENUM] {url}: Crawled: {cl['path']} (from {cl['found_on']})")

    # Generate vectors from advanced web findings
    extra_vectors = vs.vectors_for_extra_web(
        url, js_findings, http_methods, backup_findings, params, crawled,
    )
    host.setdefault("attack_vectors", []).extend(extra_vectors)

    # Vhost brute-forcing (only on first web port)
    if port in (80, 443, 8080, 8443, 8000):
        print(f"  [>] Vhost brute-forcing {target}:{port}...")
        # Use cert-derived domains + globally discovered domains for targeted vhost brute
        vhost_domains = list(host.get("_cert_domains", []))
        # Also pull domains discovered from other hosts' SSL certs
        global_domains = state.get("_discovered_domains", set())
        vhost_domains.extend(global_domains - set(vhost_domains))
        _vh_scheme = "https" if ("ssl" in svc_name or port == 443) else "http"
        vhosts = web.vhost_bruteforce(
            target, extra_domains=vhost_domains[:10],
            port=port, scheme=_vh_scheme,
        )
        # v10: persist on the host so the evidence hook can screenshot them.
        # v10.3: vhost_bruteforce now returns dicts {name, port, scheme, title,...}
        # v10.4.3: MERGE by name — a second web port (e.g. 8080) finding no
        # vhosts must not wipe the list (and deep_enum marks) from port 80.
        prior = {vh["name"]: vh for vh in host.get("vhosts", [])
                 if isinstance(vh, dict)}
        merged = []
        for vh in vhosts:
            name = vh["name"] if isinstance(vh, dict) else vh
            old = prior.pop(name, None)
            if isinstance(vh, dict) and isinstance(old, dict):
                old.update({k: v for k, v in vh.items() if v})
                merged.append(old)          # keep old deep_enum mark
            else:
                merged.append(vh)
        merged.extend(prior.values())        # keep vhosts this port didn't see
        host["vhosts"] = merged
        vhosts = merged
        for vh in vhosts:
            _n = vh["name"] if isinstance(vh, dict) else vh
            new_findings.append(f"[ENUM] {target}: Vhost discovered: {_n}")

        # v10.4.4 DIRECTORY→VHOST PROMOTION — run-22 live-catch: /monitoring
        # was a 301 in the :80 directory bust but nothing promoted it to a
        # Host-header probe, and the brute's alphabetical cap evicted
        # monitoring.inlanefreight.local. Any bust-found directory that
        # isn't a generic asset dir becomes a targeted vhost candidate
        # against every discovered base domain. Wordlist-independent.
        try:
            _GENERIC_DIRS = {
                "css", "js", "img", "images", "fonts", "ico", "icon", "icons",
                "static", "assets", "media", "javascript", "style", "styles",
                "dist", "build", "vendor", "doc", "docs", "documentation",
            }
            _bases = sorted({
                str(d).strip().lower().split("->")[0].strip()
                for d in (vhost_domains or [])
                if d and "." in str(d)
            })
            _have = {vh["name"].lower() for vh in host.get("vhosts", [])
                     if isinstance(vh, dict)}
            _promoted = 0
            for wa in host.get("web_apps", []):
                if not isinstance(wa, dict):
                    continue
                if str(wa.get("url", "")).startswith("https"):
                    continue
                for d in (wa.get("directories") or []):
                    p = str(d.get("path", "")).strip().strip("/")
                    if not p or "/" in p or "." in p:
                        continue
                    if p.lower() in _GENERIC_DIRS or p.lower() in _have:
                        continue
                    for b in _bases:
                        cand = f"{p}.{b}"
                        if cand in _have:
                            break
                        vh = web.probe_vhost(target, cand, port=port, scheme=scheme)
                        if vh:
                            host.setdefault("vhosts", []).append(vh)
                            _have.add(vh["name"].lower())
                            new_findings.append(
                                f"[ENUM] {target}: Vhost promoted from directory "
                                f"'/{p}': {vh['name']} ({vh['status']}, {vh['size']}b)"
                            )
                            print(f"    [+] Vhost (dir-promoted): {vh['name']} "
                                  f"({vh['size']}b{', ' + repr(vh['title']) if vh['title'] else ''})")
                            _promoted += 1
                        break   # one base domain is enough per dir name
                    if _promoted >= 10:
                        break
                if _promoted >= 10:
                    break
        except Exception as e:
            swallow(__name__ + ":dir2vhost", e)

    # v10.2 RECURSIVE vhost enumeration: each named vhost gets its own
    # fingerprint + directory bust (Host-header override) + config check +
    # one-level subdirectory recursion. Budget-capped so a 9-vhost shared IP
    # can't turn into an hour of gobuster. v10.4.3: per-vhost deep_enum mark
    # (new vhosts discovered on ANY port get their pass; old blunt
    # vhost_enum_done skipped them).
    pending = [vh for vh in host.get("vhosts", [])
               if not (isinstance(vh, dict) and vh.get("deep_enum"))
               and not (isinstance(vh, str) and host.get("vhost_enum_done"))]
    if pending:
        budget = state.get("vhost_enum_budget", 10)
        for vport, svc in host["services"].items():
            if not _is_web_service((svc.get("service") or "").lower(), vport):
                continue
            vscheme = "https" if ("ssl" in (svc.get("service") or "").lower() or int(vport) in (443, 8443)) else "http"
            for vh in pending[:budget]:
                _enumerate_vhost(state, host, target, int(vport), vscheme, vh, new_findings)
            break  # one web port per pass — deepest (first) wins
        host["vhost_enum_done"] = True

    # CMS-specific enumeration
    tech_str = " ".join(tech.get("technologies", [])).lower() if tech else ""
    if _HAS_EXTRA:
        if "wordpress" in tech_str or "wp-content" in str(page_data):
            wp_info = extra.wordpress_enum(url)
            if wp_info.get("users"):
                new_findings.append(f"[ENUM] {url}: WordPress users: {', '.join(wp_info['users'])}")
            if wp_info.get("version"):
                new_findings.append(f"[ENUM] {url}: WordPress version: {wp_info['version']}")
            if wp_info.get("plugins"):
                new_findings.append(f"[ENUM] {url}: WordPress plugins: {', '.join(wp_info['plugins'][:5])}")
        elif "joomla" in tech_str:
            joom_info = extra.joomla_enum(url)
            if joom_info:
                new_findings.append(f"[ENUM] {url}: Joomla detected: {joom_info}")
        elif "drupal" in tech_str:
            drup_info = extra.drupal_enum(url)
            if drup_info:
                new_findings.append(f"[ENUM] {url}: Drupal detected: {drup_info}")

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

    # Password policy
    pw_policy = ad.get_password_policy(dc_ip, domain_name)
    if pw_policy:
        di["password_policy"] = pw_policy
        new_findings.append(f"[ENUM] {target}: Password policy: {pw_policy}")

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

    # enum4linux
    print(f"  [>] enum4linux on {target}...")
    enum4 = ad.run_enum4linux(target)
    if enum4.get("users"):
        new_findings.append(f"[ENUM] {target}: enum4linux found {len(enum4['users'])} users")
        state.setdefault("_domain_users", []).extend(enum4["users"])
    if enum4.get("password_policy"):
        new_findings.append(f"[ENUM] {target}: password policy: {enum4['password_policy']}")
    if enum4.get("os_info"):
        new_findings.append(f"[ENUM] {target}: OS: {enum4['os_info']}")

    # GPP password check
    gpp = ad.check_gpp_password(target)
    for g in gpp:
        new_findings.append(f"[!] {target}: {g['detail']}")

    # WebDAV check
    if ad.check_webdav(target):
        new_findings.append(f"[ENUM] {target}: WebDAV enabled")


def _enumerate_dns(state, host, target, new_findings):
    """DNS enumeration."""
    if not _HAS_DNS:
        return

    print(f"  [>] DNS enumeration on {target}...")

    # Zone transfer attempts
    # Try to infer domain from SSL SANs or known domains
    domains_to_try = set()
    di = state.get("domain_info") or {}
    if di.get("name"):
        domains_to_try.add(di["name"])

    # Extract domains from cert SANs
    for port, svc in host["services"].items():
        banner = svc.get("banner", "")
        sans = re.findall(r"sans.*?:\s*(.+)", banner)
        for s in sans:
            for domain in s.split(","):
                d = domain.strip()
                if "." in d and "localhost" not in d:
                    domains_to_try.add(d)

    for domain in domains_to_try:
        zt = dns.zone_transfer(target, domain)
        if zt and zt.get("records"):
            new_findings.append(
                f"[!] DNS zone transfer successful on {target} for {domain}! "
                f"{len(zt['records'])} records"
            )
            # v8.3.1: promote DNS TXT flags here too (this path fired on
            # .153/.149 via LDAP-derived domain before web enum ran)
            import re as _re_zt
            _existing = {f.get("flag_value") for f in state.get("flags_captured", []) if isinstance(f, dict)}
            for _r in zt["records"]:
                if _r.get("type") == "TXT":
                    for _m in _re_zt.findall(r"(?:HTB|FLAG|CTF|DANTE)\{[^}]+\}", str(_r.get("value", ""))):
                        if _m not in _existing:
                            new_findings.append(f"[FLAG] 🚩 {_m} (DNS TXT record, {domain})")
                            state["flags_captured"] = state.get("flags_captured", []) + [{
                                "host_ip": target,
                                "flag_type": "dns_txt",
                                "flag_value": _m,
                                "path": f"AXFR {domain}",
                                "captured_at": __import__("time").strftime("%Y-%m-%dT%H:%M:%S"),
                                "method": "DNS zone transfer TXT record",
                            }]
                            state["flags_found_count"] = state.get("flags_found_count", 0) + 1
                            _existing.add(_m)

    # DNS recursion check
    if dns.check_dns_recursion(target):
        new_findings.append(f"[ENUM] {target}: DNS recursion enabled (open resolver)")

    # SRV records (AD)
    if di.get("name"):
        srv_records = dns.enum_srv_records(target, di["name"])
        if srv_records:
            new_findings.append(f"[ENUM] {target}: {len(srv_records)} SRV records")
            for sr in srv_records[:5]:
                new_findings.append(f"  → {sr}")
        # v10: subdomain brute on the AD/domain_info name (deduped in-module
        # against the cert/mail-domain paths) + promote new IPs into scope
        import tools.dns_enum as dns_mod
        subs = dns_mod.subdomain_bruteforce(target, di["name"])
        if subs:
            new_findings.append(
                f"[INTEL] {target}: {len(subs)} subdomains of {di['name']} "
                f"(first: {', '.join(subs[:5])})"
            )
            for sub in subs[:5]:
                state.setdefault("_discovered_domains", set()).add(sub)
            _promote_dns_targets(state, target, subs, new_findings)


def _enumerate_snmp(state, host, target, new_findings):
    """SNMP enumeration."""
    if not _HAS_SNMP:
        return

    print(f"  [>] SNMP enumeration on {target}...")

    # Try common communities
    community = snmp.try_communities(target)
    if not community:
        return

    new_findings.append(f"[ENUM] {target}: SNMP community '{community}' works")

    # System info
    sysinfo = snmp.snmp_enum_system(target, community)
    if sysinfo:
        new_findings.append(f"[ENUM] {target}: SNMP sysDescr: {sysinfo.get('description', '')[:80]}")
        new_findings.append(f"[ENUM] {target}: SNMP sysName: {sysinfo.get('hostname', '')}")

    # Processes
    procs = snmp.snmp_enum_processes(target, community)
    if procs:
        new_findings.append(f"[ENUM] {target}: SNMP {len(procs)} processes discovered")
        # Look for interesting processes
        for p in procs:
            if any(kw in p.lower() for kw in ["ssh", "ftp", "http", "nginx", "apache",
                                                "mysql", "postgres", "redis", "docker"]):
                new_findings.append(f"  → process: {p[:80]}")

    # Network interfaces (may reveal internal networks)
    netinfo = snmp.snmp_enum_network(target, community)
    if netinfo:
        for iface in netinfo[:5]:
            ip = iface.get("ip", "")
            if ip and not ip.startswith("127."):
                new_findings.append(f"[ENUM] {target}: SNMP interface IP: {ip}")
                # Add internal networks to accessible_subnets
                parts = ip.split(".")
                if len(parts) == 4:
                    subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                    if subnet not in state["accessible_subnets"]:
                        state["accessible_subnets"].append(subnet)
                        new_findings.append(f"[ENUM] {target}: New network via SNMP: {subnet}")


def _enumerate_nfs(state, host, target, new_findings):
    """NFS enumeration."""
    if not _HAS_EXTRA:
        return

    print(f"  [>] NFS enumeration on {target}...")
    exports = extra.nfs_enum(target)
    if exports:
        new_findings.append(f"[ENUM] {target}: {len(exports)} NFS export(s)")
        for exp in exports:
            new_findings.append(
                f"  → {exp['directory']} (hosts: {exp.get('hosts', '*')})"
            )


def _enumerate_extra_services(state, host, target, new_findings):
    """Check databases and other services that might be unauthenticated."""
    for port, svc in host["services"].items():
        svc_name = svc["service"].lower()

        # MSSQL
        if "mssql" in svc_name or port == 1433:
            mssql_info = extra.check_mssql(target, port)
            if mssql_info:
                new_findings.append(f"[ENUM] {target}:{port}: MSSQL info: {mssql_info}")

        # MongoDB
        if "mongodb" in svc_name or port == 27017:
            mongo_info = extra.check_mongodb(target, port)
            if mongo_info and mongo_info.get("accessible"):
                new_findings.append(f"[!] {target}:{port}: MongoDB unauthenticated!")

        # Redis
        if "redis" in svc_name or port == 6379:
            redis_info = extra.check_redis(target, port)
            if redis_info and redis_info.get("accessible"):
                new_findings.append(f"[!] {target}:{port}: Redis unauthenticated!")

        # Elasticsearch
        if "elasticsearch" in svc_name or port == 9200:
            es_info = extra.check_elasticsearch(target, port)
            if es_info and es_info.get("accessible"):
                new_findings.append(f"[!] {target}:{port}: Elasticsearch open!")

        # SMTP user enum
        if "smtp" in svc_name or port in (25, 587):
            smtp_users = extra.smtp_enum_users(target, port)
            if smtp_users:
                new_findings.append(
                    f"[ENUM] {target}:{port}: SMTP users: {', '.join(smtp_users[:10])}"
                )
                state.setdefault("_domain_users", []).extend(smtp_users)

        # FTP anonymous content
        if "ftp" in svc_name or port == 21:
            ftp_info = extra.check_ftp_content(target, port)
            if ftp_info and ftp_info.get("anonymous"):
                files = ftp_info.get("files", [])
                new_findings.append(f"[ENUM] {target}:{port}: FTP anonymous access, {len(files)} files")
                for f in files[:10]:
                    new_findings.append(f"  → {f}")

                # Check downloaded file contents for flags/creds/intel
                file_contents = ftp_info.get("file_contents", {})
                for fname, content in file_contents.items():
                    # v8.3.3: host-tag every line — run-15 saw .153 and .149
                    # both produce "[FTP] Contents of flag.txt:"; _dedup would
                    # silently drop the second host's identical findings.
                    new_findings.append(f"[FTP] {target}:{port} contents of {fname}:")
                    # Scan for flags
                    import re as _re
                    for pattern in [r'DANTE\{[^}]+\}', r'FLAG\{[^}]+\}', r'HTB\{[^}]+\}']:
                        flags = _re.findall(pattern, content)
                        for flag in flags:
                            new_findings.append(f"[FLAG] 🚩 {flag} (from FTP {target}: {fname})")
                            state["flags_captured"] = state.get("flags_captured", []) + [{
                                "host_ip": target,
                                "flag_type": "ftp",
                                "flag_value": flag,
                                "path": f"ftp://{fname}",
                                "captured_at": __import__("time").strftime("%Y-%m-%dT%H:%M:%S"),
                                "method": "FTP file download",
                            }]
                            state["flags_found_count"] = state.get("flags_found_count", 0) + 1
                    # Show content preview
                    for line in content.split("\n")[:5]:
                        if line.strip():
                            new_findings.append(f"  {line.strip()[:120]}")
                    # Scan for intel (passwords, users, hints)
                    lower_content = content.lower()
                    if any(kw in lower_content for kw in ["password", "credential", "lfi", "reset", "pending", "todo", "secret"]):
                        new_findings.append(f"[!] Intel in {fname} — potential actionable info")

                    # Extract credentials from FTP file contents
                    # Matches user:pass@host, password=value, DB_USER/DB_PASSWORD
                    for cred_pat, cred_type in [
                        (r'https?://([^:/\s]+):([^@\s]+)@', 'url_cred'),
                        (r'(?:password|passwd|pwd)\s*[=:]\s*[\'"]?([^\'"\s;]{4,60})', 'password_kv'),
                        (r'DB_PASSWORD[=:\'\"]+\s*[\'"]?([^\'"]+)', 'wp_db_pass'),
                        (r'DB_USER[=:\'\"]+\s*[\'"]?([^\'"]+)', 'wp_db_user'),
                    ]:
                        for cm2 in _re.finditer(cred_pat, content, _re.IGNORECASE):
                            try:
                                if cred_type == 'url_cred':
                                    u, v = cm2.group(1), cm2.group(2)
                                elif cred_type == 'wp_db_pass':
                                    u, v = 'wp_db', cm2.group(1)
                                elif cred_type == 'wp_db_user':
                                    u, v = cm2.group(1), None
                                else:
                                    u, v = '?', cm2.group(1)
                                if v and v.lower() not in ('none', 'null', 'true', 'false', ''):
                                    new_findings.append(
                                        f"[CRED] FTP {fname}: {u}:{v[:20]} ({cred_type})"
                                    )
                                    print(f"    [CRED] FTP {fname}: {u}:{v[:20]}")
                            except (IndexError, ValueError):
                                continue


def _run_cve_research_host(state, host, target, new_findings):
    """Per-host CVE research — runs during enumeration, not just analyze."""
    if not _HAS_CVE_RESEARCH:
        return
    researched = state.setdefault("_cve_researched", set())

    for port, svc in host.get("services", {}).items():
        service_name = svc.get("service", "")
        version = svc.get("version", "")
        if not version or len(version) < 2:
            continue

        # Normalize version: extract just the product + version number
        # e.g. "Apache httpd 2.4.29 ((Ubuntu))" -> service="apache", version="2.4.29"
        import re as _re
        ver_match = _re.search(r'(\d+\.\d+(?:\.\d+)?)', version)
        clean_version = ver_match.group(1) if ver_match else version

        # Map common service names
        svc_lower = service_name.lower()
        if "apache" in version.lower() or "httpd" in version.lower():
            clean_service = "apache httpd"
        elif "powerdns" in version.lower():
            clean_service = "powerdns"
        elif "openssh" in version.lower():
            clean_service = "openssh"
        elif "nginx" in version.lower():
            clean_service = "nginx"
        elif "iis" in version.lower():
            clean_service = "iis"
        else:
            clean_service = service_name.split("/")[0]

        research_key = f"{clean_service}:{clean_version}"
        if research_key in researched:
            continue
        researched.add(research_key)

        print(f"  [>] CVE research: {clean_service} {clean_version} ({target}:{port})...")
        try:
            cves = cve_res.search_cves(clean_service, clean_version)
            if cves:
                high_cves = [c for c in cves if c.get("severity") in ("HIGH", "CRITICAL")]
                if high_cves:
                    new_findings.append(
                        f"[CVE] {clean_service} {clean_version} ({target}:{port}): "
                        f"{len(high_cves)} high/critical CVEs"
                    )
                    for cve in high_cves[:3]:
                        new_findings.append(
                            f"  -> {cve['id']} (CVSS {cve.get('cvss_score', '?')}): "
                            f"{cve.get('description', '')[:70]}"
                        )
                    # Generate CVE vectors
                    for cve in high_cves[:3]:
                        vectors = vs.vectors_for_cve(target, port, clean_service, clean_version, cve)
                        host.setdefault("attack_vectors", []).extend(vectors)

            # Exploit commands
            commands = cve_res.generate_exploit_commands({
                "service": clean_service, "version": clean_version,
                "target": f"{target}:{port}",
            })
            if commands:
                new_findings.append(f"[EXPLOIT-CMD] {clean_service} {clean_version}:")
                for cmd in commands[:2]:
                    new_findings.append(f"  -> {cmd}")
        except Exception as e:
            print(f"  [!] CVE research failed for {clean_service}: {e}")


# ═══════════════════════════════════════════════════════════════════════
# CVE RESEARCH & CREDENTIAL TESTING
# ═══════════════════════════════════════════════════════════════════════

def _run_cve_research(state: ReconState) -> List[str]:
    """Search NVD and searchsploit for version-specific CVEs."""
    if not _HAS_CVE_RESEARCH:
        return []

    findings = []
    researched = set()

    for ip, host in state["hosts"].items():
        for port, svc in host.get("services", {}).items():
            service_name = svc.get("service", "")
            version = svc.get("version", "")
            if not version or len(version) < 2:
                continue

            # Deduplicate by service+version
            research_key = f"{service_name}:{version}"
            if research_key in researched:
                continue
            researched.add(research_key)

            print(f"  [>] CVE research: {service_name} {version} ({ip}:{port})...")
            try:
                cves = cve_res.search_cves(service_name, version)
                if cves:
                    high_cves = [c for c in cves if c.get("severity") in ("HIGH", "CRITICAL")]
                    if high_cves:
                        findings.append(
                            f"[CVE] {service_name} {version} ({ip}:{port}): "
                            f"{len(high_cves)} high/critical CVEs found"
                        )
                        for cve in high_cves[:5]:
                            findings.append(
                                f"  → {cve['id']} (CVSS {cve.get('cvss_score', '?')}: "
                                f"{cve.get('description', '')[:80]})"
                            )

                    # Also check exploitdb
                    exploits = cve_res.search_exploitdb_online(f"{service_name} {version}")
                    if exploits:
                        findings.append(
                            f"[EXPLOIT-DB] {service_name} {version}: "
                            f"{len(exploits)} exploits found"
                        )
                        for exp in exploits[:3]:
                            findings.append(
                                f"  → {exp.get('title', '?')} [{exp.get('type', '?')}]"
                            )

                    # Generate concrete exploit commands
                    commands = cve_res.generate_exploit_commands({
                        "service": service_name,
                        "version": version,
                        "target": f"{ip}:{port}",
                    })
                    if commands:
                        findings.append(f"[EXPLOIT-CMD] Commands for {service_name} {version}:")
                        for cmd in commands[:3]:
                            findings.append(f"  → {cmd}")
            except Exception as e:
                print(f"  [!] CVE research failed for {service_name}: {e}")

    return findings


def _run_cred_test(state: ReconState) -> List[str]:
    """Test default credentials against discovered services.
    
    After finding valid creds on any host, immediately:
    1. Record them as Credential objects in state
    2. Test them against ALL services on ALL hosts (cred reuse)
    3. Run authenticated web scanning on hosts where HTTP Basic worked
    """
    if not _HAS_CRED_TEST:
        return ["[CRED] Credential testing module not available"]
    if not state.get("test_creds"):
        return []

    findings = []
    valid_creds = []  # (username, password, source_service, source_ip)

    # Phase 1: Standard cred scan per host
    for ip, host in state["hosts"].items():
        services = host.get("services", {})
        print(f"  [>] Testing default creds on {ip}...")
        try:
            results = cred.run_cred_scan(ip, list(services.values()))
            for r in results:
                if r.get("success"):
                    findings.append(
                        f"[CRED] ✓ VALID CREDENTIAL: {r['service']} on {ip} — "
                        f"{r['username']}:{r['password']} ({r.get('detail', '')})"
                    )
                    valid_creds.append((r["username"], r["password"], r["service"], ip))
                    # Store as Credential in state
                    # NOTE: must be `discovered_credentials` (declared in
                    # ReconState). The old `state["credentials"]` key was
                    # UNDECLARED → LangGraph silently dropped it on node
                    # return → valid creds (e.g. admin:admin on run 11)
                    # vanished from state before exploit/privesc phases.
                    state.setdefault("discovered_credentials", []).append({
                        "username": r["username"],
                        "password": r["password"],
                        "source_host": ip,
                        "source_service": r["service"],
                        "valid_on": [ip],
                    })
                    # v8.3.0 (vault PA-06/07): a validated cred immediately
                    # earns a fleet-spray vector. The old agent validated
                    # admin:admin on .72 then NEVER sprayed the Windows
                    # fleet — the single biggest missed prolab move.
                    _sv = state.setdefault("attack_vectors", [])
                    if not any(v.get("id") == f"cred_spray_{r['username']}" for v in _sv):
                        _sv.append(AttackVector(
                            id=f"cred_spray_{r['username']}",
                            target="fleet",
                            category="credential_attack",
                            vector_type="password_spray",
                            title=f"Fleet spray: {r['username']} (validated on {ip})",
                            description=(f"Spray validated {r['username']} credential "
                                         f"across SMB/WinRM/SSH/web forms fleet-wide "
                                         f"(vault: Password Attacks 06/07)"),
                            confidence="high",
                            score=85,
                            evidence=[f"validated on {ip} as {r['service']}"],
                            exploit_suggestions=["netexec smb", "sshpass", "form POST"],
                            prerequisites=[], cves=[], references=[],
                        ))
                        print(f"  [+] Queued fleet-spray vector for {r['username']} (score 85)")
                else:
                    findings.append(
                        f"[CRED] ✗ {r['service']} on {ip} — "
                        f"{r['username']}:{r['password']} failed"
                    )
        except Exception as e:
            print(f"  [!] Cred test failed for {ip}: {e}")

    # Phase 2: Credential reuse — test valid creds against ALL hosts' services
    if valid_creds:
        print(f"\n  [>] Testing {len(valid_creds)} valid cred(s) against all hosts (cred reuse)...")
        for username, password, src_svc, src_ip in valid_creds:
            for ip, host in state["hosts"].items():
                if ip == src_ip:
                    continue  # Already tested on source
                services = host.get("services", {})
                for port, svc in services.items():
                    svc_name = svc.get("service", "").lower()
                    # Test HTTP Basic on web services
                    if _is_web_service(svc_name, port):
                        scheme = "https" if ("ssl" in svc_name or "https" in svc_name or port == 443) else "http"
                        url = f"{scheme}://{ip}:{port}"
                        try:
                            import requests as _req
                            # v9.1: HTTP 200 alone is NOT validation. Basic auth is
                            # only bookable when the app actually challenged us
                            # (401 + WWW-Authenticate) and then accepted the creds.
                            # A form-login app ignores Basic auth and serves its
                            # public page with 200 → run-20 false positive.
                            anon = _req.get(url, timeout=5, verify=False, allow_redirects=False)
                            challenged = anon.status_code == 401 and "www-authenticate" in {k.lower() for k in anon.headers}
                            if not challenged:
                                continue
                            r = _req.get(url, auth=(username, password),
                                        timeout=5, verify=False, allow_redirects=False)
                            if r.status_code == 200:
                                findings.append(
                                    f"[CRED-REUSE] ✓ {username}:{password} works on {url} "
                                    f"(Basic auth challenge accepted — reused from {src_ip})"
                                )
                                # Update credential record
                                for cred_rec in state.get("discovered_credentials", []):
                                    if cred_rec["username"] == username and cred_rec["password"] == password:
                                        if ip not in cred_rec["valid_on"]:
                                            cred_rec["valid_on"].append(ip)
                        except Exception as e:
                            swallow(__name__ + ":1483", e)
                    # Test SSH
                    elif "ssh" in svc_name or port == 22:
                        try:
                            import paramiko
                            client = paramiko.SSHClient()
                            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                            client.connect(ip, port=port, username=username, password=password, timeout=5)
                            findings.append(
                                f"[CRED-REUSE] ✓ {username}:{password} SSH works on {ip}:{port} "
                                f"(reused from {src_ip})"
                            )
                            client.close()
                        except Exception as e:
                            swallow(__name__ + ":1497", e)

    # Phase 3: Authenticated web scanning on hosts where HTTP Basic worked
    for username, password, src_svc, src_ip in valid_creds:
        host = state["hosts"].get(src_ip, {})
        if not host:
            continue
        for port, svc in host.get("services", {}).items():
            svc_name = svc.get("service", "").lower()
            if _is_web_service(svc_name, port):
                scheme = "https" if ("ssl" in svc_name or "https" in svc_name or port == 443) else "http"
                url = f"{scheme}://{src_ip}:{port}"
                print(f"  [>] Authenticated scan on {url} with {username}:{password}...")
                auth_findings = _authenticated_web_scan(url, username, password)
                findings.extend(auth_findings)

    return findings


def _authenticated_web_scan(url: str, username: str, password: str) -> List[str]:
    """Scan web app with HTTP Basic auth — discover admin panels, uploads, etc."""
    findings = []
    try:
        import requests as _req
        auth = (username, password)
        
        # Fetch authenticated pages
        auth_paths = [
            "/admin", "/admin/", "/administrator/", "/dashboard",
            "/panel", "/manage", "/console", "/upload",
            "/admin/upload", "/admin/users", "/admin/config",
            "/phpmyadmin", "/adminer", "/wp-admin/",
        ]
        for path in auth_paths:
            try:
                r = _req.get(f"{url}{path}", auth=auth, timeout=5, verify=False, allow_redirects=True)
                if r.status_code == 200 and len(r.text) > 200:
                    # Check for interesting content
                    title_match = re.search(r"<title>(.*?)</title>", r.text, re.I)
                    title = title_match.group(1).strip() if title_match else ""
                    findings.append(
                        f"[AUTH-SCAN] {url}{path}: HTTP 200 ({len(r.text)}b) "
                        f"title='{title}' — authenticated content accessible"
                    )
                    # Look for upload forms
                    if "upload" in r.text.lower() or "file" in r.text.lower() and "input" in r.text.lower():
                        findings.append(
                            f"[!] {url}{path}: Upload form detected behind auth!"
                        )
                    # Look for user/data tables
                    if any(kw in r.text.lower() for kw in ["user", "password", "email", "credential"]):
                        findings.append(
                            f"[!] {url}{path}: User/credential data visible behind auth!"
                        )
            except Exception as e:
                swallow(__name__ + ":1552", e)
    except ImportError:
        pass
    return findings


# ═══════════════════════════════════════════════════════════════════════
# ANALYZE NODE — LLM-powered attack path analysis and ranking
# ═══════════════════════════════════════════════════════════════════════

def analyze_node(state: ReconState) -> ReconState:
    """LLM-powered analysis of all findings to rank attack vectors."""
    print("\n" + "=" * 60)
    print("  PHASE: ATTACK PATH ANALYSIS")
    print("=" * 60)

    summary = get_engagement_summary(state)

    # Run CVE research (if enabled and not already done)
    if state.get("cve_research", True) and not state.get("_cve_research_done"):
        print("\n  [>] Running CVE research (NVD + searchsploit)...")
        cve_findings = _run_cve_research(state)
        if cve_findings:
            state["findings"] = _dedup(cve_findings, state.get("findings", []))
            for f in cve_findings:
                print(f"    {f}")
        state["_cve_research_done"] = True

    # Run credential testing (if enabled and not already done)
    if state.get("test_creds") and not state.get("_cred_test_done"):
        print("\n  [>] Testing default credentials...")
        cred_findings = _run_cred_test(state)
        if cred_findings:
            state["findings"] = _dedup(cred_findings, state.get("findings", []))
            for f in cred_findings:
                print(f"    {f}")
        state["_cred_test_done"] = True

    # Collect all findings for LLM context
    all_findings = state.get("findings", [])[-200:]
    findings_text = "\n".join(all_findings[-100:])

    # v8.2.1: handler-awareness for the prompt (run-13 lesson: LLM suggested
    # an XSS step that no dispatcher could run — wasted iteration)
    try:
        from tools.exploit import HANDLED_VECTOR_TYPES
        handled_types = ", ".join(sorted(HANDLED_VECTOR_TYPES))
    except ImportError:
        handled_types = "unknown (handler registry unavailable)"

    # Collect all attack vectors — DEDUP by ID
    all_vectors = []
    seen_ids = set()
    for ip, host in state["hosts"].items():
        for v in host.get("attack_vectors", []):
            vid = v.get("id", "")
            if vid not in seen_ids:
                all_vectors.append(v)
                seen_ids.add(vid)
    for v in state.get("attack_vectors", []):
        vid = v.get("id", "")
        if vid not in seen_ids:
            all_vectors.append(v)
            seen_ids.add(vid)

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

    # Vault knowledge pack — inject relevant HTB playbooks into LLM context
    knowledge_text = ""
    try:
        from knowledge.retrieval import knowledge_pack, registry_stats
        kstats = registry_stats()
        if kstats.get("available"):
            svc_set, tech_list, vt_set = set(), [], set()
            for ip, host in state["hosts"].items():
                for port_info in (host.get("ports") or {}).values():
                    sname = (port_info or {}).get("service", "")
                    if sname:
                        svc_set.add(sname.split("|")[0].strip())
                    prod = (port_info or {}).get("version", "")
                    if prod:
                        tech_list.append(prod)
                for v in host.get("attack_vectors", []):
                    vt_set.add(v.get("vector_type", ""))
            pack = knowledge_pack(services=svc_set, technologies=tech_list,
                                  vector_types=vt_set, phase="",
                                  max_notes=10, max_chars=10000)
            if pack:
                knowledge_text = pack["text"]
                state["knowledge_matches"] = pack["matches"]
                print(f"  [+] Vault knowledge pack: {len(pack['matches'])} matched notes injected")
        else:
            print("  [i] Vault registry not built (knowledge/registry.json) — run knowledge/parse_vault.py")
    except Exception as e:
        print(f"  [!] Knowledge pack skipped: {e}")

    prompt = f"""You are a senior penetration tester analyzing enumeration results.
Your task is to RANK attack vectors, identify the MOST LIKELY attack paths,
and suggest exploitation strategies.

## Current Engagement
{summary}

## Recent Findings (last 100)
{findings_text}

## Discovered Attack Vectors (heuristic-generated)
{vectors_text}

## Relevant HTB Playbooks (operator's technique vault — proven commands)
{knowledge_text}

## Your Task
Analyze ALL the above data and provide:

1. **Top 5 Attack Paths** — ranked by likelihood of success
2. **Exploit Suggestions** for each path (specific commands/tools)
3. **Privilege Escalation** paths for each potential foothold
4. **Lateral Movement** opportunities
5. **Missing Intelligence** — what else should be enumerated?

## Hard Constraint — Exploit Handler Coverage
Your attack paths are EXECUTED, not just admired: `_dispatch_attack_path`
runs each step's commands verbatim, and vector dispatch only supports these
types: {handled_types}.
Do NOT suggest steps whose technique falls outside this set (e.g. pure
client-side XSS, CSRF, clickjacking, social engineering — nothing runs
them; a wasted suggestion = a wasted iteration). Credentials in state,
nmap/gobuster/sqlmap/hydra/showmount/curl-style commands are all runnable.

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

    # Merge all vectors into state — DEDUP by vector ID to prevent double counting
    seen_ids = {v.get("id", "") for v in state.get("attack_vectors", [])}
    merged = list(state.get("attack_vectors", []))
    for v in all_vectors:
        vid = v.get("id", "")
        if vid not in seen_ids:
            merged.append(v)
            seen_ids.add(vid)
    state["attack_vectors"] = merged[-500:]

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

    # Priority 3.25: Exploit high-confidence attack vectors (StrikeARC)
    threshold = state.get("exploit_threshold", 70)
    attempted_ids = {a.get("vector_id", "") for a in state.get("exploit_attempts", [])}
    # v8.4.0 failure memoization: LLM attack paths get FRESH ids every
    # analyze pass, so attempted_ids can't stop identical re-dispatch
    # (run 18 executed the same gitlab Host-header path twice; the stall
    # descent re-offered dead vectors 17→1). Block (technique, target)
    # pairs that already failed. Stable-id vectors (cred_spray_*) are
    # unaffected — their ids are deterministic.
    _failed_pairs = {
        (a.get("technique", ""), a.get("target", ""))
        for a in state.get("exploit_attempts", [])
        if not a.get("success")
    }
    # Merged view: global + per-host vectors (per-host is all that exists
    # before the first analyze run or when resuming from a save)
    _merged_vecs = list(state.get("attack_vectors", []))
    for _h in state["hosts"].values():
        _merged_vecs.extend(_h.get("attack_vectors", []))
    # v8.2.1 selection guard (run-12 lesson): only offer vectors whose type
    # has a registered exploit handler. Without this, 9/15 resume-run
    # iterations dispatched xss ("Missing CSP") vectors that attempt_exploit
    # could only reject with "No exploit handler" — guaranteed no-ops.
    try:
        from tools.exploit import HANDLED_VECTOR_TYPES
    except ImportError:
        HANDLED_VECTOR_TYPES = None  # older exploit module: skip guard
    _skipped_unhandled = 0
    unexploited = []
    for v in _merged_vecs:
        if v.get("score", 0) < threshold or v.get("id") in attempted_ids:
            continue
        if (v.get("vector_type", "").lower(), v.get("target", "")) in _failed_pairs:
            continue  # v8.4.0: identical (technique, target) already failed
        if HANDLED_VECTOR_TYPES is not None and v.get("vector_type", "").lower() not in HANDLED_VECTOR_TYPES:
            _skipped_unhandled += 1
            continue
        unexploited.append(v)
    if _skipped_unhandled and not unexploited:
        print(f"  [i] {_skipped_unhandled} vectors skipped at selection — no exploit handler for their type")
    if unexploited:
        best = max(unexploited, key=lambda v: v.get("score", 0))
        print(f"\n  → ACTION: Exploit {best.get('target', '?')} — {best.get('title', '?')} (score: {best.get('score', 0)})")
        return {**state, "current_phase": "exploit"}

    # Priority 3.3: Flag hunt on compromised hosts (StrikeARC)
    session_hosts = {s["host_ip"] for s in state.get("sessions", [])}
    checked_hosts = {f["host_ip"] for f in state.get("flags_captured", []) if isinstance(f, dict) and f.get("host_ip")}
    if session_hosts - checked_hosts:
        print(f"\n  → ACTION: Flag hunt on compromised hosts")
        return {**state, "current_phase": "flag_hunt"}

    # Priority 3.5: Post-exploitation on compromised hosts
    compromised = state.get("compromised_hosts", {})
    unenumerated_compromised = {
        ip: ch for ip, ch in compromised.items()
        if not ch.get("enumerated")
    }
    if unenumerated_compromised:
        target_ip = list(unenumerated_compromised.keys())[0]
        print(f"\n  → ACTION: Post-exploit enumerate {target_ip}")
        return {**state, "current_target": target_ip, "current_phase": "post_exploit"}

    # Priority 3.6: Pivot to newly discovered internal networks
    new_subnets = []
    for ip, ch in compromised.items():
        if ch.get("enumerated"):
            for subnet in ch.get("discovered_subnets", []):
                if subnet not in state.get("scanned_subnets", []) and subnet not in new_subnets:
                    new_subnets.append(subnet)
    if new_subnets:
        print(f"\n  → ACTION: Pivot — discover internal network {new_subnets[0]}")
        for s in new_subnets:
            if s not in state["accessible_subnets"]:
                state["accessible_subnets"].append(s)
        return {**state, "current_phase": "pivot"}

    # Priority 4: Check stall condition
    # If no new findings were added since last iteration, we're spinning.
    # With the credential explosion bug fixed, legitimate stalls indicate
    # all vectors are exhausted — go to report immediately.
    findings_len = len(state["findings"])
    if state.get("last_findings_len") == findings_len:
        state["stall_count"] = state.get("stall_count", 0) + 1
    else:
        state["stall_count"] = 0
    state["last_findings_len"] = findings_len

    # v10.2: a "stall" is only real if no RECURSIVE work remains — hosts with
    # discovered vhosts not yet deep-enumerated keep the loop alive so their
    # subdomains/directories actually get fuzzed instead of the agent exiting.
    if state.get("stall_count", 0) >= 1 and _recursive_work_pending(state):
        print(f"\n  → ACTION: Recursive enumeration pending "
              f"(vhosts/promoted hosts) — overriding stall")
        state["stall_count"] = 0
        # fall through: pick that work up below via the normal priority chain

    if state.get("stall_count", 0) >= 1:
        # Priority 4.5: Lab-death detection (run-15 gap: lab expired ~2h in;
        # the agent ground through ~40 more iterations / 159 connection-failed
        # cred tests / 28 doomed exploits against hosts that were all down).
        # On every stall, probe up to 5 hosts on ports we KNOW were open.
        # If none respond, the environment is gone — no vector can succeed.
        probe_targets = []
        for ip, h in list(state["hosts"].items())[:5]:
            # NB: after save/load (JSON), services keys are digit STRINGS —
            # accept both int and str forms.
            ports = [int(p) for p in (h.get("services") or {}).keys()
                     if isinstance(p, int) or (isinstance(p, str) and p.isdigit())]
            if ip and ports:
                probe_targets.append((ip, ports[0]))
        alive = 0
        for ip, port in probe_targets:
            try:
                import socket as _probe_sock
                _p = _probe_sock.socket(_probe_sock.AF_INET, _probe_sock.SOCK_STREAM)
                _p.settimeout(3)
                _p.connect((ip, port))
                alive += 1
                _p.close()
            except ConnectionRefusedError:
                alive += 1  # refused = host is up, service died
            except Exception:
                pass
        if probe_targets and alive == 0:
            print(f"\n  [!] Environment unreachable: probed {len(probe_targets)} known-open"
                  f" ports, 0 responded.")
            print("      (Lab expired or VPN dropped — remaining vectors cannot succeed.)")
            print("  [*] Generating report instead of spinning against dead targets.")
            return {**state, "current_phase": "report"}

        # Check if there are any remaining unexploited vectors below the
        # current threshold before giving up entirely
        attempted_ids = {a.get("vector_id", "") for a in state.get("exploit_attempts", [])}
        _failed_pairs_stall = {
            (a.get("technique", ""), a.get("target", ""))
            for a in state.get("exploit_attempts", [])
            if not a.get("success")
        }
        _merged_vecs = list(state.get("attack_vectors", []))
        for _h in state["hosts"].values():
            _merged_vecs.extend(_h.get("attack_vectors", []))
        remaining = [
            v for v in _merged_vecs
            if v.get("id") not in attempted_ids
            and (v.get("vector_type", "").lower(), v.get("target", "")) not in _failed_pairs_stall
        ]
        if remaining:
            # Lower the threshold and try again
            best_remaining = max(remaining, key=lambda v: v.get("score", 0))
            threshold = state.get("exploit_threshold", 70)
            state["exploit_threshold"] = max(best_remaining.get("score", 0), 30)
            print(f"\n  [!] Stall detected. Lowering exploit threshold to {state['exploit_threshold']} "
                  f"to try {len(remaining)} remaining vectors.")
            state["stall_count"] = 0  # reset to allow one more attempt
            return {**state, "current_phase": "scope"}
        print("\n  [*] No new findings and no remaining vectors. Generating report.")
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
            if _is_web_service(svc_name, port):
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

    # v8.2.2 (run-14): show the planner what's actually attackable — the
    # old menu (discover/enumerate/analyze/report) could never order an
    # attack, so stall→analyze→stall looped forever without dispatching.
    try:
        from tools.exploit import HANDLED_VECTOR_TYPES
    except ImportError:
        HANDLED_VECTOR_TYPES = None
    attempted = {a.get("vector_id", "") for a in state.get("exploit_attempts", [])}
    _vecs = list(state.get("attack_vectors", []))
    for _h in state.get("hosts", {}).values():
        _vecs.extend(_h.get("attack_vectors", []))
    threshold = state.get("exploit_threshold", 70)
    eligible = [
        v for v in _vecs
        if v.get("id") not in attempted
        and v.get("score", 0) >= threshold
        and (HANDLED_VECTOR_TYPES is None
             or v.get("vector_type", "").lower() in HANDLED_VECTOR_TYPES)
    ]
    n_unattempted = len(eligible)
    best_vector_desc = "none eligible"
    if eligible:
        _best = max(eligible, key=lambda v: v.get("score", 0))
        best_vector_desc = f"{_best.get('title', '?')} → {_best.get('target', '?')} (score {_best.get('score', 0)})"

    prompt = f"""You are the strategic planner for an enumeration engagement.

## Current State
{summary}{user_context}

## Available Actions
- discover: Scan for new hosts (if new subnets accessible)
- enumerate: Deep-dive on a host
- analyze: Re-analyze findings for attack paths
- exploit: Dispatch the best unattempted attack vector NOW. Use this
  when unattempted vectors exist ({n_unattempted} currently eligible,
  e.g. {best_vector_desc}) — attacking beats more analysis.
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

    # Deduplicate flags_captured by flag_value
    seen_flag_values = set()
    unique_flags = []
    for f in state.get("flags_captured", []):
        val = f.get("flag_value", "")
        if val not in seen_flag_values:
            seen_flag_values.add(val)
            unique_flags.append(f)
    state["flags_captured"] = unique_flags

    summary = get_engagement_summary(state)

    # Collect all attack vectors — DEDUP by ID to prevent double counting
    all_vectors = []
    seen_ids = set()
    for ip, host in state["hosts"].items():
        for v in host.get("attack_vectors", []):
            vid = v.get("id", "")
            if vid not in seen_ids:
                all_vectors.append(v)
                seen_ids.add(vid)
    for v in state.get("attack_vectors", []):
        vid = v.get("id", "")
        if vid not in seen_ids:
            all_vectors.append(v)
            seen_ids.add(vid)

    # v10.4: high-severity web probe findings become attack vectors
    seen_ids_probe = set()
    for r in (state.get("web_probe_results") or []):
        if r["sev"] != "high":
            continue
        vid = f"probe_{r['tech']}_{r['target']}".replace(" ", "_").replace(":", "_")
        if vid in seen_ids_probe:
            continue
        seen_ids_probe.add(vid)
        matching = [l for l in (state.get("web_probe_leads") or [])
                    if l["tech"].startswith(r["tech"].split("-")[0])
                    and l["target"] == r["target"]]
        cmds = [m["command"].splitlines()[0] for m in matching[:2] if m.get("command")]
        all_vectors.append(AttackVector(
            id=vid, target=r["target"], category="initial_access",
            vector_type=r["tech"],
            title=f"[probe] {r['finding'][:80]}",
            description=(r.get("evidence") or "")[:160] or "vault-driven probe hit",
            confidence="high",
            score=70 + (5 if cmds else 0),
            evidence=[r.get("finding", "")] + ([r.get("evidence", "")] if r.get("evidence") else []),
            exploit_suggestions=cmds or [f"vault: {r.get('vault','')}"],
            prerequisites=[], cves=[],
            references=[r.get("vault", "")],
        ))

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

    # ── Lead dashboard: coverage matrix + manual leads + evidence index ─────
    try:
        from knowledge.coverage import (build_coverage, coverage_stats,
                                        manual_leads)
        cov = state.get("coverage") or build_coverage(state)
        if cov:
            dash = _render_lead_dashboard(state, cov)
            if dash:
                with open(report_path, "a") as f:
                    f.write("\n\n" + dash)
                print(f"  [+] Lead dashboard appended ({len(dash)} chars)")
    except Exception as exc:
        print(f"  [COV] lead dashboard failed (non-fatal): {exc}")

    # Print top 5 attack vectors
    print(f"\n  [+] Top Attack Vectors ({len(all_vectors)} total):")
    for i, v in enumerate(all_vectors[:5]):
        print(f"    #{i+1} [{v['confidence']}/{v['score']}] {v['title']}")
        print(f"        Target: {v['target']}")
        if v.get("exploit_suggestions"):
            print(f"        → {v['exploit_suggestions'][0]}")

    save_state(state)
    return {**state, "current_phase": "complete"}


def _render_lead_dashboard(state: ReconState, cov: list) -> str:
    """Manual-guidance dashboard: coverage matrix, ranked leads with the exact
    commands from vault notes, and the evidence index."""
    from knowledge.coverage import coverage_stats, display_commands, manual_leads

    stats = coverage_stats(cov)
    vault = os.path.expanduser("~")
    lines = []
    lines.append("---\n")
    lines.append("## 9. Manual Lead Dashboard (Vault Coverage)")
    lines.append(
        f"\nEvery host×service below is mapped to your HTB-Academy vault techniques "
        f"({stats['enum_safe']} enum-safe, {stats['manual_leads']} manual leads). "
        f"Enum-safe items were candidates for automation; manual leads are yours to run.\n")
    lines.append(f"| Metric | Value |")
    lines.append(f"|---|---|")
    lines.append(f"| Techniques applicable | {stats['total']} |")
    lines.append(f"| Enum-safe automated | {stats['done']} done, {stats['skipped']} skipped |")
    lines.append(f"| Pending enum-safe | {stats['pending_enum']} |")
    lines.append(f"| **Manual leads** | **{stats['manual_leads']}** |\n")

    # Coverage matrix — host × service with done/pending counts
    lines.append("### Coverage Matrix")
    lines.append("\n| Host | Service | Enum-safe (done/total) | Manual leads |")
    lines.append("|---|---|---|---|")
    agg = {}
    for item in cov:
        key = (item["host"], item["service"])
        d = agg.setdefault(key, {"safe_done": 0, "safe_total": 0, "manual": 0})
        if item["classification"] == "enum-safe":
            d["safe_total"] += 1
            if item["status"] == "done":
                d["safe_done"] += 1
        else:
            d["manual"] += 1
    for (host, svc), d in sorted(agg.items(), key=lambda x: -x[1]["manual"]):
        lines.append(f"| {host} | {svc} | {d['safe_done']}/{d['safe_total']} | {d['manual']} |")

    # Top manual leads with commands
    lines.append("\n### Top Manual Leads (ranked)")
    leads = manual_leads(cov, limit=25)
    for n, lead in enumerate(leads, 1):
        note = os.path.join(vault, "Documents/Purple-Teaming", lead["note_path"])
        lines.append(f"\n**{n}. {lead['title'].replace('.md','')}** — `{lead['host']}:{lead['port']}` ({lead['service']}, match {lead['match']:.2f})")
        lines.append(f"- Module: {lead['module']} · Note: `{note}`")
        if lead.get("reason"):
            lines.append(f"- Lead reason: {lead['reason']}")
        cmds = display_commands(lead)
        if cmds:
            lines.append("- Commands from your notes:")
            lines.append("  ```bash")
            for c in cmds[:4]:
                if isinstance(c, dict):
                    text = c.get("text", "").strip()
                    if text:
                        lines.append(f"  # {lead['note_path'].rsplit('/',1)[-1]} :: {c.get('lang','bash')}")
                        lines.append("  " + text.replace("\n", "\n  "))
                else:
                    lines.append(f"  {c}")
            lines.append("  ```")

    # v10.4: web-app probe battery findings + vault manual leads
    pr = state.get("web_probe_results") or []
    if pr:
        hi = [r for r in pr if r["sev"] == "high"]
        med = [r for r in pr if r["sev"] == "med"]
        lines.append(f"\n### Web App Probe Battery ({len(pr)} findings)")
        lines.append(f"\n_Enum-safe vault-driven probes across {len({r['target'] for r in pr})} "
                     f"web surface(s): {len(hi)} high, {len(med)} medium._")
        for r in (hi + med)[:20]:
            lines.append(f"- {'**HIGH**' if r['sev']=='high' else 'med'} `{r['target']}` — {r['finding']}"
                         + (f" _({r['evidence'][:50]})_" if r.get("evidence") else ""))
            if r.get("vault"):
                lines.append(f"  - vault: `{r['vault']}`")
    wl = state.get("web_probe_leads") or []
    if wl:
        lines.append(f"\n### Web App Manual Leads (vault commands)")
        sev_rank = {"high": 0, "med": 1, "low": 2}
        wl_sorted = sorted(wl, key=lambda l: sev_rank.get(l["sev"], 3))
        for n, l in enumerate(wl_sorted[:25], 1):
            lines.append(f"\n**{n}. {l['tech']}** — `{l['target']}` ({l['sev']})")
            lines.append(f"- why: {l['why']} · vault: `{l['vault']}`")
            lines.append("- command:")
            lines.append("  ```bash")
            for ln in l["command"].splitlines():
                lines.append(f"  {ln}")
            lines.append("  ```")

    # Evidence index
    lines.append("\n### Evidence Index")
    ev_dir = state.get("evidence_dir")
    if not ev_dir:
        lines.append("\n_No web evidence captured this session (no web hosts enumerated)._")
    else:
        lines.append(f"\nAll screenshots, headers, HTML bodies, and the aquatone gallery live under:\n`{ev_dir}`")
        pages = state.get("evidence_web", [])
        if pages:
            lines.append("\n| URL | Title | Status | Screenshot |")
            lines.append("|---|---|---|---|")
            for p in pages:
                shot = f"`{p['screenshot']}`" if p.get("screenshot") else "—"
                title = (p.get("title") or "?").replace("|", "\\|")[:40]
                lines.append(f"| {p['url']} | {title} | {p.get('status','?')} | {shot} |")
    return "\n".join(lines)


def _generate_heuristic_report(state: ReconState, summary: str,
                                 vectors: List[AttackVector]) -> str:
    """Generate report without LLM (fallback)."""
    lines = [
        "# StrikeARC Enumeration Report",
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

    # CVE and Exploit Commands section
    cve_findings = [f for f in findings if f.startswith("[CVE]") or f.startswith("[EXPLOIT")]
    if cve_findings:
        lines.append(f"\n## CVE Research & Exploit Commands\n")
        lines.append("### Discovered CVEs\n")
        for f in sorted(set(cve_findings)):
            lines.append(f"- {f}")

    # Credential test results
    cred_findings = [f for f in findings if f.startswith("[CRED]")]
    if cred_findings:
        lines.append(f"\n## Credential Test Results\n")
        valid_creds = [f for f in cred_findings if "VALID CREDENTIAL" in f]
        if valid_creds:
            lines.append("### ✅ Valid Credentials Found!\n")
            for f in valid_creds:
                lines.append(f"- **{f}**")
        failed_creds = [f for f in cred_findings if "✗" in f]
        if failed_creds:
            lines.append("\n### Tested (Failed)\n")
            for f in failed_creds[:20]:
                lines.append(f"- {f}")

    # Exploit commands from CVE research
    exploit_cmd_findings = [f for f in findings if f.startswith("[EXPLOIT-CMD]")]
    if exploit_cmd_findings:
        lines.append(f"\n## Concrete Exploit Commands\n")
        for f in sorted(set(exploit_cmd_findings)):
            lines.append(f"- {f}")

    # Cross-host correlation
    lines.extend(_cross_host_correlation(state))

    # ── Attack Chains (v6) ──────────────────────────────────────────
    if _HAS_CHAINS:
        try:
            chains = chain_mod.compose_chains(
                vectors, state.get("discovered_credentials", []),
                state.get("hosts", {}), state.get("topology", {}),
            )
            if chains:
                lines.append(f"\n## Attack Chains ({len(chains)} identified)\n")
                lines.append("_Multi-step compromise paths chaining individual vectors._\n")
                chain_lines = chain_mod.format_chains_for_report(chains)
                lines.extend(chain_lines)
        except Exception as e:
            lines.append(f"\n<!-- Attack chain composition failed: {e} -->")

    # ── Credential Reuse Map (v6) ───────────────────────────────────
    cred_reuse = [f for f in findings if "[CRED-REUSE]" in f]
    if cred_reuse:
        lines.append(f"\n## Credential Reuse Results\n")
        for f in sorted(set(cred_reuse)):
            lines.append(f"- **{f}**")

    # ── Authenticated Scan Results (v6) ─────────────────────────────
    auth_scan = [f for f in findings if "[AUTH-SCAN]" in f]
    if auth_scan:
        lines.append(f"\n## Authenticated Content Discovery\n")
        lines.append("_Content found behind valid credentials._\n")
        for f in sorted(set(auth_scan)):
            lines.append(f"- {f}")

    return "\n".join(lines)


def _cross_host_correlation(state: ReconState) -> List[str]:
    """Analyze all hosts for shared infrastructure, SSL orgs, and relationships."""
    lines = []
    hosts = state.get("hosts", {})
    if len(hosts) < 2:
        return lines

    # Collect SSL cert orgs/issuers per host
    cert_hosts = {}  # org -> [ips]
    for ip, host in hosts.items():
        cert = host.get("cert_info", {})
        if not cert:
            continue
        for field in ("subject_org", "issuer_org", "subject_ou", "subject_cn"):
            val = cert.get(field, "")
            if val and val != "Unknown":
                cert_hosts.setdefault(val, []).append(ip)

    # Find shared orgs
    shared = {org: ips for org, ips in cert_hosts.items() if len(set(ips)) > 1}
    if shared:
        lines.append("\n## Cross-Host Correlation\n")
        lines.append("### Shared SSL Certificate Organizations\n")
        for org, ips in shared.items():
            unique_ips = sorted(set(ips))
            lines.append(f"- **{org}**: hosts {', '.join(unique_ips)}")
            lines.append(f"  → These hosts likely belong to the same organization/infrastructure")

    # Collect all SSL cert names for vhost suggestions
    all_cert_names = set()
    for ip, host in hosts.items():
        cert = host.get("cert_info", {})
        if cert.get("subject_cn"):
            all_cert_names.add(cert["subject_cn"])
        all_cert_names.update(cert.get("san_list", []))

    if all_cert_names:
        lines.append("\n### Discovered Hostnames (from SSL certs)\n")
        for name in sorted(all_cert_names):
            lines.append(f"- `{name}`")
            lines.append(f"  → Add to /etc/hosts or use for vhost testing")

    # Same-server headers across hosts
    server_hosts = {}
    for ip, host in hosts.items():
        for wa in host.get("web_apps", []):
            server = wa.get("server", "")
            if server:
                server_hosts.setdefault(server, []).append(ip)
    shared_servers = {s: ips for s, ips in server_hosts.items() if len(set(ips)) > 1}
    if shared_servers:
        if not shared:  # Only add header if not already added
            lines.append("\n## Cross-Host Correlation\n")
        lines.append("\n### Shared Web Server Versions\n")
        for server, ips in shared_servers.items():
            lines.append(f"- **{server}**: {', '.join(sorted(set(ips)))}")

    return lines


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


# ═══════════════════════════════════════════════════════════════════════
# POST-EXPLOITATION & PIVOT NODES (v5)
# ═══════════════════════════════════════════════════════════════════════

try:
    import transport as _transport_mod
    _HAS_TRANSPORT = True
except ImportError:
    _HAS_TRANSPORT = False

try:
    import tools.post_exploit as pe
    _HAS_POST_EXPLOIT = True
except ImportError:
    _HAS_POST_EXPLOIT = False


def post_exploit_node(state: ReconState) -> ReconState:
    """Run local enumeration on a compromised host via the transport layer.

    This node executes when a session exists on a compromised host. It:
    1. Creates a transport from the session config
    2. Enumerates local network interfaces, routes, ARP cache
    3. Discovers internal subnets visible from this position
    4. Enumerates system info (users, groups, services, cron jobs)
    5. Searches for credentials left on the system
    6. Identifies privilege escalation vectors
    7. Does a quick ping sweep of newly discovered subnets
    """
    target_ip = state.get("current_target", "")
    print("\n" + "=" * 60)
    print(f"  PHASE: POST-EXPLOIT — {target_ip}")
    print("=" * 60)

    if not _HAS_POST_EXPLOIT:
        print("  [!] post_exploit module not available")
        state["compromised_hosts"][target_ip]["enumerated"] = True
        return {**state, "current_phase": "scope"}

    # Find the session for this host
    sessions = state.get("sessions", [])
    target_sessions = [s for s in sessions if s.get("host_ip") == target_ip]
    if not target_sessions:
        print(f"  [!] No active session for {target_ip}")
        return {**state, "current_phase": "scope"}

    session = target_sessions[0]
    transport_type = session.get("transport_type", "local")

    # Create the transport
    transport = None
    if _HAS_TRANSPORT:
        try:
            mgr = _transport_mod.TransportManager()
            transport = mgr.create_from_session(session)
        except Exception as e:
            print(f"  [!] Failed to create transport: {e}")

    if not transport:
        print(f"  [!] No transport available, using local (fallback)")
        transport = _transport_mod.LocalTransport() if _HAS_TRANSPORT else None

    new_findings = []

    if transport:
        # 1. Local network discovery
        print("  [>] Enumerating local network interfaces...")
        try:
            net_info = pe.enum_local_network(transport)
            interfaces = net_info.get("interfaces", [])
            routes = net_info.get("routes", [])
            arp = net_info.get("arp_cache", [])

            for iface in interfaces:
                new_findings.append(
                    f"[POST-ENUM] {target_ip} interface {iface.get('name','?')}: "
                    f"{iface.get('ip','?')} ({iface.get('mac','?')})"
                )
            for entry in arp[:10]:
                new_findings.append(
                    f"[POST-ENUM] {target_ip} ARP: {entry.get('ip','?')} "
                    f"({entry.get('mac','?')})"
                )

            # Store in compromised host record
            ch = state["compromised_hosts"].get(target_ip, {})
            ch["interfaces"] = interfaces
            ch["os_info"] = {**ch.get("os_info", {}), "routes": routes}
            state["compromised_hosts"][target_ip] = ch

        except Exception as e:
            print(f"  [!] Network enum failed: {e}")

        # 2. Discover internal networks
        print("  [>] Discovering internal networks...")
        try:
            internal_subnets = pe.discover_internal_networks(transport)
            ch = state["compromised_hosts"].get(target_ip, {})
            ch["discovered_subnets"] = internal_subnets
            state["compromised_hosts"][target_ip] = ch

            for subnet in internal_subnets:
                new_findings.append(f"[POST-ENUM] {target_ip} can reach subnet: {subnet}")
                # Add to accessible networks for scope_node to discover
                if subnet not in state["accessible_subnets"]:
                    state["accessible_subnets"].append(subnet)
                    print(f"  [+] New accessible subnet discovered: {subnet}")

            # Update session
            session["discovered_subnets"] = internal_subnets

        except Exception as e:
            print(f"  [!] Internal network discovery failed: {e}")

        # 3. System info
        print("  [>] Enumerating system info...")
        try:
            sysinfo = pe.enum_system_info(transport)
            ch = state["compromised_hosts"].get(target_ip, {})
            ch["os_info"] = {**ch.get("os_info", {}), **sysinfo}
            ch["local_users"] = sysinfo.get("users", [])
            state["compromised_hosts"][target_ip] = ch

            new_findings.append(
                f"[POST-ENUM] {target_ip}: {sysinfo.get('hostname','?')} "
                f"({sysinfo.get('os','?')}) user={sysinfo.get('current_user','?')}"
            )
            if sysinfo.get("users"):
                new_findings.append(
                    f"[POST-ENUM] {target_ip} users: {', '.join(sysinfo['users'][:15])}"
                )
        except Exception as e:
            print(f"  [!] System enum failed: {e}")

        # 4. Credential discovery
        print("  [>] Searching for credentials...")
        try:
            cred_files = pe.enum_credentials(transport)
            ch = state["compromised_hosts"].get(target_ip, {})
            ch["files_of_interest"] = cred_files
            state["compromised_hosts"][target_ip] = ch

            cred_ids = []
            for cf in cred_files:
                cred_id = f"cred_{target_ip}_{len(state.get('all_credentials', []))}"
                state["all_credentials"].append({
                    "id": cred_id,
                    "username": "",
                    "password": None,
                    "hash": None,
                    "hash_type": None,
                    "key_path": None,
                    "source": cf.get("type", "file"),
                    "source_host": target_ip,
                    "validated": False,
                    "validated_against": None,
                    "notes": cf.get("path", ""),
                })
                cred_ids.append(cred_id)
                new_findings.append(
                    f"[POST-ENUM] {target_ip} cred file: "
                    f"{cf.get('type','?')} at {cf.get('path','?')}"
                )
            ch["credentials_found"] = cred_ids

        except Exception as e:
            print(f"  [!] Credential search failed: {e}")

        # 5. Privilege escalation vectors
        print("  [>] Identifying privilege escalation vectors...")
        try:
            privesc = pe.enum_privesc(transport)
            ch = state["compromised_hosts"].get(target_ip, {})

            # Convert to AttackVectors
            sysinfo = ch.get("os_info", {})
            privesc_vectors = pe.generate_privesc_vectors(privesc, sysinfo)
            ch["privesc_vectors"] = privesc_vectors
            state["compromised_hosts"][target_ip] = ch

            # Add high-severity privesc to findings
            for pv in privesc:
                sev = pv.get("severity", "info")
                if sev in ("high", "critical"):
                    new_findings.append(
                        f"[PRIVESC] {target_ip}: {pv.get('detail','?')} ({sev})"
                    )

            # Add vectors to global list
            if privesc_vectors:
                state["attack_vectors"] = state.get("attack_vectors", []) + privesc_vectors

        except Exception as e:
            print(f"  [!] Privesc enum failed: {e}")

        # 6. Local services
        print("  [>] Enumerating local services...")
        try:
            local_svcs = pe.enum_services_local(transport)
            ch = state["compromised_hosts"].get(target_ip, {})
            ch["local_services"] = local_svcs
            state["compromised_hosts"][target_ip] = ch

            for svc in local_svcs[:10]:
                if svc.get("port") and svc.get("port") not in state["hosts"].get(target_ip, {}).get("services", {}):
                    new_findings.append(
                        f"[POST-ENUM] {target_ip} local service: "
                        f"{svc.get('port','?')}/{svc.get('protocol','?')} "
                        f"({svc.get('process','?')})"
                    )
        except Exception as e:
            print(f"  [!] Service enum failed: {e}")

        transport.close()

    # Mark as enumerated
    if target_ip in state.get("compromised_hosts", {}):
        state["compromised_hosts"][target_ip]["enumerated"] = True

    # Merge findings
    state["findings"] = _dedup(new_findings, state["findings"])

    print(f"\n  [+] Post-exploit complete: {len(new_findings)} new findings")
    return {**state, "current_phase": "scope"}


def pivot_node(state: ReconState) -> ReconState:
    """Discover and enumerate hosts in newly discovered internal networks.

    NOT a duplicate of exploit_nodes.pivot_tunnel_node: this node (recon
    graph) discovers+enumerates new subnets found during post-exploit;
    pivot_tunnel_node (strike graph) establishes SOCKS tunnels through
    compromised hosts. Both are intentionally in the workflow.

    This node runs after post_exploit discovers internal subnets. It:
    1. Identifies subnets that are accessible but not yet scanned
    2. Creates a SOCKS transport or uses existing sessions to reach them
    3. Runs ping sweeps through the pivot to find alive hosts
    4. Adds discovered hosts to the hosts dict for normal enumeration
    """
    print("\n" + "=" * 60)
    print(f"  PHASE: PIVOT — Discover internal networks")
    print("=" * 60)

    # Find unscanned subnets that were discovered from compromised hosts
    scanned = state.get("scanned_subnets", [])
    compromised = state.get("compromised_hosts", {})

    pivot_targets = []
    for ip, ch in compromised.items():
        if ch.get("enumerated"):
            for subnet in ch.get("discovered_subnets", []):
                if subnet not in scanned and subnet not in pivot_targets:
                    pivot_targets.append((subnet, ip))

    if not pivot_targets:
        print("  [*] No new internal networks to pivot to.")
        return {**state, "current_phase": "report"}

    new_findings = []

    for subnet, via_host in pivot_targets:
        print(f"\n  [>] Pivoting to {subnet} via {via_host}...")

        # Find a session for the pivot host
        sessions = state.get("sessions", [])
        pivot_sessions = [s for s in sessions if s.get("host_ip") == via_host]
        if not pivot_sessions:
            print(f"  [!] No session on {via_host} for pivot")
            continue

        session = pivot_sessions[0]

        # Create transport and run ping sweep through it
        if _HAS_TRANSPORT and _HAS_POST_EXPLOIT:
            try:
                mgr = _transport_mod.TransportManager()
                transport = mgr.create_from_session(session)

                print(f"  [>] Ping sweeping {subnet} via {via_host}...")
                alive_hosts = pe.enum_pivot_targets(transport, [subnet])
                transport.close()

                for alive_ip in alive_hosts:
                    new_findings.append(
                        f"[PIVOT] {alive_ip} discovered via {via_host} (subnet {subnet})"
                    )

                    # Add topology edge
                    state["topology_edges"].append({
                        "from_host": via_host,
                        "to_host": alive_ip,
                        "edge_type": "discovered",
                        "transport": "pivot",
                        "session_id": session.get("id", ""),
                        "notes": f"Discovered during pivot to {subnet}",
                    })

                    # Add to hosts dict if not present
                    if alive_ip not in state["hosts"]:
                        state["hosts"][alive_ip] = NetworkHost(
                            ip=alive_ip, hostname=None, os="unknown",
                            os_version="", domain=None, services={},
                            web_apps=[], ad_info=None, findings=[],
                            attack_vectors=[], enumerated=False,
                            notes=f"Discovered via pivot from {via_host}",
                        )
                        print(f"  [+] New host: {alive_ip}")

                # Mark subnet as scanned
                if subnet not in scanned:
                    scanned.append(subnet)
                state["scanned_subnets"] = scanned

            except Exception as e:
                print(f"  [!] Pivot to {subnet} failed: {e}")

    state["findings"] = _dedup(new_findings, state["findings"])
    state["pivot_depth"] = state.get("pivot_depth", 0) + 1

    print(f"\n  [+] Pivot complete: {len(new_findings)} new findings")
    return {**state, "current_phase": "scope"}
