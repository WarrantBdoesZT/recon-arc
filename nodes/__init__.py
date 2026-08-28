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
            if "http" not in svc_name and "ssl" not in svc_name:
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
        if "ssl" in svc["service"].lower() or "https" in svc["service"].lower() or port == 443:
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
        if "http" in svc_name or "ssl" in svc_name or "https" in svc_name:
            _enumerate_web(state, host, target, port, svc, new_findings)

    # Nuclei scan on web services
    for port, svc in host["services"].items():
        svc_name = svc["service"].lower()
        if "http" in svc_name or "ssl" in svc_name or "https" in svc_name:
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
    if port == 80 or port == 443:
        print(f"  [>] Vhost brute-forcing {target}...")
        # Use cert-derived domains + globally discovered domains for targeted vhost brute
        vhost_domains = list(host.get("_cert_domains", []))
        # Also pull domains discovered from other hosts' SSL certs
        global_domains = state.get("_discovered_domains", set())
        vhost_domains.extend(global_domains - set(vhost_domains))
        vhosts = web.vhost_bruteforce(target, extra_domains=vhost_domains[:10])
        for vh in vhosts:
            new_findings.append(f"[ENUM] {target}: Vhost discovered: {vh}")

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
                    new_findings.append(f"[FTP] Contents of {fname}:")
                    # Scan for flags
                    import re as _re
                    for pattern in [r'DANTE\{[^}]+\}', r'FLAG\{[^}]+\}', r'HTB\{[^}]+\}']:
                        flags = _re.findall(pattern, content)
                        for flag in flags:
                            new_findings.append(f"[FLAG] 🚩 {flag} (from FTP: {fname})")
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
                    if "http" in svc_name or "ssl" in svc_name or port in (80, 443, 8080, 8443):
                        scheme = "https" if ("ssl" in svc_name or "https" in svc_name or port == 443) else "http"
                        url = f"{scheme}://{ip}:{port}"
                        try:
                            import requests as _req
                            r = _req.get(url, auth=(username, password),
                                        timeout=5, verify=False, allow_redirects=False)
                            if r.status_code == 200:
                                findings.append(
                                    f"[CRED-REUSE] ✓ {username}:{password} works on {url} "
                                    f"(HTTP 200 — reused from {src_ip})"
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
            if "http" in svc_name or "ssl" in svc_name or port in (80, 443):
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
    # Merged view: global + per-host vectors (per-host is all that exists
    # before the first analyze run or when resuming from a save)
    _merged_vecs = list(state.get("attack_vectors", []))
    for _h in state["hosts"].values():
        _merged_vecs.extend(_h.get("attack_vectors", []))
    unexploited = [
        v for v in _merged_vecs
        if v.get("score", 0) >= threshold and v.get("id") not in attempted_ids
    ]
    if unexploited:
        best = max(unexploited, key=lambda v: v.get("score", 0))
        print(f"\n  → ACTION: Exploit {best.get('target', '?')} — {best.get('title', '?')} (score: {best.get('score', 0)})")
        return {**state, "current_phase": "exploit"}

    # Priority 3.3: Flag hunt on compromised hosts (StrikeARC)
    session_hosts = {s["host_ip"] for s in state.get("sessions", [])}
    checked_hosts = {f["host_ip"] for f in state.get("flags_captured", [])}
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

    if state.get("stall_count", 0) >= 1:
        # Check if there are any remaining unexploited vectors below the
        # current threshold before giving up entirely
        attempted_ids = {a.get("vector_id", "") for a in state.get("exploit_attempts", [])}
        _merged_vecs = list(state.get("attack_vectors", []))
        for _h in state["hosts"].values():
            _merged_vecs.extend(_h.get("attack_vectors", []))
        remaining = [
            v for v in _merged_vecs
            if v.get("id") not in attempted_ids
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
