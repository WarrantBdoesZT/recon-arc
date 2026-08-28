#!/usr/bin/env python3
"""
StrikeARC — Advanced Reconnaissance & Attack-path Ranking Console
==================================================================
An LLM-powered enumeration agent for HTB labs and CTF environments.
Scans web and internal networks, identifies attack vectors, and ranks
them by likelihood of success — WITHOUT executing any exploit.

Usage:
    python3 enum_agent.py --subnet 10.10.10.0/24
    python3 enum_agent.py --targets 10.10.10.5 10.10.10.10
    python3 enum_agent.py --subnet 10.10.10.0/24 --no-llm
    python3 enum_agent.py --resume ~/projects/recon-arc/saves/session.json

IMPORTANT: Only use against networks you own or have explicit written permission to test.
"""

import argparse
import os
import sys

# Ensure local imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from langgraph.graph import StateGraph, END

from state import ReconState, initial_state, load_state, save_state, get_engagement_summary
from llm import test_connectivity, print_llm_stats
from utils import detect_listener_ip, run_command
from nodes import (
    scope_node, discover_node, enumerate_node,
    analyze_node, report_node,
)
try:
    from nodes import post_exploit_node, pivot_node
    _HAS_POST_EXPLOIT = True
except ImportError:
    _HAS_POST_EXPLOIT = False


def build_graph():
    """
    Build the cyclic enumeration graph with post-exploitation support.

    scope (hub) → discover → enumerate → analyze → [post_exploit → pivot] → report
    All action nodes return to scope for next routing decision.

    When compromised hosts exist, scope routes to post_exploit which runs
    local enumeration on the compromised host via the transport layer.
    Pivot node discovers new internal networks and adds them to scope.
    """
    workflow = StateGraph(ReconState)

    workflow.add_node("scope", scope_node)
    workflow.add_node("discover", discover_node)
    workflow.add_node("enumerate", enumerate_node)
    workflow.add_node("analyze", analyze_node)
    workflow.add_node("report", report_node)

    if _HAS_POST_EXPLOIT:
        workflow.add_node("post_exploit", post_exploit_node)
        workflow.add_node("pivot", pivot_node)

    workflow.set_entry_point("scope")

    def route_from_scope(state: ReconState) -> str:
        phase = state.get("current_phase", "report")
        valid = {
            "discover": "discover",
            "enumerate": "enumerate",
            "analyze": "analyze",
            "post_exploit": "post_exploit" if _HAS_POST_EXPLOIT else "report",
            "pivot": "pivot" if _HAS_POST_EXPLOIT else "report",
            "report": "report",
            "complete": END,
        }
        return valid.get(phase, "report")

    routes = {
        "discover": "discover",
        "enumerate": "enumerate",
        "analyze": "analyze",
        "report": "report",
        END: END,
    }
    if _HAS_POST_EXPLOIT:
        routes["post_exploit"] = "post_exploit"
        routes["pivot"] = "pivot"

    workflow.add_conditional_edges("scope", route_from_scope, routes)

    for node in ["discover", "enumerate", "analyze"]:
        workflow.add_edge(node, "scope")

    if _HAS_POST_EXPLOIT:
        workflow.add_edge("post_exploit", "scope")
        workflow.add_edge("pivot", "scope")

    workflow.add_edge("report", END)

    return workflow.compile()


def init_tools():
    """Verify required enumeration tools are available."""
    tools = [
        "nmap", "gobuster", "curl", "openssl",
        "searchsploit", "smbclient", "ldapsearch",
    ]
    missing = []
    available = []

    for tool in tools:
        result = run_command(f"which {tool} 2>/dev/null", timeout=5)
        if result["stdout"]:
            available.append(tool)
        else:
            missing.append(tool)

    print(f"[TOOLS] Available: {', '.join(available)}")
    if missing:
        print(f"[TOOLS] Missing (optional): {', '.join(missing)}")

    # Check Python deps
    deps_ok = True
    for dep in ["langchain_openai", "langgraph", "requests"]:
        try:
            __import__(dep)
        except ImportError:
            print(f"[!] Missing Python package: {dep}")
            deps_ok = False

    return missing, deps_ok


def main():
    parser = argparse.ArgumentParser(
        description="StrikeARC — Advanced Reconnaissance & Attack-path Ranking",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
IMPORTANT: Only use against networks you own or have explicit written permission to test.

Examples:
    # Full subnet enumeration
    python3 enum_agent.py --subnet 10.10.10.0/24

    # Specific targets only
    python3 enum_agent.py --targets 10.10.10.5

    # Offline mode (no LLM, heuristic-only)
    python3 enum_agent.py --subnet 10.10.10.0/24 --no-llm

    # With custom wordlist
    python3 enum_agent.py --subnet 10.10.10.0/24 -w /usr/share/wordlists/dirb/big.txt

    # Resume a previous session
    python3 enum_agent.py --resume ~/projects/recon-arc/saves/20240101_120000.json
        """,
    )
    parser.add_argument(
        "--subnet", "-s",
        help="Subnet to scan (CIDR, e.g. 10.10.10.0/24)",
    )
    parser.add_argument(
        "--targets", "-t", nargs="*",
        help="Specific host IPs to enumerate (skips subnet sweep). "
             "e.g. --targets 10.10.10.5 10.10.10.10",
    )
    parser.add_argument(
        "--exclude", nargs="*",
        help="Host IPs to exclude from scanning",
    )
    parser.add_argument(
        "--goals", "-g", nargs="*", default=[],
        help="Engagement goals for context (e.g. 'Capture all flags' 'Domain Admin')",
    )
    parser.add_argument(
        "--max-iterations", "-i", type=int, default=50,
        help="Maximum iterations (default: 50)",
    )
    parser.add_argument(
        "--listener-ip", default=None,
        help="Listener IP (auto-detected from VPN if omitted)",
    )
    parser.add_argument(
        "--vpn-interface", default="tun0",
        help="VPN interface name (default: tun0)",
    )
    parser.add_argument(
        "--wordlist", "-w",
        default="/usr/share/wordlists/dirb/common.txt",
        help="Wordlist for directory busting (default: dirb/common.txt)",
    )
    parser.add_argument(
        "--output-dir", "-o",
        help="Output directory for reports (default: ~/projects/recon-arc/output/)",
    )
    parser.add_argument(
        "--no-llm", action="store_true",
        help="Offline mode: skip LLM calls, use heuristic-only analysis",
    )
    parser.add_argument(
        "--resume", "-r",
        help="Resume from saved state file",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Initialize and print plan without executing",
    )
    parser.add_argument(
        "--test-creds", action="store_true",
        help="Test default credentials against discovered services (splunk, pfsense, ssh, etc.)",
    )
    parser.add_argument(
        "--quick", action="store_true",
        help="Quick mode: port scan + service ID + top CVEs only (2 iterations max)",
    )
    parser.add_argument(
        "--cve-research", action="store_true", default=True,
        help="Search NVD/searchsploit for version-specific CVEs after enumeration (default: on)",
    )
    parser.add_argument(
        "--session-file", metavar="SESSION_JSON",
        help="Load session config (compromised hosts, transports, credentials) from JSON file. "
             "Enables post-exploitation enumeration from compromised positions.",
    )
    parser.add_argument(
        "--post-exploit", action="store_true",
        help="Run post-exploitation enumeration on compromised hosts (requires --session-file or existing sessions)",
    )
    args = parser.parse_args()

    # Preflight — surface missing external tooling before the engagement starts
    try:
        from tools.preflight import preflight_report
        preflight_report(verbose=True)
    except Exception as e:
        print(f"[!] preflight skipped: {e}")

    print("=" * 60)
    print("  StrikeARC — Advanced Reconnaissance &")
    print("             Attack-path Ranking Console")
    print("=" * 60)

    # Resume or new session
    if args.resume:
        print(f"\n[SESSION] Resuming from {args.resume}")
        state = load_state(args.resume)
        print(f"[SESSION] Session: {state['session_id']}")
        print(f"[SESSION] Iteration: {state['iteration']}/{state['max_iterations']}")
    else:
        if not args.subnet and not args.targets:
            parser.error("--subnet or --targets is required for new engagements "
                         "(or use --resume)")

        # Use target IPs to infer subnet if --subnet not given
        subnet = args.subnet
        if not subnet and args.targets:
            first_ip = args.targets[0]
            parts = first_ip.split(".")
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

        # Detect listener IP
        listener_ip = args.listener_ip or detect_listener_ip(args.vpn_interface)

        print(f"\n[SESSION] Starting new enumeration engagement")
        print(f"  Subnet:         {subnet}")
        print(f"  Listener IP:    {listener_ip}")
        print(f"  VPN interface:  {args.vpn_interface}")
        print(f"  Max iterations: {args.max_iterations}")
        print(f"  Wordlist:       {args.wordlist}")
        mode = "OFFLINE (heuristic-only)" if args.no_llm else "LLM-POWERED (GLM-5.2)"
        if args.quick:
            mode += " + QUICK"
        if args.test_creds:
            mode += " + CRED-TEST"
        print(f"  Mode:           {mode}")
        if args.exclude:
            print(f"  Out of scope:   {', '.join(args.exclude)}")

        state = initial_state(
            initial_subnet=subnet,
            listener_ip=listener_ip,
            vpn_interface=args.vpn_interface,
            max_iterations=args.max_iterations,
            wordlist=args.wordlist,
            output_dir=args.output_dir or "",
            out_of_scope=args.exclude,
            no_llm=args.no_llm,
        )
        # Store feature flags in state
        state["test_creds"] = args.test_creds
        state["cve_research"] = args.cve_research
        state["quick_mode"] = args.quick

        # Load session file for post-exploitation (v5)
        if args.session_file:
            import json as _json
            print(f"\n[SESSION] Loading session config from {args.session_file}")
            try:
                with open(os.path.expanduser(args.session_file)) as f:
                    session_data = _json.load(f)

                # Load compromised hosts as sessions
                for sess in session_data.get("sessions", []):
                    state["sessions"].append(sess)
                    # Add topology edge: VPN → compromised host
                    state["topology_edges"].append({
                        "from_host": state["listener_ip"],
                        "to_host": sess["host_ip"],
                        "edge_type": "direct",
                        "transport": sess["transport_type"],
                        "session_id": sess["id"],
                        "notes": "Loaded from session file",
                    })
                    # Mark the host as having post-exploit potential
                    if sess["host_ip"] not in state["compromised_hosts"]:
                        state["compromised_hosts"][sess["host_ip"]] = {
                            "ip": sess["host_ip"],
                            "hostname": None,
                            "sessions": [sess["id"]],
                            "local_users": [],
                            "local_services": [],
                            "interfaces": sess.get("interfaces", []),
                            "discovered_subnets": sess.get("discovered_subnets", []),
                            "credentials_found": [],
                            "privesc_vectors": [],
                            "files_of_interest": [],
                            "os_info": {},
                            "enumerated": False,
                            "notes": f"Loaded via {sess['transport_type']} session",
                        }

                # Load pre-discovered credentials
                for cred in session_data.get("credentials", []):
                    state["all_credentials"].append(cred)

                # Add discovered internal subnets to accessible networks
                for sess in state["sessions"]:
                    for subnet in sess.get("discovered_subnets", []):
                        if subnet not in state["accessible_subnets"]:
                            state["accessible_subnets"].append(subnet)
                            print(f"  [+] Added accessible subnet: {subnet}")

                # Add discovered internal subnets from compromised hosts
                for ip, ch in state["compromised_hosts"].items():
                    for subnet in ch.get("discovered_subnets", []):
                        if subnet not in state["accessible_subnets"]:
                            state["accessible_subnets"].append(subnet)

                print(f"  [+] Loaded {len(state['sessions'])} session(s)")
                print(f"  [+] Loaded {len(state['compromised_hosts'])} compromised host(s)")
                print(f"  [+] Loaded {len(state['all_credentials'])} credential(s)")

                state["session_file"] = args.session_file

            except Exception as e:
                print(f"  [!] Failed to load session file: {e}")

        if args.post_exploit:
            if not state.get("sessions"):
                print("\n[!] --post-exploit requires sessions. Use --session-file to provide them.")
                sys.exit(1)
            # Set phase to start with post-exploitation
            state["current_phase"] = "post_exploit"
            print(f"\n[POST-EXPLOIT] Will enumerate {len(state['sessions'])} compromised host(s)")

        # If --targets specified, pre-seed them
        if args.targets:
            import tools.recon as recon
            from state import NetworkHost
            print(f"\n[INIT] Targeting {len(args.targets)} specific host(s)")
            for ip in args.targets:
                print(f"  [>] Quick scan {ip}...")
                services, os_hint, _ = recon.quick_scan(ip)
                if services:
                    host = NetworkHost(
                        ip=ip, hostname=None, os=os_hint, os_version="",
                        domain=None, services=services,
                        web_apps=[], ad_info=None,
                        findings=[], attack_vectors=[],
                        enumerated=False, notes="",
                    )
                    state["hosts"][ip] = host
                    print(f"  [+] {ip}: {len(services)} services, OS: {os_hint}")
                else:
                    print(f"  [!] {ip}: no services detected")
            # Mark subnet as scanned
            state["scanned_subnets"] = [subnet]

        # Quick mode: limit iterations and skip deep enumeration
        if args.quick:
            state["max_iterations"] = min(state["max_iterations"], 3)
            state["quick_mode"] = True
            print(f"\n[QUICK] Quick mode enabled — limited to {state['max_iterations']} iterations")
            print("[QUICK] Deep web enum, UDP scan, and AD enum will be skipped")

        # Store goals in findings for context
        for goal in args.goals:
            state["findings"].append(f"[GOAL] {goal}")

    # Verify tools
    print("\n[INIT] Checking tools...")
    missing, deps_ok = init_tools()

    if not deps_ok:
        print("\n[!] Missing Python dependencies. Install with:")
        print("    pip install langchain-openai langgraph requests")
        sys.exit(1)

    # LLM connectivity test
    if not args.no_llm:
        print("\n[LLM] Will test on first use (saves 1 API call)")
    else:
        print("\n[LLM] Offline mode — no LLM calls will be made")

    if args.dry_run:
        print("\n[DRY RUN] Would start with:")
        print(f"  Phase: {state['current_phase']}")
        print(f"  Subnet: {state['initial_subnet']}")
        summary = get_engagement_summary(state)
        print(f"\n{summary}")
        return

    # Build and run the graph
    print("\n[GRAPH] Building enumeration graph...")
    app = build_graph()
    print("[GRAPH] Graph compiled")
    print("[GRAPH] Mode: scope → discover → enumerate → analyze → report")

    print(f"\n[ENGAGEMENT] Starting execution (session: {state['session_id']})")
    print("-" * 60)

    try:
        final_state = app.invoke(state, {"recursion_limit": 200})

        print("\n" + "=" * 60)
        print("  ENGAGEMENT COMPLETE")
        print("=" * 60)

        summary = get_engagement_summary(final_state)
        print(f"\n{summary}")

        # Final save
        save_path = save_state(final_state)
        print(f"\n[SESSION] State saved to: {save_path}")

        print_llm_stats()

    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user. Last checkpoint is on disk.")
        print(f"[SESSION] Resume with --resume {state.get('save_path', '')}")
        sys.exit(0)

    except Exception as e:
        print(f"\n[!] Error during execution: {e}")
        import traceback
        traceback.print_exc()
        print(f"[SESSION] Resume with --resume {state.get('save_path', '')}")
        sys.exit(1)


if __name__ == "__main__":
    main()
