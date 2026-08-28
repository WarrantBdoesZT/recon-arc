#!/usr/bin/env python3
"""
StrikeARC — Strike Automation & Routing for Cyber Attack Chains
================================================================
A full kill-chain automation agent for HTB Pro Labs and CTF environments.

RECON → EXPLOIT → PRIVESC → LATERAL → PIVOT → FLAG HUNT

Built on the LangGraph cyclic engine. The scope node (brain) evaluates
the current state each iteration and routes to the highest-priority phase:
discovering hosts, enumerating services, exploiting vulnerabilities,
escalating privileges, moving laterally, establishing tunnels, and
hunting flags.

Usage:
    # Full kill-chain on a subnet
    python3 strike_agent.py --subnet 10.10.110.0/24 --exploit --no-llm

    # Specific targets with exploitation
    python3 strike_agent.py -t 10.10.110.100 --exploit --test-creds

    # Recon only (safe mode — no exploitation)
    python3 strike_agent.py --subnet 10.10.110.0/24 --no-llm

    # Resume a previous engagement
    python3 strike_agent.py --resume ~/projects/recon-arc/saves/session.json

IMPORTANT: Only use against networks you own or have explicit written
permission to test (e.g. HackTheBox Pro Labs).
"""

import argparse
import os
import sys

# Ensure local imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from langgraph.graph import StateGraph, END

from state import (
    ReconState, initial_state, load_state, save_state,
    get_engagement_summary,
)
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

# Import strike nodes (exploitation, privesc, lateral, pivot, flag hunt)
try:
    from nodes.exploit_nodes import (
        exploit_node, privesc_node, lateral_node,
        pivot_tunnel_node, flag_hunt_node,
        strike_scope_router,
    )
    _HAS_STRIKE = True
except ImportError as e:
    print(f"[!] Strike nodes not available: {e}")
    _HAS_STRIKE = False


def build_graph(exploit_mode: bool = False):
    """
    Build the StrikeARC kill-chain graph.

    RECON MODE (exploit_mode=False):
        scope → discover → enumerate → analyze → report

    STRIKE MODE (exploit_mode=True):
        scope → discover → enumerate → exploit → privesc →
                lateral → pivot_tunnel → flag_hunt → analyze → report

    The scope node uses strike_scope_router to decide which phase to enter.
    """
    workflow = StateGraph(ReconState)

    # Core nodes (always present)
    workflow.add_node("scope", scope_node)
    workflow.add_node("discover", discover_node)
    workflow.add_node("enumerate", enumerate_node)
    workflow.add_node("analyze", analyze_node)
    workflow.add_node("report", report_node)

    # Post-exploit nodes (v5)
    if _HAS_POST_EXPLOIT:
        workflow.add_node("post_exploit", post_exploit_node)
        workflow.add_node("pivot", pivot_node)

    # Strike nodes (v7 — exploitation, privesc, lateral, flag hunting)
    if exploit_mode and _HAS_STRIKE:
        workflow.add_node("exploit", exploit_node)
        workflow.add_node("privesc", privesc_node)
        workflow.add_node("lateral", lateral_node)
        workflow.add_node("pivot_tunnel", pivot_tunnel_node)
        workflow.add_node("flag_hunt", flag_hunt_node)

    workflow.set_entry_point("scope")

    # ── Routing from scope ────────────────────────────────────────────
    def route_from_scope(state: ReconState) -> str:
        # Check termination first
        if state.get("iteration", 0) >= state.get("max_iterations", 50):
            return "report"

        phase = state.get("current_phase", "") or state.get("kill_chain_phase", "")

        # Use enhanced router in strike mode
        if exploit_mode and _HAS_STRIKE:
            # Let the scope_node set current_phase, then route
            # The scope_node has already run and set the phase
            route = strike_scope_router(state)
            if route:
                return route

        # Standard routing
        valid = {
            "discover": "discover",
            "enumerate": "enumerate",
            "analyze": "analyze",
            "exploit": "exploit" if _HAS_STRIKE else "analyze",
            "privesc": "privesc" if _HAS_STRIKE else "analyze",
            "lateral": "lateral" if _HAS_STRIKE else "analyze",
            "pivot_tunnel": "pivot_tunnel" if _HAS_STRIKE else "report",
            "flag_hunt": "flag_hunt" if _HAS_STRIKE else "report",
            "post_exploit": "post_exploit" if _HAS_POST_EXPLOIT else "report",
            "pivot": "pivot" if _HAS_POST_EXPLOIT else "report",
            "report": "report",
            "complete": END,
            "": "report",  # fallback
        }
        return valid.get(phase, "report")

    # Build route mapping for conditional edges
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
    if exploit_mode and _HAS_STRIKE:
        routes["exploit"] = "exploit"
        routes["privesc"] = "privesc"
        routes["lateral"] = "lateral"
        routes["pivot_tunnel"] = "pivot_tunnel"
        routes["flag_hunt"] = "flag_hunt"

    workflow.add_conditional_edges("scope", route_from_scope, routes)

    # All action nodes return to scope for next routing decision
    for node in ["discover", "enumerate", "analyze"]:
        workflow.add_edge(node, "scope")

    if _HAS_POST_EXPLOIT:
        workflow.add_edge("post_exploit", "scope")
        workflow.add_edge("pivot", "scope")

    if exploit_mode and _HAS_STRIKE:
        for node in ["exploit", "privesc", "lateral", "pivot_tunnel", "flag_hunt"]:
            workflow.add_edge(node, "scope")

    workflow.add_edge("report", END)

    return workflow.compile()


def init_tools():
    """Verify required tools are available."""
    recon_tools = ["nmap", "gobuster", "openssl", "searchsploit", "smbclient", "ldapsearch"]
    strike_tools = ["sshpass", "crackmapexec", "proxychains", "curl", "nc"]

    available = []
    missing = []

    for tool in recon_tools + strike_tools:
        result = run_command(f"which {tool} 2>/dev/null", timeout=5)
        if result["stdout"]:
            available.append(tool)
        else:
            missing.append(tool)

    print(f"[TOOLS] Available: {', '.join(available)}")
    if missing:
        print(f"[TOOLS] Missing: {', '.join(missing)}")

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
        description="StrikeARC — Kill-Chain Automation for HTB Labs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Full kill-chain with exploitation
    python3 strike_agent.py --subnet 10.10.110.0/24 --exploit --no-llm

    # Specific targets
    python3 strike_agent.py -t 10.10.110.100 --exploit --test-creds

    # Recon only (no exploitation)
    python3 strike_agent.py --subnet 10.10.110.0/24 --no-llm

    # With LLM-powered decision making
    python3 strike_agent.py --subnet 10.10.110.0/24 --exploit

    # Resume a previous session
    python3 strike_agent.py --resume ~/projects/recon-arc/saves/session.json
        """,
    )
    parser.add_argument("--subnet", "-s", help="Subnet to scan (CIDR)")
    parser.add_argument("--targets", "-t", nargs="*", help="Specific host IPs")
    parser.add_argument(
        "--sweep", action="store_true",
        help="With --targets: also sweep the derived /24 for additional hosts "
             "(finds pivot/dual-homed neighbors the single target can't see)",
    )
    parser.add_argument("--exclude", nargs="*", help="Host IPs to exclude")
    parser.add_argument("--goals", "-g", nargs="*", default=[], help="Engagement goals")
    parser.add_argument("--max-iterations", "-i", type=int, default=50, help="Max iterations (default: 50)")
    parser.add_argument("--listener-ip", default=None, help="Listener IP (auto-detected)")
    parser.add_argument("--vpn-interface", default="tun0", help="VPN interface (default: tun0)")
    parser.add_argument("--wordlist", "-w", default="/usr/share/wordlists/dirb/common.txt")
    parser.add_argument("--output-dir", "-o")
    parser.add_argument("--no-llm", action="store_true", help="Offline mode (no LLM)")
    parser.add_argument("--resume", "-r", help="Resume from saved state")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--test-creds", action="store_true", help="Test default credentials")
    parser.add_argument("--quick", action="store_true", help="Quick mode")
    parser.add_argument("--cve-research", action="store_true", default=True, help="Search for CVEs")
    parser.add_argument(
        "--exploit", action="store_true",
        help="Enable exploitation mode (full kill-chain: exploit → privesc → lateral → flag hunt)",
    )
    parser.add_argument(
        "--interactive", "--copilot", action="store_true",
        help="Interactive copilot mode: recon runs autonomously, exploitation decisions go to the human",
    )
    parser.add_argument(
        "--auto-approve", action="store_true",
        help="Copilot mode: auto-approve high-confidence hypotheses (still pauses on medium/low)",
    )
    parser.add_argument(
        "--exploit-threshold", type=int, default=70,
        help="Minimum attack vector score to auto-exploit (default: 70)",
    )
    parser.add_argument("--session-file", metavar="JSON", help="Load session config")
    parser.add_argument("--post-exploit", action="store_true", help="Run post-exploit enum")
    args = parser.parse_args()

    # Preflight — surface missing external tooling before the engagement starts
    try:
        from tools.preflight import preflight_report
        preflight_report(verbose=True)
    except Exception as e:
        print(f"[!] preflight skipped: {e}")

    print("=" * 60)
    if args.exploit:
        print("  StrikeARC — Kill-Chain Automation")
        print("             RECON → EXPLOIT → PRIVESC → LATERAL → FLAG")
    else:
        print("  StrikeARC — Reconnaissance & Attack-path Ranking")
    print("=" * 60)

    # Resume or new session
    if args.resume:
        print(f"\n[SESSION] Resuming from {args.resume}")
        state = load_state(args.resume)
    else:
        if not args.subnet and not args.targets:
            parser.error("--subnet or --targets required (or use --resume)")

        subnet = args.subnet
        if not subnet and args.targets:
            parts = args.targets[0].split(".")
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

        listener_ip = args.listener_ip or detect_listener_ip(args.vpn_interface)

        print(f"\n[SESSION] Starting new {'strike' if args.exploit else 'recon'} engagement")
        print(f"  Subnet:         {subnet}")
        print(f"  Listener IP:    {listener_ip}")
        print(f"  VPN interface:  {args.vpn_interface}")
        print(f"  Max iterations: {args.max_iterations}")
        mode = "OFFLINE" if args.no_llm else "LLM-POWERED"
        if args.exploit:
            mode += " + STRIKE"
        if args.quick:
            mode += " + QUICK"
        if args.test_creds:
            mode += " + CRED-TEST"
        print(f"  Mode:           {mode}")

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
        state["test_creds"] = args.test_creds
        state["cve_research"] = args.cve_research
        state["quick_mode"] = args.quick
        state["exploit_threshold"] = args.exploit_threshold
        if args.interactive:
            state["auto_approve"] = args.auto_approve

        # Load session file
        if args.session_file:
            import json as _json
            print(f"\n[SESSION] Loading session config from {args.session_file}")
            try:
                with open(os.path.expanduser(args.session_file)) as f:
                    session_data = _json.load(f)
                for sess in session_data.get("sessions", []):
                    state["sessions"].append(sess)
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
                            "notes": "",
                        }
                for cred in session_data.get("credentials", []):
                    state["all_credentials"].append(cred)
                print(f"  [+] Loaded {len(state['sessions'])} session(s)")
            except Exception as e:
                print(f"  [!] Failed to load session file: {e}")

        if args.post_exploit and not state.get("sessions"):
            print("\n[!] --post-exploit requires sessions. Use --session-file.")
            sys.exit(1)

        # Pre-seed targets
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
                    print(f"  [!] {ip}: no services detected (may need sudo for SYN scan)")
            state["scanned_subnets"] = [subnet] if not args.sweep else []

            if args.sweep:
                print("  [SWEEP] Subnet left unscanned — discovery will sweep "
                      f"{subnet} for additional hosts (pivot/neighbor discovery)")

        if args.quick:
            state["max_iterations"] = min(state["max_iterations"], 3)
            state["quick_mode"] = True
            print(f"\n[QUICK] Limited to {state['max_iterations']} iterations")

        for goal in args.goals:
            state["findings"].append(f"[GOAL] {goal}")

    # Verify tools
    print("\n[INIT] Checking tools...")
    missing, deps_ok = init_tools()
    if not deps_ok:
        print("\n[!] Missing Python dependencies.")
        sys.exit(1)

    if args.no_llm:
        print("\n[LLM] Offline mode — no LLM calls")
    else:
        print("\n[LLM] Will test on first use")

    if args.dry_run:
        print("\n[DRY RUN] Plan:")
        print(f"  Mode: {'STRIKE' if args.exploit else 'RECON'}")
        print(f"  Phase: {state.get('current_phase', 'discover')}")
        summary = get_engagement_summary(state)
        print(f"\n{summary}")
        return

    # Build and run the graph
    if args.interactive:
        print("\n[GRAPH] Building copilot graph...")
        try:
            from copilot import run_copilot
        except ImportError as e:
            print(f"[!] Copilot module unavailable: {e}")
            sys.exit(1)
        print("[GRAPH] Nodes: scope → discover → enumerate → copilot_checkpoint → report")
        print(f"\n[ENGAGEMENT] Starting copilot session (session: {state['session_id']})")
        print("-" * 60)
        try:
            run_copilot(state)
        except KeyboardInterrupt:
            print("\n\n[!] Interrupted by user.")
            print(f"[SESSION] Resume with --interactive --resume {state.get('save_path', '')}")
            sys.exit(0)
        return

    print("\n[GRAPH] Building kill-chain graph...")
    app = build_graph(exploit_mode=args.exploit)
    print(f"[GRAPH] Graph compiled — {'STRIKE' if args.exploit else 'RECON'} mode")
    if args.exploit and _HAS_STRIKE:
        print("[GRAPH] Nodes: scope → discover → enumerate → exploit → privesc → lateral → pivot → flag_hunt → report")
    else:
        print("[GRAPH] Nodes: scope → discover → enumerate → analyze → report")

    print(f"\n[ENGAGEMENT] Starting execution (session: {state['session_id']})")
    print("-" * 60)

    try:
        final_state = app.invoke(state, {"recursion_limit": 200})

        print("\n" + "=" * 60)
        print("  ENGAGEMENT COMPLETE")
        print("=" * 60)

        summary = get_engagement_summary(final_state)
        print(f"\n{summary}")

        # Print flag summary if any captured
        flags = final_state.get("flags_captured", [])
        if flags:
            try:
                import tools.flag_hunter as fh
                flag_summary = fh.get_flag_summary(flags)
                print(f"\n{'=' * 40}")
                print(flag_summary)
                print(f"{'=' * 40}")
            except ImportError:
                print(f"\n[FLAGS] {len(flags)} flag(s) captured")

        save_path = save_state(final_state)
        print(f"\n[SESSION] State saved to: {save_path}")
        print_llm_stats()

    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user.")
        print(f"[SESSION] Resume with --resume {state.get('save_path', '')}")
        sys.exit(0)

    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        print(f"[SESSION] Resume with --resume {state.get('save_path', '')}")
        sys.exit(1)


if __name__ == "__main__":
    main()
