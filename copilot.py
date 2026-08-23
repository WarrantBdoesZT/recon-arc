#!/usr/bin/env python3
"""
StrikeARC — Interactive Copilot Mode
=====================================
Human-in-the-loop exploitation. Ported from prolab-agent's interactive
architecture and rebuilt on StrikeARC's own machinery:

  - Recon + enumeration run autonomously (no LLM, no human)
  - At each exploitation decision point the LLM (or heuristics, offline)
    synthesizes findings into ranked attack hypotheses
  - The human picks one (or types a custom command / drops to shell)
  - The agent executes, extracts flags + creds, loops for next decision

The LLM proposes — the human disposes. In copilot mode the LLM never
autonomously decides an attack path; it only ranks options for approval.

Graph shape:

    scope ──→ discover ──→ scope
           ──→ enumerate ──→ scope
           ──→ copilot_checkpoint ──→ scope   (human decision point)
           ──→ report ──→ END

Usage (via strike_agent.py):
    python3 strike_agent.py --interactive --subnet 10.10.110.0/24
    python3 strike_agent.py --interactive --resume saves/session.json
"""

from __future__ import annotations

import os
import re as _re
import shlex
import time
from typing import Dict, List, Optional, Tuple

from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import StateGraph, END

from state import (
    ReconState, save_state, get_engagement_summary,
    get_attack_vectors_by_confidence, FlagEntry,
)
from llm import llm_invoke, parse_llm_json, print_llm_stats
from utils import run_command
from credential_manager import CredentialManager

import tools.flag_hunter as flag_hunter


# ═══════════════════════════════════════════════════════════════════════
# Hypothesis synthesis — LLM (or heuristic fallback)
# ═══════════════════════════════════════════════════════════════════════

def _synthesis_prompt(state: ReconState, target: str, host: dict) -> str:
    """Build the attack-hypothesis prompt from live engagement state."""
    summary = get_engagement_summary(state)

    vectors = []
    seen = set()
    for v in get_attack_vectors_by_confidence(state):
        if v.get("id") in seen:
            continue
        seen.add(v.get("id"))
        vectors.append(v)
    vectors = vectors[:12]

    if vectors:
        vector_lines = "\n".join(
            f"- [{v.get('confidence','?')}/{v.get('score',0)}] {v.get('title','?')} "
            f"({v.get('vector_type','?')}) → {v.get('target','?')}\n"
            f"  evidence: {'; '.join(v.get('evidence', [])[:2])}\n"
            f"  suggested: {'; '.join(v.get('exploit_suggestions', [])[:2])}"
            for v in vectors
        )
    else:
        vector_lines = "(none yet — run more enumeration)"

    creds = CredentialManager(state).summary()
    services = ", ".join(
        f"{s.get('service','?')}/{p}"
        for p, s in sorted(host.get("services", {}).items())
    ) or "none known"

    return f"""You are a senior penetration tester. Based on the current
enumeration state, synthesize up to 4 concrete attack hypotheses for the
human operator. Each must include exact, runnable commands.

TARGET HOST: {target} ({host.get('os', '?')})
SERVICES: {services}

ENGAGEMENT SUMMARY:
{summary}

TOP ATTACK VECTORS (heuristic + LLM ranked):
{vector_lines}

CREDENTIAL DATABASE:
{creds}

Return ONLY a JSON array. Each element:
{{
  "technique": "short name, e.g. 'SSH password reuse (wp-config)'",
  "confidence": "high" | "medium" | "low",
  "reasoning": "1-2 sentences citing evidence",
  "commands": ["exact shell commands", ...]
}}"""


def _synthesize_hypotheses(
    state: ReconState, target: str, host: dict
) -> List[dict]:
    """LLM-synthesized hypotheses with heuristic fallback when offline."""
    fallback = _heuristic_hypotheses(state, target, host)

    if state.get("no_llm"):
        return fallback

    try:
        raw = llm_invoke(
            [
                SystemMessage(content=(
                    "You are an offensive security operator. "
                    "Output only a JSON array — no prose, no markdown fences."
                )),
                HumanMessage(content=_synthesis_prompt(state, target, host)),
            ],
            fast_fail=True,
        )
        hyps = parse_llm_json(raw)
        if isinstance(hyps, list) and hyps:
            cleaned = []
            for h in hyps:
                if isinstance(h, dict) and h.get("commands"):
                    h.setdefault("technique", "unnamed technique")
                    h.setdefault("confidence", "medium")
                    h.setdefault("reasoning", "")
                    cleaned.append(h)
            if cleaned:
                return cleaned
    except Exception as e:
        print(f"  [!] LLM synthesis failed ({e}) — using heuristics")

    return fallback


def _heuristic_hypotheses(
    state: ReconState, target: str, host: dict
) -> List[dict]:
    """Offline: derive hypotheses directly from ranked attack vectors."""
    cm = CredentialManager(state)
    hyps: List[dict] = []

    # 1. Best attack vectors → commands
    seen = set()
    for v in get_attack_vectors_by_confidence(state):
        vid = v.get("id", "")
        if vid in seen or v.get("score", 0) < 40:
            continue
        seen.add(vid)
        cmds = v.get("exploit_suggestions", [])
        if not cmds:
            continue
        hyps.append({
            "technique": v.get("title", "attack vector"),
            "confidence": v.get("confidence", "medium"),
            "reasoning": v.get("description", "")[:200],
            "commands": cmds[:3],
        })
        if len(hyps) >= 3:
            break

    # 2. Untested credentials → spray the best target
    spray_targets = cm.get_spray_targets()
    if spray_targets:
        ip, creds, svc_names = spray_targets[0]
        top = cm.prioritize(creds)[0]
        cmd = None
        if top.get("password"):
            cmd = (
                f"crackmapexec smb {ip} -u '{top['username']}' "
                f"-p '{top['password']}' --continue-on-success"
            )
        elif top.get("hash"):
            cmd = (
                f"crackmapexec smb {ip} -u '{top['username']}' "
                f"-H '{top['hash']}' --continue-on-success"
            )
        if cmd:
            hyps.append({
                "technique": f"Credential spray: {top['username']} → {ip}",
                "confidence": "medium",
                "reasoning": (
                    "Untried credential vs host with auth services "
                    f"({', '.join(svc_names[:3])})"
                ),
                "commands": [cmd],
            })

    # 3. HTTP service → content discovery
    for port, svc in sorted(host.get("services", {}).items()):
        name = (svc.get("service") or "").lower()
        if name in ("http", "https"):
            scheme = "https" if name.endswith("s") else "http"
            hyps.append({
                "technique": f"Web content discovery on :{port}",
                "confidence": "low",
                "reasoning": "HTTP service present; directory brute-force may reveal hidden apps",
                "commands": [
                    f"gobuster dir -u {scheme}://{target}:{port}/ "
                    f"-w {state.get('wordlist', '/usr/share/wordlists/dirb/common.txt')} -t 30"
                ],
            })
            break

    return hyps


# ═══════════════════════════════════════════════════════════════════════
# Copilot graph node
# ═══════════════════════════════════════════════════════════════════════

def copilot_checkpoint_node(state: ReconState) -> ReconState:
    """
    Present ranked hypotheses to the human operator, execute the choice,
    harvest flags/creds from output, and loop back to scope.
    """
    print("\n" + "=" * 60)
    print("  PHASE: COPILOT CHECKPOINT — human decision")
    print("=" * 60)

    state["iteration"] = state.get("iteration", 0) + 1
    if state.get("iteration", 0) >= state.get("max_iterations", 50):
        state["current_phase"] = "report"
        return state

    target, host = _select_target(state)
    if not target:
        print("  [*] No targets left — generating report")
        state["current_phase"] = "report"
        return state

    hypotheses = _synthesize_hypotheses(state, target, host)

    cmds = _human_checkpoint(target, host, hypotheses, state)
    if cmds is None:  # operator chose report/exit
        state["current_phase"] = "report"
        return state

    cm = CredentialManager(state)
    for cmd in cmds:
        cmd = _substitute(cmd, target, host)
        print(f"\n  $ {cmd}")
        result = run_command(cmd, timeout=180)
        out = (result.get("stdout") or "") + "\n" + (result.get("stderr") or "")
        print(_preview(out, 600))
        if result.get("blocked"):
            print("  [!] Command blocked by safety filter")

        _harvest_output(state, cm, out, target)

    # Loop back for the next decision
    state["current_phase"] = "copilot"
    return state


def _select_target(state: ReconState) -> Tuple[Optional[str], Optional[dict]]:
    """Best target: compromised > richest unenumerated > richest any."""
    hosts = state.get("hosts", {})
    if not hosts:
        return None, None

    skipped = set(state.get("_copilot_skip_hosts", []))

    compromised = set(state.get("compromised_hosts", {}).keys())
    compromised |= {s["host_ip"] for s in state.get("sessions", [])}

    for ip in compromised:
        if ip in hosts and ip not in skipped:
            return ip, hosts[ip]

    best = max(
        ((ip, h) for ip, h in hosts.items() if not h.get("enumerated") and ip not in skipped),
        key=lambda kv: len(kv[1].get("services", {})),
        default=(None, None),
    )
    if best[0]:
        return best

    remaining = [(ip, h) for ip, h in hosts.items() if ip not in skipped]
    if not remaining:
        return None, None
    ip = max(remaining, key=lambda kv: len(kv[1].get("services", {})))[0]
    return ip, hosts[ip]


def _substitute(cmd: str, target: str, host: dict) -> str:
    """Expand {TARGET} / {PORT} placeholders in custom commands."""
    port = ""
    services = host.get("services", {})
    if services:
        http_ports = [
            p for p, s in services.items()
            if (s.get("service") or "").lower() in ("http", "https")
        ]
        port = http_ports[0] if http_ports else max(services.keys(), key=int)
    return cmd.replace("{TARGET}", target).replace("{PORT}", str(port))


def _human_checkpoint(
    target: str, host: dict, hypotheses: List[dict], state: ReconState
) -> Optional[List[str]]:
    """
    Present hypotheses and wait for the human. Returns commands to run,
    or None when the operator chooses report/exit. The human ALWAYS has
    the final say.
    """
    auto = state.get("auto_approve", False)
    if auto and hypotheses:
        high = [h for h in hypotheses if h.get("confidence") == "high"]
        if high and high[0].get("commands"):
            print(f"\n  [AUTO] Auto-approving: {high[0].get('technique')} (high confidence)")
            print(f"  [AUTO] $ {high[0]['commands'][0][:100]}")
            return high[0]["commands"]
        print("\n  [AUTO] No high-confidence hypothesis — pausing for human.")

    print(f"\n{'─' * 60}")
    print(f"  🎯 {target} ({host.get('os', '?')}) — {len(hypotheses)} attack hypotheses")
    print(f"{'─' * 60}")

    for i, h in enumerate(hypotheses, 1):
        conf = h.get("confidence", "medium")
        icon = {"high": "🔥", "medium": "⚡", "low": "🔹"}.get(conf, "⚡")
        print(f"\n  [{i}] {icon} {h.get('technique', '?')}  ({conf})")
        if h.get("reasoning"):
            print(f"      {h['reasoning'][:200]}")
        cmds = h.get("commands", [])
        if cmds:
            preview = cmds[0][:100].replace("\n", " ↵ ")
            print(f"      $ {preview}")
            if len(cmds) > 1:
                print(f"      (+ {len(cmds) - 1} more command(s))")

    n_hyp = len(hypotheses)
    custom_idx = n_hyp + 1
    shell_idx = n_hyp + 2
    next_idx = n_hyp + 3
    view_idx = n_hyp + 4
    report_idx = n_hyp + 5

    print(f"\n  [{custom_idx}] ✍️  Custom command")
    print(f"  [{shell_idx}] 🐚  Drop to shell on {target}")
    print(f"  [{next_idx}] ⏭️  Skip to next host")
    print(f"  [{view_idx}] 📋  View engagement state")
    print(f"  [{report_idx}] 📝  Generate report & exit")

    while True:
        try:
            choice = input(f"\n  ▶ Choice [1-{report_idx}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  [!] No interactive stdin — auto-selecting top hypothesis.")
            if hypotheses and hypotheses[0].get("commands"):
                return hypotheses[0]["commands"]
            return None

        if not choice:
            continue
        if choice.isdigit():
            n = int(choice)
            if 1 <= n <= n_hyp:
                cmds = hypotheses[n - 1].get("commands", [])
                if cmds:
                    return cmds
                print("  [!] That hypothesis has no commands. Pick another.")
                continue
            if n == custom_idx:
                return _prompt_custom_command()
            if n == shell_idx:
                _drop_to_shell(target, host, state)
                continue
            if n == next_idx:
                state["_copilot_skip_hosts"] = (
                    state.get("_copilot_skip_hosts", []) + [target]
                )
                return []  # loop back without executing
            if n == view_idx:
                print("\n" + get_engagement_summary(state))
                continue
            if n == report_idx:
                return None
        print(f"  [!] Enter a number 1-{report_idx}")


def _prompt_custom_command() -> List[str]:
    print("\n  ✍️  Enter command(s), one per line. Empty line to finish.")
    print("      Placeholders: {TARGET} {PORT} auto-substituted.")
    cmds = []
    while True:
        try:
            line = input("  $ ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            break
        cmds.append(line)
    return cmds


def _drop_to_shell(target: str, host: dict, state: ReconState):
    """Interactive shell on target: SSH creds → evil-winrm → nc."""
    cm = CredentialManager(state)
    creds = cm.get_validated_for_host(target) or cm.get_validated()
    services = host.get("services", {})

    cred = creds[0] if creds else None
    has_ssh = any(
        (svc.get("service") or "").lower().startswith("ssh") or int(p) == 22
        for p, svc in services.items()
    )

    if cred and cred.get("password") and has_ssh:
        print(f"\n  [SHELL] ssh {cred['username']}@{target} (password auth)")
        os.system(
            f"sshpass -p {shlex.quote(cred['password'])} "
            f"ssh -o StrictHostKeyChecking=no {cred['username']}@{target}"
        )
        return
    if cred and cred.get("password"):
        print(f"\n  [SHELL] evil-winrm -i {target} -u {cred['username']}")
        os.system(
            f"evil-winrm -i {target} "
            f"-u {shlex.quote(cred['username'])} -p {shlex.quote(cred['password'])}"
        )
        return

    if services:
        port = max(services.keys(), key=int)
        print(f"\n  [SHELL] nc {target} {port} (interactive — Ctrl-C to return)")
        os.system(f"timeout 120 nc {target} {port}")
    else:
        print("  [!] No services to connect to")


# ═══════════════════════════════════════════════════════════════════════
# Output harvesting — flags + credentials
# ═══════════════════════════════════════════════════════════════════════

def _scan_flags(output: str) -> List[Tuple[str, str]]:
    """Scan command output for flag patterns (strict set only)."""
    hits = []
    for pat in flag_hunter.FLAG_PATTERNS_STRICT:
        for m in _re.finditer(pat, output):
            hits.append((m.group(0), "command output"))
    return hits


_CRED_PATTERNS = [
    # (compiled regex, username_group, secret_group, source)
    (_re.compile(r"DB_PASSWORD['\"]?\s*[:,=]\s*['\"]?([^\s'\";]+)", _re.I),
     None, 1, "db_config"),
    (_re.compile(r"([A-Za-z0-9_.-]+)[:/]([A-Za-z0-9!@#$%^&*._-]{6,})@",
                 _re.I),
     1, 2, "uri"),
    (_re.compile(r"password(?:\s+is)?\s*[:=]\s*['\"]?(\S{4,})['\"]?", _re.I),
     None, 1, "config"),
]


def _harvest_output(
    state: ReconState, cm: CredentialManager, output: str, target: str
) -> None:
    """Extract flags + credentials from command output into state."""
    # Flags
    seen_vals = {f.get("flag_value") for f in state.get("flags_captured", [])}
    for val, path in _scan_flags(output):
        if val in seen_vals:
            continue
        state["flags_captured"] = state.get("flags_captured", []) + [FlagEntry(
            host_ip=target,
            flag_type=flag_hunter._classify_flag({"path": path}),
            flag_value=val,
            path=path,
            captured_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
            method="copilot_manual_command",
        )]
        state["flags_found_count"] = state.get("flags_found_count", 0) + 1
        print(f"  [FLAG] ✓ {val}")

    # Credentials
    for regex, user_group, secret_group, source in _CRED_PATTERNS:
        for m in regex.finditer(output):
            secret = m.group(secret_group)
            username = m.group(user_group) if user_group else "unknown"
            cm.add_credential(
                username=username, password=secret,
                source=source, source_host=target,
            )


def _preview(text: str, limit: int = 400) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n  ... ({len(text) - limit} more bytes)"


# ═══════════════════════════════════════════════════════════════════════
# Graph builder + entrypoint
# ═══════════════════════════════════════════════════════════════════════

def build_copilot_graph():
    """
    scope → {discover, enumerate, copilot_checkpoint} → scope → report → END

    The scope node (StrikeARC's strategic hub) sets current_phase; this
    router just honors it. The checkpoint node sets current_phase="copilot"
    so the next scope pass routes straight back to the human, while
    discover/enumerate pass through their normal autonomous logic.
    """
    from nodes import (
        scope_node as _scope_node,
        discover_node as _discover_node,
        enumerate_node as _enumerate_node,
        report_node as _report_node,
    )

    workflow = StateGraph(ReconState)

    workflow.add_node("scope", _scope_node)
    workflow.add_node("discover", _discover_node)
    workflow.add_node("enumerate", _enumerate_node)
    workflow.add_node("copilot_checkpoint", copilot_checkpoint_node)
    workflow.add_node("report", _report_node)

    workflow.set_entry_point("scope")

    def route_from_scope(state: ReconState) -> str:
        if state.get("iteration", 0) >= state.get("max_iterations", 50):
            return "report"
        phase = state.get("current_phase", "") or ""
        # All offensive phases route to the human — the LLM proposes,
        # the human disposes. Recon phases stay autonomous.
        if phase in ("copilot", "analyze", "exploit", "privesc",
                     "lateral", "pivot", "pivot_tunnel", "flag_hunt",
                     "post_exploit"):
            return "copilot_checkpoint"
        if phase in ("discover",):
            return "discover"
        if phase in ("enumerate", ""):
            return "enumerate"
        return "report"

    workflow.add_conditional_edges(
        "scope", route_from_scope,
        {
            "discover": "discover",
            "enumerate": "enumerate",
            "copilot_checkpoint": "copilot_checkpoint",
            "report": "report",
            END: END,
        },
    )

    for node in ("discover", "enumerate", "copilot_checkpoint"):
        workflow.add_edge(node, "scope")
    workflow.add_edge("report", END)

    return workflow.compile()


def run_copilot(state: ReconState) -> ReconState:
    """Interactive entrypoint used by strike_agent.py --interactive."""
    app = build_copilot_graph()
    final_state = app.invoke(state, {"recursion_limit": 200})

    print("\n" + "=" * 60)
    print("  COPILOT ENGAGEMENT COMPLETE")
    print("=" * 60)
    print(f"\n{get_engagement_summary(final_state)}")

    flags = final_state.get("flags_captured", [])
    if flags:
        print("\n" + flag_hunter.get_flag_summary(flags))

    path = save_state(final_state)
    print(f"\n[SESSION] State saved to: {path}")
    print_llm_stats()
    return final_state
