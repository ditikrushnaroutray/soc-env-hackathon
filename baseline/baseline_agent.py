"""
baseline_agent.py — Rule-Based SOC Baseline Agent
===================================================
A simple, deterministic security agent that monitors `SOCObservation` state
from the SOC Incident Response Environment and returns a `SOCAction` to isolate
the network whenever a critical security alert is detected.

No LLM required — the agent uses heuristic rules directly on the log data.

Usage:
    python baseline_agent.py               # Runs the built-in test simulation
    python baseline_agent.py --task hard   # Run a specific task (easy|medium|hard)
"""

import sys
import argparse
import requests
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

# ─── Configuration ────────────────────────────────────────────────────────────

BASE_URL = "http://127.0.0.1:8000"

# Status codes that signal malicious activity
CRITICAL_STATUS_CODES = {401, 403, 500}

# User-agent substrings that strongly indicate automated/bot traffic
MALICIOUS_USER_AGENTS = [
    "sqlmap",
    "python-requests",
    "nikto",
    "nmap",
    "masscan",
    "zgrab",
    "curl",
    "wget",
]

# An IP that hits the server this many times with error codes is flagged
ERROR_THRESHOLD = 3

# ─── Decision Engine ──────────────────────────────────────────────────────────

@dataclass
class ThreatSignal:
    """Represents a detected threat from one or more log entries."""
    ip: str
    error_count: int = 0
    bot_agent_hits: int = 0
    error_codes: list = field(default_factory=list)
    severity: str = "low"          # low | medium | critical

    @property
    def score(self) -> int:
        """Higher score → higher threat priority."""
        return self.error_count * 2 + self.bot_agent_hits * 3


def _is_bot_agent(user_agent: str) -> bool:
    """Return True if the User-Agent string matches a known malicious tool."""
    ua_lower = user_agent.lower()
    return any(sig in ua_lower for sig in MALICIOUS_USER_AGENTS)


def analyse_observation(observation: dict) -> list[ThreatSignal]:
    """
    Inspect a SOCObservation dict and return a ranked list of ThreatSignals.

    Detection rules applied (in priority order):
      1. Any IP hitting critical status codes (401 / 403 / 500).
      2. Any IP using a known-malicious User-Agent tool signature.
      3. An IP is promoted to ``critical`` severity when BOTH rules fire
         or its error count exceeds ERROR_THRESHOLD.
    """
    current_logs = observation.get("current_logs", [])
    already_blocked: set[str] = set(observation.get("blocked_ips", []))

    ip_stats: dict[str, ThreatSignal] = defaultdict(lambda: ThreatSignal(ip=""))

    for log in current_logs:
        ip = log.get("source_ip", "")
        status = log.get("status_code", 200)
        ua = log.get("user_agent", "")

        if ip in already_blocked:
            continue  # skip already-handled IPs

        signal = ip_stats[ip]
        signal.ip = ip

        if status in CRITICAL_STATUS_CODES:
            signal.error_count += 1
            signal.error_codes.append(status)

        if _is_bot_agent(ua):
            signal.bot_agent_hits += 1

    # Assign severity labels
    threats: list[ThreatSignal] = []
    for signal in ip_stats.values():
        if signal.error_count == 0 and signal.bot_agent_hits == 0:
            continue  # benign traffic — skip

        if signal.error_count >= ERROR_THRESHOLD or (
            signal.error_count > 0 and signal.bot_agent_hits > 0
        ):
            signal.severity = "critical"
        elif signal.error_count > 0 or signal.bot_agent_hits > 0:
            signal.severity = "medium"

        threats.append(signal)

    # Sort by descending threat score so the worst offender is first
    threats.sort(key=lambda s: s.score, reverse=True)
    return threats


def decide_action(observation: dict) -> Optional[dict]:
    """
    Core policy function.

    Given a SOCObservation, return the best SOCAction payload dict, or
    ``None`` when no actionable threat is found.

    Isolation policy:
      • CRITICAL severity → ``block_ip``  (network isolation)
      • MEDIUM severity   → ``escalate``  (flag for human review)
    """
    threats = analyse_observation(observation)

    if not threats:
        return None

    top = threats[0]  # worst offender

    if top.severity == "critical":
        return {
            "action_type": "block_ip",
            "target_ip": top.ip,
            "reasoning": (
                f"CRITICAL ALERT: IP {top.ip} triggered {top.error_count} "
                f"error-code hit(s) {top.error_codes} and {top.bot_agent_hits} "
                f"bot-agent signature(s). Isolating via firewall block."
            ),
        }

    # Medium-severity → escalate rather than auto-block to avoid false positives
    return {
        "action_type": "escalate",
        "target_ip": top.ip,
        "reasoning": (
            f"MEDIUM ALERT: IP {top.ip} shows suspicious activity "
            f"(errors={top.error_count}, bot-agent hits={top.bot_agent_hits}). "
            f"Escalating to human analyst for verification."
        ),
    }

# ─── Agent Loop ───────────────────────────────────────────────────────────────

def run_agent(task_id: str) -> dict:
    """
    Run the baseline agent against a single task episode.

    Returns a summary dict with session_id, steps, final_score, and outcome.
    """
    divider = "─" * 55

    print(f"\n{divider}")
    print(f"  🛡️  SOC Baseline Agent  │  Task: {task_id.upper()}")
    print(divider)

    # ── Step 1: Reset environment and get initial observation ──────────────
    print("\n📡 [1/4]  Initialising environment …")
    try:
        reset_resp = requests.post(f"{BASE_URL}/reset?task_id={task_id}", timeout=10)
        reset_resp.raise_for_status()
    except requests.exceptions.ConnectionError:
        print("❌  Cannot reach the API server.  Is it running?")
        print(f"    Start it with:  cd api && uvicorn main:app --reload\n")
        sys.exit(1)

    reset_data = reset_resp.json()
    session_id = reset_data["session_id"]
    observation = reset_data["observation"]

    print(f"✅  Session created   → {session_id}")
    print(f"📋  System status     → {observation['system_status']}")
    print(f"📄  Log entries       → {len(observation['current_logs'])}")
    print(f"🔒  Blocked IPs       → {observation['blocked_ips'] or 'none'}")

    # ── Step 2: Analyse observation ─────────────────────────────────────────
    print("\n🔍 [2/4]  Analysing logs …")
    threats = analyse_observation(observation)

    if threats:
        print(f"  Threats detected   : {len(threats)}")
        for t in threats:
            print(
                f"    {'🔴' if t.severity == 'critical' else '🟡'} "
                f"{t.ip:<18}  severity={t.severity:<8}  "
                f"errors={t.error_count}  bot-sigs={t.bot_agent_hits}"
            )
    else:
        print("  ✅ No actionable threats found in current observation.")

    # ── Step 3: Act ─────────────────────────────────────────────────────────
    print("\n⚡ [3/4]  Sending action to environment …")
    action = decide_action(observation)

    if action is None:
        print("  ℹ️  No action taken (environment looks clean).")
        return {"session_id": session_id, "steps": 0, "final_score": 0.0, "outcome": "no_threat"}

    print(f"  Action type  : {action['action_type'].upper()}")
    print(f"  Target IP    : {action['target_ip']}")
    print(f"  Reasoning    : {action['reasoning']}")

    try:
        step_resp = requests.post(
            f"{BASE_URL}/step?session_id={session_id}",
            json=action,
            timeout=10,
        )
        step_resp.raise_for_status()
    except requests.exceptions.RequestException as exc:
        print(f"❌  Step request failed: {exc}")
        sys.exit(1)

    step_data = step_resp.json()
    reward = step_data["reward"]
    done   = step_data["done"]
    info   = step_data["info"]

    # ── Step 4: Report ──────────────────────────────────────────────────────
    print(f"\n📊 [4/4]  Results")
    print(divider)
    print(f"  Reward this step : {reward:+.1f}")
    print(f"  Episode done     : {'Yes ✅' if done else 'No 🔄'}")
    print(f"  Steps taken      : {info['steps_taken']}")
    print(f"  Cumulative score : {info['current_score']:+.1f}")
    print(f"  Server message   : {info['message']}")
    print(divider)

    return {
        "session_id": session_id,
        "steps": info["steps_taken"],
        "final_score": info["current_score"],
        "outcome": "success" if reward > 0 else "failure",
    }

# ─── Test Simulation ──────────────────────────────────────────────────────────

def run_simulation():
    """
    Automatically runs the agent against all three built-in tasks and
    prints a consolidated performance summary.
    """
    tasks = ["task_easy", "task_medium", "task_hard"]
    results = []

    print("\n" + "═" * 55)
    print("  🧪  SOC Baseline Agent — Automated Test Simulation")
    print("═" * 55)
    print(f"  Running {len(tasks)} task(s): {', '.join(tasks)}")

    for task in tasks:
        result = run_agent(task)
        results.append((task, result))

    # ── Consolidated summary ───────────────────────────────────────────────
    print("\n" + "═" * 55)
    print("  📈  SIMULATION SUMMARY")
    print("═" * 55)
    print(f"  {'Task':<15}  {'Outcome':<10}  {'Score':>8}  {'Steps':>6}")
    print(f"  {'─'*15}  {'─'*10}  {'─'*8}  {'─'*6}")

    total_score = 0.0
    for task, r in results:
        icon = "✅" if r["outcome"] == "success" else ("⚠️ " if r["outcome"] == "no_threat" else "❌")
        print(
            f"  {task:<15}  {icon} {r['outcome']:<8}  "
            f"{r['final_score']:>+7.1f}  {r['steps']:>6}"
        )
        total_score += r["final_score"]

    print(f"  {'─'*15}  {'─'*10}  {'─'*8}  {'─'*6}")
    print(f"  {'TOTAL':<15}  {'':10}  {total_score:>+7.1f}")
    print("═" * 55 + "\n")

# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SOC Baseline Agent — monitors SOCObservation and blocks critical threats."
    )
    parser.add_argument(
        "--task",
        choices=["easy", "medium", "hard"],
        default=None,
        help="Run a single task (easy | medium | hard). Omit to run all tasks.",
    )
    args = parser.parse_args()

    if args.task:
        run_agent(f"task_{args.task}")
    else:
        # Default: full test simulation across all tasks
        run_simulation()
