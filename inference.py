#!/usr/bin/env python3
"""
Multi-Agent heuristic inference for SOC Analyst Environment.

Phase 3 — Lightweight Multi-Agent Team
────────────────────────────────────────
Two cooperating agents process observations in a pipeline:

  Agent 1 (Tier-1 Triage):
    Scans current_logs, classifies every IP as BENIGN, SUSPICIOUS,
    or MALICIOUS using heuristic rules (status codes, user-agents,
    request paths, known scanner signatures).  Outputs a filtered
    list of threat candidates.

  Agent 2 (Incident Responder):
    Receives the filtered candidates from Agent 1, identifies the
    likely MITRE ATT&CK stage from request-path patterns, and
    decides the action (block_ip / allow_ip / escalate) plus
    priority ordering so the most critical IP is handled first.

The __main__ loop drives the /reset → /step cycle, feeding
observations through both agents until done=True.

Structured stdout: [START], [STEP], [END] in exact autograder format.
"""

import os
import sys
import json
import time
import re
import traceback
import urllib.parse
import requests

# ═══════════════════════════════════════════════════════════════════
# 1. ENVIRONMENT VARIABLES
# ═══════════════════════════════════════════════════════════════════
API_KEY = os.environ.get("API_KEY")
API_BASE_URL = os.environ.get("API_BASE_URL")
MODEL_NAME = os.environ.get("MODEL_NAME", "multi-agent-heuristic")
ENV_URL = os.environ.get("ENV_URL") or "http://localhost:7860"

MIN_SCORE = 0.001
MAX_SCORE = 0.999
MAX_STEPS = 10

# ── Episodic Tracker ──────────────────────────────────────────────
EPISODIC_IP_LEDGER = {}


# ═══════════════════════════════════════════════════════════════════
# 2. STRUCTURED LOGGING HELPERS
# ═══════════════════════════════════════════════════════════════════

def log_start(task_id: str, env: str, model: str) -> None:
    """Print [START] line. MUST be the first output for each task."""
    print(f"[START] task={task_id} env={env} model={model}", flush=True)


def log_step(step: int, action_str: str, reward: float, done: bool, error: str = None) -> None:
    """Print [STEP] line with exact formatting."""
    error_val = error if error else "null"
    done_val = str(done).lower()
    print(
        f"[STEP] step={step} action={action_str} reward={reward:.2f} done={done_val} error={error_val}",
        flush=True,
    )


def log_end(task_id: str, success: bool, steps: int, score: float, rewards: list) -> None:
    """
    Print [END] line with exact formatting.

    - success as lowercase true/false
    - score as .3f
    - rewards as comma-separated .2f with NO SPACES
    """
    success_val = str(success).lower()

    if not rewards:
        rewards = [MIN_SCORE]

    clamped_rewards = [max(MIN_SCORE, min(MAX_SCORE, float(r))) for r in rewards]
    rewards_str = ",".join(f"{r:.2f}" for r in clamped_rewards)

    # Final score clamp
    clamped_score = max(MIN_SCORE, min(MAX_SCORE, float(score)))

    print(
        f"[END] task={task_id} success={success_val} steps={steps} score={clamped_score:.3f} rewards={rewards_str}",
        flush=True,
    )


# ═══════════════════════════════════════════════════════════════════
# 3. AGENT 1 — TIER-1 TRIAGE
# ═══════════════════════════════════════════════════════════════════

# Known benign signatures — never block these.
_BENIGN_SUBNETS = ("192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                   "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                   "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                   "172.30.", "172.31.")

_BENIGN_USER_AGENTS = {
    "InternalMonitor",   # internal health checker
    "Nessus",            # authorised vulnerability scanner
}

_BENIGN_PATHS = frozenset({
    "/", "/health", "/metrics", "/favicon.ico",
    "/api/v1/health", "/api/v1/dashboard", "/api/v1/products",
    "/api/v1/settings", "/api/v1/notifications", "/api/v1/cart",
    "/api/v1/reports", "/images/hero.png", "/images/logo.png",
    "/static/css/style.css",
})

# Suspicious request-path patterns (regex).
_SUSPICIOUS_PATH_PATTERNS = [
    re.compile(r"(union|select|drop|insert|delete)\b", re.IGNORECASE),   # SQLi
    re.compile(r"['\";].*--"),                                            # SQLi
    re.compile(r"/debug/exec", re.IGNORECASE),                           # RCE
    re.compile(r"\bcmd=", re.IGNORECASE),                                # RCE
    re.compile(r"/uploads?/.*\.(php|jsp|asp)", re.IGNORECASE),           # Webshell
    re.compile(r"/admin", re.IGNORECASE),                                # Admin probe
    re.compile(r"/wp-admin", re.IGNORECASE),                             # WP probe
    re.compile(r"\.env$", re.IGNORECASE),                                # Env leak
    re.compile(r"/webhook/outbound", re.IGNORECASE),                     # Exfil
    re.compile(r"action=create.*role=admin", re.IGNORECASE),             # Backdoor
    re.compile(r"export=csv|dump\?tables=|show=secrets", re.IGNORECASE), # Data harvest
    re.compile(r"/(sitemap\.xml|robots\.txt|\.well-known/)", re.IGNORECASE),  # Recon
    re.compile(r"privesc|/shell\.", re.IGNORECASE),                      # Priv esc / shell
]

# Suspicious user-agent patterns.
_SUSPICIOUS_UA_PATTERNS = [
    re.compile(r"python-requests", re.IGNORECASE),
    re.compile(r"curl/", re.IGNORECASE),
    re.compile(r"sqlmap", re.IGNORECASE),
    re.compile(r"Googlebot.*compatible", re.IGNORECASE),  # Spoofed Googlebot
]


def _is_benign_user_agent(ua: str) -> bool:
    """Check if user-agent belongs to a known benign internal service."""
    for sig in _BENIGN_USER_AGENTS:
        if sig in ua:
            return True
    return False


def _is_internal_ip(ip: str) -> bool:
    """Check if IP is in a known internal/private range."""
    return any(ip.startswith(prefix) for prefix in _BENIGN_SUBNETS) or ip.startswith("10.")


def tier1_triage(logs: list, blocked_ips: list) -> list:
    """
    Agent 1: Tier-1 Triage.

    Scans all logs and produces a list of IP assessments:
    [
        {
            "ip": "x.x.x.x",
            "verdict": "MALICIOUS" | "SUSPICIOUS" | "BENIGN",
            "reasons": ["..."],
            "score": float,   # threat score 0..1
            "log_count": int,
            "stages_detected": [...],
        },
        ...
    ]

    IPs already blocked are excluded.
    """
    # ── Zero-Trust Field Stripping ────────────────────────────────
    # Explicitly sanitize logs so the agent cannot cheat by reading
    # hidden generator metadata (like attack_stage).
    sanitized_logs = []
    for raw_log in logs:
        sanitized_logs.append({
            "source_ip": raw_log.get("source_ip", ""),
            "request_path": raw_log.get("request_path", "/"),
            "status_code": raw_log.get("status_code", 200),
            "user_agent": raw_log.get("user_agent", ""),
        })

    ip_data = {}

    for log in sanitized_logs:
        ip = log.get("source_ip", "")
        if not ip or ip in blocked_ips:
            continue

        global EPISODIC_IP_LEDGER
        EPISODIC_IP_LEDGER[ip] = EPISODIC_IP_LEDGER.get(ip, 0) + 1

        if ip not in ip_data:
            ip_data[ip] = {
                "ip": ip,
                "reasons": [],
                "score": 0.0,
                "log_count": 0,
                "status_codes": [],
                "paths": [],
                "user_agents": set(),
                "path_flags": [],
            }

        entry = ip_data[ip]
        entry["log_count"] += 1
        entry["status_codes"].append(log.get("status_code", 200))
        entry["paths"].append(log.get("request_path", "/"))
        entry["user_agents"].add(log.get("user_agent", ""))

    # ── Score each IP ─────────────────────────────────────────────
    results = []

    for ip, data in ip_data.items():
        score = 0.0
        reasons = []

        ua_str = " | ".join(data["user_agents"])

        # Rule 1: Known benign internal service — BUT only if paths
        # are ALL innocuous.  A compromised internal host may masquerade
        # with a legit UA while hitting admin/exfil endpoints.
        if _is_benign_user_agent(ua_str) and _is_internal_ip(ip):
            has_suspicious_path = False
            for path in data["paths"]:
                decoded_path = urllib.parse.unquote(path)
                for pattern in _SUSPICIOUS_PATH_PATTERNS:
                    if pattern.search(decoded_path):
                        has_suspicious_path = True
                        break
                if has_suspicious_path:
                    break

            if not has_suspicious_path:
                data["verdict"] = "BENIGN"
                data["reasons"] = ["Known internal service/scanner"]
                data["score"] = 0.0
                results.append(data)
                continue
            # else: fall through to full scoring — paths are suspicious

        # Rule 2: Status code analysis
        bad_statuses = [s for s in data["status_codes"] if s >= 400]
        if bad_statuses:
            score += 0.3
            reasons.append(f"{len(bad_statuses)}x status>={min(bad_statuses)}")

        # Rule 3: Suspicious user-agent
        for pattern in _SUSPICIOUS_UA_PATTERNS:
            if pattern.search(ua_str):
                score += 0.15
                reasons.append(f"Suspicious UA: {pattern.pattern}")
                break

        # Rule 4: Suspicious request paths
        for path in data["paths"]:
            decoded_path = urllib.parse.unquote(path)
            for pattern in _SUSPICIOUS_PATH_PATTERNS:
                if pattern.search(decoded_path):
                    score += 0.2
                    reasons.append(f"Suspicious path: {path[:60]}")
                    data["path_flags"].append(pattern.pattern)
                    break  # one flag per path

        # Rule 5: Volume — many requests from a single IP
        global_count = EPISODIC_IP_LEDGER.get(ip, data["log_count"])
        if global_count > 3:
            score += 0.5
            reasons.append(f"High volume: {global_count} requests")

        # Rule 6: External IP bonus (non-internal IPs are riskier)
        if not _is_internal_ip(ip):
            score += 0.1
            reasons.append("External IP")

        # Rule 7: Only benign-looking paths
        all_benign_paths = all(p in _BENIGN_PATHS for p in data["paths"])
        if all_benign_paths and not bad_statuses:
            score = max(score - 0.5, 0.0)

        # Clamp score
        score = min(score, 1.0)

        # Verdict
        if score >= 0.4:
            verdict = "MALICIOUS"
        elif score >= 0.15:
            verdict = "SUSPICIOUS"
        else:
            verdict = "BENIGN"

        data["verdict"] = verdict
        data["reasons"] = reasons
        data["score"] = score
        results.append(data)

    # Sort by score descending (most dangerous first)
    results.sort(key=lambda x: x["score"], reverse=True)
    return results


# ═══════════════════════════════════════════════════════════════════
# 4. AGENT 2 — INCIDENT RESPONDER
# ═══════════════════════════════════════════════════════════════════

# MITRE stage detection patterns (ordered by kill-chain severity).
_STAGE_PATTERNS = [
    ("exfiltration",         re.compile(r"webhook/outbound|dest=.*size=", re.IGNORECASE)),
    ("collection",           re.compile(r"export=csv|dump\?tables=|show=secrets", re.IGNORECASE)),
    ("defense_evasion",      re.compile(r"cmd=(rm|history|del)\b|/admin/config$", re.IGNORECASE)),
    ("privilege_escalation", re.compile(r"privesc|cmd=(id|sudo)\b", re.IGNORECASE)),
    ("persistence",          re.compile(r"shell\.(php|jsp|asp)|action=create.*role=admin|/upload$", re.IGNORECASE)),
    ("execution",            re.compile(r"/debug/exec\?cmd=", re.IGNORECASE)),
    ("initial_access",       re.compile(r"/api/v\d+/login", re.IGNORECASE)),
    ("reconnaissance",       re.compile(r"robots\.txt|sitemap\.xml|security\.txt|Googlebot", re.IGNORECASE)),
]


def _detect_stages(paths: list, user_agents: set) -> list:
    """Detect MITRE kill-chain stages from request paths and UAs."""
    stages = []
    searchable = " ".join(paths) + " " + " ".join(user_agents)
    for stage_name, pattern in _STAGE_PATTERNS:
        if pattern.search(searchable):
            if stage_name not in stages:
                stages.append(stage_name)
    return stages


def incident_responder(triage_results: list, observation: dict) -> dict:
    """
    Agent 2: Incident Responder.

    Receives the Tier-1 triage results and decides the best action.

    Strategy for multi-step (task_hard):
      - Process IPs in priority order (highest threat score first).
      - Skip BENIGN IPs (allow them implicitly by not acting on them,
        or explicitly allow them if no threats remain).
      - BLOCK malicious IPs, prioritising late-stage kill chain activity.
      - ESCALATE uncertain IPs.

    Strategy for 1-shot (task_easy/medium):
      - Block the worst IP immediately.
    """
    blocked_ips = observation.get("blocked_ips", [])
    system_status = observation.get("system_status", "Normal")

    # Separate triaged IPs by verdict
    malicious = [r for r in triage_results if r["verdict"] == "MALICIOUS" and r["ip"] not in blocked_ips]
    suspicious = [r for r in triage_results if r["verdict"] == "SUSPICIOUS" and r["ip"] not in blocked_ips]
    benign = [r for r in triage_results if r["verdict"] == "BENIGN" and r["ip"] not in blocked_ips]

    # ── Priority 0: Zero-Day Stealth Attack (Path + Volume) ───────
    stealth_attackers = []
    for r in malicious + suspicious:
        has_suspicious_path = any("Suspicious path" in reason for reason in r["reasons"])
        has_high_volume = any("High volume" in reason for reason in r["reasons"])
        if has_suspicious_path and has_high_volume:
            stealth_attackers.append(r)

    if stealth_attackers:
        target = stealth_attackers[0]
        ip = target["ip"]
        stages = _detect_stages(target["paths"], target["user_agents"])
        stage_str = ", ".join(stages) if stages else "unknown"

        reasoning = (
            f"Zero-Day Stealth Threat: IP {ip} combines high request volume "
            f"with suspicious paths. MITRE stages: [{stage_str}]. "
            f"Indicators: {'; '.join(target['reasons'][:5])}. "
            f"Blocking immediately."
        )

        return {
            "action_type": "block_ip",
            "target_ip": ip,
            "reasoning": reasoning,
        }

    # ── Priority 1: Block the most dangerous malicious IP ─────────
    if malicious:
        target = malicious[0]  # already sorted by score (highest first)
        ip = target["ip"]

        # Detect MITRE stages for richer reasoning
        stages = _detect_stages(target["paths"], target["user_agents"])
        stage_str = ", ".join(stages) if stages else "unknown"

        reasoning = (
            f"MITRE kill chain stages detected: [{stage_str}]. "
            f"Threat indicators: {'; '.join(target['reasons'][:5])}. "
            f"Request paths include: {', '.join(target['paths'][:3])}. "
            f"Blocking IP {ip} to neutralise the attack."
        )

        return {
            "action_type": "block_ip",
            "target_ip": ip,
            "reasoning": reasoning,
        }

    # ── Priority 2: Block suspicious IPs ──────────────────────────
    if suspicious:
        target = suspicious[0]
        ip = target["ip"]
        stages = _detect_stages(target["paths"], target["user_agents"])
        stage_str = ", ".join(stages) if stages else "unclassified"

        reasoning = (
            f"Suspicious activity from {ip}. "
            f"Possible stages: [{stage_str}]. "
            f"Indicators: {'; '.join(target['reasons'][:5])}. "
            f"Blocking as precaution."
        )

        return {
            "action_type": "block_ip",
            "target_ip": ip,
            "reasoning": reasoning,
        }

    # ── Priority 3: All threats handled — allow remaining benign ──
    if benign:
        target = benign[0]
        ip = target["ip"]
        reasoning = (
            f"All threats neutralised. IP {ip} identified as benign: "
            f"{'; '.join(target['reasons'][:3]) or 'Normal traffic patterns'}. "
            f"Allowing normal traffic."
        )
        return {
            "action_type": "allow_ip",
            "target_ip": ip,
            "reasoning": reasoning,
        }

    # ── Fallback: nothing left to do ──────────────────────────────
    logs = observation.get("current_logs", [])
    if logs:
        first_ip = logs[0].get("source_ip", "unknown")
        return {
            "action_type": "escalate",
            "target_ip": first_ip,
            "reasoning": "No actionable threats remaining. Escalating for human review.",
        }

    return {
        "action_type": "escalate",
        "target_ip": "unknown",
        "reasoning": "No logs available. Escalating for human review.",
    }


# ═══════════════════════════════════════════════════════════════════
# 5. COMBINED MULTI-AGENT DECISION
# ═══════════════════════════════════════════════════════════════════

def llm_reasoning_fallback(ip_data: dict) -> str:
    """
    Dummy LLM integration for Deep Analysis of Gray Zone threats.
    Simulates a failure when no local inference endpoint is available.
    """
    try:
        raise TimeoutError("Simulated LLM API Timeout.")
    except (TimeoutError, NotImplementedError):
        return "[AI_ROUTING_UNAVAILABLE: FALLBACK_TO_HEURISTIC]"


def multi_agent_decide(observation: dict) -> dict:
    """
    Pipeline: Agent 1 (Triage) → Agent 2 (Incident Responder).

    Returns the final action dict.
    """
    logs = observation.get("current_logs", [])
    blocked_ips = observation.get("blocked_ips", [])

    # Agent 1: Triage
    triage_results = tier1_triage(logs, blocked_ips)

    # Hybrid AI/ML Routing: The Gray Zone
    gray_zone_tags = {}
    for r in triage_results:
        if 0.4 <= r["score"] <= 0.69:
            tag = llm_reasoning_fallback(r)
            if tag:
                gray_zone_tags[r["ip"]] = tag

    # Agent 2: Respond
    action = incident_responder(triage_results, observation)

    # Append tag if target was in the Gray Zone
    target_ip = action.get("target_ip")
    if target_ip and target_ip in gray_zone_tags:
        action["reasoning"] += f" {gray_zone_tags[target_ip]}"

    return action


# ═══════════════════════════════════════════════════════════════════
# 6. LLM INTERACTION (OPTIONAL — FALLS BACK TO MULTI-AGENT)
# ═══════════════════════════════════════════════════════════════════

SYSTEM_PROMPT = """
You are a highly skilled SOC Analyst checking server firewall access logs.
Your ONLY GOAL is to isolate threats (status_code >= 400 or suspicious user_agent) by returning exactly a JSON payload.
DO NOT include markdown code blocks. Return ONLY the raw JSON object.
Valid Action Types: "block_ip", "allow_ip", or "escalate".
JSON SCHEMA TO EXACTLY MATCH:
{
  "action_type": "block_ip",
  "target_ip": "192.168.x.x",
  "reasoning": "Detected 500 status code indicating SQL Injection attempt."
}
"""


def call_llm(observation: dict) -> dict:
    """
    Call the LLM API to decide on an action.

    Falls back to multi-agent heuristic if API is unavailable.
    Uses regex to extract JSON from model response.
    """
    try:
        from openai import OpenAI
        client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)

        prompt = (
            f"Current Logs: {json.dumps(observation.get('current_logs', []))}\n"
            f"System Status: {observation.get('system_status')}\n"
            f"Blocked IPs: {observation.get('blocked_ips')}"
        )

        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
        )
        raw_content = response.choices[0].message.content.strip()

        # Regex JSON extraction — handles markdown-wrapped responses
        match = re.search(r'\{.*\}', raw_content, re.DOTALL)
        if match:
            action = json.loads(match.group(0))
            # Validate required fields
            if "action_type" not in action or "target_ip" not in action:
                raise ValueError("Missing required fields in action JSON")
            return action
        else:
            raise ValueError("No JSON object found in LLM response.")

    except Exception:
        # Fall back to multi-agent heuristic on any LLM error
        return multi_agent_decide(observation)


# ═══════════════════════════════════════════════════════════════════
# 7. TASK SOLVER
# ═══════════════════════════════════════════════════════════════════

def solve_task(task_id: str) -> float:
    """
    Solve a single task.

    Guarantees:
      - [START] is printed FIRST before any other logic
      - [END] is ALWAYS printed via try/finally
      - Score is clamped to (0.001, 0.999)
      - Never raises to caller
    """
    # [START] printed FIRST — before any potential crashes
    log_start(task_id=task_id, env="soc-env", model=MODEL_NAME)

    rewards = []
    steps = 0
    final_score = MIN_SCORE
    success = False
    done = False
    session_id = None
    use_llm = bool(API_KEY and API_BASE_URL)

    try:
        # ── Reset the environment ──────────────────────────────
        try:
            reset_resp = requests.post(
                f"{ENV_URL}/reset",
                json={"task_id": task_id},
                timeout=15,
            )
            reset_resp.raise_for_status()
            data = reset_resp.json()
            session_id = data.get("session_id")
            obs = data.get("observation", {})
        except Exception as e:
            error_msg = f"Reset Error: {str(e)}".replace("\n", " ")
            log_step(step=0, action_str="reset", reward=MIN_SCORE, done=True, error=error_msg)
            rewards.append(MIN_SCORE)
            return MIN_SCORE

        # Reset episode-level tracker
        global EPISODIC_IP_LEDGER
        EPISODIC_IP_LEDGER.clear()

        # ── Interaction loop ───────────────────────────────────
        consecutive_errors = 0

        while not done and steps < MAX_STEPS:
            steps += 1

            # Decide action via multi-agent pipeline (or LLM)
            try:
                if use_llm:
                    action = call_llm(obs)
                else:
                    action = multi_agent_decide(obs)
                consecutive_errors = 0
            except Exception as e:
                action = {
                    "action_type": "escalate",
                    "target_ip": "unknown",
                    "reasoning": f"Decision error: {str(e)}",
                }
                consecutive_errors += 1
                if consecutive_errors >= 2:
                    done = True

            action_str = json.dumps(action).replace("\n", " ")

            # Execute action via /step
            try:
                step_resp = requests.post(
                    f"{ENV_URL}/step",
                    json={"session_id": session_id, "action": action},
                    timeout=15,
                )
                step_resp.raise_for_status()
                step_data = step_resp.json()
            except Exception as e:
                error_msg = f"Step Error: {str(e)}".replace("\n", " ")
                log_step(step=steps, action_str=action_str, reward=MIN_SCORE, done=True, error=error_msg)
                rewards.append(MIN_SCORE)
                done = True
                break

            # Parse response
            obs = step_data.get("observation", {})
            done = done or step_data.get("done", True)

            raw_reward = float(step_data.get("reward", MIN_SCORE))
            reward = max(MIN_SCORE, min(MAX_SCORE, raw_reward))

            raw_score = obs.get("metadata", {}).get("current_score", final_score)
            final_score = max(MIN_SCORE, min(MAX_SCORE, float(raw_score)))

            rewards.append(reward)
            log_step(step=steps, action_str=action_str, reward=reward, done=done, error=None)

    except Exception as e:
        print(f"[ERROR] Execution failed: {str(e)}", flush=True)
        log_step(step=steps, action_str="fatal", reward=MIN_SCORE, done=True, error=str(e).replace("\n", " "))
        rewards.append(MIN_SCORE)

    finally:
        # GUARANTEED: Final score clamp and [END] output
        final_score = max(MIN_SCORE, min(MAX_SCORE, float(final_score)))
        success = final_score > 0.1

        log_end(
            task_id=task_id,
            success=success,
            steps=steps,
            score=final_score,
            rewards=rewards,
        )
        return final_score


# ═══════════════════════════════════════════════════════════════════
# 8. MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    try:
        tasks = ["task_easy", "task_medium", "task_hard"]

        # Wait for server to be ready
        connected = False
        for attempt in range(12):
            try:
                r = requests.get(f"{ENV_URL}/health", timeout=5)
                if r.status_code == 200:
                    connected = True
                    break
            except Exception:
                pass
            print(f"Waiting for server at {ENV_URL}... (Attempt {attempt + 1}/12)", flush=True)
            time.sleep(5)

        if not connected:
            print(f"[WARNING] Could not connect to {ENV_URL}, proceeding anyway...", flush=True)

        # Solve each task
        all_scores = []
        for t in tasks:
            score = solve_task(t)
            all_scores.append(score)

    except Exception as e:
        print(f"[ERROR] Main loop failed: {e}", flush=True)
        traceback.print_exc()

    finally:
        # NEVER exit non-zero
        sys.exit(0)