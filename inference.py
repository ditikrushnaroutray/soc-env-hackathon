#!/usr/bin/env python3
"""
Hardened baseline inference agent for SOC Analyst Environment.

Phase-2 Hackathon compliant:
  - Structured stdout: [START], [STEP], [END] in exact format
  - Booleans as lowercase true/false
  - reward/rewards formatted to .2f, score to .3f
  - rewards list comma-separated with NO SPACES
  - Score clamped to (0.001, 0.999)
  - Always flush=True
  - NEVER exits non-zero on expected errors
  - Always emits [END] then exits 0

Usage:
    export API_KEY="your-key"
    export API_BASE_URL="https://api.openai.com/v1"
    export MODEL_NAME="gpt-4o"
    export ENV_URL="http://localhost:7860"
    python inference.py
"""

import os
import sys
import json
import time
import re
import traceback
import requests

# ═══════════════════════════════════════════════════════════════════
# 1. ENVIRONMENT VARIABLES
# ═══════════════════════════════════════════════════════════════════
API_KEY = os.environ.get("API_KEY")
API_BASE_URL = os.environ.get("API_BASE_URL")
MODEL_NAME = os.environ.get("MODEL_NAME", "default-model")
ENV_URL = os.environ.get("ENV_URL") or "http://localhost:7860"

MIN_SCORE = 0.001
MAX_SCORE = 0.999
MAX_STEPS = 10

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
# 3. HEURISTIC AGENT (LOCAL FALLBACK)
# ═══════════════════════════════════════════════════════════════════

def heuristic_decide(observation: dict) -> dict:
    """
    Local heuristic agent that doesn't require an LLM API.
    
    Strategy: Find the first IP with status_code >= 400 and block it.
    If none found, escalate the first IP.
    """
    logs = observation.get("current_logs", [])

    # Find malicious IPs (status >= 400)
    malicious_ips = {}
    for log in logs:
        ip = log.get("source_ip", "")
        status = log.get("status_code", 200)
        if status >= 400:
            malicious_ips[ip] = malicious_ips.get(ip, 0) + 1

    if malicious_ips:
        # Pick the IP with the most malicious entries
        worst_ip = max(malicious_ips, key=malicious_ips.get)
        return {
            "action_type": "block_ip",
            "target_ip": worst_ip,
            "reasoning": f"Detected {malicious_ips[worst_ip]} requests with status >= 400 from {worst_ip}. Blocking as likely attack.",
        }

    # No obvious threats — escalate the first IP
    if logs:
        first_ip = logs[0].get("source_ip", "unknown")
        return {
            "action_type": "escalate",
            "target_ip": first_ip,
            "reasoning": "No clear threats detected. Escalating for human review.",
        }

    return {
        "action_type": "escalate",
        "target_ip": "unknown",
        "reasoning": "No logs available. Escalating for human review.",
    }


# ═══════════════════════════════════════════════════════════════════
# 4. LLM INTERACTION
# ═══════════════════════════════════════════════════════════════════

def call_llm(observation: dict) -> dict:
    """
    Call the LLM API to decide on an action.
    
    Falls back to heuristic if API is unavailable.
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
        # Fall back to heuristic on any LLM error
        return heuristic_decide(observation)


# ═══════════════════════════════════════════════════════════════════
# 5. TASK SOLVER
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

        # ── Interaction loop ───────────────────────────────────
        consecutive_errors = 0

        while not done and steps < MAX_STEPS:
            steps += 1

            # Decide action
            try:
                if use_llm:
                    action = call_llm(obs)
                else:
                    action = heuristic_decide(obs)
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
# 6. MAIN ENTRY POINT
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