import os
import time
import json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

# =========================================================
# PHASE 1 STATIC CHECKER REQUIREMENTS
# Do not change or remove these exact variable declarations!
API_BASE_URL = os.getenv("API_BASE_URL", "https://api.openai.com/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "gpt-4o")
HF_TOKEN = os.getenv("HF_TOKEN")
# =========================================================

# =========================================================
# PHASE 2 LLM PROXY FIX (FOOLPROOF VERSION)
# We aggressively hunt for the key using 'or' instead of strict 'if' conditions.
# If they inject API_KEY, we use it. If OPENAI_API_KEY, we use it. Else HF_TOKEN.
_api_key = os.getenv("API_KEY") or os.getenv("OPENAI_API_KEY") or HF_TOKEN
_base_url = os.getenv("API_BASE_URL") or API_BASE_URL

if not _api_key:
    raise ValueError("Missing API credentials. Please set API_KEY or HF_TOKEN.")

client = OpenAI(
    base_url=_base_url,
    api_key=_api_key
)
# =========================================================

LOCAL_ENV_URL = "http://localhost:8000"

# Rigid Strict Prompting for Schema
SYSTEM_PROMPT = """
You are a highly skilled SOC Analyst checking server firewall access logs.
You must closely examine the given SOCObservation to find malicious behavior.

Your ONLY GOAL is to isolate threats (status_code >= 400 or suspicious user_agent) by returning exactly a JSON payload.
You must NOT return markdown blocks (```json). You must return PURE text JSON containing an action_type, target_ip, and reasoning.

Valid Action Types: "block_ip" (for attackers), "allow_ip" (for completely clean normal behavior), or "escalate" (if unsure).

JSON SCHEMA TO EXACTLY MATCH:
{
  "action_type": "block_ip",
  "target_ip": "192.168.x.x",
  "reasoning": "Detected 500 status code indicating SQL Injection attempt."
}

DO NOT OUTPUT ANY SURROUNDING TEXT OR MARKDOWN.
"""

def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)

def log_step(step: int, action: str, reward: float, done: bool, error: str) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}",
        flush=True,
    )

def log_end(success: bool, steps: int, score: float, rewards: list[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}", flush=True)


def solve_task(task_id: str):
    import requests
    
    log_start(task=task_id, env="soc-env-hackathon", model=MODEL_NAME)
    
    # Reset Environment
    try:
        reset_resp = requests.post(
            f"{LOCAL_ENV_URL}/reset", 
            json={"task_id": task_id}, 
            timeout=10
        )
        reset_resp.raise_for_status()
    except Exception as e:
        log_step(step=0, action="reset", reward=0.0, done=True, error=str(e).replace('\n', ' '))
        log_end(success=False, steps=0, score=0.01, rewards=[])
        return 0.0

    data = reset_resp.json()
    session_id = data.get("session_id")
    obs = data.get("observation")
    
    done = False
    steps = 0
    final_score = 0.0
    rewards = []
    error = None
    
    while not done and steps < 10:
        steps += 1
        
        # Format the observation for the LLM
        prompt = f"Current Logs: {json.dumps(obs.get('current_logs', []))}\nSystem Status: {obs.get('system_status')}\nBlocked IPs: {obs.get('blocked_ips')}"
        
        try:
            response = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1
            )
            
            raw_content = response.choices[0].message.content.strip()
            if raw_content.startswith("```json"):
                raw_content = raw_content.replace("```json\n", "").replace("\n```", "")
            
            action = json.loads(raw_content)
        except Exception as e:
            error = f"LLM Generation Parse Failure: {e}"
            action = {"action_type": "escalate", "target_ip": "unknown", "reasoning": "Fallback due to parse error."}
            
        # action string must not contain newlines per rules
        action_str = json.dumps(action).replace('\n', ' ')

        # Step Environment
        try:
            step_resp = requests.post(
                f"{LOCAL_ENV_URL}/step", 
                json={
                    "session_id": session_id,
                    "action": action
                },
                timeout=10
            )
            step_resp.raise_for_status()
            step_data = step_resp.json()
            obs = step_data.get("observation", {})
            done = step_data.get("done", True)
            reward = float(step_data.get("reward", 0.0))
            
            current_score = obs.get("metadata", {}).get("current_score", 0.0)
            final_score = current_score
            
        except Exception as e:
            error = f"Step dispatch failed: {e}"
            reward = 0.0
            done = True

        rewards.append(reward)
        log_step(step=steps, action=action_str, reward=reward, done=done, error=error)
        
        error = None
    
    # define success as having a positive score at the end of the episode
    # clamp score to 0.0 - 1.0 for the log output
    final_score = max(0.01, min(0.99, float(final_score)))
    success = final_score > 0.0
    log_end(success=success, steps=steps, score=final_score, rewards=rewards)
    return final_score


if __name__ == "__main__":
    import requests
    time.sleep(1)  # Ensure server up
    
    try:
        r = requests.get(f"{LOCAL_ENV_URL}/tasks", timeout=5)
        tasks = [t["id"] for t in r.json().get("tasks", [])]
    except Exception:
        tasks = ["task_easy", "task_medium", "task_hard"]

    for t in tasks:
        solve_task(t)
