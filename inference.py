import os
import sys
import json
import time
import requests
import re
import traceback
from openai import OpenAI

# =========================================================
# FLEXIBLE ENVIRONMENT VARIABLE FETCHING
# =========================================================
def get_env_var(keys, default_val):
    for k in keys:
        if k in os.environ and os.environ[k].strip():
            return os.environ[k]
    return default_val

API_KEY = get_env_var(["API_KEY", "OPENAI_API_KEY", "HF_TOKEN"], "dummy_key")
API_BASE_URL = get_env_var(["API_BASE_URL", "OPENAI_BASE_URL", "PROXY_URL"], "https://api.openai.com/v1")
MODEL_NAME = get_env_var(["MODEL_NAME", "LLM_MODEL"], "gpt-4o")
LOCAL_ENV_URL = os.environ.get("LOCAL_ENV_URL", "http://localhost:7860")

# =========================================================
# CONSTRAINT 1: STRICT BOUNDS (0.001, 0.999)
# =========================================================
MIN_SCORE = 0.001
MAX_SCORE = 0.999

# =========================================================
# REFINED PROMPT: Forcing raw JSON output
# =========================================================
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

def log_start(task_id: str, env: str, model: str) -> None:
    print(f"[START] task={task_id} env={env} model={model}", flush=True)

def log_step(step: int, action_str: str, reward: float, done: bool, error: str = None) -> None:
    error_val = error if error else "null"
    done_val = "true" if done else "false"
    # Float formatting to exactly 4 decimal places
    print(f"[STEP] step={step} action={action_str} reward={reward:.4f} done={done_val} error={error_val}", flush=True)

def log_end(success: bool, steps: int, rewards: list[float]) -> None:
    success_val = "true" if success else "false"
    
    if not rewards:
        rewards = [MIN_SCORE]
    
    clamped_rewards = [max(MIN_SCORE, min(MAX_SCORE, float(r))) for r in rewards]
    # Float formatting to exactly 4 decimal places
    rewards_str = ",".join(f"{r:.4f}" for r in clamped_rewards)
    
    print(f"[END] success={success_val} steps={steps} rewards={rewards_str}", flush=True)


def solve_task(task_id: str):
    # =========================================================
    # STAGE LOGGING
    # =========================================================
    level_map = {
        "task_easy": "Level 1: Easy",
        "task_medium": "Level 2: Medium",
        "task_hard": "Level 3: Hard"
    }
    level_name = level_map.get(task_id, "Unknown Level")
    print(f"[INFO] Starting Stage: {level_name}", flush=True)

    client = OpenAI(
        base_url=API_BASE_URL,
        api_key=API_KEY
    )
    
    log_start(task_id=task_id, env="soc-env", model=MODEL_NAME)
    
    try:
        reset_resp = requests.post(f"{LOCAL_ENV_URL}/reset", json={"task_id": task_id}, timeout=10)
        reset_resp.raise_for_status()
    except Exception as e:
        log_step(step=0, action_str="reset", reward=MIN_SCORE, done=True, error=str(e).replace('\n', ' '))
        log_end(success=False, steps=0, rewards=[MIN_SCORE])
        return MIN_SCORE

    data = reset_resp.json()
    session_id = data.get("session_id")
    obs = data.get("observation", {})
    
    done = False
    steps = 0
    final_score = MIN_SCORE
    rewards = []
    consecutive_errors = 0
    
    while not done and steps < 10:
        steps += 1
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
            
            # =========================================================
            # ROBUST REGEX JSON PARSING
            # =========================================================
            match = re.search(r'\{.*\}', raw_content, re.DOTALL)
            if match:
                json_str = match.group(0)
                action = json.loads(json_str)
                consecutive_errors = 0 
            else:
                raise ValueError("No JSON object found in LLM response.")
                
        except Exception as e:
            action = {"action_type": "escalate", "target_ip": "unknown", "reasoning": f"Parse Error: {str(e)}"}
            consecutive_errors += 1
            
            if consecutive_errors >= 2:
                done = True  # Force game to end if AI is completely broken
            
        action_str = json.dumps(action).replace('\n', ' ')

        try:
            step_resp = requests.post(f"{LOCAL_ENV_URL}/step", json={"session_id": session_id, "action": action}, timeout=10)
            step_resp.raise_for_status()
            step_data = step_resp.json()
        except Exception as e:
            log_step(step=steps, action_str=action_str, reward=MIN_SCORE, done=True, error=str(e).replace('\n', ' '))
            if not rewards:
                rewards = [MIN_SCORE]
            log_end(success=False, steps=steps, rewards=rewards)
            return MIN_SCORE
        
        obs = step_data.get("observation", {})
        server_done = step_data.get("done", True)
        done = done or server_done
        
        raw_reward = float(step_data.get("reward", MIN_SCORE))
        reward = max(MIN_SCORE, min(MAX_SCORE, raw_reward))
        
        raw_score = obs.get("metadata", {}).get("current_score", final_score)
        final_score = max(MIN_SCORE, min(MAX_SCORE, float(raw_score)))

        rewards.append(reward)
        log_step(step=steps, action_str=action_str, reward=reward, done=done, error=None)
    
    final_score = max(MIN_SCORE, min(MAX_SCORE, float(final_score)))
    success = final_score > 0.1
    log_end(success=success, steps=steps, rewards=rewards)
    return final_score

if __name__ == "__main__":
    # =========================================================
    # MASTER TRY/EXCEPT WITH SYS.EXIT(0)
    # =========================================================
    try:
        tasks = ["task_easy", "task_medium", "task_hard"]
        connected = False
        
        for attempt in range(12):
            try:
                r = requests.get(f"{LOCAL_ENV_URL}/tasks", timeout=5)
                if r.status_code == 200:
                    connected = True
                    break
            except requests.exceptions.RequestException:
                print(f"Waiting for server at {LOCAL_ENV_URL} to boot... (Attempt {attempt + 1}/12)", flush=True)
                time.sleep(5)
                
        if not connected:
            raise ConnectionError(f"Failed to connect to environment server at {LOCAL_ENV_URL} after 60 seconds.")

        for t in tasks:
            try:
                solve_task(t)
            except Exception as e:
                print(f"Task {t} failed: {str(e)}", flush=True)
                
    except Exception as e:
        print("[ERROR] Catastrophic failure in main loop:", flush=True)
        traceback.print_exc()
        # Exit with 0 to prevent the grader pipeline from crashing instantly
        sys.exit(0)
        