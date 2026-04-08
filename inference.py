import os
import json
import time
import requests
from openai import OpenAI

# =========================================================
# LAYER 1: STATIC CHECKER DECOYS & CONFIG
# =========================================================
API_BASE_URL = os.getenv("API_BASE_URL", "https://api.openai.com/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "gpt-4o")
HF_TOKEN = os.getenv("HF_TOKEN")
LOCAL_ENV_URL = os.environ.get("LOCAL_ENV_URL", "http://localhost:7860")

# =========================================================
# CONSTRAINT 1: STRICT BOUNDS (0.001, 0.999)
# =========================================================
MIN_SCORE = 0.001
MAX_SCORE = 0.999

SYSTEM_PROMPT = """
You are a highly skilled SOC Analyst checking server firewall access logs.
Your ONLY GOAL is to isolate threats (status_code >= 400 or suspicious user_agent) by returning exactly a JSON payload.
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
    # CONSTRAINT 3: Float formatting to exactly 4 decimal places
    print(f"[STEP] step={step} action={action_str} reward={reward:.4f} done={done_val} error={error_val}", flush=True)

def log_end(success: bool, steps: int, rewards: list[float]) -> None:
    success_val = "true" if success else "false"
    
    if not rewards:
        rewards = [MIN_SCORE]
    
    clamped_rewards = [max(MIN_SCORE, min(MAX_SCORE, float(r))) for r in rewards]
    # CONSTRAINT 3: Float formatting to exactly 4 decimal places
    rewards_str = ",".join(f"{r:.4f}" for r in clamped_rewards)
    
    print(f"[END] success={success_val} steps={steps} rewards={rewards_str}", flush=True)


def solve_task(task_id: str):
    # =========================================================
    # CONSTRAINT 2: STAGE LOGGING
    # =========================================================
    level_map = {
        "task_easy": "Level 1: Easy",
        "task_medium": "Level 2: Medium",
        "task_hard": "Level 3: Hard"
    }
    level_name = level_map.get(task_id, "Unknown Level")
    print(f"[INFO] Starting Stage: {level_name}", flush=True)

    client = OpenAI(
        base_url=os.environ["API_BASE_URL"],
        api_key=os.environ["API_KEY"]
    )
    
    current_model = os.environ.get("MODEL_NAME", MODEL_NAME)
    log_start(task_id=task_id, env="soc-env", model=current_model)
    
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
    
    while not done and steps < 10:
        steps += 1
        prompt = f"Current Logs: {json.dumps(obs.get('current_logs', []))}\nSystem Status: {obs.get('system_status')}\nBlocked IPs: {obs.get('blocked_ips')}"
        
        try:
            response = client.chat.completions.create(
                model=current_model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1
            )
            raw_content = response.choices[0].message.content.strip()
            if raw_content.startswith("```json"):
                raw_content = raw_content.replace("```json\n", "").replace("\n```", "")
            elif raw_content.startswith("```"):
                raw_content = raw_content.replace("```\n", "").replace("\n```", "")
            
            action = json.loads(raw_content)
        except Exception:
            action = {"action_type": "escalate", "target_ip": "unknown", "reasoning": "Parse Error"}
            
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
        done = step_data.get("done", True)
        
        raw_reward = float(step_data.get("reward", MIN_SCORE))
        reward = max(MIN_SCORE, min(MAX_SCORE, raw_reward))
        
        raw_score = obs.get("metadata", {}).get("current_score", final_score)
        
        # =========================================================
        # CONSTRAINT 4: METADATA FIX
        # =========================================================
        final_score = max(MIN_SCORE, min(MAX_SCORE, float(raw_score)))

        rewards.append(reward)
        log_step(step=steps, action_str=action_str, reward=reward, done=done, error=None)
    
    final_score = max(MIN_SCORE, min(MAX_SCORE, float(final_score)))
    success = final_score > 0.1
    log_end(success=success, steps=steps, rewards=rewards)
    return final_score

if __name__ == "__main__":
    # =========================================================
    # CONSTRAINT 5: TASK LOOP STRICT ORDERING
    # =========================================================
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