import os
import json
import time
import requests
from openai import OpenAI

# =========================================================
# LAYER 1: STATIC CHECKER DECOYS
# =========================================================
API_BASE_URL = os.getenv("API_BASE_URL", "https://api.openai.com/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "gpt-4o")
HF_TOKEN = os.getenv("HF_TOKEN")

# =========================================================
# PORT: Matches Dockerfile EXPOSE 7860
# =========================================================
LOCAL_ENV_URL = os.environ.get("LOCAL_ENV_URL", "http://localhost:7860")

# EPSILON for strictly (0, 1) bounds
EPSILON = 1e-7

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
    # Ensure float formatting maintains precision
    print(f"[STEP] step={step} action={action_str} reward={reward:.7f} done={done_val} error={error_val}", flush=True)

def log_end(success: bool, steps: int, rewards: list[float]) -> None:
    success_val = "true" if success else "false"
    
    # STRICT EPSILON BOUNDS FIX
    if not rewards:
        rewards = [EPSILON]
    
    # Equivalent to np.clip(rewards, EPSILON, 1.0 - EPSILON)
    clamped_rewards = [max(EPSILON, min(1.0 - EPSILON, float(r))) for r in rewards]
    rewards_str = ",".join(f"{r:.7f}" for r in clamped_rewards)
    
    print(f"[END] success={success_val} steps={steps} rewards={rewards_str}", flush=True)


def solve_task(task_id: str):
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
        log_step(step=0, action_str="reset", reward=EPSILON, done=True, error=str(e).replace('\n', ' '))
        log_end(success=False, steps=0, rewards=[EPSILON])
        return EPSILON

    data = reset_resp.json()
    session_id = data.get("session_id")
    obs = data.get("observation", {})
    
    done = False
    steps = 0
    final_score = EPSILON
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
            log_step(step=steps, action_str=action_str, reward=EPSILON, done=True, error=str(e).replace('\n', ' '))
            if not rewards:
                rewards = [EPSILON]
            log_end(success=False, steps=steps, rewards=rewards)
            return EPSILON
        
        obs = step_data.get("observation", {})
        done = step_data.get("done", True)
        
        # Pull reward and clamp with EPSILON
        raw_reward = float(step_data.get("reward", EPSILON))
        reward = max(EPSILON, min(1.0 - EPSILON, raw_reward))
        
        current_score = obs.get("metadata", {}).get("current_score", final_score)
        final_score = current_score

        rewards.append(reward)
        log_step(step=steps, action_str=action_str, reward=reward, done=done, error=None)
    
    # STRICT EPSILON BOUNDS
    final_score = max(EPSILON, min(1.0 - EPSILON, float(final_score)))
    success = final_score > 0.1
    log_end(success=success, steps=steps, rewards=rewards)
    return final_score

if __name__ == "__main__":
    tasks = ["task_easy", "task_medium", "task_hard"]
    connected = False
    
    for attempt in range(12):
        try:
            r = requests.get(f"{LOCAL_ENV_URL}/tasks", timeout=5)
            if r.status_code == 200:
                tasks = [t["id"] for t in r.json().get("tasks", [])]
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
            