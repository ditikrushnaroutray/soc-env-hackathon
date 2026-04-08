import os
import sys
import json
import time
import requests
import re
import traceback
from openai import OpenAI

# =========================================================
# 1. STRICT ENVIRONMENT FETCHING (Checklist Alignment)
# =========================================================
# MUST use exact variables. No fallback to HF_TOKEN as primary.
API_KEY = os.environ.get("API_KEY")
API_BASE_URL = os.environ.get("API_BASE_URL")
MODEL_NAME = os.environ.get("MODEL_NAME", "default-model")

# Check ENV_URL first per checklist, then LOCAL_ENV_URL, then fallback to 7860
ENV_URL = os.environ.get("ENV_URL") or os.environ.get("LOCAL_ENV_URL") or "http://localhost:7860"

MIN_SCORE = 0.001
MAX_SCORE = 0.999

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
    done_val = str(done).lower()
    print(f"[STEP] step={step} action={action_str} reward={reward:.2f} done={done_val} error={error_val}", flush=True)

def log_end(success: bool, steps: int, score: float, rewards: list[float], task_id: str) -> None:
    success_val = str(success).lower()
    
    if not rewards:
        rewards = [MIN_SCORE]
    
    clamped_rewards = [max(MIN_SCORE, min(MAX_SCORE, float(r))) for r in rewards]
    rewards_str = ",".join(f"{r:.2f}" for r in clamped_rewards)
    
    print(f"[END] task={task_id} success={success_val} steps={steps} score={score:.3f} rewards={rewards_str}", flush=True)


def solve_task(task_id: str):
    # [START] printed FIRST, before ANY potential crashes per checklist
    log_start(task_id=task_id, env="soc-env", model=MODEL_NAME)
    
    rewards = []
    steps = 0
    final_score = MIN_SCORE
    success = False
    done = False
    session_id = None
    consecutive_errors = 0

    if not API_KEY or not API_BASE_URL:
        error_msg = "Missing API_KEY or API_BASE_URL"
        print(f"[ERROR] {error_msg}", flush=True)
        log_step(step=0, action_str="fatal_error", reward=MIN_SCORE, done=True, error=error_msg)
        log_end(success=False, steps=0, score=MIN_SCORE, rewards=[MIN_SCORE], task_id=task_id)
        return MIN_SCORE

    try:
        client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)
        
        try:
            # Must strictly use HTTP POST to /reset
            reset_resp = requests.post(f"{ENV_URL}/reset", json={"task_id": task_id}, timeout=10)
            reset_resp.raise_for_status()
            data = reset_resp.json()
            session_id = data.get("session_id")
            obs = data.get("observation", {})
        except Exception as e:
            log_step(step=0, action_str="reset", reward=MIN_SCORE, done=True, error=f"Reset Error: {str(e)}".replace('\n', ' '))
            return MIN_SCORE

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
                
                match = re.search(r'\{.*\}', raw_content, re.DOTALL)
                if match:
                    json_str = match.group(0)
                    action = json.loads(json_str)
                    consecutive_errors = 0 
                else:
                    raise ValueError("No JSON object found in response.")
                    
            except Exception as e:
                action = {"action_type": "escalate", "target_ip": "unknown", "reasoning": f"Error: {str(e)}"}
                consecutive_errors += 1
                if consecutive_errors >= 2:
                    done = True  
                
            action_str = json.dumps(action).replace('\n', ' ')

            try:
                # Must strictly use HTTP POST to /step
                step_resp = requests.post(f"{ENV_URL}/step", json={"session_id": session_id, "action": action}, timeout=10)
                step_resp.raise_for_status()
                step_data = step_resp.json()
            except Exception as e:
                log_step(step=steps, action_str=action_str, reward=MIN_SCORE, done=True, error=f"Step Error: {str(e)}".replace('\n', ' '))
                done = True
                break
            
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
        log_step(step=steps, action_str="fatal", reward=MIN_SCORE, done=True, error=str(e).replace('\n', ' '))
    finally:
        # GUARANTEED TO RUN: Final bounded score logic and [END] block per checklist
        final_score = max(MIN_SCORE, min(MAX_SCORE, float(final_score)))
        success = final_score > 0.1
        
        log_end(success=success, steps=steps, score=final_score, rewards=rewards, task_id=task_id)
        return final_score


if __name__ == "__main__":
    try:
        # Loop over exactly the 3 simple task IDs
        tasks = ["task_easy", "task_medium", "task_hard"]
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
                
        # Loop through exactly the 3 tasks in a single execution
        for t in tasks:
            solve_task(t)
            
    except Exception as e:
        print(f"[ERROR] Main loop failed: {e}", flush=True)
        traceback.print_exc()
    finally:
        sys.exit(0)
        