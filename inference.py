import os
import time
import json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

# Strict Environment Constraints
API_BASE_URL = os.environ.get("API_BASE_URL", "https://api.openai.com/v1")
MODEL_NAME = os.environ.get("MODEL_NAME", "gpt-4o")
HF_TOKEN = os.environ.get("HF_TOKEN")

if not HF_TOKEN:
    raise ValueError("Missing HF_TOKEN environment variable required by automated judging.")

# Connect using exact OpenAI standard client requirement
client = OpenAI(
    base_url=API_BASE_URL,
    api_key=HF_TOKEN
)

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

def solve_task(task_id: str):
    import requests
    
    print("[START]")
    print(f"[STEP] Beginning Simulation Task: {task_id}")
    
    # Reset Environment (FIXED: Payload goes in the JSON body, not the URL)
    try:
        reset_resp = requests.post(
            f"{LOCAL_ENV_URL}/reset", 
            json={"task_id": task_id}, 
            timeout=10
        )
        reset_resp.raise_for_status()
    except Exception as e:
        print(f"[STEP] Failed to reset environment: {e}")
        return

    data = reset_resp.json()
    session_id = data.get("session_id")
    obs = data.get("observation")
    
    done = False
    steps = 0
    
    while not done and steps < 10:
        steps += 1
        print(f"[STEP] Task {task_id}: Step {steps} reasoning over logs...")
        
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
            # Clean up markdown if model hallucinates it despite strict prompts
            if raw_content.startswith("```json"):
                raw_content = raw_content.replace("```json\n", "").replace("\n```", "")
            
            action = json.loads(raw_content)
        except Exception as e:
            print(f"[STEP] LLM Generation Parse Failure, Escaping: {e}")
            action = {"action_type": "escalate", "target_ip": "unknown", "reasoning": "Fallback due to parse error."}
            
        print(f"[STEP] Selected Action -> {action.get('action_type')} on IP -> {action.get('target_ip')}")

        # Step Environment (FIXED: session_id and action must be packed into the JSON body)
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
            obs = step_data.get("observation")
            done = step_data.get("done")
            print(f"[STEP] Result -> Reward: {step_data.get('reward')} | Current Score: {step_data.get('info', {}).get('current_score')}")
        except Exception as e:
            print(f"[STEP] Step dispatch failed: {e}")
            break
            
    print(f"[STEP] Completed Task: {task_id}")


if __name__ == "__main__":
    import requests
    time.sleep(1) # Ensure server up
    try:
        print("[START]")
        print(f"[STEP] Grabbing Tasks configuration via API...")
        r = requests.get(f"{LOCAL_ENV_URL}/tasks", timeout=5)
        tasks = [t["id"] for t in r.json().get("tasks", [])]
    except Exception:
        print(f"[STEP] Using default tasks list")
        tasks = ["task_easy", "task_medium", "task_hard"]

    for t in tasks:
        solve_task(t)
    
    print("[END]")
    