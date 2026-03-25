import requests
import time

BASE_URL = "http://127.0.0.1:8000"

def run_baseline():
    print("🤖 [AGENT] Booting up SOC Automated Response Bot...")
    
    # 1. Start a new session
    print("🤖 [AGENT] Requesting new environment state (task_easy)...")
    reset_res = requests.post(f"{BASE_URL}/reset?task_id=task_easy").json()
    
    session_id = reset_res["session_id"]
    logs = reset_res["observation"]["current_logs"]
    
    print(f"✅ [SERVER] Session created: {session_id}")
    print(f"🤖 [AGENT] Analyzing {len(logs)} server logs...")
    
    # 2. The "Brain" - Look for anomalies (Status codes 400 or 500)
    target_ip = None
    for log in logs:
        if log["status_code"] >= 400:
            target_ip = log["source_ip"]
            break
            
    if not target_ip:
        print("🤖 [AGENT] No threats detected. Standing by.")
        return

    # 3. Fire the action
    print(f"🚨 [AGENT] THREAT DETECTED! Malicious activity from {target_ip}.")
    print(f"🤖 [AGENT] Executing 'block_ip' action...")
    
    action_payload = {
        "action_type": "block_ip",
        "target_ip": target_ip,
        "reasoning": "Baseline agent heuristic detected high error status codes."
    }
    
    step_res = requests.post(f"{BASE_URL}/step?session_id={session_id}", json=action_payload).json()
    
    # 4. Read the Grade
    reward = step_res["reward"]
    msg = step_res["info"]["message"]
    
    print("\n" + "="*40)
    print("📊 INCIDENT RESOLUTION REPORT")
    print("="*40)
    print(f"Action Grade : {reward} points")
    print(f"Server Notes : {msg}")
    print("="*40 + "\n")

if __name__ == "__main__":
    run_baseline()
    