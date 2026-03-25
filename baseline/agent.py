import requests
import os
from openai import OpenAI
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

BASE_URL = "http://127.0.0.1:8000"
# Initialize OpenAI Client (Reads from environment variable as per rules)
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def run_baseline():
    print("🤖 [AGENT] Booting up SOC Automated Response Bot (LLM Mode)...")
    
    # 1. Start a new session
    print("🤖 [AGENT] Requesting new environment state (task_easy)...")
    reset_res = requests.post(f"{BASE_URL}/reset?task_id=task_easy").json()
    
    session_id = reset_res["session_id"]
    logs = reset_res["observation"]["current_logs"]
    
    print(f"✅ [SERVER] Session created: {session_id}")
    print(f"🤖 [AGENT] Analyzing {len(logs)} server logs with LLM...")
    
    # 2. The "Brain" - Using OpenAI to analyze logs
    # We convert logs to a string so the AI can read them
    log_summary = "\n".join([f"IP: {l['source_ip']} | Method: {l['method']} | Status: {l['status_code']}" for l in logs])
    
    prompt = (
        "You are a SOC Analyst. Look at these logs and identify the ONE malicious IP address "
        "attempting a brute force or unauthorized access (look for 401/403/500 errors). "
        "Return ONLY the IP address and nothing else.\n\n"
        f"LOGS:\n{log_summary}"
    )

    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}]
    )
    
    target_ip = response.choices[0].message.content.strip()

    if not target_ip:
        print("🤖 [AGENT] No threats detected. Standing by.")
        return

    # 3. Fire the action
    print(f"🚨 [AGENT] LLM THREAT DETECTION! Malicious activity from {target_ip}.")
    print(f"🤖 [AGENT] Executing 'block_ip' action...")
    
    action_payload = {
        "action_type": "block_ip",
        "target_ip": target_ip,
        "reasoning": "Inference from OpenAI model based on log anomaly detection."
    }
    
    step_res = requests.post(f"{BASE_URL}/step?session_id={session_id}", json=action_payload).json()
    
    # 4. Read the Grade
    reward = step_res["reward"]
    msg = step_res["info"]["message"]
    
    print("\n" + "="*40)
    print("📊 INCIDENT RESOLUTION REPORT (LLM)")
    print("="*40)
    print(f"Action Grade : {reward} points")
    print(f"Server Notes : {msg}")
    print("="*40 + "\n")

if __name__ == "__main__":
    run_baseline()
    