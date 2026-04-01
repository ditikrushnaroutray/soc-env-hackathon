import random
from datetime import datetime, timedelta

def generate_logs(task_id: str, num_logs: int = 15) -> list[dict]:
    """Generates a mix of normal traffic and malicious attacks based on difficulty."""
    logs = []
    now = datetime.now()
    
    # Pool of normal, innocent users
    normal_ips = [f"192.168.1.{i}" for i in range(10, 50)]
    normal_paths = ["/", "/dashboard", "/api/v1/health", "/images/logo.png"]
    
    # 1. Generate normal background noise
    for _ in range(num_logs):
        logs.append({
            "timestamp": (now - timedelta(seconds=random.randint(1, 600))).isoformat(),
            "source_ip": random.choice(normal_ips),
            "request_path": random.choice(normal_paths),
            "status_code": 200,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        })

    # 2. Inject the specific cyber attacks
    if task_id == "task_easy":
        # BRUTE FORCE: One loud IP failing logins repeatedly
        bad_ip = "104.22.33.44"
        for _ in range(5):
            logs.append({
                "timestamp": now.isoformat(),
                "source_ip": bad_ip,
                "request_path": "/api/v1/login",
                "status_code": 401, # Unauthorized
                "user_agent": "python-requests/2.28.1" # Bot behavior
            })
            
    elif task_id == "task_medium":
        # SQL INJECTION: Multiple IPs trying to drop the database
        for _ in range(3):
            logs.append({
                "timestamp": now.isoformat(),
                "source_ip": f"185.33.22.{random.randint(1, 200)}",
                "request_path": "/users?id=1' OR '1'='1",
                "status_code": 500, # Server error triggered by bad SQL
                "user_agent": "sqlmap/1.5.8"
            })
            
    elif task_id == "task_hard":
        # MIXED: SQL Injection + Brute force + Decoy normal traffic
        logs.append({"timestamp": now.isoformat(), "source_ip": "45.11.22.33", "request_path": "/admin", "status_code": 403, "user_agent": "curl/7.68.0"})
        logs.append({"timestamp": now.isoformat(), "source_ip": "104.22.33.44", "request_path": "/login", "status_code": 401, "user_agent": "python-requests"})

    # Shuffle the logs so the AI has to actually hunt for the attacks
    random.shuffle(logs)
    return logs
    