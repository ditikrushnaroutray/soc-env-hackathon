# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
FastAPI application for the Soc Analyst Env Environment.
"""

try:
    from openenv.core.env_server.http_server import create_app
except Exception as e:
    raise ImportError(
        "openenv is required for the web interface. Install dependencies with '\n    uv sync\n'"
    ) from e

try:
    from ..models import SOCAction, SOCObservation
    from .soc_analyst_env_environment import SOCAnalystEnv
except (ModuleNotFoundError, ImportError):
    from models import SOCAction, SOCObservation
    from server.soc_analyst_env_environment import SOCAnalystEnv

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

# Create the app with web interface and README integration
app = create_app(
    SOCAnalystEnv,
    SOCAction,
    SOCObservation,
    env_name="soc_analyst_env",
    max_concurrent_envs=1,
)

SESSIONS = {}

class RootInterceptMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/" and request.method == "GET":
            return JSONResponse(content={
                "status": "online",
                "message": "SOC Analyst Environment API is running! 🛡️",
                "endpoints": [
                    "/tasks",
                    "/health",
                    "/baseline",
                    "/grader",
                    "/step",
                    "/reset",
                    "/docs"
                ]
            })
        return await call_next(request)

app.add_middleware(RootInterceptMiddleware)

@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok"}

@app.get("/tasks")
def get_tasks():
    try:
        from ..models import SOCAction
    except (ModuleNotFoundError, ImportError):
        from models import SOCAction
        
    return {
        "tasks": [
            {"id": "task_easy", "description": "Block the single IP attempting a brute force login."},
            {"id": "task_medium", "description": "Identify and block a distributed SQL injection attack."},
            {"id": "task_hard", "description": "Triage a mixed-traffic environment with decoy attacks and false positives."}
        ],
        "action_schema": SOCAction.model_json_schema()
    }

@app.get("/baseline")
def run_baseline():
    import subprocess
    import os
    import re
    
    script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../inference.py"))
    if not os.path.exists(script_path):
        script_path = "inference.py"
    
    try:
        result = subprocess.run(
            ["python3", script_path],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        output = result.stdout + result.stderr
        
        scores = {
            "task_easy": 0.01,  # STRICT BOUNDS FIX
            "task_medium": 0.01, # STRICT BOUNDS FIX
            "task_hard": 0.01   # STRICT BOUNDS FIX
        }
        
        for task_name in ["task_easy", "task_medium", "task_hard"]:
            pattern = rf"{task_name}.*score[=:\s]+([0-9.]+)"
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                scores[task_name] = float(match.group(1))
            
            if scores[task_name] <= 0.01:
                pattern = rf"final[_\s]score[=:\s]+([0-9.]+)"
                match = re.search(pattern, output, re.IGNORECASE)
                if match:
                    scores[task_name] = float(match.group(1))
        
        for task in scores:
            scores[task] = max(0.01, min(0.99, scores[task]))
        
        return scores
        
    except subprocess.TimeoutExpired:
        return {
            "error": "Inference timeout (>300s)",
            "task_easy": 0.01,
            "task_medium": 0.01,
            "task_hard": 0.01
        }
    except Exception as e:
        return {
            "error": str(e),
            "task_easy": 0.01,
            "task_medium": 0.01,
            "task_hard": 0.01
        }

@app.get("/grader")
def run_grader(session_id: str):
    try:
        from .soc_analyst_env_environment import SESSIONS
        
        if session_id in SESSIONS:
            env = SESSIONS[session_id]
            score = getattr(env, 'total_score', 0.01)
            score = max(0.01, min(0.99, float(score)))
            return {"session_id": session_id, "final_score": score}
            
        # STRICT BOUNDS FIX: Return 0.01 on error, NOT 0.0
        return {"session_id": session_id, "final_score": 0.01, "error": "Session not found"}
    except Exception as e:
        return {"session_id": session_id, "final_score": 0.01, "error": str(e)}

def main(host: str = "0.0.0.0", port: int = 8000):
    import uvicorn
    uvicorn.run(app, host=host, port=port)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    main(port=args.port)
    