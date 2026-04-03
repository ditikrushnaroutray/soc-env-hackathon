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

# Create the app with web interface and README integration
app = create_app(
    SOCAnalystEnv,
    SOCAction,
    SOCObservation,
    env_name="soc_analyst_env",
    max_concurrent_envs=1,
)

# Global session storage for grading
SESSIONS = {}

# Clear any existing root routes set by OpenEnv to avoid conflicts
app.router.routes = [route for route in app.router.routes if getattr(route, "path", "") != "/"]

@app.get("/", include_in_schema=False)
async def root(request: Request):
    """Root endpoint to show the API is alive in the browser."""
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

@app.get("/health", include_in_schema=False)
def health():
    """Health check endpoint."""
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
    """
    Programmatically triggers the inference script and returns actual scores.
    """
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
            "task_easy": 0.0,
            "task_medium": 0.0,
            "task_hard": 0.0
        }
        
        for task_name in ["task_easy", "task_medium", "task_hard"]:
            pattern = rf"{task_name}.*score[=:\s]+([0-9.]+)"
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                scores[task_name] = float(match.group(1))
            
            if scores[task_name] == 0.0:
                pattern = rf"final[_\s]score[=:\s]+([0-9.]+)"
                match = re.search(pattern, output, re.IGNORECASE)
                if match:
                    scores[task_name] = float(match.group(1))
        
        for task in scores:
            scores[task] = max(0.0, min(1.0, scores[task]))
        
        return scores
        
    except subprocess.TimeoutExpired:
        return {
            "error": "Inference timeout (>300s)",
            "task_easy": 0.0,
            "task_medium": 0.0,
            "task_hard": 0.0
        }
    except Exception as e:
        return {
            "error": str(e),
            "task_easy": 0.0,
            "task_medium": 0.0,
            "task_hard": 0.0
        }

@app.get("/grader")
def run_grader(session_id: str):
    """
    Returns the score for a session from the SESSIONS registry.
    """
    try:
        from .soc_analyst_env_environment import SESSIONS
        
        if session_id in SESSIONS:
            env = SESSIONS[session_id]
            score = getattr(env, 'total_score', 0.0)
            score = max(0.0, min(1.0, float(score)))
            return {"session_id": session_id, "final_score": score}
        return {"session_id": session_id, "final_score": 0.0, "error": "Session not found"}
    except Exception as e:
        return {"session_id": session_id, "final_score": 0.0, "error": str(e)}

def main(host: str = "0.0.0.0", port: int = 8000):
    """Entry point for direct execution via uv run or python -m."""
    import uvicorn
    uvicorn.run(app, host=host, port=port)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    main(port=args.port)
    