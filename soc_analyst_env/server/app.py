"""
FastAPI application for the SOC Analyst Environment.

Standalone server — no openenv SDK dependency.
Provides endpoints: /health, /tasks, /reset, /step, /grader, /
"""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .models import (
    ResetRequest,
    ResetResponse,
    SOCAction,
    StepRequest,
    StepResponse,
)
from .soc_analyst_env_environment import SESSIONS, SOCAnalystEnv

# ── Create FastAPI application ────────────────────────────────────
app = FastAPI(
    title="SOC Analyst RL Environment",
    description="OpenEnv-compliant SOC Analyst reinforcement learning environment.",
    version="2.0.0",
)


# ── Root endpoint ─────────────────────────────────────────────────
@app.get("/")
def root():
    """API information and available endpoints."""
    return {
        "status": "online",
        "message": "SOC Analyst Environment API is running! 🛡️",
        "version": "2.0.0",
        "endpoints": [
            "/health",
            "/tasks",
            "/reset",
            "/step",
            "/grader",
            "/docs",
        ],
    }


# ── Health check ──────────────────────────────────────────────────
@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "ok"}


# ── Task listing ──────────────────────────────────────────────────
@app.get("/tasks")
def get_tasks():
    """Return available tasks and action schema."""
    return {
        "tasks": [
            {
                "id": "task_easy",
                "description": "Block the single IP attempting a brute force login.",
            },
            {
                "id": "task_medium",
                "description": "Identify and block a distributed SQL injection attack.",
            },
            {
                "id": "task_hard",
                "description": "Triage a mixed-traffic environment with decoy attacks and false positives.",
            },
        ],
        "action_schema": SOCAction.model_json_schema(),
    }


# ── Reset endpoint ────────────────────────────────────────────────
@app.post("/reset")
def reset(request: ResetRequest):
    """
    Reset the environment for a new episode.

    Expects JSON body: {"task_id": "task_easy"}
    Returns: {"session_id": "...", "observation": {...}}
    """
    try:
        env = SOCAnalystEnv()
        result = env.reset(task_id=request.task_id)
        return result
    except Exception as e:
        return JSONResponse(
            status_code=200,  # Never return error status codes
            content={
                "session_id": "error",
                "observation": {
                    "current_logs": [],
                    "blocked_ips": [],
                    "system_status": "Error",
                    "reward": 0.001,
                    "done": True,
                    "metadata": {"message": f"Reset error: {str(e)}"},
                },
            },
        )


# ── Step endpoint ─────────────────────────────────────────────────
@app.post("/step")
def step(request: StepRequest):
    """
    Apply an agent action and return the next observation.

    Expects JSON body: {"session_id": "...", "action": {"action_type": "...", "target_ip": "...", "reasoning": "..."}}
    Returns: {"observation": {...}, "reward": float, "done": bool, "message": "..."}
    """
    try:
        env = SESSIONS.get(request.session_id)
        if env is None:
            return JSONResponse(
                status_code=200,
                content={
                    "observation": {
                        "current_logs": [],
                        "blocked_ips": [],
                        "system_status": "Error",
                        "reward": 0.001,
                        "done": True,
                        "metadata": {"message": "Session not found. Call /reset first."},
                    },
                    "reward": 0.001,
                    "done": True,
                    "message": "Session not found.",
                },
            )

        result = env.step(action=request.action)
        return result

    except Exception as e:
        return JSONResponse(
            status_code=200,
            content={
                "observation": {
                    "current_logs": [],
                    "blocked_ips": [],
                    "system_status": "Error",
                    "reward": 0.001,
                    "done": True,
                    "metadata": {"message": f"Step error: {str(e)}"},
                },
                "reward": 0.001,
                "done": True,
                "message": f"Step error: {str(e)}",
            },
        )


# ── Grader endpoint ───────────────────────────────────────────────
@app.get("/grader")
def grader(session_id: str = ""):
    """
    Return the final score for a session.

    Query param: ?session_id=<id>
    Returns: {"session_id": "...", "final_score": float}
    """
    try:
        if session_id and session_id in SESSIONS:
            env = SESSIONS[session_id]
            score = env.get_score()
            return {"session_id": session_id, "final_score": score}

        return {
            "session_id": session_id,
            "final_score": 0.001,
            "error": "Session not found.",
        }
    except Exception as e:
        return {
            "session_id": session_id,
            "final_score": 0.001,
            "error": str(e),
        }


# ── Main entry point ─────────────────────────────────────────────
def main(host: str = "0.0.0.0", port: int = 7860):
    """Run the server using uvicorn."""
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=7860)
    args = parser.parse_args()
    main(port=args.port)