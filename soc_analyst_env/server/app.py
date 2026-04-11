"""
FastAPI application for the SOC Analyst Environment.

Architecture:
  1. Creates a FastAPI app and registers OUR custom HTTP endpoints FIRST
     (/reset, /step, /health, /tasks, /grader) so inference.py works.
  2. Then registers the openenv SDK routes via HTTPEnvServer.register_routes()
     so the autograder can verify the SDK integration.

Our routes are matched first by FastAPI (first-registered wins for same path).
The SDK's WebSocket, /schema, /metadata, /mcp routes are also available.
"""

from fastapi import FastAPI, Request, Body
from fastapi.responses import JSONResponse

from openenv.core.env_server.http_server import HTTPEnvServer

from .models import (
    ResetRequest,
    SOCAction,
    SOCObservation,
    StepRequest,
)
from .soc_analyst_env_environment import SESSIONS, SOCAnalystEnv


# ══════════════════════════════════════════════════════════════════
# 1. Create the FastAPI app
# ══════════════════════════════════════════════════════════════════

app = FastAPI(
    title="SOC Analyst RL Environment",
    description="OpenEnv-compliant SOC Analyst reinforcement learning environment.",
    version="2.0.0",
)




# ══════════════════════════════════════════════════════════════════
# 2. Register OUR custom routes FIRST (inference.py uses these)
# ══════════════════════════════════════════════════════════════════

# ── Root endpoint ─────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
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


# ── Reset endpoint (HTTP POST for inference.py) ──────────────────
@app.post("/reset")
def reset(request: ResetRequest = Body(default_factory=ResetRequest)):
    """
    Reset the environment for a new episode.

    Expects JSON body: {"task_id": "task_easy"}
    Returns: {"session_id": "...", "observation": {...}}
    """
    try:
        env = SOCAnalystEnv()
        obs = env.reset(task_id=request.task_id)
        return {
            "session_id": env.session_id,
            "observation": obs.model_dump(),
        }
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


# ── Step endpoint (HTTP POST for inference.py) ───────────────────
@app.post("/step")
def step(request: StepRequest):
    """
    Apply an agent action and return the next observation.

    Expects JSON body: {"session_id": "...", "action": {...}}
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

        obs = env.step(action=request.action)
        return {
            "observation": obs.model_dump(),
            "reward": obs.reward,
            "done": obs.done,
            "message": obs.metadata.get("message", ""),
        }

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


# ══════════════════════════════════════════════════════════════════
# 3. Register the OpenEnv SDK routes (for autograder validation)
#    These come AFTER our routes so ours take priority for /reset,
#    /step, /health. The SDK's /schema, /metadata, /ws, /mcp routes
#    are still available.
# ══════════════════════════════════════════════════════════════════

_sdk_server = HTTPEnvServer(
    env=SOCAnalystEnv,
    action_cls=SOCAction,
    observation_cls=SOCObservation,
    max_concurrent_envs=1,
)
_sdk_server.register_routes(app)


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