"""
Data models for the SOC Analyst Environment server.

Inherits from openenv-core SDK base classes (Action, Observation)
so that the Phase 3 autograder can verify class hierarchy.
"""

from pydantic import BaseModel, Field
from typing import Any, Dict, List, Literal, Optional

from openenv.core import Action, Observation


# ── Log entry (plain Pydantic, not an SDK type) ──────────────────

class HealthCheck(BaseModel):
    """Health check response model."""
    status: str = "ok"


class LogEntry(BaseModel):
    """A single server access log entry."""
    timestamp: str
    source_ip: str
    request_path: str
    status_code: int
    user_agent: str


# ── Observation (inherits from openenv.core.Observation) ─────────

class SOCObservation(Observation):
    """
    Observation returned by the environment to the agent.

    Inherits done, reward, metadata from openenv.core.Observation.
    Adds SOC-specific fields: current_logs, blocked_ips, system_status.
    """
    current_logs: List[LogEntry] = Field(
        default_factory=list,
        description="The latest batch of server access logs to analyze.",
    )
    blocked_ips: List[str] = Field(
        default_factory=list,
        description="A list of IP addresses currently blocked by the firewall.",
    )
    system_status: str = Field(
        default="Normal",
        description="Current health of the server (e.g., 'Normal', 'Under Attack').",
    )


# ── Action (inherits from openenv.core.Action) ──────────────────

class SOCAction(Action):
    """
    Action submitted by the agent.

    Inherits metadata from openenv.core.Action.
    Must specify an action type, target IP, and reasoning.
    """
    action_type: Literal["block_ip", "allow_ip", "escalate"] = Field(
        description="The action to take. 'block_ip' bans the IP. 'allow_ip' marks it safe. 'escalate' flags it for a human.",
    )
    target_ip: str = Field(
        description="The IP address to apply the action to.",
    )
    reasoning: str = Field(
        default="",
        description="A brief explanation of why this action was taken.",
    )


# ── Request / Response models (plain Pydantic for FastAPI) ───────

class ResetRequest(BaseModel):
    """Request body for the /reset endpoint."""
    task_id: str = Field(description="Task identifier (task_easy, task_medium, task_hard).")


class StepRequest(BaseModel):
    """Request body for the /step endpoint."""
    session_id: str = Field(description="Session identifier from /reset response.")
    action: SOCAction = Field(description="The agent's action to apply.")


class ResetResponse(BaseModel):
    """Response body from the /reset endpoint."""
    session_id: str
    observation: Dict[str, Any]


class StepResponse(BaseModel):
    """Response body from the /step endpoint."""
    observation: Dict[str, Any]
    reward: float
    done: bool
    message: str = ""
