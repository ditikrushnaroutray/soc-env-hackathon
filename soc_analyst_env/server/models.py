"""
Data models for the SOC Analyst Environment server.

Standalone Pydantic models — no openenv SDK dependency.
"""

from pydantic import BaseModel, Field
from typing import Any, Dict, List, Literal, Optional


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


class SOCObservation(BaseModel):
    """
    Observation returned by the environment to the agent.

    Contains the current state of the server including access logs,
    blocked IPs, system status, reward from last action, episode
    completion flag, and metadata.
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
    reward: float = Field(
        default=0.0,
        description="Reward from the previous action.",
    )
    done: bool = Field(
        default=False,
        description="Whether the episode has terminated.",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata (steps_taken, current_score, message, threat_intel).",
    )


class SOCAction(BaseModel):
    """
    Action submitted by the agent.

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
