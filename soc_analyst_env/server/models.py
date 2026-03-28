from pydantic import BaseModel, Field
from typing import List, Literal

class LogEntry(BaseModel):
    timestamp: str
    source_ip: str
    request_path: str
    status_code: int
    user_agent: str

class SOCObservation(BaseModel):
    current_logs: List[LogEntry] = Field(description="The latest batch of server access logs to analyze.")
    blocked_ips: List[str] = Field(description="A list of IP addresses currently blocked by the firewall.")
    system_status: str = Field(description="Current health of the server (e.g., 'Normal', 'Under Attack').")

class SOCAction(BaseModel):
    action_type: Literal["block_ip", "allow_ip", "escalate"] = Field(
        description="The action to take. 'block_ip' bans the IP. 'allow_ip' marks it safe. 'escalate' flags it for a human."
    )
    target_ip: str = Field(description="The IP address to apply the action to.")
    reasoning: str = Field(description="A brief explanation of why this action was taken.")