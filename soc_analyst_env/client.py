"""
SOC Analyst Environment Client.

Standalone HTTP client for interacting with the SOC Analyst Environment
server. No openenv SDK dependency.
"""

import requests
from typing import Any, Dict, Optional


class SOCAnalystClient:
    """
    HTTP client for the SOC Analyst Environment.

    Provides methods to reset/step the environment via REST API.
    """

    def __init__(self, base_url: str = "http://localhost:7860", timeout: int = 10):
        """
        Initialize the client.

        Args:
            base_url: URL of the SOC Analyst Environment server.
            timeout: HTTP request timeout in seconds.
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session_id: Optional[str] = None

    def health(self) -> Dict[str, Any]:
        """Check server health."""
        resp = requests.get(f"{self.base_url}/health", timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def get_tasks(self) -> Dict[str, Any]:
        """Get available tasks."""
        resp = requests.get(f"{self.base_url}/tasks", timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def reset(self, task_id: str) -> Dict[str, Any]:
        """
        Reset the environment for a new episode.

        Args:
            task_id: Task identifier (task_easy, task_medium, task_hard).

        Returns:
            Dict with session_id and observation.
        """
        resp = requests.post(
            f"{self.base_url}/reset",
            json={"task_id": task_id},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        self.session_id = data.get("session_id")
        return data

    def step(
        self,
        action_type: str,
        target_ip: str,
        reasoning: str = "",
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Submit an action and get the next observation.

        Args:
            action_type: "block_ip", "allow_ip", or "escalate".
            target_ip: IP address to act on.
            reasoning: Explanation for the action.
            session_id: Optional override for session_id.

        Returns:
            Dict with observation, reward, done, message.
        """
        sid = session_id or self.session_id
        if not sid:
            raise ValueError("No session_id. Call reset() first.")

        resp = requests.post(
            f"{self.base_url}/step",
            json={
                "session_id": sid,
                "action": {
                    "action_type": action_type,
                    "target_ip": target_ip,
                    "reasoning": reasoning,
                },
            },
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def get_score(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Get the grader score for a session."""
        sid = session_id or self.session_id
        resp = requests.get(
            f"{self.base_url}/grader",
            params={"session_id": sid or ""},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()
