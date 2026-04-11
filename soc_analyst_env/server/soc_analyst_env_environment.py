"""
Core SOC Analyst Environment — standalone implementation.

No openenv SDK dependency. Manages sessions, scenario loading,
action evaluation, and score tracking.

All scores are strictly clamped to (0.001, 0.999).
"""

import uuid
from typing import Any, Dict, Optional

from .models import LogEntry, SOCAction, SOCObservation
from .generators import generate_logs, get_expected_keywords, get_threat_intel
from .engine import evaluate_action
from .telemetry import SOCTelemetry

# Try to import agents for threat intel enrichment
try:
    from ..agents import ThreatIntelAgent
except ImportError:
    ThreatIntelAgent = None  # type: ignore[assignment, misc]

MIN_SCORE = 0.001
MAX_SCORE = 0.999

# ── Global session storage ────────────────────────────────────────
SESSIONS: Dict[str, "SOCAnalystEnv"] = {}


def _clamp_score(score: float) -> float:
    """Clamp score to (MIN_SCORE, MAX_SCORE)."""
    return max(MIN_SCORE, min(MAX_SCORE, float(score)))


class SOCAnalystEnv:
    """
    SOC Analyst RL Environment.

    Manages a single episode: loading scenario logs on reset,
    evaluating agent actions on step, tracking cumulative score.
    """

    def __init__(self):
        self.session_id: str = str(uuid.uuid4())
        self.task_id: str = "unknown"
        self.step_count: int = 0
        self.total_score: float = MIN_SCORE
        self.done: bool = False
        self.current_obs: Optional[SOCObservation] = None
        self.telemetry: Optional[SOCTelemetry] = None
        self._expected_keywords: list = []
        self._threat_intel_agent: Any = None

        # Register in global sessions
        SESSIONS[self.session_id] = self

    def reset(self, task_id: str) -> Dict[str, Any]:
        """
        Reset the environment for a new episode.

        Args:
            task_id: Task identifier (task_easy, task_medium, task_hard).

        Returns:
            Dict with session_id and observation.
        """
        self.session_id = str(uuid.uuid4())
        self.task_id = task_id
        self.step_count = 0
        self.total_score = MIN_SCORE
        self.done = False

        # Load scenario data
        raw_logs = generate_logs(task_id)
        parsed_logs = [LogEntry(**log) for log in raw_logs]
        self._expected_keywords = get_expected_keywords(task_id)

        # Load threat intel (Phase 4)
        threat_intel_data = get_threat_intel(task_id)
        threat_intel_enrichment = []
        if ThreatIntelAgent is not None and threat_intel_data:
            self._threat_intel_agent = ThreatIntelAgent()
            self._threat_intel_agent.load_threat_intel(threat_intel_data)
            threat_intel_enrichment = threat_intel_data

        # Determine system status
        has_attack = any(log.status_code >= 400 for log in parsed_logs)
        system_status = "Under Attack" if has_attack else "Normal"

        # Build observation
        self.current_obs = SOCObservation(
            current_logs=parsed_logs,
            blocked_ips=[],
            system_status=system_status,
            reward=0.0,
            done=False,
            metadata={
                "steps_taken": 0,
                "current_score": self.total_score,
                "message": f"Environment reset for {task_id}.",
                "threat_intel": threat_intel_enrichment,
            },
        )

        # Initialize telemetry
        self.telemetry = SOCTelemetry(task_id=task_id)

        # Register with new session_id
        SESSIONS[self.session_id] = self

        return {
            "session_id": self.session_id,
            "observation": self.current_obs.model_dump(),
        }

    def step(self, action: SOCAction) -> Dict[str, Any]:
        """
        Apply an agent action and return the resulting observation.

        Args:
            action: SOCAction with action_type, target_ip, reasoning.

        Returns:
            Dict with observation, reward, done, message.
        """
        if self.current_obs is None:
            # Safety: auto-reset if no observation exists
            return {
                "observation": SOCObservation(
                    metadata={"message": "Error: no active session. Call /reset first."},
                    reward=MIN_SCORE,
                    done=True,
                ).model_dump(),
                "reward": MIN_SCORE,
                "done": True,
                "message": "No active session. Call /reset first.",
            }

        self.step_count += 1

        # Evaluate the action
        reward, done, message = evaluate_action(
            action=action,
            state=self.current_obs,
            expected_keywords=self._expected_keywords,
        )

        # Update total score
        self.total_score += reward
        self.total_score = _clamp_score(self.total_score)

        # Update blocked IPs
        if action.action_type == "block_ip" and action.target_ip not in self.current_obs.blocked_ips:
            self.current_obs.blocked_ips.append(action.target_ip)

        # Check max steps
        if self.step_count >= 10:
            done = True
            message += " | Max steps reached."

        self.done = done

        # Record telemetry
        if self.telemetry:
            is_fp = (
                action.action_type == "block_ip"
                and not any(
                    log.status_code >= 400
                    for log in self.current_obs.current_logs
                    if log.source_ip == action.target_ip
                )
            )
            self.telemetry.record_action(
                step=self.step_count,
                action_type=action.action_type,
                target_ip=action.target_ip,
                reward=reward,
                reasoning_score=1.0,  # Will be enriched when rubrics are wired
                is_false_positive=is_fp,
                message=message,
            )

        # Update observation
        self.current_obs.reward = reward
        self.current_obs.done = done
        self.current_obs.metadata = {
            "steps_taken": self.step_count,
            "current_score": self.total_score,
            "message": message,
        }

        # Enrich with threat intel if available
        if self._threat_intel_agent is not None:
            enriched = self._threat_intel_agent.enrich_observation(
                self.current_obs.model_dump()
            )
            if "metadata" in enriched and "threat_intel" in enriched["metadata"]:
                self.current_obs.metadata["threat_intel"] = enriched["metadata"]["threat_intel"]

        return {
            "observation": self.current_obs.model_dump(),
            "reward": reward,
            "done": done,
            "message": message,
        }

    def get_score(self) -> float:
        """Get the current clamped total score."""
        return _clamp_score(self.total_score)

    def get_telemetry_report(self) -> Dict[str, Any]:
        """Get the telemetry report for this episode."""
        if self.telemetry:
            return self.telemetry.get_report()
        return {"task_id": self.task_id, "error": "No telemetry available."}