"""
Core SOC Analyst Environment — inherits from openenv.core.Environment.

Manages sessions, scenario loading, action evaluation, and score tracking.
All scores are strictly clamped to (0.001, 0.999).
"""

import uuid
from typing import Any, Dict, Optional

from openenv.core import Environment, State

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


class SOCAnalystEnv(Environment[SOCAction, SOCObservation, State]):
    """
    SOC Analyst RL Environment.

    Inherits from openenv.core.Environment with proper generic types.
    Manages a single episode: loading scenario logs on reset,
    evaluating agent actions on step, tracking cumulative score.
    """

    SUPPORTS_CONCURRENT_SESSIONS: bool = True

    def __init__(self):
        super().__init__()
        self._state = State(episode_id=str(uuid.uuid4()), step_count=0)
        self.task_id: str = "unknown"
        self.total_score: float = MIN_SCORE
        self.current_obs: Optional[SOCObservation] = None
        self.telemetry: Optional[SOCTelemetry] = None
        self._expected_keywords: list = []
        self._threat_intel_agent: Any = None

        self.session_id: str = self._state.episode_id
        # Register in global sessions
        SESSIONS[self.session_id] = self

    # ── OpenEnv SDK required: reset() ─────────────────────────────

    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        **kwargs: Any,
    ) -> SOCObservation:
        """
        Reset the environment for a new episode.

        Conforms to openenv.core.Environment.reset() signature.
        Accepts task_id via kwargs.
        """
        self.task_id = kwargs.get("task_id", self.task_id)
        self._state = State(
            episode_id=episode_id or str(uuid.uuid4()),
            step_count=0,
        )
        self.total_score = MIN_SCORE
        self.session_id = self._state.episode_id

        # Register with new session_id
        SESSIONS[self.session_id] = self

        # Load scenario data
        raw_logs = generate_logs(self.task_id)
        parsed_logs = [LogEntry(**log) for log in raw_logs]
        self._expected_keywords = get_expected_keywords(self.task_id)

        # Load threat intel (Phase 4)
        threat_intel_data = get_threat_intel(self.task_id)
        threat_intel_enrichment: list = []
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
                "message": f"Environment reset for {self.task_id}.",
                "threat_intel": threat_intel_enrichment,
            },
        )

        # Initialize telemetry
        self.telemetry = SOCTelemetry(task_id=self.task_id)

        return self.current_obs

    # ── OpenEnv SDK required: step() ──────────────────────────────

    def step(
        self,
        action: SOCAction,
        timeout_s: Optional[float] = None,
        **kwargs: Any,
    ) -> SOCObservation:
        """
        Apply an agent action and return the resulting observation.

        Conforms to openenv.core.Environment.step() signature.
        """
        if self.current_obs is None:
            # Safety: auto-reset if no observation exists
            self.current_obs = SOCObservation(
                metadata={"message": "Error: no active session. Call /reset first."},
                reward=MIN_SCORE,
                done=True,
            )
            return self.current_obs

        self._state.step_count += 1

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
        if self._state.step_count >= 10:
            done = True
            message += " | Max steps reached."

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
                step=self._state.step_count,
                action_type=action.action_type,
                target_ip=action.target_ip,
                reward=reward,
                reasoning_score=1.0,
                is_false_positive=is_fp,
                message=message,
            )

        # Update observation (uses inherited done/reward/metadata from SDK)
        self.current_obs.reward = reward
        self.current_obs.done = done
        self.current_obs.metadata = {
            "steps_taken": self._state.step_count,
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

        return self.current_obs

    # ── OpenEnv SDK required: state property ──────────────────────

    @property
    def state(self) -> State:
        """Get the current environment state."""
        return self._state

    # ── Helper methods ────────────────────────────────────────────

    def get_score(self) -> float:
        """Get the current clamped total score."""
        return _clamp_score(self.total_score)

    def get_telemetry_report(self) -> Dict[str, Any]:
        """Get the telemetry report for this episode."""
        if self.telemetry:
            return self.telemetry.get_report()
        return {"task_id": self.task_id, "error": "No telemetry available."}