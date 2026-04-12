"""
Core SOC Analyst Environment — inherits from openenv.core.Environment.

Manages sessions, scenario loading, action evaluation, and score tracking.
All scores are strictly clamped to (0.001, 0.999).

Phase 2 — Kill-Chain State Tracking
─────────────────────────────────────
On ``reset()``, the environment now:
  1. Preserves the **raw** log dicts from ``generate_logs()`` (which
     carry the hidden ``attack_stage`` / ``mitre_technique`` metadata).
  2. Builds an ``_ip_stage_map`` — a lookup from IP address to the
     list of raw log entries originating from that IP.  Only entries
     with a non-benign ``attack_stage`` are included.
  3. Computes the current kill chain stage (latest non-benign stage
     seen in the log sequence).
  4. Passes ``_ip_stage_map`` to the engine's ``evaluate_action()``
     on every ``step()`` call so the engine can weight rewards by
     kill chain severity.
  5. Exposes kill-chain metadata in the observation's ``metadata``
     dict for downstream consumers (dashboard, telemetry, agents).
"""

import uuid
from typing import Any, Dict, List, Optional

from openenv.core import Environment, State

from .models import LogEntry, SOCAction, SOCObservation
from .generators import generate_logs, get_expected_keywords, get_threat_intel, KILL_CHAIN_STAGES
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


def _build_ip_stage_map(
    raw_logs: List[Dict[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    """Build a mapping of IP → [raw log entries with attack metadata].

    Only entries whose ``attack_stage`` is a valid (non-benign) kill
    chain stage are included.  This allows the engine to look up the
    highest-severity stage associated with any IP the agent targets.
    """
    ip_map: Dict[str, List[Dict[str, Any]]] = {}
    for log in raw_logs:
        stage = log.get("attack_stage")
        if stage and stage != "benign":
            ip = log.get("source_ip", "")
            if ip:
                ip_map.setdefault(ip, []).append(log)
    return ip_map


def _compute_kill_chain_state(
    raw_logs: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Analyse raw logs to produce a kill-chain status summary.

    Returns a dict suitable for inclusion in observation metadata:
    {
        "active": true/false,
        "current_stage": "exfiltration",
        "current_stage_index": 7,
        "total_stages": 8,
        "stages_detected": ["reconnaissance", "initial_access", ...],
        "adversary_ips": ["198.51.100.14", ...],
        "techniques_observed": ["T1595", "T1078", ...],
    }
    """
    detected_stages: List[str] = []
    adversary_ips: set = set()
    techniques: set = set()

    for log in raw_logs:
        stage = log.get("attack_stage")
        if stage and stage != "benign":
            if stage not in detected_stages:
                detected_stages.append(stage)
            adversary_ips.add(log.get("source_ip", ""))
            technique = log.get("mitre_technique")
            if technique:
                techniques.add(technique)

    # Determine the latest stage based on canonical ordering.
    current_stage: Optional[str] = None
    current_index: int = -1
    for stage in detected_stages:
        if stage in KILL_CHAIN_STAGES:
            idx = KILL_CHAIN_STAGES.index(stage)
            if idx > current_index:
                current_index = idx
                current_stage = stage

    return {
        "active": len(detected_stages) > 0,
        "current_stage": current_stage,
        "current_stage_index": current_index if current_index >= 0 else None,
        "total_stages": len(KILL_CHAIN_STAGES),
        "stages_detected": detected_stages,
        "adversary_ips": sorted(adversary_ips),
        "techniques_observed": sorted(techniques),
    }


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

        # Phase 2: kill-chain state
        self._raw_logs: List[Dict[str, Any]] = []
        self._ip_stage_map: Dict[str, List[Dict[str, Any]]] = {}
        self._kill_chain_state: Dict[str, Any] = {}

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

        # Load scenario data — keep raw dicts for kill-chain metadata
        self._raw_logs = generate_logs(self.task_id, seed_key=self.session_id)
        parsed_logs = [LogEntry(**log) for log in self._raw_logs]
        self._expected_keywords = get_expected_keywords(self.task_id)

        # Phase 2: build kill-chain lookup structures
        self._ip_stage_map = _build_ip_stage_map(self._raw_logs)
        self._kill_chain_state = _compute_kill_chain_state(self._raw_logs)

        # Load threat intel (Phase 4)
        threat_intel_data = get_threat_intel(self.task_id, seed_key=self.session_id)
        threat_intel_enrichment: list = []
        if ThreatIntelAgent is not None and threat_intel_data:
            self._threat_intel_agent = ThreatIntelAgent()
            self._threat_intel_agent.load_threat_intel(threat_intel_data)
            threat_intel_enrichment = threat_intel_data

        # Determine system status using both legacy heuristic and
        # kill-chain awareness.
        has_attack = any(log.status_code >= 400 for log in parsed_logs)
        kill_chain_active = self._kill_chain_state.get("active", False)

        if kill_chain_active:
            current_stage = self._kill_chain_state.get("current_stage", "unknown")
            system_status = f"Under Attack — Kill Chain Stage: {current_stage}"
        elif has_attack:
            system_status = "Under Attack"
        else:
            system_status = "Normal"

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
                "kill_chain": self._kill_chain_state,
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

        # Evaluate the action — pass ip_stage_map for kill-chain
        # aware scoring.
        reward, done, message = evaluate_action(
            action=action,
            state=self.current_obs,
            expected_keywords=self._expected_keywords,
            ip_stage_map=self._ip_stage_map,
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
                and action.target_ip not in self._ip_stage_map
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
            "kill_chain": self._kill_chain_state,
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
            report = self.telemetry.get_report()
            # Enrich telemetry with kill-chain state
            report["kill_chain"] = self._kill_chain_state
            return report
        return {"task_id": self.task_id, "error": "No telemetry available."}

    def get_kill_chain_state(self) -> Dict[str, Any]:
        """Get the current kill chain analysis state."""
        return self._kill_chain_state