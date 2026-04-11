"""
Core evaluation engine for the SOC Analyst Environment.

Grades agent actions against the current environment state.
All rewards are strictly clamped to (0.001, 0.999).
"""

from typing import Optional, Tuple

from .models import SOCAction, SOCObservation

# Try to import rubrics; graceful fallback if unavailable
try:
    from .rubrics import evaluate_reasoning
except ImportError:
    evaluate_reasoning = None  # type: ignore[assignment]


MIN_REWARD = 0.001
MAX_REWARD = 0.999


def _clamp(value: float) -> float:
    """Clamp a value to (MIN_REWARD, MAX_REWARD)."""
    return max(MIN_REWARD, min(MAX_REWARD, float(value)))


def evaluate_action(
    action: SOCAction,
    state: SOCObservation,
    expected_keywords: Optional[list] = None,
) -> Tuple[float, bool, str]:
    """
    Evaluate an agent's action against the current observation state.

    Args:
        action: The agent's SOCAction (action_type, target_ip, reasoning).
        state: Current SOCObservation with logs and blocked IPs.
        expected_keywords: Optional keywords for reasoning evaluation.

    Returns:
        Tuple of (reward, done, message):
          - reward: float in (0.001, 0.999)
          - done: bool (always True — 1-shot episode per action)
          - message: str explanation of the grading
    """
    # ── 1. Check if target IP exists in current logs ──────────────
    target_logs = [
        log for log in state.current_logs
        if log.source_ip == action.target_ip
    ]

    if not target_logs:
        return (
            MIN_REWARD,
            True,
            f"Penalty: target IP {action.target_ip} not found in current logs.",
        )

    # ── 2. Determine if the IP is malicious ───────────────────────
    is_malicious = any(log.status_code >= 400 for log in target_logs)

    # ── 3. Grade the action ───────────────────────────────────────
    reward = MIN_REWARD
    done = True  # 1-shot: every action terminates the episode
    message = ""

    if action.action_type == "block_ip":
        if is_malicious:
            reward = MAX_REWARD
            message = f"Success: blocked malicious IP {action.target_ip}."
        else:
            reward = MIN_REWARD
            message = f"Critical failure: blocked normal user {action.target_ip}."

    elif action.action_type == "allow_ip":
        if is_malicious:
            reward = MIN_REWARD
            message = f"Critical failure: allowed malicious IP {action.target_ip} to continue."
        else:
            reward = MAX_REWARD
            message = f"Correct: allowed normal traffic from {action.target_ip}."

    elif action.action_type == "escalate":
        reward = 0.500
        message = f"Escalated {action.target_ip} to human analyst. Partial credit."

    else:
        reward = MIN_REWARD
        message = f"Unknown action type: {action.action_type}."

    # ── 4. Apply reasoning multiplier (if rubrics available) ──────
    if evaluate_reasoning is not None and action.reasoning:
        reasoning_multiplier = evaluate_reasoning(
            reasoning=action.reasoning,
            expected_keywords=expected_keywords or [],
        )
        reward = reward * reasoning_multiplier

    # ── 5. Final clamp ────────────────────────────────────────────
    reward = _clamp(reward)

    return reward, done, message