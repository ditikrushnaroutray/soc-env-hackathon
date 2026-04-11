"""
Core evaluation engine for the SOC Analyst Environment.

Grades agent actions against the current environment state.
All rewards are strictly clamped to (0.001, 0.999).

Phase 2 — Kill-Chain-Aware Scoring
────────────────────────────────────
When the environment supplies an ``ip_stage_map`` (built from the hidden
``attack_stage`` / ``mitre_technique`` metadata produced by generators),
the engine applies tiered reward multipliers:

  ┌─────────────────────────┬────────────┬───────────────────────────┐
  │ Kill Chain Tier         │ Multiplier │ Stages                    │
  ├─────────────────────────┼────────────┼───────────────────────────┤
  │ Critical  (block ASAP)  │ 1.00       │ exfiltration, collection  │
  │ High                    │ 0.90       │ privilege_escalation,     │
  │                         │            │ defense_evasion           │
  │ Medium                  │ 0.75       │ persistence, execution    │
  │ Low                     │ 0.55       │ initial_access            │
  │ Noise                   │ 0.35       │ reconnaissance            │
  │ Benign (false positive) │   —        │ benign                    │
  └─────────────────────────┴────────────┴───────────────────────────┘

If ``ip_stage_map`` is empty or ``None`` the engine falls back to the
original status-code-only heuristic, preserving backward compatibility
with task_easy / task_medium / scenario-JSON workflows.

Phase 2 Bug-Fix — Multi-Step Episode Termination
──────────────────────────────────────────────────
Episodes with kill-chain metadata (task_hard) are **multi-step**.
``done`` is only set to ``True`` when:

  1. The agent blocks/handles a **terminal** stage (exfiltration,
     collection) — mission accomplished.
  2. The agent makes a **catastrophic** mistake (blocking a benign
     IP, allowing a critical-tier attacker).
  3. The maximum step limit is reached (enforced by the environment).

For non-terminal stages the engine returns ``done=False``, allowing
the episode to continue through the full kill chain.
"""

from typing import Any, Dict, List, Optional, Tuple

from .models import SOCAction, SOCObservation

# Try to import rubrics; graceful fallback if unavailable
try:
    from .rubrics import evaluate_reasoning
except ImportError:
    evaluate_reasoning = None  # type: ignore[assignment]


MIN_REWARD = 0.001
MAX_REWARD = 0.999

# ── Kill-chain stage → reward weight ─────────────────────────────
# Higher weight = more critical to block.  Values chosen so that the
# final clamped reward stays strictly inside (0.001, 0.999).
_STAGE_WEIGHTS: Dict[str, float] = {
    "exfiltration":         1.00,
    "collection":           0.95,
    "defense_evasion":      0.90,
    "privilege_escalation": 0.90,
    "persistence":          0.75,
    "execution":            0.75,
    "initial_access":       0.55,
    "reconnaissance":       0.35,
    # "benign" is intentionally absent — blocking benign is penalised.
}

# Stages that terminate the episode when successfully handled.
# These represent the adversary's end-goal — once the agent blocks
# the exfiltration or collection stage, the mission is complete.
_TERMINAL_STAGES = frozenset({"exfiltration", "collection"})

# Stages where *allowing* the attacker is catastrophic enough to
# end the episode immediately with a heavy penalty.
_CATASTROPHIC_ALLOW_STAGES = frozenset({
    "exfiltration", "collection", "defense_evasion", "privilege_escalation",
})

# Convenience constant for the fallback when no stage metadata exists.
_DEFAULT_MALICIOUS_WEIGHT = 1.00


def _clamp(value: float) -> float:
    """Clamp a value to (MIN_REWARD, MAX_REWARD)."""
    return max(MIN_REWARD, min(MAX_REWARD, float(value)))


def _highest_stage_for_ip(
    target_ip: str,
    ip_stage_map: Dict[str, List[Dict[str, Any]]],
) -> Tuple[Optional[str], float]:
    """Return the most critical attack stage for a given IP.

    An IP may appear in multiple kill chain stages (e.g. the same
    adversary IP is used for both initial_access and execution).
    We return the *highest-weight* stage.

    Returns:
        Tuple of (stage_name | None, weight).
        ``None`` is returned when the IP has no attack-stage entries
        or is tagged as ``"benign"`` only.
    """
    entries = ip_stage_map.get(target_ip, [])
    if not entries:
        return None, 0.0

    best_stage: Optional[str] = None
    best_weight: float = 0.0

    for entry in entries:
        stage = entry.get("attack_stage", "benign")
        weight = _STAGE_WEIGHTS.get(stage, 0.0)
        if weight > best_weight:
            best_weight = weight
            best_stage = stage

    return best_stage, best_weight


def evaluate_action(
    action: SOCAction,
    state: SOCObservation,
    expected_keywords: Optional[list] = None,
    ip_stage_map: Optional[Dict[str, List[Dict[str, Any]]]] = None,
) -> Tuple[float, bool, str]:
    """
    Evaluate an agent's action against the current observation state.

    Args:
        action: The agent's SOCAction (action_type, target_ip, reasoning).
        state: Current SOCObservation with logs and blocked IPs.
        expected_keywords: Optional keywords for reasoning evaluation.
        ip_stage_map: Optional mapping of IP → list of raw log dicts
                      (each carrying ``attack_stage`` / ``mitre_technique``).
                      Built by the environment from generators' output.

    Returns:
        Tuple of (reward, done, message):
          - reward: float in (0.001, 0.999)
          - done: bool — True only for terminal conditions
                  (see module docstring for termination rules)
          - message: str explanation of the grading
    """
    ip_stage_map = ip_stage_map or {}

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

    # ── 2. Determine maliciousness via kill-chain metadata ────────
    stage, stage_weight = _highest_stage_for_ip(action.target_ip, ip_stage_map)

    # If we have stage metadata, use it; otherwise fall back to
    # the original status-code heuristic.
    has_stage_data = stage is not None
    is_malicious: bool

    if has_stage_data:
        # Stage metadata exists — IP is malicious if it has *any*
        # non-benign stage entry.
        is_malicious = True
    else:
        # Legacy path: no kill-chain metadata (task_easy, task_medium,
        # or scenario JSON without tags).
        is_malicious = any(log.status_code >= 400 for log in target_logs)
        stage_weight = _DEFAULT_MALICIOUS_WEIGHT if is_malicious else 0.0

    # ── 3. Determine episode termination mode ─────────────────────
    # Legacy (no stage data): 1-shot — every action ends the episode.
    # Kill-chain mode: multi-step — only terminal conditions end it.
    # NOTE: This is an EPISODE-level decision — if the episode has
    # *any* kill-chain metadata, all actions (even against benign IPs)
    # participate in multi-step mode.
    is_multi_step = bool(ip_stage_map)  # True when episode has kill-chain data

    # ── 4. Grade the action ───────────────────────────────────────
    reward = MIN_REWARD
    done = not is_multi_step  # legacy default: True; kill-chain default: False
    message = ""

    if action.action_type == "block_ip":
        if is_malicious:
            # Tiered reward based on kill-chain severity.
            # stage_weight ranges from 0.35 (recon) to 1.0 (exfil).
            # We map that into (0.35 * MAX_REWARD .. MAX_REWARD).
            reward = MAX_REWARD * stage_weight
            stage_label = f" [{stage}]" if stage else ""
            message = (
                f"Success: blocked malicious IP {action.target_ip}"
                f"{stage_label}. Stage weight: {stage_weight:.2f}."
            )
            # Terminal: blocking a final-stage IP ends the episode.
            if stage in _TERMINAL_STAGES:
                done = True
                message += " Kill chain terminal stage neutralised — episode complete."
        else:
            # Catastrophic: blocking a benign user always ends the episode.
            reward = MIN_REWARD
            done = True
            message = f"Critical failure: blocked normal user {action.target_ip}."

    elif action.action_type == "allow_ip":
        if is_malicious:
            # Allowing a late-stage attacker is catastrophic.
            # Penalty scales inversely with stage severity.
            penalty_severity = 1.0 - (stage_weight * 0.5)
            reward = MIN_REWARD * penalty_severity
            stage_label = f" [{stage}]" if stage else ""
            message = (
                f"Critical failure: allowed malicious IP "
                f"{action.target_ip}{stage_label} to continue."
            )
            # Catastrophic: allowing a critical-tier attacker ends the
            # episode (the breach is now unrecoverable).
            if stage in _CATASTROPHIC_ALLOW_STAGES:
                done = True
                message += " Catastrophic — attack reached critical stage unimpeded."
        else:
            reward = MAX_REWARD
            message = f"Correct: allowed normal traffic from {action.target_ip}."
            # Correctly allowing benign traffic is good — episode continues.

    elif action.action_type == "escalate":
        # Escalation is always partial credit, but slightly better
        # for high-severity stages (the analyst correctly flagged
        # something important, even if they didn't block it).
        if has_stage_data and stage_weight >= 0.75:
            reward = 0.600
            message = (
                f"Escalated high-severity IP {action.target_ip} [{stage}] "
                f"to human analyst. Good judgement — partial credit."
            )
        else:
            reward = 0.500
            message = f"Escalated {action.target_ip} to human analyst. Partial credit."
        # Escalation never terminates — the agent can keep going.

    else:
        reward = MIN_REWARD
        message = f"Unknown action type: {action.action_type}."

    # ── 5. Apply reasoning multiplier (if rubrics available) ──────
    if evaluate_reasoning is not None and action.reasoning:
        reasoning_multiplier = evaluate_reasoning(
            reasoning=action.reasoning,
            expected_keywords=expected_keywords or [],
        )
        reward = reward * reasoning_multiplier

    # ── 6. Final clamp ────────────────────────────────────────────
    reward = _clamp(reward)

    return reward, done, message