"""
Reasoning rubrics for SOC Analyst Environment.

Evaluates the quality of an agent's reasoning to produce a reward multiplier.
The multiplier adjusts the base reward from engine.evaluate_action.

Multiplier range: [0.5, 1.0]
  - 1.0 = excellent reasoning with relevant keywords and sufficient detail
  - 0.5 = minimal or absent reasoning
"""

from typing import List, Optional


def evaluate_reasoning(
    reasoning: str,
    expected_keywords: Optional[List[str]] = None,
) -> float:
    """
    Evaluate the quality of an agent's reasoning string.

    Uses keyword matching and basic heuristics (length, specificity)
    to produce a multiplier in [0.5, 1.0].

    Args:
        reasoning: The agent's explanation for its action.
        expected_keywords: Keywords that a good explanation should mention.

    Returns:
        A float multiplier in [0.5, 1.0].
    """
    if not reasoning or not reasoning.strip():
        return 0.5

    score = 0.0
    reasoning_lower = reasoning.lower().strip()

    # ── 1. Length heuristic (0–0.2) ──────────────────────────────────────
    word_count = len(reasoning_lower.split())
    if word_count >= 20:
        score += 0.20
    elif word_count >= 10:
        score += 0.15
    elif word_count >= 5:
        score += 0.10
    else:
        score += 0.05

    # ── 2. Keyword matching (0–0.3) ──────────────────────────────────────
    if expected_keywords:
        matched = sum(
            1 for kw in expected_keywords if kw.lower() in reasoning_lower
        )
        keyword_ratio = matched / len(expected_keywords) if expected_keywords else 0
        score += 0.30 * keyword_ratio
    else:
        # No expected keywords provided — give partial credit
        score += 0.15

    # ── 3. Technical specificity (0–0.25) ─────────────────────────────────
    technical_markers = [
        "status_code", "status code", "status",
        "ip", "address",
        "request", "path", "endpoint",
        "user_agent", "user agent",
        "attack", "malicious", "suspicious", "threat",
        "block", "allow", "escalate",
        "401", "403", "500", "200",
        "brute", "force", "injection", "sql",
    ]
    tech_matches = sum(1 for m in technical_markers if m in reasoning_lower)
    tech_ratio = min(tech_matches / 5.0, 1.0)  # Cap at 5 markers
    score += 0.25 * tech_ratio

    # ── 4. Coherence heuristic (0–0.25) ───────────────────────────────────
    # Reward structured reasoning patterns
    coherence_markers = [
        "because", "therefore", "indicates", "suggests",
        "detected", "found", "observed", "noticed",
        "attempt", "pattern", "multiple", "repeated",
    ]
    coherence_matches = sum(1 for m in coherence_markers if m in reasoning_lower)
    coherence_ratio = min(coherence_matches / 3.0, 1.0)  # Cap at 3 markers
    score += 0.25 * coherence_ratio

    # ── Clamp to [0.5, 1.0] ───────────────────────────────────────────────
    # raw score is [0, 1.0]; map to [0.5, 1.0]
    multiplier = 0.5 + (score * 0.5)
    return max(0.5, min(1.0, multiplier))
