"""
SOC Telemetry — records per-episode metrics for post-episode analysis.

Tracks actions, rewards, reasoning quality, false positives, mitigations,
and produces a summary report consumable by the dashboard.
"""

from typing import Any, Dict, List, Optional
import time


class SOCTelemetry:
    """Records per-episode SOC analyst actions and metrics."""

    def __init__(self, task_id: str = "unknown"):
        self.task_id = task_id
        self.start_time = time.time()
        self.actions: List[Dict[str, Any]] = []
        self.rewards: List[float] = []
        self.reasoning_scores: List[float] = []
        self.false_positives: int = 0
        self.true_positives: int = 0
        self.escalations: int = 0
        self.mitigations: int = 0
        self.errors: int = 0

    def record_action(
        self,
        step: int,
        action_type: str,
        target_ip: str,
        reward: float,
        reasoning_score: float = 1.0,
        is_false_positive: bool = False,
        message: str = "",
    ) -> None:
        """Record a single agent action and its outcome."""
        self.actions.append({
            "step": step,
            "action_type": action_type,
            "target_ip": target_ip,
            "reward": reward,
            "reasoning_score": reasoning_score,
            "is_false_positive": is_false_positive,
            "message": message,
            "timestamp": time.time(),
        })
        self.rewards.append(reward)
        self.reasoning_scores.append(reasoning_score)

        if is_false_positive:
            self.false_positives += 1

        if action_type == "block_ip" and reward > 0.5:
            self.true_positives += 1
            self.mitigations += 1
        elif action_type == "escalate":
            self.escalations += 1
        elif action_type == "block_ip" and reward <= 0.1:
            self.false_positives += 1

    def record_error(self, step: int, error_msg: str) -> None:
        """Record an error during episode execution."""
        self.errors += 1
        self.actions.append({
            "step": step,
            "action_type": "error",
            "target_ip": "N/A",
            "reward": 0.001,
            "reasoning_score": 0.0,
            "is_false_positive": False,
            "message": error_msg,
            "timestamp": time.time(),
        })

    def get_report(self) -> Dict[str, Any]:
        """
        Produce a summary report dict for the dashboard.

        Returns:
            Dict containing episode metrics and statistics.
        """
        elapsed = time.time() - self.start_time
        total_reward = sum(self.rewards) if self.rewards else 0.0
        avg_reward = total_reward / len(self.rewards) if self.rewards else 0.0
        avg_reasoning = (
            sum(self.reasoning_scores) / len(self.reasoning_scores)
            if self.reasoning_scores
            else 0.0
        )

        return {
            "task_id": self.task_id,
            "total_steps": len(self.actions),
            "elapsed_seconds": round(elapsed, 2),
            "total_reward": round(total_reward, 3),
            "average_reward": round(avg_reward, 3),
            "average_reasoning_score": round(avg_reasoning, 3),
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "escalations": self.escalations,
            "mitigations": self.mitigations,
            "errors": self.errors,
            "rewards_history": [round(r, 3) for r in self.rewards],
            "actions_log": self.actions,
        }
