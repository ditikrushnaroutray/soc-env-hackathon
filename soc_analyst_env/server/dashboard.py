"""
Post-episode ASCII dashboard for SOC Analyst Environment.

Prints a formatted summary report after the [END] log line.
Only called after all structured output is complete.
"""

from typing import Any, Dict


def print_ascii_dashboard(report: Dict[str, Any]) -> None:
    """
    Print a formatted ASCII dashboard summarizing episode metrics.

    This MUST only be called AFTER the [END] log line has been printed,
    so it does not interfere with structured grader output.

    Args:
        report: Telemetry report dict from SOCTelemetry.get_report()
    """
    width = 60

    print("", flush=True)
    print("=" * width, flush=True)
    print("  SOC ANALYST — EPISODE REPORT".center(width), flush=True)
    print("=" * width, flush=True)
    print(flush=True)

    # ── Task Info ──────────────────────────────────────────────
    print(f"  Task ID:          {report.get('task_id', 'N/A')}", flush=True)
    print(f"  Total Steps:      {report.get('total_steps', 0)}", flush=True)
    print(f"  Elapsed Time:     {report.get('elapsed_seconds', 0):.2f}s", flush=True)
    print(flush=True)

    # ── Reward Summary ────────────────────────────────────────
    print("-" * width, flush=True)
    print("  REWARD SUMMARY".center(width), flush=True)
    print("-" * width, flush=True)
    print(f"  Total Reward:     {report.get('total_reward', 0):.3f}", flush=True)
    print(f"  Average Reward:   {report.get('average_reward', 0):.3f}", flush=True)
    print(f"  Avg Reasoning:    {report.get('average_reasoning_score', 0):.3f}", flush=True)
    print(flush=True)

    # ── Detection Metrics ─────────────────────────────────────
    print("-" * width, flush=True)
    print("  DETECTION METRICS".center(width), flush=True)
    print("-" * width, flush=True)
    tp = report.get("true_positives", 0)
    fp = report.get("false_positives", 0)
    esc = report.get("escalations", 0)
    mit = report.get("mitigations", 0)
    errs = report.get("errors", 0)

    print(f"  True Positives:   {tp}", flush=True)
    print(f"  False Positives:  {fp}", flush=True)
    print(f"  Escalations:      {esc}", flush=True)
    print(f"  Mitigations:      {mit}", flush=True)
    print(f"  Errors:           {errs}", flush=True)

    # Precision
    total_detections = tp + fp
    if total_detections > 0:
        precision = tp / total_detections
        print(f"  Precision:        {precision:.1%}", flush=True)
    else:
        print("  Precision:        N/A", flush=True)

    print(flush=True)

    # ── Rewards History ───────────────────────────────────────
    rewards_hist = report.get("rewards_history", [])
    if rewards_hist:
        print("-" * width, flush=True)
        print("  REWARDS TRACE".center(width), flush=True)
        print("-" * width, flush=True)
        for i, r in enumerate(rewards_hist, 1):
            bar_len = int(r * 30)
            bar = "█" * bar_len + "░" * (30 - bar_len)
            print(f"  Step {i:>2}: {bar} {r:.3f}", flush=True)
        print(flush=True)

    # ── Actions Log ───────────────────────────────────────────
    actions_log = report.get("actions_log", [])
    if actions_log:
        print("-" * width, flush=True)
        print("  ACTIONS LOG".center(width), flush=True)
        print("-" * width, flush=True)
        for a in actions_log:
            step = a.get("step", "?")
            atype = a.get("action_type", "?")
            tip = a.get("target_ip", "?")
            rew = a.get("reward", 0)
            msg = a.get("message", "")[:40]
            print(f"  [{step:>2}] {atype:<12} {tip:<18} r={rew:.3f}  {msg}", flush=True)
        print(flush=True)

    print("=" * width, flush=True)
    print("  END OF REPORT".center(width), flush=True)
    print("=" * width, flush=True)
    print(flush=True)
