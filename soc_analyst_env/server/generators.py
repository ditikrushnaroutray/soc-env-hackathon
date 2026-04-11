"""
Scenario-driven log generator for SOC Analyst Environment.

Loads scenario data from JSON files in the scenarios/ directory.
Falls back to hardcoded generation if the JSON file is not found.
"""

import json
import os
from typing import Any, Dict, List, Optional

# Path to the scenarios directory (relative to this file)
_SCENARIOS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scenarios")


def load_scenario(task_id: str) -> Optional[Dict[str, Any]]:
    """
    Load a scenario JSON file by task_id.

    Args:
        task_id: One of 'task_easy', 'task_medium', 'task_hard'.

    Returns:
        Parsed scenario dict, or None if the file doesn't exist.
    """
    filepath = os.path.join(_SCENARIOS_DIR, f"{task_id}.json")
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


def generate_logs(task_id: str) -> List[Dict[str, Any]]:
    """
    Generate log entries for a given task.

    Loads from scenario JSON first. Falls back to hardcoded logs
    if the scenario file is not found.

    Args:
        task_id: Task identifier (task_easy, task_medium, task_hard).

    Returns:
        List of log entry dicts with keys: timestamp, source_ip,
        request_path, status_code, user_agent.
    """
    scenario = load_scenario(task_id)
    if scenario and "logs" in scenario:
        return scenario["logs"]

    # ── Fallback: hardcoded generation ────────────────────────────
    return _generate_hardcoded_logs(task_id)


def get_expected_keywords(task_id: str) -> List[str]:
    """
    Get expected keywords for reasoning evaluation.

    Args:
        task_id: Task identifier.

    Returns:
        List of keywords the agent's reasoning should mention.
    """
    scenario = load_scenario(task_id)
    if scenario:
        return scenario.get("expected_keywords", [])
    return []


def get_threat_intel(task_id: str) -> List[Dict[str, Any]]:
    """
    Get threat intelligence feed entries for a task.

    Args:
        task_id: Task identifier.

    Returns:
        List of threat intel dicts.
    """
    scenario = load_scenario(task_id)
    if scenario:
        return scenario.get("threat_intel", [])
    return []


def _generate_hardcoded_logs(task_id: str) -> List[Dict[str, Any]]:
    """
    Fallback hardcoded log generation when scenario JSON is missing.

    Deterministic — no randomization for reproducibility.
    """
    # Base normal traffic
    normal_logs = [
        {
            "timestamp": "2026-04-10T08:01:12Z",
            "source_ip": "192.168.1.10",
            "request_path": "/",
            "status_code": 200,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        },
        {
            "timestamp": "2026-04-10T08:01:14Z",
            "source_ip": "192.168.1.15",
            "request_path": "/dashboard",
            "status_code": 200,
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        },
        {
            "timestamp": "2026-04-10T08:01:18Z",
            "source_ip": "192.168.1.22",
            "request_path": "/api/v1/health",
            "status_code": 200,
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        },
        {
            "timestamp": "2026-04-10T08:01:20Z",
            "source_ip": "192.168.1.30",
            "request_path": "/images/logo.png",
            "status_code": 200,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        },
        {
            "timestamp": "2026-04-10T08:01:25Z",
            "source_ip": "192.168.1.40",
            "request_path": "/favicon.ico",
            "status_code": 200,
            "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
        },
    ]

    attack_logs: List[Dict[str, Any]] = []

    if task_id == "task_easy":
        for i in range(5):
            attack_logs.append({
                "timestamp": f"2026-04-10T08:02:0{i}Z",
                "source_ip": "104.22.33.44",
                "request_path": "/api/v1/login",
                "status_code": 401,
                "user_agent": "python-requests/2.28.1",
            })

    elif task_id == "task_medium":
        attack_ips = ["185.33.22.10", "185.33.22.45", "185.33.22.112"]
        paths = [
            "/users?id=1' OR '1'='1",
            "/users?id=1 UNION SELECT username,password FROM users--",
            "/search?q='; DROP TABLE users;--",
        ]
        for ip, path in zip(attack_ips, paths):
            attack_logs.append({
                "timestamp": "2026-04-10T10:15:10Z",
                "source_ip": ip,
                "request_path": path,
                "status_code": 500,
                "user_agent": "sqlmap/1.5.8#stable",
            })

    elif task_id == "task_hard":
        attack_logs.extend([
            {
                "timestamp": "2026-04-10T14:00:10Z",
                "source_ip": "45.11.22.33",
                "request_path": "/admin",
                "status_code": 403,
                "user_agent": "curl/7.68.0",
            },
            {
                "timestamp": "2026-04-10T14:00:18Z",
                "source_ip": "104.22.33.44",
                "request_path": "/api/v1/login",
                "status_code": 401,
                "user_agent": "python-requests/2.28.1",
            },
            {
                "timestamp": "2026-04-10T14:00:22Z",
                "source_ip": "10.0.0.5",
                "request_path": "/health",
                "status_code": 200,
                "user_agent": "InternalMonitor/3.1",
            },
            {
                "timestamp": "2026-04-10T14:00:28Z",
                "source_ip": "10.200.1.1",
                "request_path": "/api/v1/debug",
                "status_code": 404,
                "user_agent": "Nessus/10.4.1",
            },
        ])

    return normal_logs + attack_logs