"""
SOC Analyst Agents — skeleton module for multi-agent and threat-intel.

Provides base agent class and specialized agents:
  - ThreatIntelAgent: enriches observations with threat intelligence feeds
  - DecoyAgent: generates decoy/friendly scanner traffic for testing
"""

from typing import Any, Dict, List, Optional


class BaseAgent:
    """Base class for all SOC agents."""

    def __init__(self, name: str = "BaseAgent"):
        self.name = name
        self._history: List[Dict[str, Any]] = []

    def observe(self, observation: Dict[str, Any]) -> None:
        """Process an observation from the environment."""
        self._history.append(observation)

    def act(self, observation: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Produce an action based on the observation.

        Returns:
            Action dict or None if the agent has no action to take.
        """
        raise NotImplementedError

    def reset(self) -> None:
        """Reset agent state for a new episode."""
        self._history.clear()


class ThreatIntelAgent(BaseAgent):
    """
    Enriches observations with threat intelligence data.

    Simulates an external threat-intel feed (e.g., AbuseIPDB, VirusTotal)
    that provides context about known malicious IPs.
    """

    def __init__(self):
        super().__init__(name="ThreatIntelAgent")
        self._threat_db: Dict[str, Dict[str, Any]] = {}

    def load_threat_intel(self, intel_entries: List[Dict[str, Any]]) -> None:
        """
        Load threat intelligence entries.

        Args:
            intel_entries: List of dicts with keys: ip, threat_type, confidence, source
        """
        for entry in intel_entries:
            ip = entry.get("ip", "")
            if ip:
                self._threat_db[ip] = {
                    "threat_type": entry.get("threat_type", "unknown"),
                    "confidence": entry.get("confidence", 0),
                    "source": entry.get("source", "unknown"),
                    "last_seen": entry.get("last_seen", ""),
                }

    def enrich_observation(self, observation: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich an observation with threat intel for any known IPs.

        Adds a 'threat_intel' key to the observation metadata.

        Args:
            observation: The raw environment observation dict.

        Returns:
            Enriched observation dict.
        """
        enriched = dict(observation)
        logs = enriched.get("current_logs", [])
        intel_hits = []

        for log in logs:
            ip = log.get("source_ip", "") if isinstance(log, dict) else getattr(log, "source_ip", "")
            if ip in self._threat_db:
                intel_hits.append({
                    "ip": ip,
                    **self._threat_db[ip],
                })

        # Add intel to metadata
        metadata = enriched.get("metadata", {})
        if isinstance(metadata, dict):
            metadata["threat_intel"] = intel_hits
            enriched["metadata"] = metadata

        return enriched

    def act(self, observation: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """ThreatIntelAgent is passive — it enriches, doesn't act."""
        return None


class DecoyAgent(BaseAgent):
    """
    Generates decoy traffic entries to test contextual understanding.

    Creates realistic-looking but benign traffic that mimics:
      - Internal monitoring systems
      - Friendly vulnerability scanners (e.g., Nessus, Qualys)
      - Health check endpoints
    """

    def __init__(self):
        super().__init__(name="DecoyAgent")

    @staticmethod
    def generate_decoy_logs(count: int = 3) -> List[Dict[str, Any]]:
        """
        Generate decoy log entries that look suspicious but are benign.

        Args:
            count: Number of decoy entries to generate.

        Returns:
            List of log entry dicts.
        """
        decoys = [
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
            {
                "timestamp": "2026-04-10T14:00:30Z",
                "source_ip": "10.200.1.1",
                "request_path": "/.env",
                "status_code": 404,
                "user_agent": "Nessus/10.4.1",
            },
            {
                "timestamp": "2026-04-10T14:00:35Z",
                "source_ip": "10.0.0.10",
                "request_path": "/metrics",
                "status_code": 200,
                "user_agent": "Prometheus/2.40.0",
            },
            {
                "timestamp": "2026-04-10T14:00:40Z",
                "source_ip": "10.200.1.2",
                "request_path": "/admin/login",
                "status_code": 404,
                "user_agent": "Qualys/WAS/3.0",
            },
        ]
        return decoys[:count]

    @staticmethod
    def generate_friendly_scanner_logs(scanner_ip: str = "10.200.1.1") -> List[Dict[str, Any]]:
        """
        Generate logs from a friendly vulnerability scanner.

        These should NOT be blocked by a well-trained agent.

        Args:
            scanner_ip: The scanner's IP address.

        Returns:
            List of log entry dicts.
        """
        return [
            {
                "timestamp": "2026-04-10T14:00:28Z",
                "source_ip": scanner_ip,
                "request_path": "/.git/config",
                "status_code": 404,
                "user_agent": "Nessus/10.4.1",
            },
            {
                "timestamp": "2026-04-10T14:00:30Z",
                "source_ip": scanner_ip,
                "request_path": "/.env",
                "status_code": 404,
                "user_agent": "Nessus/10.4.1",
            },
            {
                "timestamp": "2026-04-10T14:00:32Z",
                "source_ip": scanner_ip,
                "request_path": "/wp-login.php",
                "status_code": 404,
                "user_agent": "Nessus/10.4.1",
            },
        ]

    def act(self, observation: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """DecoyAgent is passive — it generates test data, doesn't act."""
        return None
