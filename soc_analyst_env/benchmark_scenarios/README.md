# Benchmark Scenarios

This directory contains benchmark scenario definitions for evaluating SOC analyst agents.

## Scenario Files

Scenario JSON files are located in `soc_analyst_env/server/scenarios/` and are loaded by
the generator at runtime.

| File | Difficulty | Description |
|------|-----------|-------------|
| `task_easy.json` | 🟢 Easy | Single-IP brute-force login attack |
| `task_medium.json` | 🟡 Medium | Distributed SQL injection from multiple IPs |
| `task_hard.json` | 🔴 Hard | Mixed traffic with real attacks, decoys, and false positives |

## JSON Schema

Each scenario file follows this structure:

```json
{
  "task_id": "task_easy",
  "description": "Human-readable description",
  "difficulty": "easy|medium|hard",
  "expected_action": "block_ip|allow_ip|escalate",
  "expected_targets": ["ip1", "ip2"],
  "expected_keywords": ["keyword1", "keyword2"],
  "threat_intel": [],
  "logs": [
    {
      "timestamp": "ISO 8601",
      "source_ip": "x.x.x.x",
      "request_path": "/path",
      "status_code": 200,
      "user_agent": "User-Agent string"
    }
  ]
}
```

## Adding New Scenarios

1. Create a new JSON file in `soc_analyst_env/server/scenarios/`
2. Follow the schema above
3. Add a corresponding task entry in `openenv.yaml`
4. Test with `python inference.py`
