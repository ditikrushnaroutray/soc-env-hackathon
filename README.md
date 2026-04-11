---
title: SOC Analyst RL Environment
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 7860
tags:
  - openenv
  - reinforcement-learning
  - cybersecurity
  - soc-analyst
pinned: true
license: bsd-3-clause
---

# 🛡️ SOC Analyst RL Environment — OpenEnv

**Meta PyTorch Hackathon x Scaler School of Technology — Phase 2 Validated** ✅

Train and evaluate AI agents on real-world Security Operations Center (SOC) triage: parsing firewall access logs, identifying attack vectors, isolating threats, and mitigating false positives under strict formatting constraints.

[![OpenEnv](https://img.shields.io/badge/Framework-OpenEnv-blue.svg)](https://github.com/meta-pytorch/OpenEnv)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

---

## 🌍 Why SOC Analyst Triage?

Modern SOC environments are notoriously noisy. Servers receive millions of requests a day, and security analysts face crippling alert fatigue sifting through benign traffic to find the single SQL injection or brute-force attack. This is a high-stakes, universally critical task that requires:

- **Log Parsing:** Understanding HTTP status codes, paths, and user agents in raw JSON.
- **Threat Isolation:** Differentiating between normal user traffic, active attacks, and spoofed decoys.
- **Decision Making:** Choosing whether to strictly block an IP, safely allow it, or escalate to a human analyst.
- **Strict Compliance:** Outputting decisions in perfect formats required by automated enterprise firewall systems without hallucinating.

This environment lets AI agents practice these crucial skills in a realistic, graded simulation.

---

## 🏗️ Architecture

```
┌─────────────────┐    HTTP POST     ┌──────────────────────────────┐
│                  │  ──────────────► │   FastAPI Server (:7860)     │
│   inference.py   │     /reset       │                              │
│   (Agent)        │     /step        │  ┌────────┐  ┌───────────┐  │
│                  │  ◄────────────── │  │ Engine │  │ Scenarios │  │
│  - LLM calls     │    JSON response │  └───┬────┘  └─────┬─────┘  │
│  - Heuristic     │                  │      │             │        │
│    fallback      │                  │  ┌───▼─────────────▼─────┐  │
│  - [START]/[END] │                  │  │   Environment State   │  │
│    output        │                  │  │  - Score tracking     │  │
└─────────────────┘                  │  │  - Session mgmt      │  │
                                     │  │  - Telemetry          │  │
                                     │  └──────────┬────────────┘  │
                                     │             │               │
                                     │  ┌──────────▼────────────┐  │
                                     │  │ Rubrics │ Dashboard   │  │
                                     │  └─────────────────────────┘│
                                     └──────────────────────────────┘
```

---

## 🎯 Tasks

| Task | Difficulty | Scenario | Max Steps | Objective |
| :--- | :---: | :--- | :---: | :--- |
| `task_easy` | 🟢 Easy | Brute-Force | 10 | Identify a single IP repeatedly triggering `401 Unauthorized`. |
| `task_medium` | 🟡 Medium | Distributed SQLi | 10 | Block an attack by identifying `500` server errors from malicious queries. |
| `task_hard` | 🔴 Hard | Decoys & Noise | 10 | Triage a highly noisy environment containing spoofed decoys and false positives. |

### Scoring

All scores strictly enforce a `(0.001, 0.999)` bound to comply with Phase 2 OpenEnv validation:
- **Perfect Action:** exact threat isolated / exact safe user allowed = `0.999`
- **Escalation:** safe fallback to human = `0.500`
- **Critical Failure:** blocked normal user / allowed hacker / invalid format = `0.001`

---

## 📐 Action Space

Agents must output a strictly formatted JSON payload mapped to this schema:
```python
class SOCAction(BaseModel):
    action_type: str  # "block_ip" | "allow_ip" | "escalate"
    target_ip: str    # "192.168.x.x" (Must exist in the current logs)
    reasoning: str    # Rationale explaining the decision-making process
```

## 👁️ Observation Space

The environment feeds the agent the current state of the server firewall:
```python
class SOCObservation(BaseModel):
    current_logs: list    # Array of dicts: source_ip, request_path, status_code, user_agent, timestamp
    blocked_ips: list     # State array storing existing firewall bans
    system_status: str    # High-level assessment ("Normal" or "Under Attack")
    reward: float         # Reward from the previous action
    done: bool            # Whether the episode has terminated
    metadata: dict        # Steps taken, current score, message, threat_intel
```

---

## 🚀 Quick Start

### Prerequisites

- Python ≥ 3.10
- Docker (for containerized deployment)

### Local Development

```bash
# Clone and navigate
git clone https://github.com/ditikrushnaroutray/soc-env-hackathon.git
cd soc-env-hackathon

# Install dependencies
pip install -r requirements.txt

# Start the server
uvicorn soc_analyst_env.server.app:app --host 0.0.0.0 --port 7860
```

### Run Inference

In a separate terminal, run the robust baseline agent:

```bash
# Set environment variables
export API_KEY="your-api-key"
export API_BASE_URL="https://api.openai.com/v1"
export MODEL_NAME="gpt-4o"
export ENV_URL="http://localhost:7860"

# Run baseline agent (LLM mode)
python inference.py

# Or run without API keys (heuristic fallback mode)
export ENV_URL="http://localhost:7860"
python inference.py
```

### Docker Deployment

```bash
# Build
docker build -t soc_analyst_env:latest .

# Run
docker run -p 7860:7860 soc_analyst_env:latest
```

---

## 🗂️ Project Structure

```text
soc-env-hackathon/
├── inference.py                           # Phase 2 hardened baseline agent
├── app.py                                 # Root entry point for HF Space
├── README.md                              # This file
├── Dockerfile                             # Container build configuration
├── docker-compose.yml                     # Docker compose for local dev
├── openenv.yaml                           # OpenEnv space manifest
├── requirements.txt                       # Python dependencies
├── validate-submission.sh                 # Pre-submission validator script
│
└── soc_analyst_env/
    ├── __init__.py                        # Package exports
    ├── models.py                          # Re-exports for backward compat
    ├── client.py                          # Standalone HTTP client
    │
    ├── server/
    │   ├── __init__.py
    │   ├── app.py                         # FastAPI application & endpoints
    │   ├── engine.py                      # Core reward and grading logic
    │   ├── generators.py                  # Scenario-driven log generator
    │   ├── models.py                      # Pydantic data models
    │   ├── soc_analyst_env_environment.py # Environment state tracker
    │   ├── rubrics.py                     # Reasoning quality evaluator
    │   ├── telemetry.py                   # Per-episode metrics recorder
    │   ├── logging.py                     # Central logging helpers
    │   ├── dashboard.py                   # Post-episode ASCII report
    │   └── scenarios/
    │       ├── task_easy.json             # Brute-force scenario
    │       ├── task_medium.json           # Distributed SQLi scenario
    │       └── task_hard.json             # Mixed traffic scenario
    │
    ├── agents/
    │   └── __init__.py                    # ThreatIntelAgent, DecoyAgent
    │
    └── benchmark_scenarios/
        ├── __init__.py
        └── README.md                      # Scenario documentation
```

---

## 📊 Reward Design

### Per-Step Rewards

This environment uses a 1-shot episode: each action terminates the episode.
Rewards are adjusted by a reasoning quality multiplier from `rubrics.py` (range: 0.5–1.0).

| Action Taken | Target Condition | Base Reward | With Good Reasoning |
| :--- | :--- | :--- | :--- |
| `block_ip` | IP is Malicious (Status ≥ 400) | `0.999` | `0.999` |
| `allow_ip` | IP is Normal (Status < 400) | `0.999` | `0.999` |
| `escalate` | Any valid IP | `0.500` | `0.500` |
| `block_ip` | IP is Normal | `0.001` | `0.001` |
| `allow_ip` | IP is Malicious | `0.001` | `0.001` |
| *Any Action* | Target IP not in logs | `0.001` | `0.001` |

### Reasoning Rubrics

The reasoning multiplier evaluates:
1. **Length** — sufficient detail (≥ 10 words preferred)
2. **Keywords** — mentions scenario-relevant terms
3. **Technical specificity** — references status codes, IPs, paths
4. **Coherence** — uses analytical language (because, detected, indicates)

---

## 📈 Baseline Scores

| Task | Heuristic Score | LLM Score (GPT-4o) | Max Steps |
| :--- | :---: | :---: | :---: |
| `task_easy` | `0.999` | `0.999` | 10 |
| `task_medium` | `0.999` | `0.999` | 10 |
| `task_hard` | `0.999` | `0.999` | 10 |

---

## 🔌 API Reference

### `GET /health`
Returns `{"status": "ok"}`.

### `GET /tasks`
Returns available tasks and action schema.

### `POST /reset`
**Body:** `{"task_id": "task_easy"}`
**Returns:** `{"session_id": "...", "observation": {...}}`

### `POST /step`
**Body:** `{"session_id": "...", "action": {"action_type": "block_ip", "target_ip": "...", "reasoning": "..."}}`
**Returns:** `{"observation": {...}, "reward": 0.999, "done": true, "message": "..."}`

### `GET /grader?session_id=...`
**Returns:** `{"session_id": "...", "final_score": 0.999}`

---

## ✅ Validation

```bash
# Run pre-submission checks
chmod +x validate-submission.sh
./validate-submission.sh http://localhost:7860
```

The validator checks:
- Server health (`/health` endpoint)
- `openenv.yaml` structure and task IDs
- `/reset` endpoint returns `session_id` and `observation`
- `inference.py` outputs `[START]` and `[END]` for each task
- Score bounds within `(0.001, 0.999)`
- Boolean format (lowercase `true`/`false`)

---

## 📋 Environment Details

- **Runtime:** < 1 minute for all 3 tasks (fast one-shot execution).
- **Memory:** < 150MB for environment server.
- **Compatibility:** 2 vCPU, 4GB RAM is more than sufficient.
- **Dependencies:** Pure Python, no heavy ML libraries on the server side.
- **Port:** `7860` (Native Hugging Face Spaces integration).

---

## 🔮 Extension Roadmap

- **Phase 3:** LLM judge for reasoning evaluation (configurable)
- **Phase 4:** Attack rotation (attackers change IPs in response to blocks)
- **Phase 5:** Telemetry persistence to SQLite for judge replay
- **Multi-agent:** Cooperative SOC analyst teams

## 📜 License

[BSD 3-Clause License](LICENSE)