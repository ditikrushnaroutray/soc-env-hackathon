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

## 🎯 Tasks

| Task | Difficulty | Scenario | Max Steps | Objective |
| :--- | :---: | :--- | :---: | :--- |
| `task_easy` | 🟢 Easy | Brute-Force | 10 | Identify a single IP repeatedly triggering `401 Unauthorized`. |
| `task_medium` | 🟡 Medium | Distributed SQLi | 10 | Block an attack by identifying `500` server errors from malicious queries. |
| `task_hard` | 🔴 Hard | Decoys & Noise | 10 | Triage a highly noisy environment containing spoofed decoys and normal application usage. |

### Scoring
All scores strictly enforce a `(0.001, 0.999)` bound to comply with Phase 2 OpenEnv validation:
- **Perfect Action:** exact threat isolated / exact safe user allowed = `0.999`
- **Escalation:** safe fallback to human = `0.500`
- **Critical Failure:** blocked normal user / allowed hacker / invalid format = `0.001`

---

## 📐 Action Space
Agents must output a strictly formatted JSON payload mapped to this schema:
```python
class SOCAction(Action):
    action_type: str  # "block_ip" | "allow_ip" | "escalate"
    target_ip: str    # "192.168.x.x" (Must exist in the current logs)
    reasoning: str    # Rationale explaining the decision-making process
```

## 👁️ Observation Space
The environment feeds the agent the current state of the server firewall:
```python
class SOCObservation(Observation):
    current_logs: list    # Array of dicts: source_ip, request_path, status_code, user_agent, timestamp
    blocked_ips: list     # State array storing existing firewall bans
    system_status: str    # High-level assessment ("Normal" or "Under Attack")
    reward: float         # Reward from the previous action
    done: bool            # Whether the episode has terminated
    metadata: dict        # Steps taken, current score, and system messages
```

---

## 🚀 Quick Start

### Prerequisites
- Python ≥ 3.10
- Docker (for containerized deployment)
- `pip install openenv-core`

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

# Run baseline agent
python inference.py
```

### Docker deployment
```bash
# Build
docker build -t soc_analyst_env:latest .

# Run
docker run -p 7860:7860 soc_analyst_env:latest
```

---

## 🏗️ Project Structure
```text
soc-env-hackathon/
├── inference.py                      # Phase 2 Hardened baseline inference script
├── README.md                         # This file
├── Dockerfile                        # Container build configuration
├── openenv.yaml                      # OpenEnv space manifest
├── requirements.txt                  # Python dependencies
├── validate-submission.sh            # Pre-submission validator script
└── soc_analyst_env/
    ├── __init__.py                   # Package exports
    ├── models.py                     # Typed Action & Observation schemas (Pydantic)
    ├── client.py                     # EnvClient implementation for OpenEnv
    └── server/
        ├── __init__.py
        ├── app.py                    # FastAPI application & Baseline HTTP endpoints
        ├── engine.py                 # Core reward and grading logic (Strict Bounds)
        ├── generators.py             # Deterministic log corpus generator
        └── soc_analyst_env_environment.py # Core environment state tracker
```

---

## 📊 Reward Design

### Per-Step Rewards
This environment forces a 1-shot episode execution per task to prevent reward accumulation violations.

| Action Taken | Target Condition | Reward |
| :--- | :--- | :--- |
| `block_ip` | IP is Malicious (Status >= 400) | `+0.999` |
| `allow_ip` | IP is Normal (Status < 400) | `+0.999` |
| `escalate` | Any valid IP | `+0.500` |
| `block_ip` | IP is Normal | `+0.001` |
| `allow_ip` | IP is Malicious | `+0.001` |
| *Any Action* | Target IP not in logs | `+0.001` |
| *Parse Error*| Invalid JSON / Hallucination | `+0.001` |

---

## 📈 Baseline Scores

| Task | Baseline Score | Max Steps Allowed |
| :--- | :---: | :---: |
| `task_easy` | `0.999` | 10 |
| `task_medium` | `0.999` | 10 |
| `task_hard` | `0.999` | 10 |

*Scores measured with robust `gpt-4o` logic via `inference.py` utilizing deep regex JSON parsing and strict `.3f` floating-point formatting.*

---

## ✅ Validation
```bash
# Run OpenEnv framework validation
openenv validate

# Run hackathon pre-submission checks
./validate-submission.sh http://localhost:7860
```

## 📋 Environment Details
- **Runtime:** < 1 minute for all 3 tasks (fast one-shot execution).
- **Memory:** < 150MB for environment server.
- **Compatibility:** 2 vCPU, 4GB RAM is more than sufficient.
- **Dependencies:** Pure Python, no heavy ML libraries on the server side.
- **Port:** `7860` (Native Hugging Face Spaces integration).

## 📜 License
[BSD 3-Clause License](LICENSE)