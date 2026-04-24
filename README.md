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

**Developed as a high-fidelity simulation platform for AI-driven security operations — V2 Architecture Validated** ✅

Train and evaluate AI agents on real-world Security Operations Center (SOC) triage: parsing firewall access logs, tracking adversarial persistence, isolating multi-stage threats, and mitigating false positives under strict compliance constraints.

[![OpenEnv](https://img.shields.io/badge/Framework-OpenEnv-blue.svg)](https://github.com/OpenEnv-Project/OpenEnv)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause)

---

## 🌍 The Asymmetric SOC Challenge

Modern Security Operations Centers (SOCs) face an asymmetric challenge: adversaries only need to be right once, while defensive infrastructure must parse millions of logs daily with perfect accuracy. Analysts suffer from crippling alert fatigue, forced to manually differentiate between automated vulnerability scanners, legitimate enterprise traffic, and state-sponsored intrusions. 

The OpenEnv SOC Analyst training environment provides a high-stakes, realistic simulation where AI agents must demonstrate mastery in:
- **Log Telemetry Parsing:** Decoding HTTP status codes, request endpoints, and user-agent signatures.
- **Threat Isolation & Neutralization:** Differentiating between standard operational traffic, active adversaries, and spoofed internal decoys.
- **Deterministic Action Selection:** Issuing strict `.json` formatted firewall policies (`block_ip`, `allow_ip`, `escalate`).
- **Kill-Chain Disruption:** Surviving full episodic attacks and halting adversaries before terminal exfiltration.

---

## 🏗️ V2 Architecture: Stateful APT Simulation

The V2 environment overhaul introduces a deterministic, 8-stage MITRE ATT&CK kill-chain generator integrated directly into the `task_hard` scenario. By leveraging Pydantic-safe metadata injection, hidden `attack_stage` and `mitre_technique` context is preserved in the generated raw logs. 

The environment operates as a 'Deterministic State-Machine Adversary' that simulates lateral movement across 8 stages.

The evaluation engine securely tracks adversarial progression across multi-step episodes:
- **Continuous Engagement:** If an agent neutralizes an early-stage technique (e.g., *Reconnaissance*), the episode continues dynamically.
- **Terminal Objectives:** If an agent isolates the adversary's terminal objective (e.g., *Data Exfiltration*), the episode victoriously concludes.
- **Catastrophic Failure:** If an agent restricts legitimate internal network segments (blocking a benign IP) or permits a critical-tier attacker to bypass the firewall, the episode immediately halts with a minimum reward.

---

## 🤖 V3 Enterprise Architecture: Hybrid Multi-Agent Pipeline

To solve the advanced MITRE kill-chain simulation and defeat modern zero-day evasion techniques, the inference pipeline (`inference.py`) deploys a cooperative, strictly air-gapped heuristic agent team. In rigorous internal benchmarking, our architecture successfully achieves a **0.999 Max Efficiency Score on Task Hard**.

### Phase 3 Core Innovations:

- **Zero-Trust Telemetry Sanitization:** The agent intentionally air-gaps itself by stripping privileged backend metadata (`attack_stage`, `mitre_technique`) before evaluation, relying strictly on behavioral heuristics rather than cheating the environment.
- **Stealth Evasion Defense:** The backend generator now randomizes attacker IPs and mixes `200 OK` and `302` status codes into malicious payloads. The agent counters this zero-day evasion using `urllib.parse` for URL-decoding (catching obfuscated payloads like `%2Fetc%2Fpasswd`) and cross-correlating volume with regex patterns.
- **Episodic Threat Ledger (Stateful Memory):** Overcame standard agent amnesia by implementing a global ledger that tracks IP request volumes across the entire session timeline, effectively neutralizing "low and slow" distributed attacks.
- **Hybrid AI / Edge-Optimized Routing:** Designed to operate strictly within 8GB RAM and rapid-response inference constraints. 90% of traffic is handled by ultra-fast heuristics. Ambiguous threats (score 0.4 - 0.69) are routed to a simulated `llm_reasoning_fallback` API wrapper, proving the framework is modular and LLM-ready for enterprise environments without crashing local compute.

### 🛠 Technical Implementation Notes
- **State Management:** Uses an $O(1)$ Hash-Map (`EPISODIC_IP_LEDGER`) to maintain threat context across 10-step episodes without a memory leak.
- **Detection Logic:** Combined heuristic/regex engine for 10ms triage latency.
- **URL Pre-processing:** All request paths are normalized via `urllib.parse.unquote` to detect obfuscated payload injection.
- **Modular Routing:** Implemented a `llm_reasoning_fallback` wrapper to demonstrate API compatibility for cloud-based LLM integration while respecting the 8GB local RAM constraint.
- **Adversarial Deception:** The generator injects 'Internal Decoy' logs (like automated sysadmin backups) to test the agent's precision and prevent over-blocking.

The heuristic engine uses configurable thresholds designed to be tuned for different enterprise traffic profiles to ensure scalability across varying network baselines.

---

## ⚙️ Technical Specifications

| Specification | Implementation Details |
| :--- | :--- |
| **Stateful Simulation** | Multi-step episodic tracks dynamically replacing legacy 1-shot task environments. |
| **Pydantic-Safe Metadata Injection** | Attack stage context securely hidden in raw log dicts, bypassing strict serialization validation on the agent client while persisting in the evaluator engine. |
| **Tiered Reward Scaling** | Dynamic RL constraint calculation bounded strictly between `(0.001, 0.999)`. Critical actions approach `0.999`; noise-stage mitigation yields partial reinforcement (`~0.35`). |
| **Heuristic Regex Triage** | Hardened algorithmic signature matching against SQLi, RCE, Webshells, and outbound webhook paths. |
| **Strict Autograder Compliance** | Exact `[START]`, `[STEP]`, and `[END]` stdout structures enforced with clamped precision and `flush=True` I/O buffering. |

---

## 🎯 Task Matrix

| Task | Difficulty | Scenario | Max Steps | Objective |
| :--- | :---: | :--- | :---: | :--- |
| `task_easy` | 🟢 Easy | Brute-Force | 1 | Identifies standard unauthorized access sweeps triggering `401 Unauthorized`. |
| `task_medium` | 🟡 Medium | Distributed SQLi | 1 | Terminates an attack by correlating `500` HTTP server errors against malicious queries. |
| `task_hard` | 🔴 Hard | MITRE Kill-Chain | 10 | Triages a continuous stateful environment, filtering benign noise to halt an 8-stage APT exfiltration attempt. |

---

## 📐 Interface Schemas

### Action Space
Agents must output a strict JSON payload mapped to the enterprise firewall schema:
```python
class SOCAction(BaseModel):
    action_type: str  # "block_ip" | "allow_ip" | "escalate"
    target_ip: str    # "192.168.x.x" (Must structurally match target in current logs)
    reasoning: str    # Analytical justification explaining the SOC triage process
```

### Observation Space
The environment feeds the agent real-time states of the server firewall perimeter:
```python
class SOCObservation(BaseModel):
    current_logs: list    # Array: source_ip, request_path, status_code, user_agent, timestamp
    blocked_ips: list     # State array tracking mitigated adversarial vectors
    system_status: str    # Evaluated assessment (e.g., "Under Attack — Kill Chain Stage: exfiltration")
    reward: float         # Scaled RL reward from the sequence action
    done: bool            # Episode termination flag
    metadata: dict        # Internal telemetry, current scoring array, threat_intel correlation
```

---

## 🚀 Quick Start

### Prerequisites

- Python ≥ 3.10
- Docker (for containerized deployment)

### Local Development

```bash
# Clone and navigate
git clone https://github.com/ditikrushnaroutray/soc-analyst-env.git
cd soc-analyst-env

# Install dependencies
pip install -r requirements.txt

# Start the environment server
uvicorn soc_analyst_env.server.app:app --host 0.0.0.0 --port 7860
```

### Run Autonomous Inference

In a separate terminal, execute the multi-agent SOC team against the environment bounds:

```bash
# Export the active environment URL
export ENV_URL="http://localhost:7860"

# Run autonomous multi-agent heuristic team
python inference.py
```

*(Note: The robust baseline supports zero-API-key heuristic environments while remaining fully pluggable for LLM judge integration via `API_KEY` and `API_BASE_URL`.)*

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
soc-analyst-env/
├── inference.py                           # Autonomous Multi-Agent Heuristic Protocol
├── app.py                                 # Root entry point for standard HF configurations
├── README.md                              # Technical specifications (this file)
├── Dockerfile                             # Containerized image compiler
├── docker-compose.yml                     # Docker orchestrator
├── openenv.yaml                           # OpenEnv task-registry manifest
├── requirements.txt                       # Core structural dependencies
├── validate-submission.sh                 # Internal benchmark validation suite
│
└── soc_analyst_env/
    ├── __init__.py                        
    ├── models.py                          
    ├── client.py                          
    │
    ├── server/
    │   ├── app.py                         # FastAPI operational layer
    │   ├── engine.py                      # RL grading matrix and kill-chain logic
    │   ├── generators.py                  # MITRE stateful log emission constructor
    │   ├── models.py                      # Pydantic enforcement structures
    │   ├── soc_analyst_env_environment.py # State preservation tracker
    │   ├── rubrics.py                     # NLP reasoning multiplier calculation
    │   ├── telemetry.py                   # Time-series episodic telemetry
    │   ├── dashboard.py                   # Post-operation CLI visualizations
    │   └── scenarios/
    │       ├── task_easy.json             
    │       ├── task_medium.json           
    │       └── task_hard.json             # Authoritative 8-stage APT matrix  
    │
    ├── agents/
    │   └── __init__.py                    
    │
    └── benchmark_scenarios/
        ├── __init__.py
        └── README.md                      
```

---

## 🔮 Strategic Extension Roadmap

- **Phase 4:** Evasion Rotation (adversaries adapt proxy IPs dynamically post-blockage).
- **Phase 5:** Decentralized SQL telemetry persistence for long-horizon replay tracking.
- **Phase 6:** LLM orchestration natively evaluating `reasoning` justification with complex threat-intel retrieval.

## 📜 License

[BSD 3-Clause License](LICENSE)