---
title: SOC Analyst RL Environment
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: docker
pinned: false
app_port: 8000
tags:
- openenv
---

# SOC Analyst RL Environment (OpenEnv) 🛡️

## Motivation
Security Operations Center (SOC) environments are notoriously noisy with high false-positive rates. This project provides a standardized OpenEnv benchmark to evaluate an agent's ability to parse complex log streams, weigh severity dynamically without rigid regex filters, and determine correct isolation parameters (blocking threats vs. allowing legitimate traffic).

## Definitions
**Observation Space (`SOCObservation`)**:
- `current_logs`: List of HTTP log dictionary schemas (IP, path, status, user_agent, timestamp).
- `blocked_ips`: State array storing existing firewall bans.
- `system_status`: High-level qualitative assessment ("Normal", "Under Attack").

**Action Space (`SOCAction`)**:
- `action_type`: String literal (`block_ip`, `allow_ip`, `escalate`). 
- `target_ip`: The specific IP identifier for the action.
- `reasoning`: A required LLM rationale string explaining the decision-making process.

## Tasks
* **Easy (`task_easy`)**: Identify a standard brute-force login attack where one IP repeatedly triggers `401 Unauthorized` requests.
* **Medium (`task_medium`)**: Block a distributed SQL injection by identifying `500` server errors stemming from malicious query patterns.
* **Hard (`task_hard`)**: Triage a noisy environment containing spoofed decoys, multi-layered brute forcing, and normal application usage.

## Results
The baseline agent (using `inference.py`) achieved a perfect **3.0/3.0** score:
- `task_easy`: 1.0 
- `task_medium`: 1.0 
- `task_hard`: 1.0 

## Setup & Local Testing
To start the environment compliant with Hugging Face Space formats:
```shell
docker build -t soc-env .
docker run -p 8000:8000 soc-env

```
