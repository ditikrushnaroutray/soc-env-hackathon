# SOC Analyst Environment 🛡️

## Motivation
Security Operations Center (SOC) environments are notoriously noisy with high false positive rates. The RL and LLM agentic communities lack standard benchmarks that evaluate an agent's ability to accurately parse complex log streams, weigh severity dynamically without rigid regex filters, and determine correct isolation parameters (like blocking an active threat vs allowing normal traffic vs escalating ambiguous incidents). 

This project bridges that gap by providing a compliant OpenEnv space targeting incident diagnostics.

## Definitions
**Observation Space (`SOCObservation`)**:
- `current_logs`: List of standard HTTP log dictionary schemas (ip, path, status, user_agent, timestamp).
- `blocked_ips`: State array storing existing firewall bans.
- `system_status`: High-level qualitative assessment ("Normal", "Under Attack").

**Action Space (`SOCAction`)**:
- `action_type`: Strictly string literal ("block_ip", "allow_ip", "escalate"). 
- `target_ip`: The specific IP identifier for the action.
- `reasoning`: A required LLM rationale string explaining why the behavior led to the action.

## Tasks
* **Easy (`task_easy`)**: Identify a standard brute-force login attack where one IP repeatedly triggers `401 Unauthorized` requests.
* **Medium (`task_medium`)**: Block a distributed SQL injection by identifying `500` server errors stemming from query modifications.
* **Hard (`task_hard`)**: Triage a noisy environment containing spoofed Decoys, multi-layered brute forcing, and normal application usage without causing denial-of-service to innocent traffic.

## Results
Baseline scores representing an optimal agent:
- `task_easy`: 1.0 (Quick mitigation of 401s)
- `task_medium`: 1.0 (Precise isolation of SQL injection IPs)
- `task_hard`: 1.0 (Navigated noisy environment effectively)

Total Average: **+3.0**

## Setup

Start the complete environment compliant with Hugging Face Space formats natively using Docker:

```shell
docker compose up --build
```

Endpoints will be active at `http://localhost:8000` exposing `/baseline`, `/grader`, `/reset`, and `/step`.

To run your agent against the local instance:
```shell
export API_BASE_URL="https://api.openai.com/v1"
export MODEL_NAME="gpt-4o"
export HF_TOKEN="your_key"

python inference.py
```

---

# OpenEnv SDK Integration & Advanced Usage

The simplest way to use the Soc Analyst Env environment is through the `SocAnalystEnv` class via the OpenEnv python structure framework:

```python
from soc_analyst_env import SocAnalystAction, SocAnalystEnv

try:
    # Create environment from Docker image
    soc_analyst_envenv = SocAnalystEnv.from_docker_image("soc_analyst_env-env:latest")

    # Reset
    result = soc_analyst_envenv.reset()
    
    # Send multiple messages
    messages = ["Hello, World!", "Testing echo", "Final message"]

    for msg in messages:
        # NOTE: Action payload modified below for generalized echo env examples.
        result = soc_analyst_envenv.step(SocAnalystAction(action_type="escalate", target_ip="0.0.0.0", reasoning="Check"))

finally:
    # Always clean up
    soc_analyst_envenv.close()
```

That's it! The `SocAnalystEnv.from_docker_image()` method handles:
- Starting the Docker container
- Waiting for the server to be ready
- Connecting to the environment
- Container cleanup when you call `close()`

## Deploying to Hugging Face Spaces

You can easily deploy your OpenEnv environment to Hugging Face Spaces using the `openenv push` command:

```bash
# From the environment directory (where openenv.yaml is located)
cd soc_analyst_env
openenv push

# Or specify options
openenv push --namespace my-org --private
```

The `openenv push` command will:
1. Validate that the directory is an OpenEnv environment (checks for `openenv.yaml`)
2. Prepare a custom build for Hugging Face Docker space (enables web interface)
3. Upload to Hugging Face (ensuring you're logged in)

After deployment, your space will be available at:
`https://huggingface.co/spaces/<repo-id>`

The deployed space includes:
- **Web Interface** at `/web` - Interactive UI for exploring the environment
- **API Documentation** at `/docs` - Full OpenAPI/Swagger interface
- **Health Check** at `/health` - Container health monitoring
- **WebSocket** at `/ws` - Persistent session endpoint for low-latency interactions

### Using the Context Manager

The client supports context manager usage for automatic connection management:

```python
from soc_analyst_env import SocAnalystAction, SocAnalystEnv

# Connect with context manager (auto-connects and closes)
with SocAnalystEnv(base_url="http://localhost:8000") as env:
    result = env.reset()
    
    # Multiple steps with low latency
    for ip in ["192.168.1.1", "104.22.33.44"]:
        result = env.step(SocAnalystAction(action_type="block_ip", target_ip=ip, reasoning="Threat detected."))
        print(result.observation.system_status)
```

The client uses WebSocket connections for:
- **Lower latency**: No HTTP connection overhead per request
- **Persistent session**: Server maintains your environment state
- **Efficient for episodes**: Better for many sequential steps
