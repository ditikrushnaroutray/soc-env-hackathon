"""
llm_agent.py — LLM-Powered SOC Analyst Agent (Gemini)
======================================================
Uses Google's Gemini model via the official ``google-genai`` SDK to analyse a
SOCObservation and decide whether to ``block_ip``, ``escalate``, or ``allow_ip``.

Pipeline
--------
  SOCObservation dict
       │
       ▼
  build_prompt()          → Formats raw log data into a security-analyst prompt
       │
       ▼
  query_llm()             → Sends the prompt to Gemini and gets a text response
       │
       ▼
  parse_llm_response()    → Validates + coerces the response into a SOCAction dict
       │
       ▼
  SOCAction dict          → Posted to /step endpoint

Usage
-----
    python3 llm_agent.py                          # full simulation (all 3 tasks)
    python3 llm_agent.py --task easy              # single task
    python3 llm_agent.py --task hard --model gemini-2.5-pro

Environment variables (or edit the CONFIG section below)
---------------------------------------------------------
    GEMINI_API_KEY   → Your Gemini API key (get one free at https://aistudio.google.com)
"""

import os
import sys
import json
import re
import argparse
import requests
from typing import Optional
from dotenv import load_dotenv
from google import genai
from google.genai import types as genai_types

# ─── Load .env if present ──────────────────────────────────────────────────────
load_dotenv()

# ─── Configuration ────────────────────────────────────────────────────────────

# SOC environment API
BASE_URL = "http://127.0.0.1:8000"

# Gemini settings
# Set GEMINI_API_KEY in your environment or in baseline/.env
# Get a free key at: https://aistudio.google.com/app/apikey
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "placeholder-replace-with-real-gemini-key")
LLM_MODEL      = os.getenv("GEMINI_MODEL",   "gemini-2.5-flash")

# How many times to retry if the LLM returns unparseable output
MAX_PARSE_RETRIES = 2

# ─── Gemini Client (module-level singleton) ────────────────────────────────────
# The client reads GEMINI_API_KEY from the constructor argument.
# If the key is the placeholder it will fail only when a call is actually made.
_gemini_client = genai.Client(api_key=GEMINI_API_KEY)

# ─── Prompt Engineering ───────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are an elite SOC (Security Operations Center) analyst AI.
Your job is to inspect batches of web server access logs and make precise,
evidence-based decisions to protect the infrastructure.

You MUST respond with a single, valid JSON object — nothing else.
The JSON object must follow this exact schema:

{
  "action_type": "<one of: block_ip | allow_ip | escalate>",
  "target_ip":   "<the single IPv4 address your action targets>",
  "reasoning":   "<one concise sentence explaining your decision>"
}

Decision guide
--------------
• block_ip  — Use when you are HIGHLY CONFIDENT an IP is malicious (e.g. repeated
              401/403/500 errors, automated tool user-agents like sqlmap/python-requests,
              path probing for /admin /login /etc/passwd, or clear attack patterns).
• escalate  — Use when activity is suspicious but evidence is ambiguous; flag for
              a human analyst rather than auto-blocking.
• allow_ip  — Use only when you can confirm an IP is generating normal, benign traffic.

Always target the SINGLE most threatening IP address in the current log batch.
If no IP looks suspicious, target the one with the highest error rate and escalate.
Do NOT output markdown, code fences, or any text outside the JSON object.
"""


def build_prompt(observation: dict) -> str:
    """
    Format a SOCObservation dict into a human-readable analyst briefing
    that is injected as the USER turn of the LLM conversation.
    """
    logs       = observation.get("current_logs", [])
    blocked    = observation.get("blocked_ips", [])
    sys_status = observation.get("system_status", "Unknown")

    lines = [
        "=== SOC INCIDENT BRIEFING ===",
        f"System Status  : {sys_status}",
        f"Blocked IPs    : {', '.join(blocked) if blocked else 'None'}",
        f"Total Log Rows : {len(logs)}",
        "",
        "--- ACCESS LOG DUMP ---",
        f"{'#':<4}  {'Timestamp':<26}  {'Source IP':<18}  {'Status':<7}  "
        f"{'Path':<35}  User-Agent",
        "─" * 120,
    ]

    for idx, log in enumerate(logs, start=1):
        ts   = log.get("timestamp", "")[:26]
        ip   = log.get("source_ip", "")
        code = log.get("status_code", "")
        path = log.get("request_path", "")[:35]
        ua   = log.get("user_agent", "")

        # Visually flag suspicious rows to help the model focus
        flag = "⚠️ " if int(code) >= 400 else "   "
        lines.append(
            f"{flag}{idx:<3}  {ts:<26}  {ip:<18}  {code:<7}  {path:<35}  {ua}"
        )

    lines += [
        "",
        "=== YOUR TASK ===",
        "Analyse the logs above and return a single JSON SOCAction.",
        "Focus on the IP causing the most damage or showing the clearest attack pattern.",
    ]

    return "\n".join(lines)


# ─── LLM Interface ────────────────────────────────────────────────────────────

def query_llm(prompt: str, model: str = LLM_MODEL) -> str:
    """
    Send the formatted prompt to Gemini via the official ``google-genai`` SDK.

    The system instruction is passed through ``GenerateContentConfig`` so it is
    handled correctly by the Gemini API (it does not use an OpenAI-style
    ``system`` role message).

    Returns the raw text content of the model's reply.

    Raises
    ------
    RuntimeError
        If the Gemini API call fails for any reason.
    """
    try:
        response = _gemini_client.models.generate_content(
            model=model,
            contents=prompt,
            config=genai_types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.0,       # deterministic — we want consistent decisions
                response_mime_type="application/json",
            ),
        )
    except Exception as exc:
        raise RuntimeError(f"Gemini API call failed: {exc}") from exc

    # response.text is the convenience accessor for the first candidate's text
    text = response.text
    if text is None:
        raise RuntimeError("Gemini returned an empty response (no text candidates).")
    return text.strip()


# ─── Response Parser ──────────────────────────────────────────────────────────

VALID_ACTION_TYPES = {"block_ip", "allow_ip", "escalate"}

# Regex to fish a JSON object out of a response that may have extra text
_JSON_BLOCK_RE = re.compile(r"\{.*?\}", re.DOTALL)


def parse_llm_response(raw: str, observation: dict) -> dict:
    """
    Parse the LLM's raw text reply into a validated SOCAction dict.

    Strategy
    --------
    1. Try direct JSON parse of the full response.
    2. If that fails, extract the first ``{...}`` block with a regex and retry.
    3. Validate required fields and coerce ``action_type`` to a known value.
    4. If ``target_ip`` is missing, fall back to the first IP seen in the logs
       (ensures we always return a usable action).

    Returns a dict ready to be POST-ed to ``/step``.

    Raises
    ------
    ValueError
        If the response cannot be parsed even after fallback attempts.
    """
    # ── Attempt 1: parse the whole response as JSON ────────────────────────
    parsed: Optional[dict] = None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        pass

    # ── Attempt 2: extract first {...} block ────────────────────────────────
    if parsed is None:
        match = _JSON_BLOCK_RE.search(raw)
        if match:
            try:
                parsed = json.loads(match.group())
            except json.JSONDecodeError:
                pass

    if parsed is None:
        raise ValueError(f"Could not extract JSON from LLM response:\n{raw}")

    # ── Validate action_type ────────────────────────────────────────────────
    action_type = str(parsed.get("action_type", "")).strip().lower()
    if action_type not in VALID_ACTION_TYPES:
        # Best-effort mapping from free-text like "monitor" → "escalate"
        if "monitor" in action_type or "watch" in action_type:
            action_type = "escalate"
        elif "block" in action_type or "deny" in action_type or "isolate" in action_type:
            action_type = "block_ip"
        elif "allow" in action_type or "permit" in action_type:
            action_type = "allow_ip"
        else:
            action_type = "escalate"   # safe default

    # ── Validate target_ip ──────────────────────────────────────────────────
    target_ip = str(parsed.get("target_ip", "")).strip()
    if not target_ip or not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target_ip):
        # Fall back: pick the first IP from the logs with an error status
        fallback = next(
            (
                log["source_ip"]
                for log in observation.get("current_logs", [])
                if log.get("status_code", 200) >= 400
            ),
            observation.get("current_logs", [{}])[0].get("source_ip", "0.0.0.0"),
        )
        target_ip = fallback

    # ── Validate reasoning ──────────────────────────────────────────────────
    reasoning = str(parsed.get("reasoning", "LLM decision — no reasoning provided.")).strip()
    if not reasoning:
        reasoning = "LLM decision — no reasoning provided."

    return {
        "action_type": action_type,
        "target_ip":   target_ip,
        "reasoning":   reasoning,
    }


def decide_action_llm(observation: dict, model: str = LLM_MODEL) -> Optional[dict]:
    """
    High-level function:  SOCObservation → SOCAction (via LLM).

    Builds the analyst prompt, queries the LLM, and returns a parsed action dict.
    Returns ``None`` if the LLM call or parsing fails after retries.
    """
    prompt = build_prompt(observation)

    for attempt in range(1, MAX_PARSE_RETRIES + 2):
        try:
            raw = query_llm(prompt, model=model)
            action = parse_llm_response(raw, observation)
            return action
        except RuntimeError as exc:
            # API-level failure — no point retrying
            print(f"  ❌  LLM call failed: {exc}")
            return None
        except ValueError as exc:
            if attempt <= MAX_PARSE_RETRIES:
                print(f"  ⚠️  Parse error (attempt {attempt}/{MAX_PARSE_RETRIES + 1}). Retrying …")
            else:
                print(f"  ❌  Could not parse LLM response after {MAX_PARSE_RETRIES + 1} attempts: {exc}")
                return None

    return None


# ─── Agent Loop ───────────────────────────────────────────────────────────────

def run_agent(task_id: str, model: str = LLM_MODEL) -> dict:
    """
    Run the LLM agent against a single task episode.

    Returns a summary dict: session_id, steps, final_score, outcome, model.
    """
    divider = "─" * 60

    print(f"\n{divider}")
    print(f"  🤖  SOC LLM Agent  │  Task: {task_id.upper()}  │  Model: {model}")
    print(divider)

    # ── Step 1: Reset environment ──────────────────────────────────────────
    print("\n📡 [1/5]  Initialising environment …")
    try:
        reset_resp = requests.post(f"{BASE_URL}/reset?task_id={task_id}", timeout=10)
        reset_resp.raise_for_status()
    except requests.exceptions.ConnectionError:
        print("❌  Cannot reach the API server.  Is it running?")
        print("    Start it with:  cd api && uvicorn main:app --reload\n")
        sys.exit(1)

    reset_data  = reset_resp.json()
    session_id  = reset_data["session_id"]
    observation = reset_data["observation"]

    print(f"✅  Session created   → {session_id}")
    print(f"📋  System status     → {observation['system_status']}")
    print(f"📄  Log entries       → {len(observation['current_logs'])}")
    print(f"🔒  Already blocked   → {observation['blocked_ips'] or 'none'}")

    # ── Step 2: Build prompt ───────────────────────────────────────────────
    print("\n📝 [2/5]  Building analyst prompt …")
    prompt = build_prompt(observation)
    preview_lines = prompt.split("\n")[:8]
    print("  Prompt preview:")
    for line in preview_lines:
        print(f"    {line}")
    print(f"  … [{len(prompt)} chars total]")

    # ── Step 3: Query LLM ──────────────────────────────────────────────────
    print(f"\n🧠 [3/5]  Querying LLM ({model}) …")
    action = decide_action_llm(observation, model=model)

    if action is None:
        print("  ⚠️  LLM returned no usable action. Skipping step.")
        return {
            "session_id": session_id,
            "steps": 0,
            "final_score": 0.0,
            "outcome": "llm_error",
            "model": model,
        }

    # ── Step 4: Send action to environment ─────────────────────────────────
    print("\n⚡ [4/5]  Executing action …")
    print(f"  Action type  : {action['action_type'].upper()}")
    print(f"  Target IP    : {action['target_ip']}")
    print(f"  Reasoning    : {action['reasoning']}")

    try:
        step_resp = requests.post(
            f"{BASE_URL}/step?session_id={session_id}",
            json=action,
            timeout=10,
        )
        step_resp.raise_for_status()
    except requests.exceptions.RequestException as exc:
        print(f"❌  Step request failed: {exc}")
        sys.exit(1)

    step_data = step_resp.json()
    reward = step_data["reward"]
    done   = step_data["done"]
    info   = step_data["info"]

    # ── Step 5: Report ─────────────────────────────────────────────────────
    print(f"\n📊 [5/5]  Results")
    print(divider)
    print(f"  Reward this step : {reward:+.1f}")
    print(f"  Episode done     : {'Yes ✅' if done else 'No 🔄'}")
    print(f"  Steps taken      : {info['steps_taken']}")
    print(f"  Cumulative score : {info['current_score']:+.1f}")
    print(f"  Server message   : {info['message']}")
    print(divider)

    return {
        "session_id": session_id,
        "steps":      info["steps_taken"],
        "final_score": info["current_score"],
        "outcome":    "success" if reward > 0 else "failure",
        "model":      model,
    }


# ─── Test Simulation ──────────────────────────────────────────────────────────

def run_simulation(model: str = LLM_MODEL) -> None:
    """
    Automatically runs the LLM agent against all three built-in tasks
    (task_easy, task_medium, task_hard) and prints a consolidated score table.
    """
    tasks = ["task_easy", "task_medium", "task_hard"]
    results = []

    print("\n" + "═" * 60)
    print("  🧪  SOC LLM Agent — Automated Test Simulation")
    print("═" * 60)
    print(f"  Model  : {model}")
    print(f"  Tasks  : {', '.join(tasks)}")
    print(f"  SDK    : google-genai (Gemini Developer API)")

    # Warn loudly if using the placeholder key
    if GEMINI_API_KEY.startswith("placeholder"):
        print()
        print("  ⚠️  WARNING: Placeholder GEMINI_API_KEY detected.")
        print("     Get a free key at https://aistudio.google.com/app/apikey")
        print("     then set GEMINI_API_KEY in your environment or baseline/.env\n")
        print("  ℹ️  Continuing — expect Gemini API failures without a real key.")

    for task in tasks:
        result = run_agent(task, model=model)
        results.append((task, result))

    # ── Consolidated summary ───────────────────────────────────────────────
    print("\n" + "═" * 60)
    print("  📈  LLM AGENT SIMULATION SUMMARY")
    print("═" * 60)
    print(f"  {'Task':<15}  {'Outcome':<12}  {'Score':>8}  {'Steps':>6}")
    print(f"  {'─'*15}  {'─'*12}  {'─'*8}  {'─'*6}")

    outcome_icons = {
        "success":   "✅",
        "failure":   "❌",
        "no_threat": "⚠️ ",
        "llm_error": "🔌",
    }
    total_score = 0.0

    for task, r in results:
        icon = outcome_icons.get(r["outcome"], "❓")
        print(
            f"  {task:<15}  {icon} {r['outcome']:<10}  "
            f"{r['final_score']:>+7.1f}  {r['steps']:>6}"
        )
        total_score += r["final_score"]

    print(f"  {'─'*15}  {'─'*12}  {'─'*8}  {'─'*6}")
    print(f"  {'TOTAL':<15}  {'':12}  {total_score:>+7.1f}")
    print("═" * 60 + "\n")


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SOC LLM Agent — uses a language model to analyse logs and respond to threats."
    )
    parser.add_argument(
        "--task",
        choices=["easy", "medium", "hard"],
        default=None,
        help="Run a single task (easy | medium | hard). Omit to run all tasks.",
    )
    parser.add_argument(
        "--model",
        default=LLM_MODEL,
        help=f"Gemini model to use (default: {LLM_MODEL}).",
    )
    args = parser.parse_args()

    if args.task:
        run_agent(f"task_{args.task}", model=args.model)
    else:
        run_simulation(model=args.model)
