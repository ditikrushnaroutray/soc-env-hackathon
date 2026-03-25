from fastapi import FastAPI, HTTPException
from models import SOCObservation, SOCAction
import uuid

app = FastAPI(title="SOC Incident Response Env")

SESSIONS = {}

@app.get("/")
def read_root():
    return {"status": "online", "message": "SOC Analyst Environment is running."}

@app.get("/tasks")
def get_tasks():
    return {
        "tasks": [
            {"id": "task_easy", "description": "Block the single IP attempting a brute force login."},
            {"id": "task_medium", "description": "Identify and block a distributed SQL injection attack."},
            {"id": "task_hard", "description": "Triage a mixed-traffic environment with decoy attacks and false positives."}
        ]
    }

@app.post("/reset")
def reset_environment(task_id: str):
    session_id = str(uuid.uuid4())
    initial_observation = SOCObservation(current_logs=[], blocked_ips=[], system_status="Normal")
    
    SESSIONS[session_id] = {
        "task_id": task_id,
        "state": initial_observation,
        "score": 0.0,
        "step_count": 0
    }
    return {"session_id": session_id, "observation": initial_observation.model_dump()}

@app.post("/step")
def take_action(session_id: str, action: SOCAction):
    if session_id not in SESSIONS:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = SESSIONS[session_id]
    session["step_count"] += 1
    
    # We will build the actual engine logic tomorrow
    return {
        "observation": session["state"].model_dump(),
        "reward": 0.0,
        "done": False,
        "info": {"steps_taken": session["step_count"]}
    }

@app.get("/state")
def get_state(session_id: str):
    if session_id not in SESSIONS:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"session_id": session_id, "state": SESSIONS[session_id]["state"].model_dump()}

@app.get("/grader")
def grade_session(session_id: str):
    if session_id not in SESSIONS:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"session_id": session_id, "final_score": SESSIONS[session_id]["score"]}