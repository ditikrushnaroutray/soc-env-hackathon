from ..models import SOCAction, SOCObservation

def evaluate_action(action: SOCAction, state: SOCObservation) -> tuple[float, bool, str]:
    """Calculates the reward for the AI's action."""
    
    # 1. Find the logs for the IP the AI is targeting
    target_logs = [log for log in state.current_logs if log.source_ip == action.target_ip]
    
    if not target_logs:
        # A poor action yields 0.0 directly, avoiding unbounded cumulative negatives.
        return 0.0, False, "Penalty: AI targeted an IP that isn't even in the current logs."

    # 2. Heuristic: Is the IP actually bad? (Did it throw 401, 403, or 500 errors?)
    is_malicious = any(log.status_code >= 400 for log in target_logs)

    reward = 0.0
    done = False
    message = ""

    # 3. Grade the action
    if action.action_type == "block_ip":
        if is_malicious:
            reward = 1.0
            message = "Success: Blocked a malicious IP."
            done = True # They solved the incident
        else:
            reward = 0.0
            message = "Critical Penalty: Blocked a normal user."
            done = True # End the simulation on critical failure.
            
    elif action.action_type == "allow_ip":
        if is_malicious:
            reward = 0.0
            message = "Critical Penalty: Allowed a hacker to continue."
            done = True # End the simulation on critical failure.
        else:
            reward = 1.0 # Awarded for actively allowing normal traffic to pass if that's the only task.
            message = "Correct: Allowed normal traffic."
            done = True

    elif action.action_type == "escalate":
        reward = 0.5
        message = "Escalated to human analyst. Partial credit for safe choice."

<<<<<<< HEAD
    return reward, done, message
    
=======
    return reward, done, message
>>>>>>> df617397fa817e65274169249a501497bca0c76d
