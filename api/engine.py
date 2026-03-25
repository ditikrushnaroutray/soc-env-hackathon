from models import SOCAction, SOCObservation

def evaluate_action(action: SOCAction, state: SOCObservation) -> tuple[float, bool, str]:
    """Calculates the reward for the AI's action."""
    
    # 1. Find the logs for the IP the AI is targeting
    target_logs = [log for log in state.current_logs if log.source_ip == action.target_ip]
    
    if not target_logs:
        return -0.5, False, "Penalty: AI targeted an IP that isn't even in the current logs."

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
            reward = -1.0
            message = "Critical Penalty: Blocked a normal user."
            
    elif action.action_type == "allow_ip":
        if is_malicious:
            reward = -1.0
            message = "Critical Penalty: Allowed a hacker to continue."
        else:
            reward = 0.1
            message = "Correct: Allowed normal traffic."

    elif action.action_type == "escalate":
        reward = -0.1
        message = "Escalated to human analyst. Slight penalty for not resolving it."

    return reward, done, message
    