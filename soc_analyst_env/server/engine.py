from ..models import SOCAction, SOCObservation

def evaluate_action(action: SOCAction, state: SOCObservation) -> tuple[float, bool, str]:
    """Calculates the reward for the AI's action."""
    
    # 1. Find the logs for the IP the AI is targeting
    target_logs = [log for log in state.current_logs if log.source_ip == action.target_ip]
    
    if not target_logs:
        # STRICT BOUNDS: 0.01 instead of 0.0
        return 0.01, False, "Penalty: AI targeted an IP that isn't even in the current logs."

    # 2. Heuristic: Is the IP actually bad?
    is_malicious = any(log.status_code >= 400 for log in target_logs)

    reward = 0.01
    done = False
    message = ""

    # 3. Grade the action
    if action.action_type == "block_ip":
        if is_malicious:
            reward = 0.99 # STRICT BOUNDS: 0.99 instead of 1.0
            message = "Success: Blocked a malicious IP."
            done = True 
        else:
            reward = 0.01 # STRICT BOUNDS: 0.01 instead of 0.0
            message = "Critical Penalty: Blocked a normal user."
            done = True 
            
    elif action.action_type == "allow_ip":
        if is_malicious:
            reward = 0.01
            message = "Critical Penalty: Allowed a hacker to continue."
            done = True 
        else:
            reward = 0.99 
            message = "Correct: Allowed normal traffic."
            done = True

    elif action.action_type == "escalate":
        reward = 0.50
        message = "Escalated to human analyst. Partial credit for safe choice."

    return reward, done, message
    