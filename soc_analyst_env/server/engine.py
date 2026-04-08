from ..models import SOCAction, SOCObservation

def evaluate_action(action: SOCAction, state: SOCObservation) -> tuple[float, bool, str]:
    """Calculates the reward for the AI's action."""
    
    # 1. Find the logs for the IP the AI is targeting
    target_logs = [log for log in state.current_logs if log.source_ip == action.target_ip]
    
    if not target_logs:
        # STRICT BOUNDS FIX: End game immediately so 0.01 doesn't accumulate
        return 0.01, True, "Penalty: AI targeted an IP that isn't even in the current logs."

    # 2. Heuristic: Is the IP actually bad?
    is_malicious = any(log.status_code >= 400 for log in target_logs)

    # STRICT BOUNDS FIX: Default to 0.01 (not 0.0) and always True (1-shot game)
    reward = 0.01
    done = True  
    message = ""

    # 3. Grade the action
    if action.action_type == "block_ip":
        if is_malicious:
            reward = 0.99
            message = "Success: Blocked a malicious IP."
        else:
            reward = 0.01
            message = "Critical Penalty: Blocked a normal user."
            
    elif action.action_type == "allow_ip":
        if is_malicious:
            reward = 0.01
            message = "Critical Penalty: Allowed a hacker to continue."
        else:
            reward = 0.99 
            message = "Correct: Allowed normal traffic."

    elif action.action_type == "escalate":
        reward = 0.50
        message = "Escalated to human analyst. Partial credit for safe choice."

    # The score is now mathematically locked to exactly 0.01, 0.50, or 0.99
    return reward, True, message
    