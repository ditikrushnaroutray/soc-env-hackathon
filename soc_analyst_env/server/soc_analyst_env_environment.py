from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import State
from ..models import SOCObservation, SOCAction, LogEntry
from .generators import generate_logs
from .engine import evaluate_action
import uuid

# Global session storage - will be populated when environments are created
SESSIONS = {}

class SOCAnalystEnv(Environment[SOCAction, SOCObservation, State]):
    SUPPORTS_CONCURRENT_SESSIONS: bool = True

    def __init__(self):
        super().__init__()
        self._state = State(episode_id=str(uuid.uuid4()), step_count=0)
        self.task_id = "normal"
        self.total_score = 0.01  # STRICT BOUNDS FIX: Start at 0.01, not 0.0
        self.current_obs = None
        
        self.session_id = self._state.episode_id
        SESSIONS[self.session_id] = self

    def _ensure_obs_exists(self):
        if self.current_obs is None:
            raw_logs = generate_logs(self.task_id)
            parsed_logs = [LogEntry(**log) for log in raw_logs]
            self.current_obs = SOCObservation(
                current_logs=parsed_logs, 
                blocked_ips=[], 
                system_status="Under Attack" if self.task_id != "normal" else "Normal",
                reward=0.01,
                done=False,
                metadata={"message": "State recovered by safeguard"}
            )

    def reset(self, seed=None, episode_id=None, **kwargs) -> SOCObservation:
        self.task_id = kwargs.get("task_id", self.task_id)
        self._state = State(episode_id=str(uuid.uuid4()), step_count=0)
        self.total_score = 0.01  # STRICT BOUNDS FIX: Reset to 0.01
        
        self.session_id = self._state.episode_id
        SESSIONS[self.session_id] = self
        
        self.current_obs = None 
        self._ensure_obs_exists()
        
        return self.current_obs

    def step(self, action: SOCAction, timeout_s=None, **kwargs) -> SOCObservation:
        self._ensure_obs_exists()
        
        self._state.step_count += 1
        
        reward, done, msg = evaluate_action(action, self.current_obs)
        self.total_score += reward
        
        # STRICT BOUNDS FIX: Absolute mathematical clamp on the environment's state
        self.total_score = max(0.01, min(0.99, float(self.total_score)))
        
        if action.action_type == "block_ip" and action.target_ip not in self.current_obs.blocked_ips:
            self.current_obs.blocked_ips.append(action.target_ip)
            
        if self._state.step_count >= 10:
            done = True
            msg += " | Max steps reached."
            
        self.current_obs.reward = reward
        self.current_obs.done = done
        self.current_obs.metadata = {
            "steps_taken": self._state.step_count, 
            "message": msg, 
            "current_score": self.total_score
        }
        
        return self.current_obs

    @property
    def state(self) -> State:
        return self._state