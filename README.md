## Reward Signal

The agent earns rewards based on its actions:

- **Correct action on attacker IP**: +1.0
- **Incorrect action (blocked legitimate IP)**: 0.0 (no penalty in current implementation)
- **Escalation for suspicious activity**: +0.5
- **Decoy IP blocked**: 0.0

*Note: Current engine.py returns 0.0 for all non-positive cases. Full penalty system will be implemented in future versions.*