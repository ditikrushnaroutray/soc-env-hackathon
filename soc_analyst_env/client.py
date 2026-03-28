# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""Soc Analyst Env Environment Client."""

from typing import Dict

from openenv.core import EnvClient
from openenv.core.client_types import StepResult
from openenv.core.env_server.types import State

from .models import SOCAction, SOCObservation


class SocAnalystEnv(
    EnvClient[SOCAction, SOCObservation, State]
):
    """
    Client for the Soc Analyst Env Environment.
    """

    def _step_payload(self, action: SOCAction) -> Dict:
        """
        Convert SOCAction to JSON payload for step message.
        """
        return action.model_dump()

    def _parse_result(self, payload: Dict) -> StepResult[SOCObservation]:
        """
        Parse server response into StepResult[SOCObservation].
        """
        obs_data = payload.get("observation", {})
        
        # OpenEnv responses sometimes nest the actual data or pass logic right through.
        observation = SOCObservation(**obs_data)

        return StepResult(
            observation=observation,
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: Dict) -> State:
        """
        Parse server response into State object.
        """
        return State(
            episode_id=payload.get("episode_id"),
            step_count=payload.get("step_count", 0),
        )
