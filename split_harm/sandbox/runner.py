"""Round-robin runner over scripted agents."""

from __future__ import annotations

from copy import deepcopy

from ..monitors.base import StepRecord, Trajectory
from .agents import Agent
from .perturb import perturb_agents
from .tools import SharedMemory, build_default_registry


def run_scenario(
    agents: list[Agent],
    *,
    label: str = "",
    max_steps: int = 64,
) -> Trajectory:
    """Execute agent scripts round-robin against stub tools. Returns a Trajectory."""
    agents = [deepcopy(a) for a in agents]
    memory = SharedMemory()
    registry = build_default_registry(memory)
    records: list[StepRecord] = []
    steps = 0
    progressed = True
    while progressed and steps < max_steps:
        progressed = False
        for agent in agents:
            planned = agent.next_step()
            if planned is None:
                continue
            progressed = True
            result = registry.call(planned.tool, **planned.args)
            records.append(
                StepRecord(
                    agent=agent.name,
                    tool=planned.tool,
                    args=dict(planned.args),
                    thought=planned.thought,
                    result=result,
                )
            )
            steps += 1
            if steps >= max_steps:
                break
    return Trajectory(label=label or "unnamed", steps=records)


def run_scenario_seeded(
    agents: list[Agent],
    seed: int,
    *,
    label: str = "",
    max_steps: int = 64,
) -> Trajectory:
    """Perturb agents with ``seed`` then run. seed=0 is the unperturbed baseline."""
    perturbed = perturb_agents(agents, seed)
    return run_scenario(perturbed, label=label, max_steps=max_steps)
