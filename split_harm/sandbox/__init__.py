"""Toy multi-agent sandbox: shared memory, stub tools, scripted scenarios."""

from .agents import Agent, AgentStep
from .perturb import perturb_agents
from .runner import run_scenario, run_scenario_seeded
from .scenarios import (
    BENIGN_CFG_AUDIT,
    BENIGN_COLLAB,
    SPLIT_ENCODED,
    SPLIT_EXFIL,
    SPLIT_FRAGMENT,
    SPLIT_HEX,
    SPLIT_STEALTH,
)
from .tools import SharedMemory, ToolRegistry, build_default_registry

__all__ = [
    "Agent",
    "AgentStep",
    "BENIGN_CFG_AUDIT",
    "BENIGN_COLLAB",
    "SPLIT_ENCODED",
    "SPLIT_EXFIL",
    "SPLIT_FRAGMENT",
    "SPLIT_HEX",
    "SPLIT_STEALTH",
    "SharedMemory",
    "ToolRegistry",
    "build_default_registry",
    "perturb_agents",
    "run_scenario",
    "run_scenario_seeded",
]
