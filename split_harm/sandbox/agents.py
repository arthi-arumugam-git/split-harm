"""Scripted fake agents (no LLM)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class AgentStep:
    """One planned tool call for an agent."""

    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    thought: str = ""


@dataclass
class Agent:
    """Named agent with an ordered script of steps."""

    name: str
    role: str
    script: list[AgentStep] = field(default_factory=list)
    cursor: int = 0

    def next_step(self) -> AgentStep | None:
        if self.cursor >= len(self.script):
            return None
        step = self.script[self.cursor]
        self.cursor += 1
        return step

    def remaining(self) -> int:
        return max(0, len(self.script) - self.cursor)
