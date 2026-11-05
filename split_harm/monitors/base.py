"""Shared monitor interfaces."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class MonitorDecision(str, Enum):
    ALLOW = "allow"
    FLAG = "flag"


@dataclass(frozen=True)
class StepRecord:
    agent: str
    tool: str
    args: dict[str, Any]
    thought: str
    result: str


@dataclass
class Trajectory:
    label: str
    steps: list[StepRecord] = field(default_factory=list)

    def texts(self) -> list[str]:
        """Flattened step strings for simple keyword/heuristic monitors."""
        out: list[str] = []
        for s in self.steps:
            out.append(
                f"{s.agent}|{s.tool}|{s.thought}|{s.args}|{s.result}"
            )
        return out


@dataclass
class MonitorResult:
    decision: MonitorDecision
    score: float  # higher = more suspicious
    rationale: str
    monitor_name: str
