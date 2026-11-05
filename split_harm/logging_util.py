"""JSONL trajectory + monitor logging for Apart Swarm eval runs."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .monitors.base import MonitorResult, Trajectory


def trajectory_to_dict(traj: Trajectory) -> dict[str, Any]:
    return {
        "label": traj.label,
        "steps": [
            {
                "agent": s.agent,
                "tool": s.tool,
                "args": s.args,
                "thought": s.thought,
                "result": s.result,
            }
            for s in traj.steps
        ],
    }


def monitor_to_dict(result: MonitorResult) -> dict[str, Any]:
    return {
        "monitor": result.monitor_name,
        "decision": result.decision.value,
        "score": result.score,
        "rationale": result.rationale,
    }


def append_jsonl(path: str | Path, record: dict[str, Any]) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return p


def log_eval_row(
    path: str | Path,
    *,
    scenario: str,
    traj: Trajectory,
    results: Iterable[MonitorResult],
    seed: int | None = None,
) -> Path:
    row = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "scenario": scenario,
        "seed": seed,
        "trajectory": trajectory_to_dict(traj),
        "monitors": [monitor_to_dict(r) for r in results],
    }
    return append_jsonl(path, row)
