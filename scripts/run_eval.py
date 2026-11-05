#!/usr/bin/env python3
"""Run all toy scenarios through all monitors; append JSONL under data/."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from split_harm.logging_util import log_eval_row
from split_harm.monitors import (
    EncodedTaintMonitor,
    FragmentTaintMonitor,
    MajorityMonitor,
    SingleStepJudge,
    TaintMonitor,
    TrajectoryMonitor,
    TrustedMonitor,
)
from split_harm.sandbox import (
    BENIGN_CFG_AUDIT,
    BENIGN_COLLAB,
    SPLIT_ENCODED,
    SPLIT_EXFIL,
    SPLIT_FRAGMENT,
    SPLIT_HEX,
    SPLIT_STEALTH,
    run_scenario,
)

SCENARIOS = {
    "split_exfil": SPLIT_EXFIL,
    "split_stealth": SPLIT_STEALTH,
    "split_fragment": SPLIT_FRAGMENT,
    "split_encoded": SPLIT_ENCODED,
    "split_hex": SPLIT_HEX,
    "benign_collab": BENIGN_COLLAB,
    "benign_cfg_audit": BENIGN_CFG_AUDIT,
}
MONITORS = [
    SingleStepJudge(),
    TrajectoryMonitor(),
    MajorityMonitor(),
    TrustedMonitor(),
    TaintMonitor(),
    FragmentTaintMonitor(),
    EncodedTaintMonitor(),
]


def main() -> None:
    out = ROOT / "data" / "eval_runs.jsonl"
    for name, agents in SCENARIOS.items():
        traj = run_scenario(agents, label=name)
        results = [m.evaluate(traj) for m in MONITORS]
        log_eval_row(out, scenario=name, traj=traj, results=results)
        decisions = ", ".join(f"{r.monitor_name}={r.decision.value}" for r in results)
        print(f"{name}: {len(traj.steps)} steps | {decisions}")
    print(f"logged -> {out}")


if __name__ == "__main__":
    main()
