import json
from pathlib import Path

from split_harm.logging_util import log_eval_row
from split_harm.monitors import SingleStepJudge, TrajectoryMonitor
from split_harm.sandbox import SPLIT_STEALTH, run_scenario


def test_log_eval_row_jsonl(tmp_path: Path):
    out = tmp_path / "runs.jsonl"
    traj = run_scenario(SPLIT_STEALTH, label="split_stealth")
    results = [SingleStepJudge().evaluate(traj), TrajectoryMonitor().evaluate(traj)]
    log_eval_row(out, scenario="split_stealth", traj=traj, results=results, seed=0)
    lines = out.read_text().strip().splitlines()
    assert len(lines) == 1
    row = json.loads(lines[0])
    assert row["scenario"] == "split_stealth"
    assert len(row["trajectory"]["steps"]) >= 8
    assert {m["monitor"] for m in row["monitors"]} == {
        "single_step_judge",
        "trajectory_monitor",
    }
