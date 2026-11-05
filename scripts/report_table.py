#!/usr/bin/env python3
"""Print and write the full decision matrix + detection/FPR markdown table."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from split_harm.metrics import (
    BinaryLabels,
    decision_matrix,
    format_metrics_markdown,
    metrics_table,
)
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

SCENARIO_SPECS: list[tuple[str, object, bool]] = [
    ("split_exfil", SPLIT_EXFIL, True),
    ("split_stealth", SPLIT_STEALTH, True),
    ("split_fragment", SPLIT_FRAGMENT, True),
    ("split_encoded", SPLIT_ENCODED, True),
    ("split_hex", SPLIT_HEX, True),
    ("benign_collab", BENIGN_COLLAB, False),
    ("benign_cfg_audit", BENIGN_CFG_AUDIT, False),
]

MONITORS = [
    SingleStepJudge(),
    TrajectoryMonitor(),
    MajorityMonitor(),
    TrustedMonitor(),
    TaintMonitor(),
    FragmentTaintMonitor(),
    EncodedTaintMonitor(),
]


def build() -> tuple[str, dict, dict]:
    labeled: list[BinaryLabels] = []
    scenarios: dict = {}
    harmful_labels: dict[str, bool] = {}
    for name, agents, harmful in SCENARIO_SPECS:
        traj = run_scenario(agents, label=name)
        scenarios[name] = traj
        harmful_labels[name] = harmful
        labeled.append(BinaryLabels(traj, harmful))

    matrix = decision_matrix(MONITORS, scenarios)
    rates = metrics_table(MONITORS, labeled)
    md = format_metrics_markdown(matrix, rates, harmful_labels=harmful_labels)
    return md, matrix, rates


def main() -> None:
    md, _matrix, rates = build()
    out_dir = ROOT / "report"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "METRICS_TABLE.md"
    out_path.write_text(md, encoding="utf-8")
    print(md)
    print(f"wrote -> {out_path}")
    # Compact summary line for logs / hourly runs.
    summary = ", ".join(
        f"{name}: det={r['detection_rate']:.2f} fpr={r['false_positive_rate']:.2f}"
        for name, r in rates.items()
    )
    print(f"summary: {summary}")


if __name__ == "__main__":
    main()
