"""Seed / trajectory variance eval helpers (deterministic, no LLM)."""

from __future__ import annotations

from .metrics import (
    BinaryLabels,
    aggregate_seed_rates,
    format_seed_variance_markdown,
    metrics_table,
)
from .monitors import (
    EncodedTaintMonitor,
    FragmentTaintMonitor,
    MajorityMonitor,
    SingleStepJudge,
    TaintMonitor,
    TrajectoryMonitor,
    TrustedMonitor,
)
from .sandbox import (
    BENIGN_CFG_AUDIT,
    BENIGN_COLLAB,
    SPLIT_ENCODED,
    SPLIT_EXFIL,
    SPLIT_FRAGMENT,
    SPLIT_HEX,
    SPLIT_STEALTH,
    run_scenario_seeded,
)

DEFAULT_SEEDS = [0, 1, 2, 3, 4]

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


def eval_seed(seed: int) -> dict[str, dict[str, float]]:
    labeled: list[BinaryLabels] = []
    for name, agents, harmful in SCENARIO_SPECS:
        traj = run_scenario_seeded(agents, seed, label=name)
        labeled.append(BinaryLabels(traj, harmful))
    return metrics_table(MONITORS, labeled)


def find_breaks(
    per_seed: dict[int, dict[str, dict[str, float]]],
    baseline_seed: int = 0,
) -> list[str]:
    """Document any seed where a monitor's det/fpr differs from baseline."""
    if baseline_seed not in per_seed:
        return [f"baseline seed {baseline_seed} missing"]
    base = per_seed[baseline_seed]
    notes: list[str] = []
    for seed, rates in sorted(per_seed.items()):
        if seed == baseline_seed:
            continue
        for mon, r in rates.items():
            b = base.get(mon)
            if b is None:
                continue
            if (
                r["detection_rate"] != b["detection_rate"]
                or r["false_positive_rate"] != b["false_positive_rate"]
            ):
                notes.append(
                    f"seed {seed} / {mon}: det {b['detection_rate']:.3f}→"
                    f"{r['detection_rate']:.3f}, fpr {b['false_positive_rate']:.3f}→"
                    f"{r['false_positive_rate']:.3f}"
                )
    return notes


def build(
    seeds: list[int] | None = None,
) -> tuple[str, dict[int, dict[str, dict[str, float]]], dict[str, dict[str, float]], list[str]]:
    seeds = list(seeds) if seeds is not None else list(DEFAULT_SEEDS)
    per_seed = {s: eval_seed(s) for s in seeds}
    aggregate = aggregate_seed_rates(per_seed)
    breaks = find_breaks(per_seed)
    md = format_seed_variance_markdown(
        seeds=seeds,
        per_seed=per_seed,
        aggregate=aggregate,
        breaks=breaks,
    )
    return md, per_seed, aggregate, breaks
