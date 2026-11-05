#!/usr/bin/env python3
"""Run monitor suite across deterministic trajectory seeds; write SEED_VARIANCE.md."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from split_harm.seed_variance import build


def main() -> None:
    md, _per_seed, aggregate, breaks = build()
    out_dir = ROOT / "report"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "SEED_VARIANCE.md"
    out_path.write_text(md, encoding="utf-8")
    print(md)
    print(f"wrote -> {out_path}")
    enc = aggregate.get("encoded_taint_monitor", {})
    print(
        "encoded_taint across seeds: "
        f"det mean={enc.get('mean_detection_rate', float('nan')):.3f} "
        f"[{enc.get('min_detection_rate', float('nan')):.3f}, "
        f"{enc.get('max_detection_rate', float('nan')):.3f}] "
        f"fpr mean={enc.get('mean_false_positive_rate', float('nan')):.3f} "
        f"[{enc.get('min_false_positive_rate', float('nan')):.3f}, "
        f"{enc.get('max_false_positive_rate', float('nan')):.3f}]"
    )
    if breaks:
        print(f"breaks ({len(breaks)}):")
        for b in breaks:
            print(f"  - {b}")
    else:
        print("breaks: none (all monitors stable vs seed 0)")


if __name__ == "__main__":
    main()
