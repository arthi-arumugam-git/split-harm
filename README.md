# Split-Harm Detector for Tool-Using Agent Teams

Apart Research **Swarm Alignment 2026** — Track 4: Multi-Agent Oversight and Control.

Working title / weekend scaffold. Cash pool is secondary to higher-priority USD work; this repo is sized to ship a research report over Fri–Sun.

## Intent

Recreate a tiny sandbox where several tool-using agents share memory/tools and a harmful goal is **split** into harmless-looking steps. Compare:

1. **Single-step judge** — scores each step alone (misses compositional harm when steps look mild).
2. **Trajectory monitor** — scores the full trace (secret-touch + outbound co-occurrence in this stub).
3. **Majority monitor** — N jittered trajectory replicas; FLAG on majority vote.
4. **Trusted monitor** — stricter gate (only secret+outbound together; single signals ALLOW).
5. **Taint monitor** — value-flow: FLAG only when a secret file value reaches an outbound body (fixes BENIGN_CFG_AUDIT false positives).
6. **Fragment taint** — 5-char shared-substring coverage across outbound (catches SPLIT_FRAGMENT).
7. **Encoded taint** — reverse / base64 / hex of secret, halves, and sliding min_frag windows (catches SPLIT_ENCODED and SPLIT_HEX).

Metrics: detection rate on split-harm vs false-positive rate on benign multi-agent ops.

## Preexisting vs weekend boundary

| Source | Status |
|--------|--------|
| This `split_harm/` package | **Weekend work** (starts Thu Nov 5 scaffold) |
| RedLoop / Gray Swan IPI ideas | **Technique inspiration only** — not copied into this tree |
| Any future paste of prior eval harness code | Mark clearly in README + report as **preexisting** |

Only weekend work is judged by Apart. Do not blur that line.

## Dual-use note

The attack harness (split-exfil scenario) exists **for evaluation only**. Tools are in-process stubs: no network sockets, no real credentials, no production systems. Do not reuse the scenario design to attack live agent teams. Dual-use appendix belongs in the final report.

## Layout

```
split_harm/
  sandbox/     agents, stub tools, shared memory, scenarios, runner
  monitors/    SingleStepJudge … TaintMonitor, FragmentTaintMonitor, EncodedTaintMonitor
  metrics.py   detection_rate / false_positive_rate helpers
tests/         pytest
```

## Quickstart

```bash
cd /workspace/money/apart_swarm/split_harm
python -m pytest -q
python scripts/report_table.py
python scripts/run_seed_variance.py
```

## Citations

Omit fabricated refs. If the report cites prior art, use real public names/years only (e.g. well-known oversight / multi-agent safety papers you have actually read). No fake DOIs.

## See also

- `../PLAN.md` — sprint plan
- `../DAY0.md` — Thu evening checklist (Adaption credits, Discord, lock title)
