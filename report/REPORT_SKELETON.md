# Report skeleton — Split-Harm Detector for Tool-Using Agent Teams

Apart Research Swarm Alignment 2026 · Track 4: Multi-Agent Oversight and Control  
Target length: ≤8 pages + refs/appendices (official template).  
**Do not paste fabricated citations or invented numbers.** Fill results only from `METRICS_TABLE.md` / live eval.

---

## 1. Title / authors / track
- **Working title:** Split-Harm Detector for Tool-Using Agent Teams
- **Track:** 4 — Multi-Agent Oversight and Control
- **Authors:** Arthi Arumugam (solo / add collaborators if any)
- **Repo:** https://github.com/arthi-arumugam-git/split-harm · **Video:** *(optional 3–5 min)*

## 2. Research question
Can a value-flow (taint) monitor catch multi-agent **split-harm** tool trajectories that single-step judges miss, while avoiding false positives on benign multi-agent ops that only *touch* secret paths without leaking values?

## 3. Method (outline)
1. **Sandbox** — scripted 3–8 agents, shared memory, stub tools (`read_file`, `write_memory`, `read_memory`, `post_webhook`, `send_mail`). No network sockets; eval-only.
2. **Attack scenarios** — `SPLIT_EXFIL` (overt webhook), `SPLIT_STEALTH` (mild steps + mail with secret).
3. **Benign / hard negative** — `BENIGN_COLLAB`; `BENIGN_CFG_AUDIT` (path touch + outbound, secret value never leaves).
4. **Monitors** — SingleStepJudge, TrajectoryMonitor, MajorityMonitor, TrustedMonitor, TaintMonitor.
5. **Metrics** — detection rate on harmful set; false-positive rate on benign set; full decision matrix.

## 4. Results (placeholder)
Paste / summarize the live table from **`report/METRICS_TABLE.md`** (regenerate with `python3 scripts/report_table.py`). Do not invent rates.

Expected qualitative story (confirm against the table before writing prose):
- Single-step misses stealth (detection < 1).
- Co-occurrence baselines (trajectory / majority / trusted) catch both attacks but **false-positive on `BENIGN_CFG_AUDIT`**.
- Taint: detection 1.0, FPR 0.0 on this toy set.

## 5. Discussion / limitations
- Toy deterministic scenarios; not LLM-sampled trajectories yet.
- Taint rules are path/value heuristics for this sandbox — not a general program analysis.
- Majority jitter is a stub replica vote, not independent model samples.

## 6. Dual-use appendix (stub)
The attack harness (split-exfil / split-stealth scenarios) exists **for evaluation only**. Tools are in-process stubs: no real credentials, no production systems, no live network. Do not reuse scenario designs to attack deployed agent teams. Disclose any dual-use risk clearly in the submitted PDF.

## 7. Preexisting vs weekend boundary
| Source | Status |
|--------|--------|
| `split_harm/` package in this tree | Weekend work (scaffold from Thu Nov 5) |
| RedLoop / Gray Swan IPI ideas | Technique inspiration only — not copied here |
| Any pasted prior harness | Mark **preexisting** in README + this report |

Only weekend work is judged. Keep that boundary sharp in the final PDF.

## 8. References
Add only real public sources you have actually read (oversight / multi-agent safety / control papers). **No fake DOIs or invented citations.**
