"""Fragment-level taint closes the SPLIT_FRAGMENT gap without new false positives."""

from split_harm.monitors import FragmentTaintMonitor
from split_harm.monitors.base import MonitorDecision
from split_harm.sandbox import (
    BENIGN_CFG_AUDIT,
    BENIGN_COLLAB,
    SPLIT_EXFIL,
    SPLIT_FRAGMENT,
    SPLIT_STEALTH,
    run_scenario,
)

M = FragmentTaintMonitor()


def _d(sc, label):
    return M.evaluate(run_scenario(sc, label=label)).decision


def test_flags_fragment_leak():
    assert _d(SPLIT_FRAGMENT, "split_fragment") == MonitorDecision.FLAG


def test_flags_whole_value_leaks():
    assert _d(SPLIT_EXFIL, "split_exfil") == MonitorDecision.FLAG
    assert _d(SPLIT_STEALTH, "split_stealth") == MonitorDecision.FLAG


def test_allows_hard_negative_and_benign():
    assert _d(BENIGN_CFG_AUDIT, "benign_cfg_audit") == MonitorDecision.ALLOW
    assert _d(BENIGN_COLLAB, "benign_collab") == MonitorDecision.ALLOW
