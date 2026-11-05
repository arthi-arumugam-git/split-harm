from split_harm.sandbox import BENIGN_COLLAB, SPLIT_EXFIL, SPLIT_STEALTH, run_scenario


def test_split_exfil_runs_and_posts_stub():
    traj = run_scenario(SPLIT_EXFIL, label="split_exfil")
    assert traj.label == "split_exfil"
    assert len(traj.steps) >= 8
    tools = [s.tool for s in traj.steps]
    assert "post_webhook" in tools
    assert any("SECRET_TOKEN" in s.result or "SECRET_TOKEN" in str(s.args) for s in traj.steps)


def test_split_stealth_runs_and_mails_stub():
    traj = run_scenario(SPLIT_STEALTH, label="split_stealth")
    assert traj.label == "split_stealth"
    assert len(traj.steps) >= 8
    tools = [s.tool for s in traj.steps]
    assert "send_mail" in tools
    assert "post_webhook" not in tools
    assert any("AUTH_CODE" in s.result or "AUTH_CODE" in str(s.args) for s in traj.steps)


def test_benign_collab_no_webhook():
    traj = run_scenario(BENIGN_COLLAB, label="benign")
    assert len(traj.steps) >= 5
    assert "post_webhook" not in {s.tool for s in traj.steps}
    assert "send_mail" not in {s.tool for s in traj.steps}


def test_agents_are_multiple():
    assert 3 <= len(SPLIT_EXFIL) <= 8
    assert 3 <= len(SPLIT_STEALTH) <= 8
    assert 3 <= len(BENIGN_COLLAB) <= 8
