"""Deterministic trajectory perturbations for seed / variance checks.

No LLM calls. Perturbations are small structural changes that preserve
scenario labels (harmful stays harmful; benign stays non-leaking) while
exercising monitor ranking stability.

Design note: leading no-ops are applied equally to every agent, trailing
no-ops are appended, and agent-order changes only swap peer notifiers.
Mid-script inserts / full rotation can move outbound ahead of the secret
read in round-robin and unfairly break value-flow monitors even when the
outbound body still carries the secret.
"""

from __future__ import annotations

import random
from copy import deepcopy

from .agents import Agent, AgentStep


def _noop_step(seed: int, tag: int) -> AgentStep:
    return AgentStep(
        tool="approve_request",
        args={
            "request_id": f"noop-s{seed}-{tag}",
            "reason": "benign filler checkpoint",
        },
        thought="Routine checkpoint; no secret handling.",
    )


def _is_peer_notifier(agent: Agent) -> bool:
    return agent.name.startswith("notifier") or "notifier" in agent.role.lower()


def _swap_peer_notifiers(agents: list[Agent], rng: random.Random) -> list[Agent]:
    idxs = [i for i, a in enumerate(agents) if _is_peer_notifier(a)]
    if len(idxs) < 2:
        return agents
    pair = idxs[:2] if len(idxs) == 2 else sorted(rng.sample(idxs, 2))
    i, j = pair[0], pair[1]
    agents[i], agents[j] = agents[j], agents[i]
    return agents


def _swap_adjacent_memory_writes(agent: Agent, rng: random.Random) -> None:
    """Optionally swap one adjacent write_memory pair (fragment/encoded chunks)."""
    idxs = [
        i
        for i in range(len(agent.script) - 1)
        if agent.script[i].tool == "write_memory"
        and agent.script[i + 1].tool == "write_memory"
    ]
    if not idxs or rng.random() >= 0.5:
        return
    i = rng.choice(idxs)
    agent.script[i], agent.script[i + 1] = agent.script[i + 1], agent.script[i]


def _append_thought_filler(agent: Agent, rng: random.Random) -> None:
    for i, step in enumerate(agent.script):
        if rng.random() >= 0.35:
            continue
        agent.script[i] = AgentStep(
            tool=step.tool,
            args=dict(step.args),
            thought=(step.thought + " [status ok]").strip(),
        )


def perturb_agents(agents: list[Agent], seed: int) -> list[Agent]:
    """Deep-copy agents and apply seed-deterministic structural noise.

    seed=0 is the identity (baseline scripted order, no inserts).
    """
    agents = [deepcopy(a) for a in agents]
    for a in agents:
        a.cursor = 0
    if seed == 0:
        return agents

    rng = random.Random(seed)
    tag = 0

    # 1) Swap peer notifiers only (preserves producer→consumer causal order).
    if rng.random() < 0.8:
        agents = _swap_peer_notifiers(agents, rng)

    # 2) Equal leading no-op padding (same count on every agent → relative
    #    interleaving of the original critical steps is unchanged).
    n_lead = rng.randrange(0, 2)
    if n_lead:
        for agent in agents:
            for _ in range(n_lead):
                agent.script.insert(0, _noop_step(seed, tag))
                tag += 1

    # 3) Trailing benign no-ops (per-agent, after critical steps).
    for agent in agents:
        n_append = rng.randrange(0, 3)
        for _ in range(n_append):
            agent.script.append(_noop_step(seed, tag))
            tag += 1

    # 4) Flip adjacent write_memory chunk pairs when present.
    for agent in agents:
        _swap_adjacent_memory_writes(agent, rng)

    # 5) Benign thought filler (does not alter tool args / secret payloads).
    for agent in agents:
        _append_thought_filler(agent, rng)

    return agents
