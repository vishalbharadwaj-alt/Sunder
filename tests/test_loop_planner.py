"""LoopPlanner: the model sees real results and chooses tools; guardrails always hold."""
from __future__ import annotations

import json
from types import SimpleNamespace

from sunder.agent import LoopPlanner, SunderAgent
from sunder.config import CONFIG
from sunder.db import get_db
from sunder.seed import load_graph
from sunder.tools import graph_tools as T


def _call(i, name, **args):
    fn = SimpleNamespace(name=name, arguments=json.dumps({"reasoning": f"because {name}", **args}))
    msg = SimpleNamespace(content=None, tool_calls=[SimpleNamespace(id=f"c{i}", function=fn)])
    return msg


def _text(content):
    return SimpleNamespace(content=content, tool_calls=None)


class FakeClient:
    """Plays a fixed list of model turns and records what the model was shown."""

    def __init__(self, turns):
        self.turns = list(turns)
        self.seen = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kw):
        self.seen.append([dict(m) for m in kw["messages"]])
        if not self.turns:
            raise RuntimeError("model unavailable")
        return SimpleNamespace(choices=[SimpleNamespace(message=self.turns.pop(0))])


def _run(turns, allow_writes=True):
    db = get_db()
    load_graph(db)
    client = FakeClient(turns)
    planner = LoopPlanner(client=client)
    agent = SunderAgent(planner=planner, allow_writes=allow_writes)
    steps, report = agent.run_to_completion()
    return steps, report, client, planner


def test_model_chooses_tools_and_sees_results():
    # the model skips pagerank/communities entirely - a scripted plan never would
    turns = [_call(1, "find_entry_points"), _call(2, "all_attack_paths"), _call(3, "compute_min_cut"),
             _call(4, "simulate_cut"), _call(5, "apply_cut"), _call(6, "verify"), _call(7, "finish")]
    steps, report, client, planner = _run(turns)
    assert [s.tool for s in steps] == ["find_entry_points", "all_attack_paths", "compute_min_cut",
                                      "simulate_cut", "apply_cut", "verify"]
    assert all(s.ok for s in steps)
    assert report["verification"]["sealed"] is True
    # the model's own reasoning is in the trace, not canned text
    assert steps[0].reasoning == "because find_entry_points"
    # observe -> decide: by the 2nd model turn it had been shown the real entry-point result
    second_turn_msgs = client.seen[1]
    tool_msgs = [m for m in second_turn_msgs if m["role"] == "tool"]
    assert tool_msgs and "entry" in tool_msgs[0]["content"].lower()
    assert T.count_paths_to(CONFIG.crown_jewel, get_db()) == 0


def test_guardrail_blocks_apply_before_simulate():
    turns = [_call(1, "apply_cut"), _call(2, "compute_min_cut"), _call(3, "simulate_cut"),
             _call(4, "apply_cut"), _call(5, "verify")]
    steps, report, client, _ = _run(turns)
    names = [s.tool for s in steps]
    assert names.index("apply_cut") > names.index("simulate_cut") > names.index("compute_min_cut")
    # the refused attempt was reported back to the model
    refusals = [m["content"] for m in client.seen[1] if m["role"] == "tool" and "refused" in m["content"]]
    assert refusals


def test_model_cannot_choose_edges():
    bogus = {"cut": [{"src": "alice", "rel": "CAN_INVOKE", "dst": "billing-tool"}]}
    turns = [_call(1, "compute_min_cut"), _call(2, "simulate_cut", **bogus),
             _call(3, "apply_cut", **bogus), _call(4, "verify")]
    steps, report, _, _ = _run(turns)
    applied = next(s for s in steps if s.tool == "apply_cut")
    assert not any("alice" in a for a in applied.result["applied"])
    assert report["verification"]["sealed"] is True


def test_early_stop_is_completed_by_guardrail():
    steps, report, _, _ = _run([_call(1, "describe_mesh"), _text("I think we're done.")])
    tail = [s for s in steps if s.reasoning.startswith("[guardrail]")]
    assert {s.tool for s in tail} == {"compute_min_cut", "simulate_cut", "apply_cut", "verify"}
    assert report["verification"]["sealed"] is True


def test_api_failure_midrun_degrades_safely():
    steps, report, _, planner = _run([_call(1, "find_entry_points")])  # 2nd call raises
    assert planner.mode == "loop+fallback"
    assert report["verification"]["sealed"] is True


def test_dry_run_still_never_writes():
    turns = [_call(1, "compute_min_cut"), _call(2, "simulate_cut"), _call(3, "apply_cut"), _call(4, "verify")]
    before = None
    db = get_db()
    load_graph(db)
    before = T.count_paths_to(CONFIG.crown_jewel, db)
    _, report, _, _ = _run(turns, allow_writes=False)
    assert T.count_paths_to(CONFIG.crown_jewel, get_db()) == before > 0
    assert report["verification"]["sealed"] is False
