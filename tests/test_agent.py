"""End-to-end tests: seed the graph, run the agent, assert the jewel is sealed."""
from __future__ import annotations

from sunder.agent import ScriptedPlanner, SunderAgent
from sunder.config import CONFIG
from sunder.db import get_db
from sunder.report import build_report
from sunder.seed import load_graph
from sunder.tools import graph_tools as T


def test_graph_loads():
    db = get_db()
    counts = load_graph(db)
    assert counts["nodes"] > 0 and counts["edges"] > 0


def test_agent_seals_crown_jewel():
    db = get_db()
    load_graph(db)  # reset to pristine
    agent = SunderAgent(planner=ScriptedPlanner(), allow_writes=True)
    steps, report = agent.run_to_completion()

    # every step succeeded
    assert all(s.ok for s in steps), [s.error for s in steps if not s.ok]

    # there is a real threat to remediate
    assert report["attack_paths_before_count"] > 0

    # the cost-aware cut is optimal: its cost equals the min-cost max-flow
    assert report["cut_cost"] == report["max_flow"]
    # the fewest-edge cut is also optimal in edge count
    assert report["fewest_edge_cut_size"] == report["fewest_edge_max_flow"]
    # the cost-aware cut is no more expensive than the fewest-edge cut
    assert report["cut_cost"] <= report["fewest_edge_cut_size"] * 6
    assert report["simulation"]["paths_after"] == 0
    assert report["verification"]["remaining_paths"] == 0
    assert report["verification"]["sealed"] is True

    # target still exists, only permission edges were removed
    assert T.count_paths_to(CONFIG.crown_jewel, db) == 0


def test_dry_run_does_not_mutate():
    db = get_db()
    load_graph(db)
    before = T.count_paths_to(CONFIG.crown_jewel, db)
    agent = SunderAgent(planner=ScriptedPlanner(), allow_writes=False)
    _, report = agent.run_to_completion()
    after = T.count_paths_to(CONFIG.crown_jewel, db)
    assert before == after > 0
    assert report["verification"]["sealed"] is False
