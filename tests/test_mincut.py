"""Unit tests for SUNDER's minimum-cut engine.

The min-cut is the heart of the project, so we validate it against hand-checked
graphs and against a brute-force reference on small random graphs.
"""
from __future__ import annotations

import itertools
import random

from sunder.tools.mincut import MultiDiGraph, min_edge_cut


def mk(edges, nodes=()):
    g = MultiDiGraph()
    for n in nodes:
        g.add_node(n)
    for u, v, rel in edges:
        g.add_edge(u, v, rel, 1)
    return g


def brute_force_min_cut(edges, sources, sink):
    """Smallest number of edges whose removal disconnects sources from sink."""
    nodes = set(sources) | {sink} | {u for u, v, _ in edges} | {v for u, v, _ in edges}
    best = len(edges)
    for r in range(len(edges) + 1):
        for combo in itertools.combinations(range(len(edges)), r):
            removed = set(combo)
            adj = {n: [] for n in nodes}
            for i, (u, v, _) in enumerate(edges):
                if i not in removed:
                    adj[u].append(v)
            seen, stack = set(), list(sources)
            while stack:
                n = stack.pop()
                if n in seen:
                    continue
                seen.add(n)
                stack.extend(adj.get(n, []))
            if sink not in seen:
                return r
    return best


def test_bridge():
    g = mk([("S", "P", "r"), ("P", "Q1", "r"), ("P", "Q2", "r"), ("Q1", "T", "r"), ("Q2", "T", "r")])
    flow, cut, _ = min_edge_cut(g, ["S"], "T")
    assert flow == 1
    assert [c.key() for c in cut] == [("S", "r", "P")]


def test_diamond():
    g = mk([("S", "A", "r"), ("S", "B", "r"), ("A", "T", "r"), ("B", "T", "r")])
    flow, cut, _ = min_edge_cut(g, ["S"], "T")
    assert flow == 2
    assert len(cut) == 2


def test_super_source_covers_all_entries():
    g = mk([("S1", "X", "r"), ("S2", "X", "r"), ("X", "T1", "r"), ("X", "T2", "r"), ("X", "T3", "r"),
            ("T1", "T", "r"), ("T2", "T", "r"), ("T3", "T", "r")])
    flow, cut, _ = min_edge_cut(g, ["S1", "S2"], "T")
    assert flow == 2
    assert {c.key() for c in cut} == {("S1", "r", "X"), ("S2", "r", "X")}


def test_no_path_means_zero_cut():
    g = mk([("S", "A", "r"), ("B", "T", "r")])
    flow, cut, _ = min_edge_cut(g, ["S"], "T")
    assert flow == 0 and cut == []


def test_random_graphs_match_bruteforce():
    rng = random.Random(1234)
    for _ in range(40):
        n = rng.randint(3, 6)
        names = [f"n{i}" for i in range(n)]
        edges = []
        for _e in range(rng.randint(2, 10)):
            u, v = rng.sample(names, 2)
            edges.append((u, v, "r"))
        sources = rng.sample(names, rng.randint(1, 2))
        sink = rng.choice([x for x in names if x not in sources])
        g = mk(edges, names)
        flow, cut, _ = min_edge_cut(g, sources, sink)
        assert flow == brute_force_min_cut(edges, sources, sink), (edges, sources, sink)
        assert len(cut) == flow
