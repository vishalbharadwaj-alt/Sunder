"""Minimum edge cut.

SUNDER's signature capability: given a set of attacker entry points and a
crown-jewel target, find the *smallest* set of permission edges whose removal
disconnects every entry point from the target.

This is the classic minimum s-t cut. By the max-flow / min-cut theorem its size
equals the maximum number of edge-disjoint attack paths, so it doubles as an
optimality proof for the agent's remediation.

If a full FalkorDB build exposes ``algo.maxFlow`` we can additionally report the
flow value from the database as independent corroboration; otherwise the
pure-Python Dinic max-flow below is authoritative and dependency-free.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Hashable

Node = Hashable


@dataclass
class CutEdge:
    src: str
    rel: str
    dst: str

    def as_dict(self) -> dict:
        return {"src": self.src, "rel": self.rel, "dst": self.dst}

    def key(self) -> tuple[str, str, str]:
        return (self.src, self.rel, self.dst)


@dataclass
class MultiDiGraph:
    """Small directed multigraph with integer capacities."""

    edges: dict[tuple[Node, Node], list[tuple[str, int]]] = field(default_factory=dict)
    adj: dict[Node, set[Node]] = field(default_factory=lambda: defaultdict(set))

    def add_node(self, n: Node) -> None:
        self.adj.setdefault(n, set())

    def add_edge(self, u: Node, v: Node, rel: str, cap: int = 1) -> None:
        self.adj.setdefault(u, set()).add(v)
        self.adj.setdefault(v, set())
        self.edges.setdefault((u, v), []).append((rel, cap))

    def capacity(self, u: Node, v: Node) -> int:
        return sum(c for _, c in self.edges.get((u, v), []))

    def neighbors(self, u: Node) -> set[Node]:
        return self.adj.get(u, set())

    def edges_between(self, u: Node, v: Node) -> list[tuple[str, int]]:
        return self.edges.get((u, v), [])

    @property
    def nodes(self) -> set[Node]:
        return set(self.adj)


def _bfs_levels(residual: dict[tuple[Node, Node], int], adj, source: Node, sink: Node):
    level = {source: 0}
    q = deque([source])
    while q:
        u = q.popleft()
        for v in adj[u]:
            if residual.get((u, v), 0) > 0 and v not in level:
                level[v] = level[u] + 1
                q.append(v)
    return level if sink in level else None


def _dinic(residual: dict[tuple[Node, Node], int], adj, source: Node, sink: Node) -> int:
    total = 0
    while True:
        level = _bfs_levels(residual, adj, source, sink)
        if level is None:
            break
        it = defaultdict(int)
        order = {u: sorted(adj[u], key=str) for u in adj}

        def dfs(u: Node, pushed: int) -> int:
            if u == sink:
                return pushed
            neigh = order[u]
            while it[u] < len(neigh):
                v = neigh[it[u]]
                cap = residual.get((u, v), 0)
                if cap > 0 and level.get(v) == level[u] + 1:
                    d = dfs(v, min(pushed, cap))
                    if d > 0:
                        residual[(u, v)] -= d
                        residual[(v, u)] = residual.get((v, u), 0) + d
                        return d
                it[u] += 1
            return 0

        while True:
            pushed = dfs(source, 10**9)
            if pushed == 0:
                break
            total += pushed
    return total


def min_edge_cut(
    graph: MultiDiGraph,
    sources: list[Node],
    sink: Node,
    super_source: str = "__SRC__",
    super_sink: str = "__SNK__",
) -> tuple[int, list[CutEdge], int]:
    """Return ``(cut_size, cut_edges, max_flow)`` separating all ``sources`` from ``sink``.

    A virtual super-source is wired to every entry point with effectively
    infinite capacity, so one min-cut covers *all* entry points simultaneously.
    """
    residual: dict[tuple[Node, Node], int] = {}
    adj: dict[Node, set[Node]] = defaultdict(set)

    def add(u: Node, v: Node, cap: int):
        if cap <= 0:
            return
        residual[(u, v)] = residual.get((u, v), 0) + cap
        adj[u].add(v)
        adj[v].add(u)

    total_cap = 1
    for (u, v), edges in graph.edges.items():
        cap = sum(c for _, c in edges)
        if cap > 0:
            add(u, v, cap)
            total_cap += cap

    infinite = total_cap + 1
    for s in sources:
        if s != sink:
            add(super_source, s, infinite)
    add(sink, super_sink, infinite)

    max_flow = _dinic(residual, adj, super_source, super_sink)

    # residual-reachable set from the super source
    reachable: set[Node] = {super_source}
    q = deque([super_source])
    while q:
        u = q.popleft()
        for v in adj[u]:
            if v not in reachable and residual.get((u, v), 0) > 0:
                reachable.add(v)
                q.append(v)

    cut: list[CutEdge] = []
    for (u, v), edges in graph.edges.items():
        if u == super_source or v == super_sink:
            continue
        if u in reachable and v not in reachable:
            for rel, _cap in edges:
                cut.append(CutEdge(str(u), rel, str(v)))

    return max_flow, cut, max_flow
