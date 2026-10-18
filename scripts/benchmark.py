"""Scale benchmark for SUNDER's min-cut engine.

Generates a layered synthetic agent mesh of N nodes
(DataSource -> Agent -> Tool -> Credential -> Resource, plus delegation and
tool-chaining edges and a virtual crown-jewel sink), then for each size:

  1. runs the cost-aware minimum cut,
  2. VERIFIES it independently: removes the cut edges and BFS-checks that no
     entry point still reaches the sink, and that cut cost == max-flow value,
  3. (--check) cross-checks the flow value against networkx on the same graph,
  4. (--db) also loads the graph into FalkorDB (batched UNWIND), reads the capability
     graph back out through Cypher and cuts *that*, so the number includes the
     real database round-trip.

    python scripts/benchmark.py                        # 1k, 10k, 50k nodes
    python scripts/benchmark.py --sizes 1000 100000 --check --db
"""
from __future__ import annotations

import argparse
import random
import sys
import time
from collections import deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sunder.tools.mincut import MultiDiGraph, min_edge_cut  # noqa: E402

RELS = ["FEEDS", "CAN_INVOKE", "USES", "GRANTS", "HAS_ACCESS", "DELEGATES", "CALLS"]


def generate(n: int, seed: int = 7):
    """Return (edges, entries, sink). edges = [(u, v, rel, cost)]."""
    rng = random.Random(seed)
    layers = {
        "src": [f"src{i}" for i in range(max(2, int(n * 0.02)))],
        "agent": [f"agent{i}" for i in range(max(2, int(n * 0.08)))],
        "tool": [f"tool{i}" for i in range(max(3, int(n * 0.25)))],
        "cred": [f"cred{i}" for i in range(max(3, int(n * 0.20)))],
        "res": [f"res{i}" for i in range(max(3, int(n * 0.45)))],
    }
    edges: list[tuple[str, str, str, int]] = []

    def link(a, b, rel, cost, lo, hi):
        for u in layers[a]:
            for v in rng.sample(layers[b], min(len(layers[b]), rng.randint(lo, hi))):
                edges.append((u, v, rel, cost))

    link("src", "agent", "FEEDS", rng.randint(1, 2), 1, 3)
    link("agent", "tool", "CAN_INVOKE", 5, 3, 8)
    link("tool", "cred", "USES", 3, 0, 2)
    link("cred", "res", "GRANTS", 1, 1, 3)
    # direct tool->resource access, agent delegation, tool chaining
    for u in rng.sample(layers["tool"], len(layers["tool"]) // 5):
        edges.append((u, rng.choice(layers["res"]), "HAS_ACCESS", 1))
    for u in rng.sample(layers["agent"], len(layers["agent"]) // 3):
        edges.append((u, rng.choice(layers["agent"]), "DELEGATES", 4))
    for u in rng.sample(layers["tool"], len(layers["tool"]) // 6):
        edges.append((u, rng.choice(layers["tool"]), "CALLS", 5))
    # crown jewels: 1% of resources, joined to a virtual sink
    jewels = rng.sample(layers["res"], max(1, len(layers["res"]) // 100))
    for j in jewels:
        edges.append((j, "SINK", "GRANTS", 1000))
    return edges, layers["src"], "SINK"


def build(edges):
    g = MultiDiGraph()
    for u, v, rel, cost in edges:
        g.add_edge(u, v, rel, cost)
    return g


def reachable(edges, entries, sink, removed):
    adj: dict[str, list[str]] = {}
    for u, v, rel, _c in edges:
        if (u, rel, v) not in removed:
            adj.setdefault(u, []).append(v)
    seen, q = set(entries), deque(entries)
    while q:
        u = q.popleft()
        if u == sink:
            return True
        for v in adj.get(u, ()):
            if v not in seen:
                seen.add(v)
                q.append(v)
    return False


def run_once(n: int, check: bool, use_db: bool) -> dict:
    t0 = time.perf_counter()
    edges, entries, sink = generate(n)
    t_gen = time.perf_counter() - t0

    row = {"nodes": len({e[0] for e in edges} | {e[1] for e in edges}), "edges": len(edges), "gen_s": t_gen}
    row["paths_exist_before"] = reachable(edges, entries, sink, set())

    if use_db:
        edges_in, t_load, t_read = via_falkordb(edges)
        row["db_load_s"], row["db_read_s"] = t_load, t_read
    else:
        edges_in = edges

    g = build(edges_in)
    t0 = time.perf_counter()
    flow, cut, _ = min_edge_cut(g, entries, sink)
    row["mincut_s"] = time.perf_counter() - t0

    removed = {(c.src, c.rel, c.dst) for c in cut}
    cost_of = {(u, rel, v): c for u, v, rel, c in edges}
    cut_cost = sum(cost_of[k] for k in removed)
    row["max_flow"], row["cut_edges"], row["cut_cost"] = flow, len(cut), cut_cost
    row["verified_sealed"] = not reachable(edges, entries, sink, removed)
    row["cost_equals_flow"] = cut_cost == flow

    if check:
        try:
            import networkx as nx

            G = nx.DiGraph()
            for u, v, _rel, c in edges:
                if G.has_edge(u, v):
                    G[u][v]["capacity"] += c
                else:
                    G.add_edge(u, v, capacity=c)
            for e in entries:
                G.add_edge("__S__", e)  # no capacity attr => infinite
            t0 = time.perf_counter()
            ref = nx.maximum_flow_value(G, "__S__", sink)
            row["networkx_s"] = time.perf_counter() - t0
            row["matches_networkx"] = ref == flow
        except ImportError:
            row["matches_networkx"] = "networkx not installed"
    return row


def via_falkordb(edges):
    """Load into embedded FalkorDB, read the capability graph back via Cypher."""
    import tempfile

    from redislite import FalkorDB

    tmp = tempfile.mkdtemp()
    db = FalkorDB(dbfilename=f"{tmp}/bench.rdb")
    g = db.select_graph("bench")
    g.query("MATCH (n) DETACH DELETE n")
    names = sorted({e[0] for e in edges} | {e[1] for e in edges})
    t0 = time.perf_counter()
    for i in range(0, len(names), 5000):
        g.query("UNWIND $ids AS id CREATE (:N {id: id})", {"ids": names[i : i + 5000]})
    g.query("CREATE INDEX FOR (n:N) ON (n.id)")
    by_rel: dict[str, list[dict]] = {}
    for u, v, rel, c in edges:
        by_rel.setdefault(rel, []).append({"s": u, "t": v, "c": c})
    for rel, rows in by_rel.items():
        for i in range(0, len(rows), 5000):
            g.query(
                f"UNWIND $rows AS r MATCH (a:N {{id: r.s}}), (b:N {{id: r.t}}) CREATE (a)-[:{rel} {{cost: r.c}}]->(b)",
                {"rows": rows[i : i + 5000]},
            )
    t_load = time.perf_counter() - t0
    t0 = time.perf_counter()
    rows = g.query("MATCH (a)-[r]->(b) RETURN a.id, type(r), b.id, r.cost").result_set
    t_read = time.perf_counter() - t0
    return [(a, b, rel, c) for a, rel, b, c in rows], t_load, t_read


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", type=int, nargs="+", default=[1000, 10000, 50000])
    ap.add_argument("--check", action="store_true", help="cross-check flow value with networkx (pip install networkx)")
    ap.add_argument("--db", action="store_true", help="include the FalkorDB load + Cypher read-back")
    a = ap.parse_args()

    hdr = f"{'nodes':>8} {'edges':>9} {'min-cut s':>10} {'cut edges':>10} {'cost=flow':>10} {'sealed':>7}"
    if a.db:
        hdr += f" {'db load s':>10} {'db read s':>10}"
    if a.check:
        hdr += f" {'networkx':>9}"
    print(hdr)
    print("-" * len(hdr))
    ok = True
    for n in a.sizes:
        r = run_once(n, a.check, a.db)
        line = (f"{r['nodes']:>8} {r['edges']:>9} {r['mincut_s']:>10.2f} {r['cut_edges']:>10} "
                f"{str(r['cost_equals_flow']):>10} {str(r['verified_sealed']):>7}")
        if a.db:
            line += f" {r['db_load_s']:>10.2f} {r['db_read_s']:>10.2f}"
        if a.check:
            line += f" {str(r.get('matches_networkx')):>9}"
        print(line, flush=True)
        ok &= r["verified_sealed"] and r["cost_equals_flow"] and r.get("matches_networkx", True) is True
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
