"""Graph tools — the agent's reasoning primitives.

Each function here is a *tool*: it is exposed to the agent (and, as a separate
module, over MCP). Every tool reads or writes the FalkorDB graph and returns
plain JSON-serialisable data plus a human-readable ``summary`` so the agent can
explain its reasoning.

Tools fall into three groups:
  * perception  — entry points, attack paths, reachability
  * analysis    — centrality, choke points, communities, min-cut
  * action      — apply / simulate remediation, verify
"""
from __future__ import annotations

from typing import Any

from .. import schema as S
from ..config import CONFIG
from ..db import GraphDB, get_db
from .mincut import CutEdge, MultiDiGraph, min_edge_cut

CAP_EDGES = S.CAPABILITY_EDGES
_REL_LIST = "[" + ", ".join(f"'{r}'" for r in CAP_EDGES) + "]"


def _rows_to_dicts(rows: list[list[Any]], cols: list[str]) -> list[dict[str, Any]]:
    return [dict(zip(cols, r)) for r in rows]


# ---------------------------------------------------------------------------
# perception
# ---------------------------------------------------------------------------
def describe_mesh(db: GraphDB | None = None) -> dict[str, Any]:
    db = db or get_db()
    info = db.info()
    labels = _rows_to_dicts(db.query("MATCH (n) RETURN labels(n)[0] AS label, count(*) AS n"), ["label", "n"])
    rels = _rows_to_dicts(db.query("MATCH ()-[r]->() RETURN type(r) AS rel, count(*) AS n"), ["rel", "n"])
    return {
        "tool": "describe_mesh",
        "graph": info["graph"],
        "nodes": info["nodes"],
        "edges": info["edges"],
        "labels": labels,
        "relationships": rels,
        "algorithms_available": info["algorithms"],
        "has_format_maxflow": db.has_algorithm("algo.maxFlow"),
        "summary": f"Agent mesh has {info['nodes']} nodes and {info['edges']} edges across {len(labels)} labels.",
    }


def find_entry_points(target: str | None = None, db: GraphDB | None = None) -> dict[str, Any]:
    """Attacker-controlled entry points (low-trust agents + untrusted sources)."""
    db = db or get_db()
    rows = db.query(
        """
        MATCH (n)
        WHERE (n:Agent AND n.trust = 'low') OR (n:DataSource AND n.trusted = false)
        RETURN n.id AS id, n.name AS name, labels(n)[0] AS label,
               coalesce(n.trust, '') AS trust, coalesce(n.kind, '') AS kind
        ORDER BY label, id
        """
    )
    entries = _rows_to_dicts(rows, ["id", "name", "label", "trust", "kind"])
    return {
        "tool": "find_entry_points",
        "target": target,
        "entry_points": entries,
        "count": len(entries),
        "summary": f"Found {len(entries)} attacker-controlled entry points: "
        + ", ".join(e["id"] for e in entries),
    }


def find_attack_paths(
    source: str, target: str, max_depth: int = 8, limit: int = 200, db: GraphDB | None = None
) -> dict[str, Any]:
    """Enumerate multi-hop capability paths from one source to the target."""
    db = db or get_db()
    q = f"""
    MATCH p = (s {{id: $src}})-[*1..{int(max_depth)}]->(t {{id: $tgt}})
    WHERE all(x IN relationships(p) WHERE type(x) IN {_REL_LIST})
    RETURN [n IN nodes(p) | n.id] AS nodes, [x IN relationships(p) | type(x)] AS rels, length(p) AS hops
    ORDER BY hops
    LIMIT {int(limit)}
    """
    rows = db.query(q, {"src": source, "tgt": target})
    paths = [{"nodes": r[0], "rels": r[1], "hops": r[2]} for r in rows]
    return {
        "tool": "find_attack_paths",
        "source": source,
        "target": target,
        "paths": paths,
        "count": len(paths),
        "summary": f"{len(paths)} path(s) from {source} to {target}."
        + (f" Shortest is {paths[0]['hops']} hops: {' -> '.join(paths[0]['nodes'])}." if paths else ""),
    }


def all_attack_paths(target: str | None = None, max_depth: int = 8, limit: int = 400, db: GraphDB | None = None) -> dict[str, Any]:
    """Enumerate every attack path from any entry point to the target."""
    db = db or get_db()
    target = target or CONFIG.crown_jewel
    q = f"""
    MATCH p = (s)-[*1..{int(max_depth)}]->(t {{id: $tgt}})
    WHERE ((s:Agent AND s.trust = 'low') OR (s:DataSource AND s.trusted = false))
      AND all(x IN relationships(p) WHERE type(x) IN {_REL_LIST})
    RETURN s.id AS source, [n IN nodes(p) | n.id] AS nodes, length(p) AS hops
    ORDER BY hops
    LIMIT {int(limit)}
    """
    rows = db.query(q, {"tgt": target})
    paths = [{"source": r[0], "nodes": r[1], "hops": r[2]} for r in rows]
    sources = sorted({p["source"] for p in paths})
    shortest = paths[0] if paths else None
    return {
        "tool": "all_attack_paths",
        "target": target,
        "paths": paths,
        "count": len(paths),
        "distinct_sources": sources,
        "shortest": shortest,
        "summary": f"{len(paths)} attack path(s) from {len(sources)} entry point(s) to {target}."
        + (f" Shortest is {shortest['hops']} hops." if shortest else ""),
    }


# ---------------------------------------------------------------------------
# analysis
# ---------------------------------------------------------------------------
def rank_influential_nodes(limit: int = 10, db: GraphDB | None = None) -> dict[str, Any]:
    """PageRank: most influential nodes by incoming capability edges."""
    db = db or get_db()
    if db.has_algorithm("algo.pageRank"):
        rows = db.query(
            "CALL algo.pageRank(null, null) YIELD node, score "
            "RETURN node.id AS id, coalesce(node.name, node.id) AS name, score "
            "ORDER BY score DESC LIMIT " + str(int(limit))
        )
        ranked = [{"id": r[0], "name": r[1], "score": round(r[2], 5)} for r in rows]
    else:
        ranked = []
    return {
        "tool": "rank_influential_nodes",
        "ranked": ranked,
        "summary": "Top influential nodes: "
        + ", ".join(f"{r['id']} ({r['score']})" for r in ranked[:5]),
    }


def find_choke_points(limit: int = 8, db: GraphDB | None = None) -> dict[str, Any]:
    """Betweenness centrality: broker nodes that many paths pass through."""
    db = db or get_db()
    if db.has_algorithm("algo.betweenness"):
        rels = "[" + ", ".join(f"'{r}'" for r in CAP_EDGES) + "]"
        q = (
            "CALL algo.betweenness({relationshipTypes: " + rels + ", samplingSize: 64, samplingSeed: 42}) "
            "YIELD node, score "
            "RETURN node.id AS id, coalesce(node.name, node.id) AS name, score "
            "ORDER BY score DESC LIMIT " + str(int(limit))
        )
        rows = db.query(q)
        points = [{"id": r[0], "name": r[1], "score": round(r[2], 4)} for r in rows if r[2] and r[2] > 0]
    else:
        points = []
    return {
        "tool": "find_choke_points",
        "choke_points": points,
        "summary": "Choke points (betweenness): " + ", ".join(p["id"] for p in points[:5]) if points else "No choke points.",
    }


def permission_communities(db: GraphDB | None = None) -> dict[str, Any]:
    """Label-propagation communities: clusters of tightly-coupled permissions."""
    db = db or get_db()
    if db.has_algorithm("algo.labelPropagation"):
        rows = db.query(
            "CALL algo.labelPropagation(null) YIELD node, communityId "
            "RETURN communityId, collect(coalesce(node.id, node.name)) AS members "
            "ORDER BY size(members) DESC"
        )
        comms = [{"communityId": r[0], "members": r[1], "size": len(r[1])} for r in rows]
    else:
        comms = []
    return {
        "tool": "permission_communities",
        "communities": comms,
        "summary": f"Detected {len(comms)} permission communities.",
    }


def build_capability_graph(target: str | None = None, db: GraphDB | None = None, weight: str = "cap") -> MultiDiGraph:
    """Materialise capability edges into an in-memory multigraph.

    ``weight`` selects the capacity property: ``"cap"`` (unit-ish count) or
    ``"cost"`` (business impact of revoking the edge).
    """
    db = db or get_db()
    prop = "cost" if weight == "cost" else "cap"
    rows = db.query(
        f"MATCH (a)-[r]->(b) WHERE type(r) IN {_REL_LIST} "
        f"RETURN a.id AS src, type(r) AS rel, b.id AS dst, coalesce(r.{prop}, 1) AS w"
    )
    g = MultiDiGraph()
    for src, rel, dst, w in rows:
        g.add_edge(src, dst, rel, int(w) if w else 1)
    return g


def compute_min_cut(target: str | None = None, db: GraphDB | None = None) -> dict[str, Any]:
    """Compute the minimum set of permission edges that severs all entry points.

    Reports two optimal views:
      * the minimum-*count* cut (fewest revocations), and
      * the minimum-*cost* cut (least business impact; applied by the agent).
    """
    db = db or get_db()
    target = target or CONFIG.crown_jewel
    entries = [e["id"] for e in find_entry_points(target, db)["entry_points"]]

    count_graph = build_capability_graph(target, db, weight="cap")
    cost_graph = build_capability_graph(target, db, weight="cost")
    count_flow, count_cut, _ = min_edge_cut(count_graph, entries, target)
    cost_flow, cost_cut, _ = min_edge_cut(cost_graph, entries, target)

    cut_dicts = [c.as_dict() for c in cost_cut]
    count_cut_dicts = [c.as_dict() for c in count_cut]
    applied_cost = sum(_edge_cost(db, c) for c in cut_dicts)
    count_cut_cost = sum(_edge_cost(db, c) for c in count_cut_dicts)

    db_flow = None
    if db.has_algorithm("algo.maxFlow"):
        try:
            rels = "[" + ", ".join(f"'{r}'" for r in CAP_EDGES) + "]"
            rows = db.query(
                f"MATCH (t:Resource {{id: $tgt}}) "
                f"CALL algo.maxFlow({{sourceNodes: [], targetNodes: [t], relationshipTypes: {rels}}}) "
                "YIELD maxFlow RETURN maxFlow",
                {"tgt": target},
            )
            db_flow = rows[0][0] if rows else None
        except Exception:
            db_flow = None

    return {
        "tool": "compute_min_cut",
        "target": target,
        "entry_points": entries,
        "cut": cut_dicts,
        "cut_size": len(cut_dicts),
        "cut_cost": applied_cost,
        "cost_max_flow": cost_flow,
        "count_cut": count_cut_dicts,
        "count_size": len(count_cut_dicts),
        "count_cost": count_cut_cost,
        "count_max_flow": count_flow,
        "max_flow": cost_flow,
        "db_max_flow": db_flow,
        "summary": (
            f"Minimum-cost cut: {len(cut_dicts)} edge(s), business cost {applied_cost} "
            f"(fewest-edge cut would be {len(count_cut_dicts)} edge(s), cost "
            f"{count_cut_cost}). Cutting: "
            + ", ".join(f"{c['src']}-[{c['rel']}]->{c['dst']}" for c in cut_dicts)
        ),
    }


def _edge_cost(db: GraphDB, edge: dict) -> int:
    rows = db.query(
        "MATCH (a {id: $src})-[r]->(b {id: $dst}) WHERE type(r) = $rel "
        "RETURN coalesce(r.cost, 1)",
        {"src": edge["src"], "dst": edge["dst"], "rel": edge["rel"]},
    )
    return int(rows[0][0]) if rows else 1


# ---------------------------------------------------------------------------
# action
# ---------------------------------------------------------------------------
def count_paths_to(target: str, db: GraphDB | None = None) -> int:
    db = db or get_db()
    rows = db.query(
        f"""
        MATCH p = (s)-[*1..8]->(t {{id: $tgt}})
        WHERE ((s:Agent AND s.trust = 'low') OR (s:DataSource AND s.trusted = false))
          AND all(x IN relationships(p) WHERE type(x) IN {_REL_LIST})
        RETURN count(p)
        """,
        {"tgt": target},
    )
    return int(rows[0][0]) if rows else 0


def simulate_cut(cut: list[dict], target: str | None = None, db: GraphDB | None = None) -> dict[str, Any]:
    """Count remaining attack paths if ``cut`` edges were removed (no writes)."""
    db = db or get_db()
    target = target or CONFIG.crown_jewel
    before = count_paths_to(target, db)
    # temporarily tag edges as removed via a property, then count
    for e in cut:
        db.query(
            "MATCH (a {id: $src})-[r]->(b {id: $dst}) WHERE type(r) = $rel SET r._cut = true",
            {"src": e["src"], "dst": e["dst"], "rel": e["rel"]},
        )
    after = _count_paths_excluding_cut(target, db)
    # undo tags
    db.query("MATCH ()-[r]->() WHERE r._cut = true REMOVE r._cut")
    removed_cost = sum(_edge_cost(db, e) for e in cut)
    return {
        "tool": "simulate_cut",
        "target": target,
        "paths_before": before,
        "paths_after": after,
        "removed_cost": removed_cost,
        "summary": f"Removing {len(cut)} edge(s) (cost {removed_cost}) would reduce attack paths {before} -> {after}.",
    }


def _count_paths_excluding_cut(target: str, db: GraphDB) -> int:
    rows = db.query(
        f"""
        MATCH p = (s)-[*1..8]->(t {{id: $tgt}})
        WHERE ((s:Agent AND s.trust = 'low') OR (s:DataSource AND s.trusted = false))
          AND all(x IN relationships(p) WHERE type(x) IN {_REL_LIST} AND coalesce(x._cut, false) = false)
        RETURN count(p)
        """,
        {"tgt": target},
    )
    return int(rows[0][0]) if rows else 0


def apply_cut(cut: list[dict], db: GraphDB | None = None) -> dict[str, Any]:
    """Execute remediation: delete the given permission edges from the graph."""
    db = db or get_db()
    applied = []
    for e in cut:
        db.query(
            "MATCH (a {id: $src})-[r]->(b {id: $dst}) WHERE type(r) = $rel DELETE r",
            {"src": e["src"], "dst": e["dst"], "rel": e["rel"]},
        )
        applied.append(f"{e['src']}-[{e['rel']}]->{e['dst']}")
    return {
        "tool": "apply_cut",
        "applied": applied,
        "count": len(applied),
        "summary": f"Revoked {len(applied)} permission edge(s): " + "; ".join(applied),
    }


def verify(target: str | None = None, db: GraphDB | None = None) -> dict[str, Any]:
    """Re-run reachability to prove the target is now unreachable from entries."""
    db = db or get_db()
    target = target or CONFIG.crown_jewel
    remaining = count_paths_to(target, db)
    return {
        "tool": "verify",
        "target": target,
        "remaining_paths": remaining,
        "sealed": remaining == 0,
        "summary": ("VERIFIED: 0 attack paths remain." if remaining == 0
                    else f"WARNING: {remaining} attack path(s) still open."),
    }


TOOL_REGISTRY = {
    "describe_mesh": describe_mesh,
    "find_entry_points": find_entry_points,
    "find_attack_paths": find_attack_paths,
    "all_attack_paths": all_attack_paths,
    "rank_influential_nodes": rank_influential_nodes,
    "find_choke_points": find_choke_points,
    "permission_communities": permission_communities,
    "compute_min_cut": compute_min_cut,
    "simulate_cut": simulate_cut,
    "apply_cut": apply_cut,
    "verify": verify,
}

# tools that mutate the graph — require confirmation in the UI
WRITE_TOOLS = {"apply_cut"}
