"""Export the graph to JSON for visualisation and tooling."""
from __future__ import annotations

from typing import Any

from .db import get_db


def export_graph(db=None) -> dict[str, Any]:
    db = db or get_db()
    node_rows = db.query(
        "MATCH (n) RETURN n.id AS id, coalesce(n.name, n.id) AS name, labels(n)[0] AS label, "
        "coalesce(n.trust, '') AS trust, coalesce(n.kind, '') AS kind, coalesce(n.trusted, null) AS trusted"
    )
    nodes = [
        {"id": r[0], "name": r[1], "label": r[2], "trust": r[3], "kind": r[4], "trusted": r[5]}
        for r in node_rows
    ]
    edge_rows = db.query(
        "MATCH (a)-[r]->(b) RETURN a.id AS source, b.id AS target, type(r) AS rel, "
        "coalesce(r.cap, 1) AS cap, coalesce(r.cost, 1) AS cost"
    )
    edges = [{"source": r[0], "target": r[1], "rel": r[2], "cap": r[3], "cost": r[4]} for r in edge_rows]
    return {"nodes": nodes, "edges": edges}
