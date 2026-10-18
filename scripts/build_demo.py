"""Export the graph for the static (client-side) demo.

GitHub Pages can't run the FastAPI backend, so we publish the raw graph —
nodes, edges, and business costs — and docs/engine.js runs the *real*
algorithms (pathfinding, centrality, Dinic max-flow/min-cut) in the browser.

Usage:  python scripts/build_demo.py   ->  docs/graph.json
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sunder.config import CONFIG  # noqa: E402
from sunder.db import get_db  # noqa: E402
from sunder.graph_export import export_graph  # noqa: E402
from sunder.seed import load_graph  # noqa: E402

DOCS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs")


def main() -> None:
    db = get_db()
    load_graph(db)
    info = db.info()
    graph = export_graph(db)
    load_graph(db)

    meta = {
        "graph": info["graph"],
        "nodes": info["nodes"],
        "edges": info["edges"],
        "algorithms": info["algorithms"],
        "crown_jewel": CONFIG.crown_jewel,
        "planner": "ClientAgent (in-browser)",
        "static": True,
    }
    os.makedirs(DOCS, exist_ok=True)
    with open(os.path.join(DOCS, "graph.json"), "w") as f:
        json.dump({"meta": meta, "graph": graph}, f)
    print(f"wrote docs/graph.json: {len(graph['nodes'])} nodes, {len(graph['edges'])} edges")


if __name__ == "__main__":
    main()
