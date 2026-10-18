"""FalkorDB connection layer.

SUNDER runs against either:
  * an embedded FalkorDB (via ``redislite``) — no Docker required, or
  * a remote FalkorDB server (Docker / FalkorDB Cloud) via the ``falkordb`` client.

The graph and its algorithms are the agent's context layer: the agent reads,
reasons over, and writes back to this graph.
"""
from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

from .config import CONFIG

# Where an embedded server keeps its RDB file.
_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
os.makedirs(_DATA_DIR, exist_ok=True)


class GraphDB:
    """Thin wrapper around a FalkorDB graph handle."""

    def __init__(self) -> None:
        self._db, self._graph = self._connect()
        self._algorithms: set[str] | None = None

    # -- connection --------------------------------------------------------
    def _connect(self):
        if CONFIG.mode == "remote":
            from falkordb import FalkorDB

            db = FalkorDB(
                host=CONFIG.host,
                port=CONFIG.port,
                username=CONFIG.username or None,
                password=CONFIG.password or None,
            )
        else:
            from redislite import FalkorDB

            dbfilename = os.path.join(_DATA_DIR, "sunder.rdb")
            db = FalkorDB(dbfilename=dbfilename)
        return db, db.select_graph(CONFIG.graph_name)

    # -- raw access --------------------------------------------------------
    @property
    def graph(self):
        return self._graph

    def query(self, cypher: str, params: dict[str, Any] | None = None) -> list[list[Any]]:
        """Run Cypher and return the raw result rows."""
        return self._graph.query(cypher, params or {}).result_set

    # -- capability detection ---------------------------------------------
    def available_algorithms(self) -> set[str]:
        if self._algorithms is None:
            try:
                rows = self.query("CALL dbms.procedures()")
                self._algorithms = {
                    r[0] for r in rows if isinstance(r[0], str) and r[0].startswith("algo.")
                }
            except Exception:
                self._algorithms = set()
        return self._algorithms

    def has_algorithm(self, name: str) -> bool:
        return name.lower() in {a.lower() for a in self.available_algorithms()}

    def info(self) -> dict[str, Any]:
        stats = {}
        try:
            stats["nodes"] = self.query("MATCH (n) RETURN count(n) AS c")[0][0]
            stats["edges"] = self.query("MATCH ()-[e]->() RETURN count(e) AS c")[0][0]
        except Exception:
            stats["nodes"] = stats["edges"] = 0
        stats["algorithms"] = sorted(self.available_algorithms())
        stats["mode"] = CONFIG.mode
        stats["graph"] = CONFIG.graph_name
        return stats


@lru_cache(maxsize=1)
def get_db() -> GraphDB:
    return GraphDB()
