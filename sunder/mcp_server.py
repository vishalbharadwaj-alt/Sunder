"""SUNDER MCP server.

Exposes SUNDER's graph tools over the Model Context Protocol so *any* MCP-capable
agent (Claude Desktop, Cursor, a LangGraph agent, ...) can reason over the
agent-mesh graph and act on it. Each tool maps 1:1 to a function in
``sunder.tools.graph_tools``.

Run locally:   python -m sunder.mcp_server          # stdio transport
or:            sunder mcp

Works with both the MCP Python SDK v2 (``MCPServer``) and v1 (``FastMCP``).
"""
from __future__ import annotations

import json
from typing import Any

from .config import CONFIG
from .tools import graph_tools as T


def _make_server():
    try:  # MCP SDK >= 2.0
        from mcp.server.mcpserver import MCPServer as _Server
    except Exception:  # MCP SDK 1.x
        from mcp.server.fastmcp import FastMCP as _Server  # type: ignore

    server = _Server(
        name="sunder",
        instructions=(
            "SUNDER reasons over an AI-agent-mesh graph in FalkorDB. Use describe_mesh and "
            "find_entry_points to orient, all_attack_paths to model threats, compute_min_cut to "
            "find the minimum permission revocations that sever every entry point from the target, "
            "then simulate_cut, apply_cut and verify. To work on REAL data, call harden_mcp_configs with the "
            "path(s) of MCP client config files: it ingests them, cuts, and proves the fix."
        ),
    )
    return server


server = _make_server()


@server.tool()
def describe_mesh() -> str:
    """Summarise the agent mesh: node/edge/label counts and available graph algorithms."""
    return json.dumps(T.describe_mesh())


@server.tool()
def find_entry_points() -> str:
    """List attacker-controlled entry points (low-trust agents, untrusted data sources)."""
    return json.dumps(T.find_entry_points())


@server.tool()
def find_attack_paths(source: str, target: str, max_depth: int = 8) -> str:
    """Enumerate multi-hop capability paths from a single source to a target."""
    return json.dumps(T.find_attack_paths(source, target, max_depth=max_depth))


@server.tool()
def all_attack_paths(target: str | None = None, max_depth: int = 8) -> str:
    """Enumerate every attack path from any entry point to the target resource."""
    return json.dumps(T.all_attack_paths(target=target, max_depth=max_depth))


@server.tool()
def rank_influential_nodes(limit: int = 10) -> str:
    """PageRank: rank nodes by influence in the mesh."""
    return json.dumps(T.rank_influential_nodes(limit=limit))


@server.tool()
def find_choke_points(limit: int = 8) -> str:
    """Betweenness centrality: broker nodes that many attack paths pass through."""
    return json.dumps(T.find_choke_points(limit=limit))


@server.tool()
def permission_communities() -> str:
    """Label-propagation communities: clusters of tightly-coupled permissions."""
    return json.dumps(T.permission_communities())


@server.tool()
def compute_min_cut(target: str | None = None) -> str:
    """Minimum set of permission edges that severs ALL entry points from the target."""
    return json.dumps(T.compute_min_cut(target=target))


@server.tool()
def simulate_cut(cut: list[dict], target: str | None = None) -> str:
    """Predict remaining attack paths if the given cut edges were removed (no writes)."""
    return json.dumps(T.simulate_cut(cut, target=target))


@server.tool()
def apply_cut(cut: list[dict]) -> str:
    """Execute remediation: revoke the given permission edges from the graph (writes)."""
    return json.dumps(T.apply_cut(cut))


@server.tool()
def verify(target: str | None = None) -> str:
    """Re-check reachability and confirm the target is sealed."""
    return json.dumps(T.verify(target=target))


@server.tool()
def harden_mcp_configs(
    paths: list[str],
    target: str = "auto",
    keep: list[str] | None = None,
    out_dir: str = "sunder-out",
    dry_run: bool = True,
) -> str:
    """Real-data pipeline: ingest MCP client config file(s)/dir(s), compute the minimum-cost cut that
    seals every crown-jewel resource from every untrusted input, and prove it by re-ingesting the
    patched configs. ``keep`` lists server names that must not be removed. With dry_run=True (default)
    nothing is written; with dry_run=False patched copies + diff + plan are written to ``out_dir``
    (originals are never modified). NOTE: replaces the graph currently loaded in FalkorDB."""
    from .remediate import harden

    res = harden(paths, out_dir=out_dir, target=target, dry_run=dry_run, keep=set(keep or []))
    return json.dumps(
        {
            "proof": res.proof,
            "crown_jewels": res.spec.stats["crown_jewels"],
            "hardcoded_secrets": res.spec.stats["hardcoded_secrets"],
            "cut_cost": res.report.get("cut_cost"),
            "actions": [a.as_dict() for a in res.actions],
            "files_written": res.files,
        },
        default=str,
    )


def main(transport: str = "stdio") -> None:
    server.run(transport=transport)


if __name__ == "__main__":
    main()
