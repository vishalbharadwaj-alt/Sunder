"""Explainable report generation.

Turns the agent's run state into a human-readable, machine-parseable report:
the threat picture before remediation, the chosen minimum cut and *why it is
minimal*, and the verified result after.
"""
from __future__ import annotations

from typing import Any


def _relabel(paths: list[dict]) -> list[dict]:
    return paths


def build_report(state: dict[str, Any]) -> dict[str, Any]:
    results = state.get("results", {})
    target = state.get("target")
    before = results.get("all_attack_paths", {})
    cut_res = results.get("compute_min_cut", {})
    sim = results.get("simulate_cut", {})
    ver = results.get("verify", {})
    choke = results.get("find_choke_points", {}).get("choke_points", [])
    pr = results.get("rank_influential_nodes", {}).get("ranked", [])

    cut = state.get("cut") or cut_res.get("cut", [])
    max_flow = cut_res.get("max_flow")
    entry_points = state.get("entry_points", [])
    cut_cost = cut_res.get("cut_cost")
    count_size = cut_res.get("count_size")
    count_cut = cut_res.get("count_cut", [])
    count_cost = cut_res.get("count_cost")

    paths_before = before.get("paths", [])
    remaining = ver.get("remaining_paths", sim.get("paths_after"))

    narrative = _narrative(target, entry_points, paths_before, cut, max_flow, remaining, cut_cost, count_size, count_cost)

    return {
        "target": target,
        "entry_points": entry_points,
        "max_flow": max_flow,
        "minimum_cut_size": len(cut),
        "cut_cost": cut_cost,
        "fewest_edge_cut_size": count_size,
        "fewest_edge_cut_cost": count_cost,
        "fewest_edge_cut": count_cut,
        "fewest_edge_max_flow": cut_res.get("count_max_flow"),
        "optimality": (
            f"min-cost max-flow = {max_flow} proves no cheaper disconnection exists "
            f"(max-flow/min-cut theorem); SUNDER found one of cost {cut_cost} using {len(cut)} edge(s)."
            if max_flow is not None else "max-flow unavailable; cut is a valid, locally-minimal disconnection."
        ),
        "attack_paths_before": paths_before,
        "attack_paths_before_count": before.get("count", len(paths_before)),
        "cut": cut,
        "simulation": {"paths_before": sim.get("paths_before"), "paths_after": sim.get("paths_after"), "removed_cost": sim.get("removed_cost")},
        "verification": {"remaining_paths": remaining, "sealed": ver.get("sealed", remaining == 0)},
        "top_influential": pr[:5],
        "choke_points": choke[:5],
        "narrative": narrative,
    }


def _narrative(target, entry_points, paths, cut, max_flow, remaining, cut_cost=None, count_size=None, count_cost=None) -> str:
    lines = []
    lines.append(f"Goal: make '{target}' unreachable from attacker-controlled entry points.")
    srcs = sorted({p["source"] for p in paths if p.get("source")}) or list(entry_points)
    lines.append(
        f"The mesh exposed {len(paths)} multi-hop attack path(s) from {len(srcs)} of {len(entry_points)} entry point(s): "
        + ", ".join(srcs) + "."
    )
    if paths:
        shortest = min(paths, key=lambda p: p.get("hops", 99))
        lines.append(
            f"The shortest chain is {shortest['hops']} hops: " + " → ".join(shortest["nodes"]) + "."
        )
    lines.append(
        f"Rather than revoking every inbound edge to {target} (over-blocking), SUNDER computed the minimum-cost cut: "
        f"{len(cut)} permission edge(s), total business cost {cut_cost}."
    )
    for e in cut:
        lines.append(f"  • revoke {e['src']} —[{e['rel']}]→ {e['dst']}")
    if max_flow is not None:
        lines.append(
            f"This is provably optimal: any disconnection costs at least {max_flow}, and SUNDER achieved exactly that."
        )
    if count_size is not None and count_cost is not None:
        lines.append(
            f"(For comparison, the fewest-edge cut also uses {count_size} edge(s) but costs {count_cost} — "
            f"SUNDER's cost-aware cut is cheaper by {count_cost - (cut_cost or 0)}.)"
        )
    if remaining is not None:
        lines.append(
            f"Verified: {remaining} attack path(s) remain. "
            + ("The crown jewel is sealed." if remaining == 0 else "Further action required.")
        )
    return "\n".join(lines)
