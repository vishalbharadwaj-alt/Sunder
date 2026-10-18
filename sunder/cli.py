"""SUNDER command-line interface.

    sunder seed                 reload the synthetic agent-mesh graph
    sunder ingest PATH...       build the graph from real MCP client configs
    sunder harden PATH...       ingest -> reason -> cut -> patched configs + proof
    sunder demo                 run the agent end-to-end and print the trace
    sunder graph                dump the graph as JSON (for tools / the UI)
    sunder mcp                  run the MCP server (stdio)
    sunder serve [--port 8000]  run the web API + UI
"""
from __future__ import annotations

import argparse
import json
import sys


def _echo(msg: str) -> None:
    print(msg, flush=True)


def cmd_seed(args) -> int:
    from .db import get_db
    from .seed import load_graph

    db = get_db()
    counts = load_graph(db)
    _echo(f"seeded graph '{db.info()['graph']}': {counts['nodes']} nodes, {counts['edges']} edges")
    return 0


def cmd_graph(args) -> int:
    from .graph_export import export_graph

    _echo(json.dumps(export_graph(), indent=2 if args.pretty else None))
    return 0


def cmd_demo(args) -> int:
    from .db import get_db
    from .seed import load_graph
    from .agent import SunderAgent, make_planner

    db = get_db()
    counts = load_graph(db)
    _echo(f"graph ready: {counts['nodes']} nodes, {counts['edges']} edges")
    _echo(f"planner: {type(make_planner()).__name__}")
    _echo("")
    agent = SunderAgent(allow_writes=not args.dry_run)
    steps, report = agent.run_to_completion()
    for s in steps:
        status = "ok" if s.ok else "FAIL"
        _echo(f"[{s.step:>2}] {s.tool:<24} {status}")
        _echo(f"     why : {s.reasoning}")
        if s.summary:
            _echo(f"     out : {s.summary}")
    _echo("")
    _echo("=" * 72)
    _echo("REPORT")
    _echo("=" * 72)
    _echo(report["narrative"])
    if args.json:
        _echo("")
        _echo(json.dumps(report, indent=2))
    return 0


def _keep(args) -> set[str]:
    return {k.strip() for k in (args.keep or "").split(",") if k.strip()}


def cmd_ingest(args) -> int:
    from .db import get_db
    from .ingest import ingest_paths

    spec, _docs, origin = ingest_paths(get_db(), args.paths, args.target, args.min_sensitivity, _keep(args))
    st = spec.stats
    _echo(f"ingested {st['configs']} config(s), {st['servers']} MCP server(s) -> "
          f"{len(spec.nodes)} nodes, {len(spec.edges)} edges")
    for lab, path in origin.items():
        _echo(f"  {lab:<24} {path}")
    _echo(f"crown jewels : {', '.join(st['crown_jewels']) or '(none at this sensitivity)'}")
    if st["hardcoded_secrets"]:
        _echo(f"warning      : {st['hardcoded_secrets']} secret(s) hard-coded in config files (values are never stored)")
    _echo("next         : sunder harden " + " ".join(args.paths))
    return 0


def cmd_harden(args) -> int:
    from .remediate import harden

    res = harden(
        args.paths, out_dir=args.out, target=args.target, min_sensitivity=args.min_sensitivity,
        dry_run=args.dry_run, redact=args.redact, keep=_keep(args),
    )
    st, r, p = res.spec.stats, res.report, res.proof
    _echo(f"configs {st['configs']} · servers {st['servers']} · crown jewels: {', '.join(st['crown_jewels'])}")
    if st["hardcoded_secrets"]:
        _echo(f"warning: {st['hardcoded_secrets']} secret(s) are hard-coded in config files (values never stored)")
    _echo(f"entry points : {len(r.get('entry_points', []))}   attack paths: {p['paths_before']}")
    _echo(f"minimum cut  : {len(r['cut'])} edge(s), cost {r.get('cut_cost')} "
          f"(max-flow {r.get('max_flow')} proves nothing cheaper exists)")
    _echo("")
    for i, a in enumerate(res.actions, 1):
        tag = "patched" if a.applied_to_config else ("BLOCKED" if a.kind == "blocked" else "manual ")
        _echo(f"  {i}. [{tag}] {a.text}")
    _echo("")
    verdict = "SEALED" if p["sealed"] else "NOT SEALED by config edits alone"
    _echo(f"proof        : re-ingested patched configs -> paths {p['paths_before']} -> {p['paths_after']}  [{verdict}]")
    if args.dry_run:
        _echo("dry run      : nothing written")
    else:
        _echo(f"wrote        : {args.out}/  (patched configs, patches.diff, remediation.md, remediation.json)")
        _echo("note         : patched files keep your secrets unless you pass --redact; do not commit them")
    return 0 if p["sealed"] else 2


def cmd_mcp(args) -> int:
    from .mcp_server import main

    main(transport=args.transport)
    return 0


def cmd_serve(args) -> int:
    import uvicorn

    uvicorn.run("sunder.api:app", host=args.host, port=args.port, reload=args.reload)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sunder", description="SUNDER — minimum-cut remediation for the AI agent mesh")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("seed", help="reload the synthetic agent-mesh graph")
    s.set_defaults(func=cmd_seed)

    g = sub.add_parser("graph", help="dump the graph as JSON")
    g.add_argument("--pretty", action="store_true")
    g.set_defaults(func=cmd_graph)

    def _real_data_opts(sp):
        sp.add_argument("paths", nargs="+", help="MCP client config file(s) or director(ies)")
        sp.add_argument("--target", default="auto",
                        help="'auto' = every resource at/above --min-sensitivity, or comma-separated resource ids")
        sp.add_argument("--min-sensitivity", type=int, default=4, help="auto-target threshold, 1-5 (default 4)")
        sp.add_argument("--keep", default="", help="comma-separated server names that must NOT be removed")

    i = sub.add_parser("ingest", help="build the graph from real MCP client configs")
    _real_data_opts(i)
    i.set_defaults(func=cmd_ingest)

    h = sub.add_parser("harden", help="ingest configs, compute the min-cut, emit patched configs + proof")
    _real_data_opts(h)
    h.add_argument("--out", default="sunder-out", help="output directory (default: sunder-out)")
    h.add_argument("--dry-run", action="store_true", help="analyse and prove, write nothing")
    h.add_argument("--redact", action="store_true", help="replace secret values in the patched copies")
    h.set_defaults(func=cmd_harden)

    d = sub.add_parser("demo", help="run the agent end-to-end")
    d.add_argument("--dry-run", action="store_true", help="simulate but do not revoke edges")
    d.add_argument("--json", action="store_true", help="also print the full report as JSON")
    d.set_defaults(func=cmd_demo)

    m = sub.add_parser("mcp", help="run the MCP server")
    m.add_argument("--transport", default="stdio", choices=["stdio", "sse", "streamable-http"])
    m.set_defaults(func=cmd_mcp)

    v = sub.add_parser("serve", help="run the web API + UI")
    v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--port", type=int, default=8000)
    v.add_argument("--reload", action="store_true")
    v.set_defaults(func=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
