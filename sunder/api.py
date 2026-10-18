"""SUNDER web API.

Exposes the graph for visualisation and streams the agent's reasoning over
Server-Sent Events so the UI can animate the run step by step.

    GET  /api/meta            graph + algorithm metadata
    GET  /api/graph           full graph (nodes + edges)
    GET  /api/paths           all attack paths to the target
    POST /api/seed            reload the synthetic graph
    GET  /api/run/stream      SSE: reasoning steps, then the final report
"""
from __future__ import annotations

import asyncio
import json
import os

from fastapi import FastAPI, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sse_starlette.sse import EventSourceResponse

from .agent import SunderAgent, make_planner
from .config import CONFIG
from .db import get_db
from .graph_export import export_graph
from .report import build_report
from .seed import load_graph
from .tools import graph_tools as T

app = FastAPI(title="SUNDER", description="Minimum-cut remediation for the AI agent mesh")

_WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")


@app.get("/api/meta")
def meta():
    info = get_db().info()
    return {
        "graph": info["graph"],
        "nodes": info["nodes"],
        "edges": info["edges"],
        "algorithms": info["algorithms"],
        "crown_jewel": CONFIG.crown_jewel,
        "planner": type(make_planner()).__name__,
        "has_format_maxflow": get_db().has_algorithm("algo.maxFlow"),
    }


@app.get("/api/graph")
def graph():
    return export_graph()


@app.get("/api/paths")
def paths(target: str = Query(default=None)):
    return T.all_attack_paths(target=target)


@app.post("/api/seed")
def seed():
    counts = load_graph(get_db())
    return {"ok": True, **counts}


@app.get("/api/run/stream")
async def run_stream(dry_run: bool = Query(default=False), delay: float = Query(default=0.4)):
    async def event_gen():
        agent = SunderAgent(allow_writes=not dry_run)
        yield {"event": "start", "data": json.dumps({"target": agent.target, "dry_run": dry_run})}
        steps = []
        for step in agent.run():
            steps.append(step)
            yield {"event": "step", "data": json.dumps(step.as_dict())}
            await asyncio.sleep(delay)
        report = build_report(agent.state)
        yield {"event": "report", "data": json.dumps(report)}
        yield {"event": "done", "data": json.dumps({"steps": len(steps)})}

    return EventSourceResponse(event_gen())


@app.post("/api/reset")
def reset():
    counts = load_graph(get_db())
    return {"ok": True, **counts}


if os.path.isdir(_WEB_DIR):
    app.mount("/", StaticFiles(directory=_WEB_DIR, html=True), name="web")
else:  # pragma: no cover
    @app.get("/")
    def _index():
        return JSONResponse({"sunder": "ok", "hint": "web/ not found"})
