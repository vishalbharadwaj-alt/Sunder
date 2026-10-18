"""The in-browser ingest + engine must agree with the Python pipeline on real configs."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from sunder.db import get_db
from sunder.ingest import build_spec, load_docs
from sunder.tools import graph_tools as T
from sunder.ingest import ingest_paths

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node not installed")


def _js(*args):
    out = subprocess.run([NODE, str(ROOT / "scripts" / "web_parity.js"), *args],
                         capture_output=True, text=True, check=True, cwd=ROOT)
    return json.loads(out.stdout)


def test_sha256_matches_hashlib():
    samples = ["", "abc", "ghp_EXAMPLE_NOT_A_REAL_TOKEN_0001", "naïve — ✓", "x" * 200]
    assert _js("sha", *samples) == [hashlib.sha256(s.encode()).hexdigest() for s in samples]


@pytest.mark.parametrize("files", [
    ["examples/claude_desktop_config.json", "examples/cursor_mcp.json"],
    ["examples/cursor_mcp.json"],
    ["tests/fixtures/vscode_mcp.json"],
    ["tests/fixtures/vscode_mcp.json", "examples/claude_desktop_config.json"],
])
def test_browser_pipeline_matches_python(files):
    js = _js(*files)
    docs, _ = load_docs([str(ROOT / f) for f in files])
    spec = build_spec(docs)

    assert js["target"] == spec.target
    assert js["nodes"] == sorted(n[0] for n in spec.nodes)
    assert js["edges"] == sorted("|".join([s, r, d, str(p["cost"])]) for s, r, d, p in spec.edges)
    assert js["stats"]["servers"] == spec.stats["servers"]
    assert js["stats"]["hardcoded_secrets"] == spec.stats["hardcoded_secrets"]
    assert js["stats"]["crown_jewels"] == spec.stats["crown_jewels"]

    # same analysis result through the real Python tools (FalkorDB) as through the JS engine
    db = get_db()
    ingest_paths(db, [str(ROOT / f) for f in files])
    paths = T.all_attack_paths(target=spec.target, db=db)
    cut = T.compute_min_cut(spec.target, db=db)
    assert js["paths"] == paths["count"]
    assert js["cut_cost"] == cut["cut_cost"] and js["max_flow"] == cut["max_flow"]
    assert js["cut"] == sorted("|".join([c["src"], c["rel"], c["dst"]]) for c in cut["cut"])
    assert js["sealed"] is True
