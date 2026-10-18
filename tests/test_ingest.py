"""Real-data ingest + remediation: classification, secret hygiene, and the end-to-end proof."""
from __future__ import annotations

import copy
import json
import os

import pytest

from sunder import schema as S
from sunder.db import get_db
from sunder.ingest import build_spec, classify, discover, find_servers, ingest_docs, ingest_paths, load_docs
from sunder.remediate import apply_to_docs, harden, plan_actions, redact_docs

EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples")

SECRET_VALUES = [
    "ghp_EXAMPLE_NOT_A_REAL_TOKEN_0001",
    "EXAMPLE_PASSWORD",
    "xoxb-EXAMPLE-NOT-REAL",
    "AKIAEXAMPLEEXAMPLE1",
    "EXAMPLE_SECRET_NOT_REAL",
    "BSA_EXAMPLE_NOT_A_REAL_KEY",
]


@pytest.fixture()
def docs():
    d, _ = load_docs([EXAMPLES])
    return d


# ---------------------------------------------------------------- classification
@pytest.mark.parametrize(
    "name,server,expected",
    [
        ("github", {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]}, "vcs"),
        ("my-tools", {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres", "postgresql://h/db"]}, "database"),
        ("fetch", {"command": "uvx", "args": ["mcp-server-fetch"]}, "web"),
        ("desktop-commander", {"command": "npx"}, "shell"),
        ("digital-garden", {"command": "node", "args": ["/Users/me/git/thing.js"]}, None),  # 'git' only inside a path/word
    ],
)
def test_classify(name, server, expected):
    cat = classify(name, server)
    assert (cat[0] if cat else None) == expected


def test_discover_skips_non_mcp_json(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"name": "x"}))
    (tmp_path / "mcp.json").write_text(json.dumps({"mcpServers": {"fetch": {"command": "uvx"}}}))
    assert [os.path.basename(p) for p in discover([str(tmp_path)])] == ["mcp.json"]


def test_find_servers_variants():
    assert find_servers({"mcpServers": {"a": {}}}) == {"a": {}}
    assert find_servers({"servers": {"a": {}}}) == {"a": {}}
    assert find_servers({"mcp": {"servers": {"a": {}}}}) == {"a": {}}
    assert find_servers({"nothing": 1}) is None


# ---------------------------------------------------------------- secret hygiene
def test_secret_values_never_enter_the_graph(docs):
    spec = build_spec(docs)
    blob = json.dumps([spec.nodes, spec.edges], default=str)
    for secret in SECRET_VALUES:
        assert secret not in blob, f"secret leaked into graph spec: {secret}"


def test_shared_secret_collapses_to_one_credential(docs):
    spec = build_spec(docs)
    gh = [n for n in spec.nodes if n[1] == S.CREDENTIAL and n[2].get("env_key") == "GITHUB_PERSONAL_ACCESS_TOKEN"]
    assert len(gh) == 1  # same token in both clients => one node


def test_hardcoded_secrets_are_counted(docs):
    assert build_spec(docs).stats["hardcoded_secrets"] >= 6


def test_env_reference_is_not_hardcoded():
    d = {"c": {"mcpServers": {"github": {"command": "npx", "args": ["server-github"],
                                         "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"}}}}}
    cred = [n for n in build_spec(d).nodes if n[1] == S.CREDENTIAL][0]
    assert cred[2]["hardcoded"] is False


def test_single_config_file_persists_only_secret_metadata(tmp_path):
    secret = "EXAMPLE_MCP_CONFIG_SECRET_VALUE"
    config = tmp_path / "mcp.json"
    config.write_text(json.dumps({
        "mcpServers": {
            "github": {
                "command": "npx",
                "args": ["server-github"],
                "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": secret},
            }
        }
    }))

    class RecordingGraphDB:
        def __init__(self):
            self.queries = []

        def query(self, cypher, params=None):
            self.queries.append((cypher, params))
            return []

    db = RecordingGraphDB()
    spec, _docs, origin = ingest_paths(db, [str(config)])
    assert origin == {"mcp": str(config)}
    credential = next(n for n in spec.nodes if n[1] == S.CREDENTIAL)
    assert credential[2]["env_key"] == "GITHUB_PERSONAL_ACCESS_TOKEN"
    assert len(credential[2]["fingerprint"]) == 8
    assert credential[2]["hardcoded"] is True

    graph_blob = json.dumps(db.queries, default=str)
    assert secret not in graph_blob
    assert "GITHUB_PERSONAL_ACCESS_TOKEN" in graph_blob
    assert credential[2]["fingerprint"] in graph_blob


# ---------------------------------------------------------------- end to end
def test_harden_seals_all_crown_jewels_and_proof_is_independent(tmp_path, docs):
    res = harden([EXAMPLES], out_dir=str(tmp_path))
    assert res.proof["paths_before"] > 0
    assert res.proof["paths_after"] == 0 and res.proof["sealed"]
    # the cut is minimum: cost equals min-cost max-flow
    assert res.report["cut_cost"] == res.report["max_flow"]
    # harmless servers survive; dangerous capabilities are gone
    kept = {s for doc in res.patched.values() for s in (find_servers(doc) or {})}
    assert {"fetch", "slack", "brave-search", "puppeteer"} <= kept
    assert not ({"desktop-commander", "postgres", "aws"} & kept)
    # outputs exist
    for name in ("patches.diff", "remediation.md", "remediation.json"):
        assert (tmp_path / name).exists()
    assert (tmp_path / "patched" / "claude_desktop_config.json").exists()


def test_originals_are_never_modified(tmp_path):
    before = {f: open(os.path.join(EXAMPLES, f), "rb").read() for f in os.listdir(EXAMPLES)}
    harden([EXAMPLES], out_dir=str(tmp_path))
    after = {f: open(os.path.join(EXAMPLES, f), "rb").read() for f in os.listdir(EXAMPLES)}
    assert before == after


def test_refuses_to_overwrite_original(tmp_path):
    out = tmp_path / "out"
    (out / "patched").mkdir(parents=True)
    victim = out / "patched" / "mcp.json"  # exactly where the patched copy would be written
    victim.write_text(json.dumps({"mcpServers": {
        "shell": {"command": "npx", "args": ["desktop-commander"]},
        "fetch": {"command": "uvx", "args": ["mcp-server-fetch"]},
    }}))
    original = victim.read_text()
    with pytest.raises(ValueError):
        harden([str(victim)], out_dir=str(out))
    assert victim.read_text() == original


def test_dry_run_writes_nothing(tmp_path):
    out = tmp_path / "o"
    res = harden([EXAMPLES], out_dir=str(out), dry_run=True)
    assert not out.exists() and res.proof["sealed"]


def test_keep_veto_is_respected_and_reported(tmp_path):
    res = harden([EXAMPLES], out_dir=str(tmp_path), keep={"github", "slack"})
    kept = {s for doc in res.patched.values() for s in (find_servers(doc) or {})}
    assert "github" in kept and "slack" in kept            # honoured
    assert not res.proof["sealed"]                         # honest: cannot seal from config alone
    assert res.proof["outside_config_steps"] >= 1          # and says what is left to do
    assert any(a.kind == "advisory" for a in res.actions)


def test_nothing_to_do_when_no_paths(tmp_path):
    d = tmp_path / "mcp.json"
    d.write_text(json.dumps({"mcpServers": {"fetch": {"command": "uvx", "args": ["mcp-server-fetch"]}}}))
    with pytest.raises(ValueError):  # no crown-jewel resource at all
        harden([str(d)], out_dir=str(tmp_path / "o"))


def test_single_target_selection(tmp_path):
    res = harden([EXAMPLES], out_dir=str(tmp_path), target="database", dry_run=True)
    assert res.spec.target.startswith("res:database")
    assert res.proof["sealed"]
    assert len(res.actions) == 1  # only the postgres path needs cutting


# ---------------------------------------------------------------- patching units
def test_apply_to_docs_removes_server_only_in_copy(docs):
    cut = [{"src": "agent:claude_desktop", "rel": "CAN_INVOKE", "dst": "claude_desktop:postgres"}]
    meta = build_spec(docs).edge_meta
    acts = plan_actions(cut, meta)
    original = copy.deepcopy(docs)
    patched = apply_to_docs(docs, acts)
    assert docs == original
    assert "postgres" not in find_servers(patched["claude_desktop"])
    assert acts[0].applied_to_config


def test_redact_hides_every_secret(docs):
    blob = json.dumps(redact_docs(docs))
    for secret in SECRET_VALUES:
        assert secret not in blob


def test_ingested_graph_loads_into_falkordb(docs):
    db = get_db()
    spec = ingest_docs(db, docs)
    n = db.query("MATCH (n) RETURN count(n)")[0][0]
    e = db.query("MATCH ()-[r]->() RETURN count(r)")[0][0]
    assert (n, e) == (len(spec.nodes), len(spec.edges))


# ---------------------------------------------------------------- robustness
def test_odd_configs_do_not_crash():
    d = {"vscode": {"servers": {
        "remote-notion": {"type": "http", "url": "https://mcp.notion.com/mcp",
                          "headers": {"Authorization": "Bearer EXAMPLE_NOT_REAL"}},
        "cli-token": {"command": "node", "args": ["server-slack.js", "--api-key=EXAMPLE_FLAG_SECRET"]},
        "off": {"command": "npx", "args": ["server-postgres"], "disabled": True},
        "weird": "not-a-dict",
        "numbers": {"command": "x", "args": [1, 2, None], "env": {"PORT": 8080, "TOKEN": None}},
    }}}
    spec = build_spec(d, min_sensitivity=3)
    blob = json.dumps([spec.nodes, spec.edges], default=str)
    assert "EXAMPLE_NOT_REAL" not in blob and "EXAMPLE_FLAG_SECRET" not in blob
    assert all(n[0] != "vscode:off" for n in spec.nodes)  # disabled servers are ignored
    assert spec.stats["servers"] == 3


def test_mcp_server_registers_harden_tool():
    pytest.importorskip("mcp")
    import asyncio

    from sunder import mcp_server

    names = {t.name for t in asyncio.run(mcp_server.server.list_tools())}
    assert {"harden_mcp_configs", "compute_min_cut", "apply_cut", "verify"} <= names
    out = json.loads(mcp_server.harden_mcp_configs([EXAMPLES], dry_run=True))
    assert out["proof"]["sealed"] is True


def test_redact_leaves_no_secret_in_any_output_file(tmp_path):
    harden([EXAMPLES], out_dir=str(tmp_path), redact=True)
    for root, _d, files in os.walk(tmp_path):
        for f in files:
            text = open(os.path.join(root, f), encoding="utf-8").read()
            for secret in SECRET_VALUES:
                assert secret not in text, f"{secret} leaked into {f}"
