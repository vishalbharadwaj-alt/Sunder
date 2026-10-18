# SUNDER

**Autonomous minimum-cut attack-path remediation for the AI agent mesh — built on FalkorDB.**

> Graph Hacks: Context for AI Agents · **Track 1 — Agents That Act on Connected Data**

Modern enterprises are wiring AI agents to tools, credentials and data over MCP.
That convenience creates a *new* attack surface: an untrusted email can be
injected into a support agent, which calls a ticket tool, which uses an OAuth
credential, which grants a role, which unlocks the production secrets vault.
The attacker never "logs in" — they *traverse the graph*.

SUNDER is an agent that reasons over exactly that graph. It:

1. **maps** every multi-hop privilege-escalation path from attacker-controlled
   entry points to a crown-jewel resource,
2. **computes the minimum-cost set of permission edges** whose removal severs
   *all* of those paths at once, and — crucially —
3. **acts**: it revokes those edges in the graph and **proves** zero paths remain.

> **Live demo:** https://vishalbharadwaj-alt.github.io/Sunder/ — the built-in mesh is a static snapshot, but
> you can drop in **your own `mcp.json`** and the graph is built from it, in your tab (nothing is uploaded).
> The browser ingest is a port of `sunder/ingest.py`; `tests/test_web_parity.py` checks it produces the same
> graph and the same minimum cut as the Python/FalkorDB pipeline. The full engine
> (pathfinding, PageRank, betweenness, Dinic max-flow/min-cut) is ported to
> browser JS and runs in your tab. No server, no replay: press **Run SUNDER** and
> every algorithm executes live against the published graph.

```
$ python -m sunder demo
[ 3] all_attack_paths         11 attack path(s) from 4 entry point(s). Shortest is 3 hops.
[ 7] compute_min_cut          Minimum-cost cut: 3 edges, business cost 3
                              (fewest-edge cut also 3 edges but costs 6)
[ 8] simulate_cut             11 -> 0 attack paths
[ 9] apply_cut                Revoked 3 permission edge(s)
[10] verify                   VERIFIED: 0 attack paths remain. The crown jewel is sealed.
```

The point is not that it *finds* the paths — plenty of tools can. It is that it
**acts optimally**: instead of blocking every inbound edge to the vault
(over-blocking, breaking production), it finds the smallest business-cost set of
edges that disconnects the entire threat surface, and proves no cheaper fix exists.

---

## The core insight: min-cut, not hot-patching

Every capability edge has a **capacity** (how many independent paths it
represents) and a **cost** (the business impact of revoking it). SUNDER builds
the capability graph and runs a max-flow / min-cut computation with a virtual
super-source wired to *all* attacker entry points and a virtual super-sink wired
to the crown jewel.

By the **max-flow / min-cut theorem**, the value of the maximum flow equals the
capacity of the minimum cut. So:

* the cut SUNDER applies is **provably minimal** (no cheaper disconnection exists), and
* the max-flow value is the **shortest proof** that it can't be improved.

Because the flow network is built from *edge costs*, the minimum cut is the
**least business impact** remediation, not merely the fewest edges. In the demo
the fewest-edge cut and the cheapest cut both touch 3 edges, but the cheapest
one costs **3 instead of 6** — it moves the fix on the ops path from breaking
`support-agent → ops-agent` (cost 4) to revoking `deploy-role → vault` (cost 1).

> FalkorDB's embedded build doesn't register `algo.maxFlow`, so SUNDER ships a
> dependency-free Dinic max-flow implementation and feature-detects
> `algo.maxFlow` to corroborate the answer on full deployments.

---

## Run it on your own MCP configs (real data)

The synthetic mesh is a demo fixture. SUNDER also builds the graph from the files
you actually have: Claude Desktop's `claude_desktop_config.json`, Cursor's
`mcp.json`, a VS Code `mcp.json` (anything with an `mcpServers` / `servers` map).

```
$ python -m sunder harden examples # two sample configs; replace `examples` with one mcp.json path for a real config
configs 2 · servers 10 · crown jewels: res:cloud-account, res:database:db.internal/prod, res:fs:/Users/dev/.ssh, res:host-shell, res:source-repos
warning: 7 secret(s) are hard-coded in config files (values never stored)
entry points : 6   attack paths: 34
minimum cut  : 6 edge(s), cost 30 (max-flow 30 proves nothing cheaper exists)

  1. [patched] In `cursor_mcp`: remove the `aws` MCP server ...
  2. [patched] In `cursor_mcp`: remove the `github` MCP server ...
  3. [patched] In `claude_desktop`: remove the `desktop-commander` MCP server ...
  4. [patched] In `claude_desktop`: remove the `postgres` MCP server ...
  5. [patched] In `claude_desktop`: remove the `github` MCP server ...
  6. [patched] In `claude_desktop`: remove the `filesystem` MCP server ...

proof        : re-ingested patched configs -> paths 34 -> 0  [SEALED]
wrote        : sunder-out/  (patched configs, patches.diff, remediation.md, remediation.json)
```

What it does, in order: **ingest** (each config becomes an Agent, each server a
Tool, each secret a Credential, plus the resources it unlocks and the untrusted
content it ingests) -> **reason** (all attack paths, then one minimum-cost cut that
seals *every* crown-jewel resource at once) -> **patch** (a corrected copy of each
config, a unified diff, and a plain-English plan) -> **prove** (the patched files
are re-ingested into a fresh graph and the attack paths recounted, so the proof does
not depend on SUNDER's own in-graph edit having been right). Your originals are
never modified.

Useful flags:

| Flag | Meaning |
| ---- | ------- |
| `--keep github,slack` | servers you can't live without; SUNDER routes around them, or tells you exactly what is left to do outside the file and reports "not sealed by config edits alone" (exit code 2) |
| `--target database,cloud-account` | seal specific resources instead of everything at/above `--min-sensitivity` (default 4) |
| `--dry-run` | analyse and prove, write nothing |
| `--redact` | replace secret values in the patched copies (safe to share) |

A real run is committed in [`sample-output/`](sample-output/) (patched configs with secrets redacted, `patches.diff`, `remediation.md`).

`python -m sunder ingest <paths>` loads the graph only (so the web UI / MCP tools can
explore it). Over MCP the same pipeline is the `harden_mcp_configs` tool.

**How the graph is inferred, honestly.** A config says *which servers an agent can
call and with which secrets*; it does not say what each server can reach. That half is
inferred from the server's name/package (`server-postgres` -> a database, `server-github`
-> source repos **and** attacker-writable issue text, a shell server -> the host and every
other secret in that config). Every inferred edge is tagged `inferred=true` and the
rules are one table (`CATEGORIES` in `sunder/ingest.py`) you can audit and extend.
Secret **values are never stored**: only the variable name and a short SHA-256
fingerprint, so one token reused across clients collapses into a single node.
Costs: every fix SUNDER can apply by editing a config is "remove a server" (cost 5);
quarantining an untrusted input costs 6 (it blinds the agent instead of removing the
dangerous capability); edges that live outside the file (what a token may do
server-side) cost 100, so the cut only ever picks fixes SUNDER can really apply and
re-verify.

---

## Scale

`python scripts/benchmark.py --sizes 5000 20000 50000 100000 250000 --check` generates a layered
mesh (DataSource -> Agent -> Tool -> Credential -> Resource, plus delegation and tool
chaining), cuts it, then **independently verifies** each answer: the cut edges are
removed and a BFS confirms no entry point still reaches a crown jewel, cut cost must equal
the max-flow value, and the flow is cross-checked against `networkx`.

Measured on one CPU core, pure-Python Dinic (no database in the loop):

| nodes | edges | min-cut | cut edges | verified sealed | = networkx |
| ----: | ----: | ------: | --------: | :-------------: | :--------: |
| 4,110 | 6,238 | 0.03 s | 10 | yes | yes |
| 16,576 | 25,098 | 0.29 s | 52 | yes | yes |
| 41,461 | 62,710 | 0.76 s | 107 | yes | yes |
| 82,640 | 124,908 | 2.1 s | 226 | yes | yes |
| 207,315 | 313,612 | 7.8 s | 591 | yes | yes |

With `--db`, the graph is loaded into FalkorDB and read back through Cypher first:
16.6k nodes / 25k edges loads in ~5.5 s and reads back in ~0.5 s. At that size
the database round-trip, not the cut, is the cost. Known limit: the variable-length
Cypher path *listing* used for explanations is meant for human-sized meshes (it is
capped); the min-cut itself is what scales.

---

## Also leverages FalkorDB's graph algorithms

| Tool | FalkorDB algorithm | Why |
| --- | --- | --- |
| `rank_influential_nodes` | `algo.pageRank` | where privilege concentrates |
| `find_choke_points` | `algo.betweenness` | brokers many attack paths cross |
| `permission_communities` | `algo.labelPropagation` | tightly-coupled permission clusters |
| `all_attack_paths` | openCypher variable-length paths | the threat model |
| `compute_min_cut` | custom Dinic + `algo.maxFlow` (when present) | optimal remediation |

---

## Architecture

```
                         ┌──────────────────────────────────────────┐
                         │              FalkorDB                     │
                         │  Agent ──CAN_INVOKE──▶ Tool ──USES──▶ …   │
                         │     ▲ FEEDS (untrusted)      GRANTS ▼     │
                         │  DataSource                Resource(jewel)│
                         └───────────────▲──────────────────────────┘
                                         │ Cypher + algorithms
        ┌────────────────────────────────┴─────────────────────────────┐
        │  SUNDER agent (planner + reasoner)                           │
        │   • LoopPlanner → observe→decide→act, model picks each tool  │
        │   • ScriptedPlanner → deterministic, offline-safe            │
        └───────────────┬───────────────────────────┬──────────────────┘
                        │ tool calls                 │ tool calls
                 ┌──────▼──────┐              ┌──────▼───────┐
                 │ 12 MCP tools│              │  FastAPI + SSE│──▶ web UI
                 │ (any MCP    │              │  graph + trace│
                 │  client)    │              └───────────────┘
                 └─────────────┘
```

### How the agent chooses tools

With `OPENAI_API_KEY` set (any OpenAI-compatible endpoint via `OPENAI_BASE_URL`), SUNDER uses
`LoopPlanner`: **observe -> decide -> act**. The model gets the tool catalogue, calls one tool,
is shown the *real result*, and decides the next call, so it can skip analyses it doesn't need or
react to a surprising result. Guardrails are enforced in code, not left to the prompt:

* the cut that is simulated/applied always comes from `compute_min_cut` - the model cannot invent edges to revoke;
* `simulate_cut` needs `compute_min_cut`, `apply_cut` needs `simulate_cut`, `verify` needs `apply_cut`;
* a step budget bounds the run; if the model stops early or the API fails, the missing required
  steps are completed deterministically and tagged `[guardrail]` in the trace.

Without a key it runs the deterministic `ScriptedPlanner` (a fixed 10-step plan with templated reasoning),
which is what the static GitHub Pages demo does. `tests/test_loop_planner.py` exercises the loop with a fake model.

The **same tools** are exposed three ways: as Python functions, as an **MCP
server**, and over an HTTP/SSE API that drives the web UI.

---

## Quickstart (no Docker required)

```bash
# 1. environment
conda create -n sunder python=3.12 -y
conda activate sunder
pip install -r requirements.txt          # falkordblite = embedded FalkorDB

# 2. seed the synthetic agent mesh (38 nodes, 42 edges, planted attack paths)
python -m sunder seed

# 3. run the agent end-to-end
python -m sunder demo

# 4. (optional) launch the web UI with live reasoning + graph animation
python -m sunder serve            # http://127.0.0.1:8000
```

`falkordblite` embeds a FalkorDB/Redis server in-process, so the whole thing runs
locally with **zero infrastructure**. Set `FALKORDB_MODE=remote` to point at a
Docker or FalkorDB Cloud instance instead.

### Use it from any MCP agent

```bash
python -m sunder mcp               # stdio MCP server
```

Then add to Claude Desktop / Cursor (`mcp.example.json`):

```json
{ "mcpServers": { "sunder": {
  "command": "python", "args": ["-m", "sunder.mcp_server"],
  "cwd": "/absolute/path/to/Sunder" } } }
```

The model can now call `find_entry_points`, `all_attack_paths`,
`compute_min_cut`, `apply_cut`, `verify`, and friends directly.

---

## Repository layout

```
sunder/
  config.py         env-driven configuration
  db.py             FalkorDB connection (embedded or remote) + algorithm detection
  schema.py         node/relationship constants, capability edges, business costs
  seed.py           synthetic agent-mesh generator + generic load_spec()
  ingest.py         REAL data: MCP client configs -> graph (secrets never stored)
  remediate.py      cut -> patched configs, diff, plan, and re-ingest proof
  agent.py          orchestrator + LLM/Scripted planners
  report.py         explainable, optimality-proving report
  graph_export.py   JSON export for the UI
  mcp_server.py     MCP tool server (12 tools)
  api.py            FastAPI + SSE streaming
  cli.py            command line
  tools/
    mincut.py       Dinic max-flow / min-cut (dependency-free)
    graph_tools.py  the agent's 11 reasoning/action tools (the 12th MCP tool, `harden_mcp_configs`, is in mcp_server.py)
web/                dependency-free canvas UI (graph + live reasoning trace)
examples/           sample MCP client configs (fake secrets) for `sunder harden examples`
scripts/benchmark.py  scale benchmark with independent verification
tests/              min-cut vs brute-force + end-to-end agent tests
```

---

## Tests

```bash
python -m pytest -q        # 33 passed
```

The min-cut engine is validated against a **brute-force reference** on 40 random
graphs, plus end-to-end tests asserting the agent seals the crown jewel and that
the applied cut costs exactly the min-cost max-flow.

---

## How this maps to Track 1

| Track 1 focus | SUNDER |
| --- | --- |
| Multi-hop reasoning | enumerates and explains 6-hop chains across agents → tools → credentials → resources |
| Graph queries/algorithms as agent tools | PageRank, betweenness, label propagation, openCypher path finding, max-flow/min-cut |
| Tool selection through MCP | 12 tools served over MCP (incl. `harden_mcp_configs` for real configs); with an API key the `LoopPlanner` picks each tool after seeing the previous result |
| Actions based on the graph | `apply_cut` revokes edges; `verify` re-queries to prove the fix |
| Explainable results | per-step reasoning trace + optimality proof + before/after report |

---

## Graph data model

Everything lives in one FalkorDB graph (default name `sunder`). Defined in `sunder/schema.py`.

**Node labels:** `Agent`, `Tool`, `Resource`, `Credential`, `DataSource`, `Human`.
Common properties: `id`, `name`. Agents carry `trust` (`low`/`medium`/`high`); data sources carry
`trusted` (bool); resources carry `sensitivity` (1-5) and `crown_jewel` (bool).

**Relationship types (the attacker-usable capabilities):**

```
DataSource -[FEEDS]-------> Agent        untrusted input = injection entry point
Agent      -[CAN_INVOKE]--> Tool
Agent      -[DELEGATES]---> Agent
Agent      -[HAS_CREDENTIAL]-> Credential
Tool       -[CALLS]-------> Tool
Tool       -[USES]--------> Credential
Tool       -[HAS_ACCESS]--> Resource
Credential -[GRANTS]------> Resource
Human      -[OPERATES]----> Agent        (not a capability edge)
```

Every edge has `cap` (how many independent paths it represents) and `cost` (business impact of
revoking it: `FEEDS`/`GRANTS`/`HAS_ACCESS` = 1, `USES` = 3, `DELEGATES` = 4, `CAN_INVOKE`/`CALLS` = 5,
`HAS_CREDENTIAL` = 6). Edges built from real configs also carry `inferred=true` when the capability was
inferred from a server's name or package rather than stated in the file.

## Queries and algorithms the product depends on

| Purpose | Cypher / algorithm | Where |
| --- | --- | --- |
| Survey the mesh | `MATCH (n) RETURN labels(n)[0], count(*)` and the same for `type(r)` | `describe_mesh` |
| All attack paths | `MATCH p = (s)-[*1..8]->(t {id: $tgt}) ...` filtered to entry points | `all_attack_paths` |
| Load the capability graph for the cut | `MATCH (a)-[r]->(b) WHERE type(r) IN [...] RETURN ...` | `build_capability_graph` |
| Influence / chokepoints / clusters | `CALL algo.pageRank`, `algo.betweenness`, `algo.labelPropagation` | `graph_tools.py` |
| Corroborate the cut (when present) | `CALL algo.maxFlow({sourceNodes: [], targetNodes: [t], ...})` | `compute_min_cut` |
| Dry-run a cut | `SET r._cut = true` on candidate edges, count paths, then `REMOVE r._cut` | `simulate_cut` |
| Apply the fix | `MATCH (a {id:$src})-[r]->(b {id:$dst}) WHERE type(r) = $rel DELETE r` | `apply_cut` |
| Prove it | re-run the path query on the mutated graph; expect 0 | `verify` |

**What FalkorDB does in this product, honestly.** The graph is the source of truth: the mesh (or the
graph ingested from real MCP configs) is written into FalkorDB; path enumeration, PageRank, betweenness,
label propagation, the dry-run and the remediation (edge deletion) are all executed there, and `verify`
re-reads the mutated graph. The minimum-cost cut itself is a dependency-free Dinic max-flow run in Python on
the capability edges read back from FalkorDB with Cypher (FalkorDB's embedded build does not register
`algo.maxFlow`), so the optimiser is outside the database but its input and its effect are not. The GitHub
Pages demo is a separate in-browser port of the engine and uses no database.

## Running with Docker or on Windows

The embedded mode (`falkordblite`) is the zero-setup path on Linux/macOS. If it does not install on your
machine (for example native Windows), run FalkorDB in Docker and point SUNDER at it:

```bash
docker run -d --name falkordb -p 6379:6379 -p 3000:3000 falkordb/falkordb:latest
export FALKORDB_MODE=remote        # PowerShell: $env:FALKORDB_MODE="remote"
python -m sunder seed && python -m sunder demo
```

FalkorDB Browser is then at http://localhost:3000 (run `MATCH (n)-[r]->(m) RETURN n,r,m` to see the mesh).

## Configuration

Copy `.env.example` → `.env`. Key options:

| Variable | Default | Meaning |
| --- | --- | --- |
| `FALKORDB_MODE` | `embedded` | `embedded` (falkordblite) or `remote` |
| `GRAPH_NAME` | `sunder` | graph name |
| `CROWN_JEWEL` | `prod-secrets-vault` | target resource id |
| `OPENAI_API_KEY` | *(unset)* | enables the LLM planner; otherwise the deterministic planner runs |

## Development timeline and AI-assistance disclosure

Being upfront, per the Graph Hacks rules:

* **Baseline before the event.** The first version of SUNDER (graph schema, synthetic mesh, min-cut
  engine, MCP server, web UI, MCP-config ingest) was pushed to this repository on **Oct 11, 2026**, before the
  hackathon window opened on Oct 15.
* **Work done during the hackathon window (Oct 15-18, 2026).** Replaced the one-shot LLM planner with the
  observe -> decide -> act `LoopPlanner` with code-enforced guardrails (`tests/test_loop_planner.py`);
  added in-browser analysis of a visitor's own `mcp.json` (`docs/ingest.js`) with a parity test against the
  Python pipeline (`tests/test_web_parity.py`); relabelled the static-snapshot demo honestly; added this data-model,
  query and disclosure documentation.
* **AI coding assistants.** Claude (Anthropic) was used as a coding assistant, including for the work listed
  above. The participant reviews and runs the code and is responsible for explaining the graph model, queries
  and design decisions.

> TODO before submitting (owner): state in one or two sentences which parts of the baseline you wrote
> yourself and which were AI-assisted, then delete this note.

## License

MIT.
