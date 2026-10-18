# SUNDER: using minimum cuts to heal the AI agent mesh

*Graph Hacks: Context for AI Agents — Track 1: Agents That Act on Connected Data.*

## The graph is the new attack surface

We started this project from a uncomfortable observation. In 2026, an enterprise
doesn't run one AI agent — it runs dozens. A support agent, a sales agent, a
research agent, an ops agent. Each one is wired to tools (ticket systems, email,
browsers, shells, deploy CLIs), each tool holds credentials, and each credential
grants access to resources. Increasingly that wiring lives in a graph: MCP
servers, tool catalogs, IAM roles, agent-to-agent delegation.

That's wonderful for capability and terrifying for security. An attacker doesn't
need to steal a password anymore. They need to find a *path*:

```
untrusted-email ─FEEDS─▶ support-agent ─CAN_INVOKE─▶ ticket-tool
      ─USES─▶ jira-oauth ─GRANTS─▶ vault-role ─GRANTS─▶ prod-secrets-vault
```

Six hops. No single compromised credential — just a chain of individually
reasonable permissions. This is privilege escalation *as graph traversal*, and it
is the defining security problem of the agentic era.

Most tools stop at *finding* these paths. SUNDER's bet was: an agent that can
read the graph should also **act** on it — and act *optimally*.

## The insight: don't hot-patch, min-cut

The naive fix is to revoke every inbound edge to the crown jewel. That works, and
it's also how you break production. The interesting question is: *what is the
smallest set of permissions I can remove to disconnect the entire attacker
surface?*

That is the **minimum s-t cut**. Wire a virtual super-source to every attacker
entry point, a virtual super-sink to the crown jewel, and compute the min cut.
By the **max-flow / min-cut theorem**, the cut is provably minimal — and the
max-flow value is a certificate that no smaller cut exists.

Crucially, we gave every edge a **cost** — the business impact of revoking it.
Quarantining an untrusted data source is cheap (cost 1). Breaking an agent's
ability to call a tool it needs is expensive (cost 5). Now the min cut minimises
**business impact**, not edge count. The agent isn't just finding *a* fix; it's
finding the *cheapest* fix.

And here's the payoff, straight from the demo:

```
Minimum-cost cut: 3 edges, cost 3
  • revoke public-webpage  —[FEEDS]→ research-agent
  • revoke deploy-role     —[GRANTS]→ prod-secrets-vault
  • revoke jira-oauth      —[GRANTS]→ vault-role
(For comparison, the fewest-edge cut also uses 3 edges but costs 6.)
Verified: 0 attack paths remain. The crown jewel is sealed.
```

Both cuts sever the threat. SUNDER picked the one that rips out the fewest
working integrations — because it optimised for cost, not just size.

## Building it on FalkorDB

The whole thing is a graph problem, so the agent lives on a graph. We modelled
the enterprise as six node labels (`Agent`, `Tool`, `Credential`, `Resource`,
`DataSource`, `Human`) and capability relationships (`FEEDS`, `CAN_INVOKE`,
`USES`, `GRANTS`, `HAS_ACCESS`, `DELEGATES`, `CALLS`, `HAS_CREDENTIAL`).

FalkorDB does the heavy lifting:

* **openCypher variable-length paths** enumerate the multi-hop attack chains
  (`MATCH p = (s)-[*1..8]->(t) WHERE all(x IN relationships(p) WHERE type(x) IN […])`),
* **`algo.pageRank`** shows where privilege concentrates,
* **`algo.betweenness`** finds the brokers that many attack paths cross,
* **`algo.labelPropagation`** clusters tightly-coupled permissions so remediation
  respects real boundaries.

One nice detail: we run **embedded**. `falkordblite` spins up a FalkorDB server
in-process, so there is no Docker, no cloud, no network — the demo just runs.
And because the embedded build doesn't register `algo.maxFlow`, SUNDER ships a
dependency-free **Dinic max-flow** and feature-detects the built-in so it can
corroborate the answer on a full deployment. Belt and braces.

## One agent, three interfaces, eleven tools

We exposed the same eleven tools three ways:

* **Python functions** — the direct API,
* an **MCP server** — so *any* MCP client (Claude Desktop, Cursor, another agent)
  can reason over the mesh,
* a **FastAPI + SSE** endpoint that streams the agent's reasoning to a web UI.

The agent itself has two planners: a `LoopPlanner` that runs observe -> decide -> act
(the model sees each real tool result before choosing the next tool, inside guardrails:
the cut always comes from `compute_min_cut`, `apply_cut` needs a prior `simulate_cut`, and
the run always ends verified), and a `ScriptedPlanner` that is deterministic and offline-safe. The reasoning lives in the open:

```
[1] describe_mesh         38 nodes, 42 edges across 6 labels
[2] find_entry_points     5 attacker-controlled entry points
[3] all_attack_paths      11 multi-hop attack paths, shortest is 3 hops
[5] find_choke_points     support-agent, research-agent, jira-oauth, …
[7] compute_min_cut       minimum-cost cut: 3 edges, cost 3
[8] simulate_cut          11 -> 0 attack paths
[9] apply_cut             revoked 3 permission edges
[10] verify               VERIFIED: 0 attack paths remain
```

Notice the guardrails a security agent needs: it **simulates before it acts**
(`simulate_cut`) and **proves the result** (`verify`). A remediation agent that
can't demonstrate its fix didn't work isn't trustworthy; a remediation agent that
*cuts the graph* without a proof is a liability.

## Why this is the right shape for "Agents That Act on Connected Data"

The track asks for an agent that doesn't just read a graph but *does something*
with it. SUNDER reads (paths, centrality, communities), reasons (min-cost cut),
and writes (revokes edges, then re-queries to confirm). The graph is not a
retrieval scratchpad — it is the **world the agent changes**, and every change is
justified by a graph computation.

It's also, quietly, the most useful security tool I've built: a way to answer
"given this tangled agent mesh, what is the *minimum* thing I must break to make
it safe?" — with a proof attached.

## Try it

```bash
conda create -n sunder python=3.12 -y && conda activate sunder
pip install -r requirements.txt
python -m sunder seed && python -m sunder demo     # offline, no Docker
python -m sunder serve                             # web UI with live animation
```

## What's next

* **Attack simulation** with an *evolving adversary* that re-routes after each
  cut, turning remediation into a game-theoretic loop.
* **Blast-radius budgeting**: constrain the cut to a budget and return the best
  achievable coverage.
* **More ingesters.** MCP client configs are done (`sunder harden`: patched
  configs plus a proof from re-ingesting them); IAM exports and live MCP server
  introspection are next, so the graph reflects production, not a demo fixture.

The agent mesh is going to keep growing. The least we can do is give it a
graph-native immune system — one that heals by the minimum cut.

*Built with FalkorDB (embedded), an MCP tool surface, and a dependency-free
max-flow/min-cut engine.*
