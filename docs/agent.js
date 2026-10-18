"use strict";
/* SUNDER client agent — deterministic planner mirroring sunder/agent.py.
 * Tool selection is fixed here (offline), but every step runs the REAL engine
 * against the live in-browser graph.
 */

class ClientAgent {
  constructor(engine, target, allowWrites = true) {
    this.engine = engine;
    this.target = target;
    this.allowWrites = allowWrites;
    this.state = { results: {}, cut: null, entry_points: [], max_flow: null, target };
    this.engine.target = target;
  }

  _script() {
    return [
      ["describe_mesh", {}, "First, survey the terrain: how big is this agent mesh?"],
      ["find_entry_points", {}, "Identify the attacker's footholds: low-trust agents and untrusted data sources."],
      ["all_attack_paths", {}, "Enumerate every multi-hop capability chain from those footholds to the crown jewel. This is the threat model."],
      ["rank_influential_nodes", {}, "PageRank tells me where privilege concentrates in the mesh."],
      ["find_choke_points", {}, "Betweenness highlights brokers that many attack paths traverse."],
      ["permission_communities", {}, "Group tightly-coupled permissions so remediation respects real boundaries."],
      ["compute_min_cut", {}, "Now the key move: find the MINIMUM-COST set of permission edges that severs every entry point from the target at once."],
      ["simulate_cut", {}, "Before touching anything, simulate the cut and predict the remaining attack paths."],
      ["apply_cut", {}, "Apply the remediation: revoke exactly those permission edges."],
      ["verify", {}, "Prove the fix: re-run reachability. Zero attack paths means the jewel is sealed."],
    ];
  }

  _call(tool) {
    const E = this.engine, T = this.target;
    switch (tool) {
      case "describe_mesh": return E.describeMesh();
      case "find_entry_points": {
        const eps = E.entryPoints();
        return { entry_points: eps, count: eps.length, summary: `Found ${eps.length} attacker-controlled entry points: ` + eps.map((e) => e.id).join(", ") };
      }
      case "all_attack_paths": {
        const r = E.allAttackPaths(T);
        this.state.results.all_attack_paths = r;
        return r;
      }
      case "rank_influential_nodes": return E.pageRank();
      case "find_choke_points": return E.betweenness();
      case "permission_communities": return E.communities();
      case "compute_min_cut": {
        const r = E.computeMinCut(T);
        this.state.cut = r.cut;
        this.state.entry_points = r.entry_points;
        this.state.max_flow = r.max_flow;
        return r;
      }
      case "simulate_cut": {
        const r = E.simulateCut(this.state.cut, T);
        return r;
      }
      case "apply_cut": {
        if (!this.allowWrites) return { applied: [], skipped: true, summary: "write tool apply_cut suppressed (read-only run)" };
        return E.applyCut(this.state.cut);
      }
      case "verify": return E.verify(T);
      default: return { summary: "" };
    }
  }

  *steps() {
    let n = 0;
    for (const [tool, , reasoning] of this._script()) {
      n += 1;
      const args = {};
      if (["all_attack_paths", "compute_min_cut", "verify"].includes(tool)) args.target = this.target;
      if (tool === "simulate_cut") { args.cut = this.state.cut; args.target = this.target; }
      if (tool === "apply_cut") args.cut = this.state.cut;
      let result, ok = true, error = "";
      try { result = this._call(tool); }
      catch (e) { ok = false; error = String(e); result = {}; }
      yield { step: n, tool, args, reasoning, summary: result.summary || "", result, ok, error };
    }
  }
}

window.ClientAgent = ClientAgent;
