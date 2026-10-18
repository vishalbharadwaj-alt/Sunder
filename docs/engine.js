"use strict";
/* SUNDER client engine — a faithful in-browser port of the Python graph tools.
 * Runs the real algorithms (pathfinding, PageRank, betweenness, label
 * propagation, Dinic max-flow/min-cut) so the static site is genuinely live.
 */

const CAP_EDGES = new Set([
  "FEEDS", "CAN_INVOKE", "CALLS", "DELEGATES",
  "HAS_CREDENTIAL", "USES", "HAS_ACCESS", "GRANTS",
]);

function pairKey(u, v) { return u + "||" + v; }

class Engine {
  constructor(graph) {
    this.nodes = new Map();
    for (const n of graph.nodes) this.nodes.set(n.id, { ...n });
    // edges: {source, rel, target, cost}
    this.edges = graph.edges.map((e) => ({
      source: e.source, target: e.target, rel: e.rel,
      cost: e.cost != null ? e.cost : 1,
    }));
  }

  clone() { return new Engine({ nodes: [...this.nodes.values()], edges: this.edges }); }

  capEdges() { return this.edges.filter((e) => CAP_EDGES.has(e.rel)); }

  adjacency() {
    const adj = new Map();
    for (const id of this.nodes.keys()) adj.set(id, []);
    for (const e of this.capEdges()) adj.get(e.source).push({ to: e.target, rel: e.rel });
    return adj;
  }

  entryPoints() {
    const out = [];
    for (const n of this.nodes.values()) {
      if ((n.label === "Agent" && n.trust === "low") ||
          (n.label === "DataSource" && n.trusted === false)) {
        out.push({ id: n.id, name: n.name, label: n.label, trust: n.trust || "", kind: n.kind || "" });
      }
    }
    out.sort((a, b) => a.label.localeCompare(b.label) || a.id.localeCompare(b.id));
    return out;
  }

  describeMesh() {
    const labels = {};
    for (const n of this.nodes.values()) labels[n.label] = (labels[n.label] || 0) + 1;
    const rels = {};
    for (const e of this.edges) rels[e.rel] = (rels[e.rel] || 0) + 1;
    return {
      nodes: this.nodes.size, edges: this.edges.length,
      labels: Object.entries(labels).map(([label, n]) => ({ label, n })),
      relationships: Object.entries(rels).map(([rel, n]) => ({ rel, n })),
    };
  }

  /* ---------------- pathfinding ---------------- */
  _pathsFrom(source, target, maxDepth, banned) {
    const adj = this.adjacency();
    const results = [];
    const stack = [{ node: source, path: [source], }];
    while (stack.length) {
      const { node, path } = stack.pop();
      if (path.length - 1 > maxDepth) continue;
      for (const { to, rel } of adj.get(node) || []) {
        if (path.includes(to)) continue;              // no cycles
        if (banned && banned.has(to + "|" + rel + "|" + node)) continue;
        if (banned && banned.has(node + "|" + rel + "|" + to)) continue;
        const np = path.concat(to);
        if (to === target) results.push(np);
        else if (np.length - 1 < maxDepth) stack.push({ node: to, path: np });
      }
    }
    return results.map((nodes) => ({ nodes, hops: nodes.length - 1 }));
  }

  allAttackPaths(target, maxDepth = 8, limit = 400) {
    const entries = this.entryPoints().map((e) => e.id);
    let paths = [];
    for (const s of entries) paths = paths.concat(this._pathsFrom(s, target, maxDepth));
    paths.sort((a, b) => a.hops - b.hops);
    paths = paths.slice(0, limit);
    const sources = [...new Set(paths.map((p) => p.nodes[0]))].sort();
    const withSource = paths.map((p) => ({ source: p.nodes[0], nodes: p.nodes, hops: p.hops }));
    const shortest = withSource[0] || null;
    return {
      target, paths: withSource, count: withSource.length,
      distinct_sources: sources, shortest,
      summary: `${withSource.length} attack path(s) from ${sources.length} entry point(s) to ${target}.`
        + (shortest ? ` Shortest is ${shortest.hops} hops.` : ""),
    };
  }

  countPaths(target, banned, maxDepth = 8) {
    const entries = this.entryPoints().map((e) => e.id);
    let n = 0;
    for (const s of entries) n += this._pathsFrom(s, target, maxDepth, banned || null).length;
    return n;
  }

  /* ---------------- centrality ---------------- */
  pageRank(limit = 10, damping = 0.85, iters = 30) {
    const ids = [...this.nodes.keys()];
    const N = ids.length || 1;
    const adj = new Map(); const outdeg = new Map();
    for (const id of ids) { adj.set(id, []); outdeg.set(id, 0); }
    for (const e of this.capEdges()) { adj.get(e.source).push(e.target); outdeg.set(e.source, outdeg.get(e.source) + 1); }
    let rank = new Map(ids.map((id) => [id, 1 / N]));
    for (let it = 0; it < iters; it++) {
      const next = new Map(ids.map((id) => [id, (1 - damping) / N]));
      for (const id of ids) {
        const d = outdeg.get(id);
        if (d === 0) continue;
        const share = rank.get(id) / d;
        for (const to of adj.get(id)) next.set(to, next.get(to) + damping * share);
      }
      rank = next;
    }
    const ranked = ids.map((id) => ({ id, name: this.nodes.get(id).name || id, score: +rank.get(id).toFixed(5) }))
      .sort((a, b) => b.score - a.score).slice(0, limit);
    return { ranked, summary: "Top influential nodes: " + ranked.slice(0, 5).map((r) => `${r.id} (${r.score})`).join(", ") };
  }

  betweenness(limit = 8) {
    const ids = [...this.nodes.keys()];
    const adj = new Map(ids.map((id) => [id, []]));
    for (const e of this.capEdges()) adj.get(e.source).push(e.target);
    const CB = new Map(ids.map((id) => [id, 0]));
    for (const s of ids) {
      const S = [], P = new Map(ids.map((id) => [id, []]));
      const sigma = new Map(ids.map((id) => [id, 0])); sigma.set(s, 1);
      const d = new Map(ids.map((id) => [id, -1])); d.set(s, 0);
      const Q = [s];
      while (Q.length) {
        const v = Q.shift(); S.push(v);
        for (const w of adj.get(v)) {
          if (d.get(w) < 0) { d.set(w, d.get(v) + 1); Q.push(w); }
          if (d.get(w) === d.get(v) + 1) { sigma.set(w, sigma.get(w) + sigma.get(v)); P.get(w).push(v); }
        }
      }
      const delta = new Map(ids.map((id) => [id, 0]));
      while (S.length) {
        const w = S.pop();
        for (const v of P.get(w)) delta.set(v, delta.get(v) + (sigma.get(v) / sigma.get(w)) * (1 + delta.get(w)));
        if (w !== s) CB.set(w, CB.get(w) + delta.get(w));
      }
    }
    const points = ids.map((id) => ({ id, name: this.nodes.get(id).name || id, score: +CB.get(id).toFixed(2) }))
      .filter((p) => p.score > 0).sort((a, b) => b.score - a.score).slice(0, limit);
    return { choke_points: points, summary: points.length ? "Choke points (betweenness): " + points.slice(0, 5).map((p) => p.id).join(", ") : "No choke points." };
  }

  communities() {
    const ids = [...this.nodes.keys()];
    const label = new Map(ids.map((id) => [id, id]));
    const neigh = new Map(ids.map((id) => [id, []]));
    for (const e of this.capEdges()) { neigh.get(e.source).push(e.target); neigh.get(e.target).push(e.source); }
    for (let it = 0; it < 10; it++) {
      let changed = false;
      for (const id of ids) {
        const counts = new Map();
        for (const nb of neigh.get(id)) counts.set(label.get(nb), (counts.get(label.get(nb)) || 0) + 1);
        if (!counts.size) continue;
        let best = null, bestC = -1;
        for (const [lab, c] of [...counts.entries()].sort()) {
          if (c > bestC || (c === bestC && lab < best)) { best = lab; bestC = c; }
        }
        if (best !== label.get(id)) { label.set(id, best); changed = true; }
      }
      if (!changed) break;
    }
    const groups = new Map();
    for (const id of ids) { const l = label.get(id); if (!groups.has(l)) groups.set(l, []); groups.get(l).push(id); }
    const communities = [...groups.entries()].map(([communityId, members]) => ({ communityId, members, size: members.length }))
      .sort((a, b) => b.size - a.size);
    return { communities, summary: `Detected ${communities.length} permission communities.` };
  }

  /* ---------------- max-flow / min-cut (Dinic) ---------------- */
  _flow(entries, target, weightProp) {
    const residual = new Map();
    const adj = new Map();
    const add = (u, v, cap) => {
      if (cap <= 0) return;
      residual.set(pairKey(u, v), (residual.get(pairKey(u, v)) || 0) + cap);
      if (!adj.has(u)) adj.set(u, new Set());
      if (!adj.has(v)) adj.set(v, new Set());
      adj.get(u).add(v); adj.get(v).add(u);
    };
    let total = 1;
    const agg = new Map();
    for (const e of this.capEdges()) {
      const w = weightProp === "cost" ? (e.cost || 1) : 1;
      agg.set(pairKey(e.source, e.target), (agg.get(pairKey(e.source, e.target)) || 0) + w);
    }
    for (const [k, cap] of agg) { const [u, v] = k.split("||"); add(u, v, cap); total += cap; }
    const SS = "__SRC__", TT = "__SNK__";
    const INF = total + 1;
    for (const s of entries) if (s !== target) add(SS, s, INF);
    add(target, TT, INF);
    adj.set(SS, adj.get(SS) || new Set());

    const level = new Map(), it = new Map();
    const bfs = () => {
      level.clear(); level.set(SS, 0);
      const Q = [SS];
      while (Q.length) {
        const u = Q.shift();
        for (const v of adj.get(u) || []) {
          if ((residual.get(pairKey(u, v)) || 0) > 0 && !level.has(v)) { level.set(v, level.get(u) + 1); Q.push(v); }
        }
      }
      return level.has(TT);
    };
    const dfs = (u, pushed) => {
      if (u === TT) return pushed;
      const neigh = [...(adj.get(u) || [])];
      while ((it.get(u) || 0) < neigh.length) {
        const i = it.get(u) || 0;
        const v = neigh[i];
        const cap = residual.get(pairKey(u, v)) || 0;
        if (cap > 0 && level.get(v) === level.get(u) + 1) {
          const d = dfs(v, Math.min(pushed, cap));
          if (d > 0) {
            residual.set(pairKey(u, v), (residual.get(pairKey(u, v)) || 0) - d);
            residual.set(pairKey(v, u), (residual.get(pairKey(v, u)) || 0) + d);
            return d;
          }
        }
        it.set(u, (it.get(u) || 0) + 1);
      }
      return 0;
    };
    let flow = 0;
    while (bfs()) {
      it.clear();
      while (true) { const p = dfs(SS, Infinity); if (!p) break; flow += p; }
    }
    // residual reachability
    const reach = new Set([SS]); const Q = [SS];
    while (Q.length) {
      const u = Q.shift();
      for (const v of adj.get(u) || []) {
        if (!reach.has(v) && (residual.get(pairKey(u, v)) || 0) > 0) { reach.add(v); Q.push(v); }
      }
    }
    const cut = [];
    for (const e of this.capEdges()) {
      if (reach.has(e.source) && !reach.has(e.target)) cut.push({ src: e.source, rel: e.rel, dst: e.target });
    }
    return { flow, cut };
  }

  computeMinCut(target) {
    const entries = this.entryPoints().map((e) => e.id);
    const costRes = this._flow(entries, target, "cost");
    const countRes = this._flow(entries, target, "cap");
    const edgeCost = (c) => {
      const e = this.edges.find((x) => x.source === c.src && x.rel === c.rel && x.target === c.dst);
      return e ? (e.cost || 1) : 1;
    };
    const cutCost = costRes.cut.reduce((s, c) => s + edgeCost(c), 0);
    const countCost = countRes.cut.reduce((s, c) => s + edgeCost(c), 0);
    return {
      target, entry_points: entries,
      cut: costRes.cut, cut_size: costRes.cut.length, cut_cost: cutCost,
      cost_max_flow: costRes.flow,
      count_cut: countRes.cut, count_size: countRes.cut.length, count_cost: countCost, count_max_flow: countRes.flow,
      max_flow: costRes.flow,
      summary: `Minimum-cost cut: ${costRes.cut.length} edge(s), business cost ${cutCost} `
        + `(fewest-edge cut would be ${countRes.cut.length} edge(s), cost ${countCost}). Cutting: `
        + costRes.cut.map((c) => `${c.src}-[${c.rel}]->${c.dst}`).join(", "),
    };
  }

  simulateCut(cut, target) {
    const banned = new Set(cut.map((c) => `${c.src}|${c.rel}|${c.dst}`));
    const before = this.countPaths(target);
    const after = this.countPaths(target, banned);
    const removed_cost = cut.reduce((s, c) => {
      const e = this.edges.find((x) => x.source === c.src && x.rel === c.rel && x.target === c.dst);
      return s + (e ? (e.cost || 1) : 1);
    }, 0);
    return { target, paths_before: before, paths_after: after, removed_cost,
      summary: `Removing ${cut.length} edge(s) (cost ${removed_cost}) would reduce attack paths ${before} -> ${after}.` };
  }

  applyCut(cut) {
    const keyset = new Set(cut.map((c) => `${c.src}|${c.rel}|${c.dst}`));
    const applied = [];
    this.edges = this.edges.filter((e) => {
      const k = `${e.source}|${e.rel}|${e.target}`;
      if (keyset.has(k)) { applied.push(`${e.source}-[${e.rel}]->${e.target}`); return false; }
      return true;
    });
    return { applied, count: applied.length, summary: `Revoked ${applied.length} permission edge(s): ${applied.join("; ")}` };
  }

  verify(target) {
    const remaining = this.countPaths(target);
    return { target, remaining_paths: remaining, sealed: remaining === 0,
      summary: remaining === 0 ? "VERIFIED: 0 attack paths remain." : `WARNING: ${remaining} attack path(s) still open.` };
  }
}

window.Engine = Engine;
window.CAP_EDGES = CAP_EDGES;
