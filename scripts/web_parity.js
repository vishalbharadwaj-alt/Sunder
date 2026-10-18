// Loads the browser files (ingest.js, engine.js, agent.js) in a vm sandbox and runs the
// same pipeline the page runs. Prints JSON. Used by tests/test_web_parity.py.
const fs = require("fs"), vm = require("vm"), path = require("path");
const docsDir = path.join(__dirname, "..", "docs");
const ctx = vm.createContext({ console, TextEncoder, URL });
ctx.window = ctx; // engine.js/agent.js attach themselves to window
for (const f of ["ingest.js", "engine.js", "agent.js"]) {
  vm.runInContext(fs.readFileSync(path.join(docsDir, f), "utf8"), ctx, { filename: f });
}
const argv = process.argv.slice(2);
const mode = argv[0];
if (mode === "sha") {
  console.log(JSON.stringify(argv.slice(1).map((s) => vm.runInContext(`SunderIngest.sha256hex(${JSON.stringify(s)})`, ctx))));
} else {
  const docs = {};
  for (const p of argv) {
    const label = path.basename(p, ".json").replace("_config", "").replace(/[^a-zA-Z0-9._-]+/g, "-");
    docs[label] = JSON.parse(fs.readFileSync(p, "utf8"));
  }
  ctx.__docs = docs;
  const out = vm.runInContext(`(() => {
    const spec = SunderIngest.buildSpec(__docs, {});
    const eng = new Engine(spec.graph);
    const agent = new ClientAgent(eng, spec.target, true);
    const steps = [...agent.steps()];
    const by = Object.fromEntries(steps.map((s) => [s.tool, s.result]));
    return {
      target: spec.target, stats: spec.stats,
      nodes: spec.graph.nodes.map((n) => n.id).sort(),
      edges: spec.graph.edges.map((e) => [e.source, e.rel, e.target, e.cost].join("|")).sort(),
      entry: by.find_entry_points.entry_points.map((e) => e.id).sort(),
      paths: by.all_attack_paths.count,
      cut: by.compute_min_cut.cut.map((c) => [c.src, c.rel, c.dst].join("|")).sort(),
      cut_cost: by.compute_min_cut.cut_cost, max_flow: by.compute_min_cut.max_flow,
      sealed: by.verify.sealed,
      fixes: by.compute_min_cut.cut.map((c) => SunderIngest.describeFix(spec, c)),
    };
  })()`, ctx);
  console.log(JSON.stringify(out));
}
