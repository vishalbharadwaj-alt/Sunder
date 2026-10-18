"use strict";

const LABEL_COLORS = {
  Agent: "#38bdf8", Tool: "#a78bfa", Resource: "#f472b6",
  Credential: "#fbbf24", DataSource: "#34d399", Human: "#94a3b8",
};
const $ = (id) => document.getElementById(id);

let PRISTINE = null;       // {meta, graph}
let meta = {};
let engine = null;         // live Engine
let nodes = [], edges = [], byId = new Map();
let highlightNodes = new Set(), highlightEdges = new Set(), cutEdges = new Set(), removed = new Set();
let target = "prod-secrets-vault";
let SPEC = null;           // set when the graph was built from the visitor's own configs
const esc = (t) => String(t == null ? "" : t).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

// ------------------------------------------------------------------ canvas
const canvas = $("graph");
const ctx = canvas.getContext("2d");
let W = 0, H = 0, DPR = Math.min(window.devicePixelRatio || 1, 2);
function resize() {
  const r = canvas.getBoundingClientRect();
  W = r.width; H = r.height;
  canvas.width = W * DPR; canvas.height = H * DPR;
  ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
}
window.addEventListener("resize", resize);

function radius(n) { return n.id === target ? 16 : (n.label === "Resource" ? 11 : 8); }

function simulate() {
  const cx = W / 2, cy = H / 2;
  for (let i = 0; i < nodes.length; i++) {
    const a = nodes[i];
    for (let j = i + 1; j < nodes.length; j++) {
      const b = nodes[j];
      let dx = a.x - b.x, dy = a.y - b.y;
      let d2 = dx * dx + dy * dy || 0.01;
      let f = 5200 / d2, d = Math.sqrt(d2);
      a.vx += (dx / d) * f; a.vy += (dy / d) * f; b.vx -= (dx / d) * f; b.vy -= (dy / d) * f;
    }
  }
  for (const e of edges) {
    if (removed.has(edgeKey(e))) continue;
    const a = byId.get(e.source), b = byId.get(e.target);
    if (!a || !b) continue;
    let dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx * dx + dy * dy) || 0.01, f = (d - 95) * 0.008;
    a.vx += (dx / d) * f; a.vy += (dy / d) * f; b.vx -= (dx / d) * f; b.vy -= (dy / d) * f;
  }
  for (const n of nodes) {
    n.vx += (cx - n.x) * 0.0016; n.vy += (cy - n.y) * 0.0016;
    n.vx *= 0.86; n.vy *= 0.86; n.x += n.vx; n.y += n.vy;
    n.x = Math.max(24, Math.min(W - 24, n.x)); n.y = Math.max(24, Math.min(H - 24, n.y));
  }
}
function edgeKey(e) { return `${e.source}|${e.rel}|${e.target}`; }
function pairKey(e) { return `${e.source}|${e.target}`; }

function draw() {
  ctx.clearRect(0, 0, W, H);
  for (const e of edges) {
    if (removed.has(edgeKey(e))) continue;
    const a = byId.get(e.source), b = byId.get(e.target);
    if (!a || !b) continue;
    const isCut = cutEdges.has(edgeKey(e)), inPath = highlightEdges.has(pairKey(e));
    ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y);
    if (isCut) { ctx.strokeStyle = "#f59e0b"; ctx.lineWidth = 3.2; }
    else if (inPath) { ctx.strokeStyle = "rgba(244,63,94,.6)"; ctx.lineWidth = 2.2; }
    else { ctx.strokeStyle = "rgba(148,163,184,.18)"; ctx.lineWidth = 1; }
    ctx.stroke();
    const ang = Math.atan2(b.y - a.y, b.x - a.x), rr = radius(b);
    const hx = b.x - Math.cos(ang) * (rr + 2), hy = b.y - Math.sin(ang) * (rr + 2);
    ctx.beginPath(); ctx.moveTo(hx, hy);
    ctx.lineTo(hx - Math.cos(ang - 0.4) * 7, hy - Math.sin(ang - 0.4) * 7);
    ctx.lineTo(hx - Math.cos(ang + 0.4) * 7, hy - Math.sin(ang + 0.4) * 7);
    ctx.closePath();
    ctx.fillStyle = isCut ? "#f59e0b" : inPath ? "rgba(244,63,94,.6)" : "rgba(148,163,184,.25)";
    ctx.fill();
  }
  for (const n of nodes) {
    const r = radius(n);
    const dim = highlightNodes.size && !highlightNodes.has(n.id);
    const base = LABEL_COLORS[n.label] || "#94a3b8";
    ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
    ctx.fillStyle = dim ? "rgba(100,116,139,.35)" : base; ctx.fill();
    if (n.id === target) {
      ctx.lineWidth = 3; ctx.strokeStyle = "#f43f5e"; ctx.stroke();
      ctx.beginPath(); ctx.arc(n.x, n.y, r + 6, 0, Math.PI * 2);
      ctx.strokeStyle = "rgba(244,63,94,.35)"; ctx.lineWidth = 2; ctx.stroke();
    }
    ctx.fillStyle = dim ? "rgba(148,163,184,.5)" : "#e5e7eb";
    ctx.font = "11px ui-monospace, monospace"; ctx.textAlign = "center";
    ctx.fillText(n.name || n.id, n.x, n.y - r - 5);
  }
}
function loop() { simulate(); draw(); requestAnimationFrame(loop); }

// ------------------------------------------------------------------ data
async function loadAll() {
  PRISTINE = await (await fetch("graph.json?v=3", { cache: "no-store" })).json();
  SPEC = null;
  meta = PRISTINE.meta;
  resetAll();      // create the live Engine + graph first
  buildTargets();  // now engine.nodes exists
  renderMeta();    // chips/legend/goal with the selected target
}

function resetAll() {
  engine = new Engine(PRISTINE.graph);
  buildGraph(PRISTINE.graph);
  highlightNodes = new Set(); highlightEdges = new Set(); cutEdges = new Set(); removed = new Set();
  $("report").className = "report";
  $("trace").innerHTML = '<div class="hint">Press <b>Run SUNDER</b> — every algorithm runs live in your browser.</div>';
}

function buildGraph(g) {
  edges = g.edges;
  nodes = g.nodes.map((n, i) => ({ ...n, x: 0, y: 0, vx: 0, vy: 0, _a: (i / g.nodes.length) * Math.PI * 2 }));
  byId = new Map(nodes.map((n) => [n.id, n]));
  resize();
  nodes.forEach((n, i) => {
    n.x = W / 2 + Math.cos(n._a) * (120 + (i % 5) * 40);
    n.y = H / 2 + Math.sin(n._a) * (120 + (i % 5) * 40);
  });
}

function renderMeta() {
  $("chips").innerHTML = [
    `<span class="chip">nodes <b>${meta.nodes}</b></span>`,
    `<span class="chip">edges <b>${meta.edges}</b></span>`,
    `<span class="chip">jewel <b>${esc(target)}</b></span>`,
    `<span class="chip">engine <b>live, in-browser</b></span>`,
    `<span class="chip">data <b>${SPEC ? "your config" : "static demo snapshot"}</b></span>`,
  ].join("");
  $("legend").innerHTML = Object.entries(LABEL_COLORS).map(([k, c]) => `<span><i style="background:${c}"></i>${k}</span>`).join("");
  $("goal").innerHTML = `Goal: make <b>${esc(target)}</b> unreachable from attacker-controlled entry points using the cheapest set of permission revocations.`;
}

function buildTargets() {
  const sel = $("target");
  const resources = [...engine.nodes.values()].filter((n) => n.label === "Resource");
  sel.innerHTML = resources.map((r) => `<option value="${esc(r.id)}"${r.id === meta.crown_jewel ? " selected" : ""}>${esc(r.name || r.id)}</option>`).join("");
  target = sel.value;
  sel.onchange = () => { target = sel.value; resetAll(); renderMeta(); };
}

// ------------------------------------------------------------------ report
function buildReport(engine, dryRun) {
  const before = engine._lastBefore || { paths: [], count: 0 };
  const cutRes = engine._lastCut || { cut: [], cut_cost: 0, count_size: 0, count_cost: 0, max_flow: 0 };
  const remaining = engine.countPaths(target);
  const paths = before.paths || [];
  const shortest = paths.slice().sort((a, b) => a.hops - b.hops)[0];
  const lines = [];
  lines.push(`Goal: make '${target}' unreachable from attacker-controlled entry points.`);
  lines.push(`The mesh exposed ${before.count} multi-hop attack path(s) from ${engine.entryPoints().length} entry point(s): ${engine.entryPoints().map((e) => e.id).join(", ")}.`);
  if (shortest) lines.push(`The shortest chain is ${shortest.hops} hops: ${shortest.nodes.join(" → ")}.`);
  lines.push(`Rather than revoking every inbound edge to ${target} (over-blocking), SUNDER computed the minimum-cost cut: ${cutRes.cut.length} permission edge(s), total business cost ${cutRes.cut_cost}.`);
  for (const c of cutRes.cut) lines.push(`  • revoke ${c.src} —[${c.rel}]→ ${c.dst}`);
  lines.push(`This is provably optimal: any disconnection costs at least ${cutRes.max_flow}, and SUNDER achieved exactly that.`);
  lines.push(`(For comparison, the fewest-edge cut also uses ${cutRes.count_size} edge(s) but costs ${cutRes.count_cost} — SUNDER's cost-aware cut is cheaper by ${cutRes.count_cost - cutRes.cut_cost}.)`);
  if (SPEC) {
    lines.push("How to apply it to your config:");
    for (const c of cutRes.cut) lines.push("  - " + SunderIngest.describeFix(SPEC, c));
    lines.push(`(Edges are inferred from server names, so treat this as a plan to review. ${SPEC.stats.hardcoded_secrets} secret(s) were hard-coded in the config; values are not stored.)`);
  }
  lines.push(`Verified: ${dryRun ? before.count : remaining} attack path(s) remain. ${(!dryRun && remaining === 0) ? "The crown jewel is sealed." : "Further action required."}`);
  return {
    narrative: lines.join("\n"), sealed: !dryRun && remaining === 0,
    remaining_paths: dryRun ? before.count : remaining,
    attack_paths_before_count: before.count,
  };
}

function stepEl(s) {
  const div = document.createElement("div");
  div.className = "step active" + (s.ok ? " ok" : " fail");
  div.innerHTML = `<span class="n">#${s.step}</span>
    <div class="t">${esc(s.tool)}</div>
    <div class="why">${esc(s.reasoning || "")}</div>
    <div class="out">${esc(s.summary || s.error || "")}</div>`;
  return div;
}

function showReport(r) {
  const badge = r.sealed ? `<span class="badge ok">SEALED · 0 paths</span>` : `<span class="badge bad">${r.remaining_paths} paths remain</span>`;
  $("report").className = "report show";
  $("report").innerHTML = `<h3>REPORT ${badge}</h3>` + r.narrative.replace(/&/g, "&amp;").replace(/</g, "&lt;");
  $("report").scrollIntoView({ behavior: "smooth" });
}

const sleep = (ms) => new Promise((res) => setTimeout(res, ms));

async function run() {
  const dry = $("dry").checked;
  $("run").disabled = true;
  $("trace").innerHTML = "";
  $("report").className = "report";
  engine = new Engine(PRISTINE.graph);   // fresh live engine
  highlightNodes = new Set(); highlightEdges = new Set(); cutEdges = new Set(); removed = new Set();

  const agent = new ClientAgent(engine, target, !dry);
  for (const s of agent.steps()) {
    document.querySelectorAll(".step.active").forEach((e) => e.classList.remove("active"));
    const el = stepEl(s);
    $("trace").appendChild(el);
    el.scrollIntoView({ behavior: "smooth", block: "end" });
    applyStepVisual(s, dry);
    await sleep(430);
  }
  showReport(buildReport(engine, dry));
  $("run").disabled = false;
}

function applyStepVisual(s, dry) {
  const r = s.result || {};
  if (s.tool === "all_attack_paths") {
    engine._lastBefore = { paths: r.paths || [], count: r.count || 0 };
    highlightNodes = new Set(); highlightEdges = new Set();
    for (const p of (r.paths || [])) {
      const ns = p.nodes || [];
      ns.forEach((n) => highlightNodes.add(n));
      for (let i = 0; i + 1 < ns.length; i++) highlightEdges.add(`${ns[i]}|${ns[i + 1]}`);
    }
  }
  if (s.tool === "compute_min_cut") {
    engine._lastCut = { cut: r.cut || [], cut_cost: r.cut_cost, count_size: r.count_size, count_cost: r.count_cost, max_flow: r.max_flow };
    cutEdges = new Set((r.cut || []).map((c) => `${c.src}|${c.rel}|${c.dst}`));
  }
  if (s.tool === "apply_cut" && !dry) {
    for (const c of (engine._lastCut.cut || [])) removed.add(`${c.src}|${c.rel}|${c.dst}`);
  }
  if (s.tool === "verify" && r.sealed && !dry) highlightEdges = new Set();
}

// ------------------------------------------------------------------ your own config
function labelFor(name, used) {
  const base = (name.replace(/\.[^.]+$/, "").replace("_config", "").replace(/[^a-zA-Z0-9._-]+/g, "-").replace(/^-+|-+$/g, "")) || "config";
  let label = base, n = 2;
  while (used.has(label)) label = `${base}-${n++}`;
  used.add(label);
  return label;
}
function ownMsg(html) { $("ownmsg").innerHTML = html; }

function analyseDocs(docs) {
  const keep = $("keep").value.split(",").map((s) => s.trim()).filter(Boolean);
  const spec = SunderIngest.buildSpec(docs, { keep });
  if (!spec.stats.configs) return ownMsg("No MCP server map found (expected an <code>mcpServers</code> or <code>servers</code> object).");
  if (!spec.target) return ownMsg(`Parsed ${spec.stats.servers} server(s) but found no crown-jewel resource (database, cloud, shell, repos...). Nothing to seal.`);
  SPEC = spec;
  PRISTINE = { meta: { nodes: spec.graph.nodes.length, edges: spec.graph.edges.length, crown_jewel: spec.target, static: false }, graph: spec.graph };
  meta = PRISTINE.meta;
  resetAll(); buildTargets(); renderMeta();
  const eps = engine.entryPoints().length;
  ownMsg(`Built from your config: <b>${spec.stats.servers}</b> server(s), <b>${spec.stats.hardcoded_secrets}</b> hard-coded secret(s), <b>${eps}</b> untrusted entry point(s). ` +
    (eps ? "Press <b>Run SUNDER</b>." : "No untrusted entry points (no web/mail/repo-style servers), so there is no attack path to cut."));
}

async function analyseFromInputs() {
  try {
    const docs = {}, used = new Set();
    for (const f of $("files").files) docs[labelFor(f.name, used)] = JSON.parse(await f.text());
    const txt = $("paste").value.trim();
    if (txt) docs[labelFor("pasted", used)] = JSON.parse(txt);
    if (!Object.keys(docs).length) return ownMsg("Choose a file or paste JSON first.");
    analyseDocs(docs);
  } catch (e) { ownMsg("Could not parse that as JSON: " + esc(e.message)); }
}
async function loadSamples() {
  try {
    const docs = {};
    for (const n of ["claude_desktop_config.json", "cursor_mcp.json"]) {
      docs[n.replace("_config", "").replace(".json", "")] = await (await fetch("examples/" + n)).json();
    }
    analyseDocs(docs);
  } catch (e) { ownMsg("Could not load samples: " + esc(e.message)); }
}
$("analyse").addEventListener("click", analyseFromInputs);
$("sample").addEventListener("click", loadSamples);
$("demo").addEventListener("click", async () => { await loadAll(); ownMsg("Back on the built-in demo mesh."); });

$("run").addEventListener("click", run);
$("seed").addEventListener("click", resetAll);

(async function init() {
  loop();
  try { await loadAll(); }
  catch (e) {
    $("trace").innerHTML = '<div class="hint">Could not initialize — ' + e.message + "</div>";
    console.error(e);
  }
})();
