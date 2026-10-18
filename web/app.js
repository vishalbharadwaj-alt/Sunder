"use strict";

const LABEL_COLORS = {
  Agent: "#38bdf8", Tool: "#a78bfa", Resource: "#f472b6",
  Credential: "#fbbf24", DataSource: "#34d399", Human: "#94a3b8",
};
const $ = (id) => document.getElementById(id);

let nodes = [], edges = [], byId = new Map();
let highlightNodes = new Set(), highlightEdges = new Set(), cutEdges = new Set();
let removed = new Set();
let meta = {};

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

function radius(n) { return n.id === meta.crown_jewel ? 16 : (n.label === "Resource" ? 11 : 8); }

function simulate() {
  const cx = W / 2, cy = H / 2;
  for (let i = 0; i < nodes.length; i++) {
    const a = nodes[i];
    for (let j = i + 1; j < nodes.length; j++) {
      const b = nodes[j];
      let dx = a.x - b.x, dy = a.y - b.y;
      let d2 = dx * dx + dy * dy || 0.01;
      let f = 5200 / d2;
      let d = Math.sqrt(d2);
      let fx = (dx / d) * f, fy = (dy / d) * f;
      a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
    }
  }
  for (const e of edges) {
    if (removed.has(edgeKey(e))) continue;
    const a = byId.get(e.source), b = byId.get(e.target);
    if (!a || !b) continue;
    let dx = b.x - a.x, dy = b.y - a.y;
    let d = Math.sqrt(dx * dx + dy * dy) || 0.01;
    const target = 95;
    let f = (d - target) * 0.008;
    let fx = (dx / d) * f, fy = (dy / d) * f;
    a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
  }
  for (const n of nodes) {
    n.vx += (cx - n.x) * 0.0016;
    n.vy += (cy - n.y) * 0.0016;
    n.vx *= 0.86; n.vy *= 0.86;
    n.x += n.vx; n.y += n.vy;
    n.x = Math.max(24, Math.min(W - 24, n.x));
    n.y = Math.max(24, Math.min(H - 24, n.y));
  }
}

function edgeKey(e) { return `${e.source}|${e.rel}|${e.target}`; }
function pairKey(e) { return `${e.source}|${e.target}`; }

function draw() {
  ctx.clearRect(0, 0, W, H);
  // edges
  for (const e of edges) {
    const a = byId.get(e.source), b = byId.get(e.target);
    if (!a || !b) continue;
    const key = edgeKey(e), pk = pairKey(e);
    const isCut = cutEdges.has(key), inPath = highlightEdges.has(pk);
    const isRemoved = removed.has(key);
    ctx.beginPath();
    ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y);
    if (isCut) { ctx.strokeStyle = "#f59e0b"; ctx.lineWidth = 3.2; }
    else if (isRemoved) { ctx.strokeStyle = "rgba(244,63,94,.18)"; ctx.lineWidth = 1; ctx.setLineDash([4, 4]); }
    else if (inPath) { ctx.strokeStyle = "rgba(244,63,94,.6)"; ctx.lineWidth = 2.2; }
    else { ctx.strokeStyle = "rgba(148,163,184,.18)"; ctx.lineWidth = 1; }
    ctx.stroke();
    ctx.setLineDash([]);
    // arrow head
    if (!isRemoved) {
      const ang = Math.atan2(b.y - a.y, b.x - a.x);
      const rr = radius(b);
      const hx = b.x - Math.cos(ang) * (rr + 2), hy = b.y - Math.sin(ang) * (rr + 2);
      ctx.beginPath();
      ctx.moveTo(hx, hy);
      ctx.lineTo(hx - Math.cos(ang - 0.4) * 7, hy - Math.sin(ang - 0.4) * 7);
      ctx.lineTo(hx - Math.cos(ang + 0.4) * 7, hy - Math.sin(ang + 0.4) * 7);
      ctx.closePath();
      ctx.fillStyle = isCut ? "#f59e0b" : inPath ? "rgba(244,63,94,.6)" : "rgba(148,163,184,.25)";
      ctx.fill();
    }
  }
  // nodes
  for (const n of nodes) {
    const r = radius(n);
    const dim = highlightNodes.size && !highlightNodes.has(n.id);
    const base = LABEL_COLORS[n.label] || "#94a3b8";
    ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
    ctx.fillStyle = dim ? "rgba(100,116,139,.35)" : base;
    ctx.fill();
    if (n.id === meta.crown_jewel) {
      ctx.lineWidth = 3; ctx.strokeStyle = "#f43f5e"; ctx.stroke();
      ctx.beginPath(); ctx.arc(n.x, n.y, r + 6, 0, Math.PI * 2);
      ctx.strokeStyle = "rgba(244,63,94,.35)"; ctx.lineWidth = 2; ctx.stroke();
    }
    ctx.fillStyle = dim ? "rgba(148,163,184,.5)" : "#e5e7eb";
    ctx.font = "11px ui-monospace, monospace";
    ctx.textAlign = "center";
    ctx.fillText(n.name || n.id, n.x, n.y - r - 5);
  }
}

function loop() { simulate(); draw(); requestAnimationFrame(loop); }

// ------------------------------------------------------------------ data
async function loadGraph() {
  const g = await (await fetch("/api/graph")).json();
  edges = g.edges;
  nodes = g.nodes.map((n, i) => {
    const ang = (i / g.nodes.length) * Math.PI * 2;
    return { ...n, x: 0, y: 0, vx: 0, vy: 0, _a: ang };
  });
  byId = new Map(nodes.map((n) => [n.id, n]));
  resize();
  nodes.forEach((n, i) => {
    n.x = W / 2 + Math.cos(n._a) * (120 + (i % 5) * 40);
    n.y = H / 2 + Math.sin(n._a) * (120 + (i % 5) * 40);
  });
}

async function loadMeta() {
  meta = await (await fetch("/api/meta")).json();
  $("chips").innerHTML = [
    `<span class="chip">nodes <b>${meta.nodes}</b></span>`,
    `<span class="chip">edges <b>${meta.edges}</b></span>`,
    `<span class="chip">jewel <b>${meta.crown_jewel}</b></span>`,
    `<span class="chip">planner <b>${meta.planner}</b></span>`,
    `<span class="chip">algos <b>${meta.algorithms.filter(a => a.startsWith("algo.")).length}</b></span>`,
  ].join("");
  $("goal").innerHTML = `Goal: make <b>${meta.crown_jewel}</b> unreachable from attacker-controlled entry points using the fewest permission revocations.`;
  $("legend").innerHTML = Object.entries(LABEL_COLORS)
    .map(([k, c]) => `<span><i style="background:${c}"></i>${k}</span>`).join("");
}

// ------------------------------------------------------------------ run
function stepEl(s) {
  const div = document.createElement("div");
  div.className = "step active" + (s.ok ? " ok" : " fail");
  div.innerHTML = `<span class="n">#${s.step}</span>
    <div class="t">${s.tool}</div>
    <div class="why">${s.reasoning || ""}</div>
    <div class="out">${s.summary || s.error || ""}</div>`;
  return div;
}

function showReport(r) {
  const badge = r.verification.sealed
    ? `<span class="badge ok">SEALED · 0 paths</span>`
    : `<span class="badge bad">${r.verification.remaining_paths} paths remain</span>`;
  $("report").className = "report show";
  $("report").innerHTML = `<h3>REPORT ${badge}</h3>` + r.narrative
    .replace(/&/g, "&amp;").replace(/</g, "&lt;");
  $("report").scrollIntoView({ behavior: "smooth" });
}

function run() {
  const dry = $("dry").checked;
  $("run").disabled = true;
  $("trace").innerHTML = "";
  $("report").className = "report";
  highlightNodes = new Set(); highlightEdges = new Set(); cutEdges = new Set(); removed = new Set();

  const es = new EventSource(`/api/run/stream?dry_run=${dry}&delay=0.45`);
  es.addEventListener("step", (ev) => {
    const s = JSON.parse(ev.data);
    // deactivate previous
    document.querySelectorAll(".step.active").forEach((e) => e.classList.remove("active"));
    const el = stepEl(s);
    $("trace").appendChild(el);
    el.scrollIntoView({ behavior: "smooth", block: "end" });
    applyStepVisual(s);
  });
  es.addEventListener("report", (ev) => showReport(JSON.parse(ev.data)));
  es.addEventListener("done", () => { es.close(); $("run").disabled = false; });
  es.addEventListener("error", () => { es.close(); $("run").disabled = false; });
}

function applyStepVisual(s) {
  const r = s.result || {};
  if (s.tool === "all_attack_paths" || s.tool === "find_attack_paths") {
    highlightNodes = new Set(); highlightEdges = new Set();
    for (const p of (r.paths || [])) {
      const ns = p.nodes || [];
      ns.forEach((n) => highlightNodes.add(n));
      for (let i = 0; i + 1 < ns.length; i++) highlightEdges.add(`${ns[i]}|${ns[i + 1]}`);
    }
  }
  if (s.tool === "compute_min_cut" || s.tool === "simulate_cut") {
    cutEdges = new Set();
    for (const c of (r.cut || (s.args && s.args.cut) || [])) cutEdges.add(`${c.src}|${c.rel}|${c.dst}`);
  }
  if (s.tool === "apply_cut") {
    for (const c of (r.applied || [])) { /* applied strings are not keys; use args */ }
    for (const c of (s.args && s.args.cut) || []) removed.add(`${c.src}|${c.rel}|${c.dst}`);
  }
  if (s.tool === "verify" && r.sealed) { highlightEdges = new Set(); }
}

$("run").addEventListener("click", run);
$("seed").addEventListener("click", async () => {
  await fetch("/api/seed", { method: "POST" });
  highlightNodes = new Set(); highlightEdges = new Set(); cutEdges = new Set(); removed = new Set();
  await loadGraph(); await loadMeta();
  $("report").className = "report";
  $("trace").innerHTML = '<div class="hint">Graph reloaded. Press <b>Run SUNDER</b>.</div>';
});

(async function init() {
  await loadMeta();
  await loadGraph();
  loop();
})();
