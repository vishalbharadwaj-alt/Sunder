"use strict";
/* SUNDER browser ingest - a port of sunder/ingest.py (build_spec).
 *
 * Turns MCP client configs (claude_desktop_config.json, Cursor mcp.json, VS Code
 * mcp.json ...) into the same capability graph the Python pipeline builds, entirely
 * in the visitor's tab: nothing is uploaded, and secret VALUES are never kept -
 * only the variable name and a short SHA-256 fingerprint.
 *
 * Parity with the Python implementation is checked by tests/test_web_parity.py.
 */

const SunderIngest = (() => {
  const SINK_ID = "crown-jewels";
  const NOT_CONFIGURABLE = 100, SINK_COST = 1000, COST_REMOVE_SERVER = 5, COST_QUARANTINE = 6;

  // (category, resource id, sensitivity, attacker-writable content?, lateral?, keywords)
  const CATEGORIES = [
    ["shell", "host-shell", 5, false, true, ["shell", "terminal", "commander", "bash", "powershell", "exec", "ssh", "cmd"]],
    ["cloud", "cloud-account", 5, false, false, ["aws", "gcp", "gcloud", "azure", "kubernetes", "k8s", "kubectl", "terraform", "cloudflare", "vercel", "netlify", "pulumi"]],
    ["database", "database", 5, false, false, ["postgres", "postgresql", "mysql", "mariadb", "mongodb", "mongo", "redis", "sqlite", "supabase", "neon", "bigquery", "snowflake", "clickhouse", "dynamodb", "pg"]],
    ["payments", "payments-api", 4, false, false, ["stripe", "paypal", "square", "payments", "billing"]],
    ["mail", "mailbox", 4, true, false, ["gmail", "imap", "smtp", "outlook", "email", "mail"]],
    ["vcs", "source-repos", 4, true, false, ["github", "gitlab", "bitbucket", "git"]],
    ["messaging", "chat-workspace", 3, true, false, ["slack", "discord", "teams", "telegram", "whatsapp"]],
    ["workspace", "work-tracker", 3, true, false, ["notion", "jira", "linear", "confluence", "asana", "trello", "airtable", "gdrive", "drive", "sheets", "zendesk", "intercom", "hubspot", "salesforce"]],
    ["web", null, 1, true, false, ["fetch", "puppeteer", "playwright", "browser", "brave", "search", "firecrawl", "scrape", "crawl", "tavily", "exa", "selenium", "web", "http", "browserbase"]],
    ["filesystem", "filesystem", 3, false, false, ["filesystem", "fs", "files", "file"]],
  ].map(([cat, res, sens, untrusted, lateral, kws]) => ({ cat, res, sens, untrusted, lateral, kws: new Set(kws) }));

  const SECRET_KEY = /(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|BEARER|DSN|CONNECTION_?STRING|DATABASE_?URL|(^|_)KEY($|_)|(^|_)PASS($|_)|(^|_)AUTH)/i;
  const SECRET_VALUE = /^(ghp_|gho_|ghs_|github_pat_|xox[abprs]-|sk-|AKIA|ASIA|AIza|ya29\.)/;
  const URL_USERINFO = /[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:[^/\s@]+@/i;
  const SERVER_KEYS = ["mcpServers", "servers", "context_servers"];
  const BROAD_FS = /^(\/|~|[A-Za-z]:[\\/]?|\/(Users|home)\/[^/]+\/?)$/;

  // ---- sha256 (UTF-8) -> hex; used only for short fingerprints, so it can stay synchronous
  function sha256hex(str) {
    const K = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    const bytes = Array.from(new TextEncoder().encode(str));
    const bitLen = bytes.length * 8;
    bytes.push(0x80);
    while (bytes.length % 64 !== 56) bytes.push(0);
    const hi = Math.floor(bitLen / 0x100000000), lo = bitLen >>> 0;
    for (const w of [hi, lo]) for (let s = 24; s >= 0; s -= 8) bytes.push((w >>> s) & 0xff);
    let h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    const rotr = (x, n) => (x >>> n) | (x << (32 - n));
    for (let off = 0; off < bytes.length; off += 64) {
      const w = new Array(64);
      for (let i = 0; i < 16; i++) {
        w[i] = ((bytes[off + 4 * i] << 24) | (bytes[off + 4 * i + 1] << 16) | (bytes[off + 4 * i + 2] << 8) | bytes[off + 4 * i + 3]) >>> 0;
      }
      for (let i = 16; i < 64; i++) {
        const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      let [a, b, c, d, e, f, g, hh] = h;
      for (let i = 0; i < 64; i++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const t1 = (hh + S1 + ch + K[i] + w[i]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) >>> 0;
        hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h = [a, b, c, d, e, f, g, hh].map((v, i) => (h[i] + v) >>> 0);
    }
    return h.map((v) => v.toString(16).padStart(8, "0")).join("");
  }
  const fp = (v) => sha256hex(String(v)).slice(0, 8);
  const slug = (t) => t.replace(/[^a-zA-Z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || "x";
  const basename = (p) => String(p).split("/").pop();
  const isObj = (x) => x !== null && typeof x === "object" && !Array.isArray(x);

  function findServers(doc) {
    if (!isObj(doc)) return null;
    for (const k of SERVER_KEYS) if (isObj(doc[k])) return doc[k];
    if (isObj(doc.mcp) && isObj(doc.mcp.servers)) return doc.mcp.servers;
    return null;
  }

  const tokens = (text) => (String(text).toLowerCase().match(/[a-z0-9]+/g) || []);
  function packageArgs(args) {
    return args.filter((a) => typeof a === "string" && !a.startsWith("-") && !a.includes("://")
      && !/^[/~.]/.test(a) && !a.includes("\\"));
  }
  function match(toks) {
    for (const c of CATEGORIES) {
      for (const t of toks) {
        if (c.kws.has(t)) return c;
        for (const k of c.kws) if (k.length >= 6 && t.startsWith(k)) return c;
      }
    }
    return null;
  }
  function classify(name, server) {
    const args = Array.isArray(server.args) ? server.args : [];
    let cat = match(tokens(name));
    if (cat === null) {
      const extra = [server.command === undefined ? "" : String(server.command), ...packageArgs(args)];
      if (typeof server.url === "string") {
        try { extra.push(new URL(server.url).hostname || ""); } catch (e) { extra.push(""); }
      }
      cat = match(tokens(extra.join(" ")));
    }
    return cat;
  }

  function isSecretEnv(key, value) {
    if (URL_USERINFO.test(value) || SECRET_VALUE.test(value)) return true;
    if (!SECRET_KEY.test(key)) return false;
    return !["", "true", "false"].includes(value) && !/^\d+$/.test(value);
  }
  const isLiteral = (v) => { const s = v.trim(); return !(s.startsWith("${") || s.startsWith("$") || s.startsWith("env:") || s === ""); };

  function collectSecrets(server) {
    const found = [];
    if (isObj(server.env)) {
      for (const [k, v0] of Object.entries(server.env)) {
        const v = v0 === null || v0 === undefined ? "" : String(v0);
        if (isSecretEnv(String(k), v)) found.push({ key: String(k), value: v, where: "env" });
      }
    }
    if (isObj(server.headers)) {
      for (const [k, v0] of Object.entries(server.headers)) {
        const v = v0 === null || v0 === undefined ? "" : String(v0);
        if (/(auth|token|key|secret)/i.test(String(k))) found.push({ key: String(k), value: v, where: "header" });
      }
    }
    const args = Array.isArray(server.args) ? server.args : [];
    args.forEach((a, i) => {
      if (typeof a !== "string") return;
      if (URL_USERINFO.test(a)) found.push({ key: `arg${i}:url-credentials`, value: a, where: "arg" });
      else if (a.startsWith("--") && a.includes("=") && SECRET_KEY.test(a.split("=")[0])) {
        const eq = a.indexOf("=");
        found.push({ key: a.slice(0, eq).replace(/^-+/, ""), value: a.slice(eq + 1), where: "arg" });
      } else if (a.startsWith("--") && SECRET_KEY.test(a) && i + 1 < args.length && typeof args[i + 1] === "string") {
        found.push({ key: a.replace(/^-+/, ""), value: args[i + 1], where: "arg" });
      }
    });
    return found.map((s) => ({ ...s, literal: isLiteral(s.value) }));
  }

  function dbTarget(server, secrets, name) {
    const args = Array.isArray(server.args) ? server.args : [];
    const candidates = secrets.map((s) => s.value).concat(args.filter((a) => typeof a === "string" && a.includes("://")));
    for (const c of candidates) {
      const m = /[a-z][a-z0-9+.-]*:\/\//i.exec(c);
      if (m) {
        try {
          const u = new URL(c.slice(m.index));
          if (u.hostname) {
            let path = u.pathname;
            if (path === "/" && /^https?:$/.test(u.protocol)) path = "";
            return `${u.hostname}${path}`;
          }
        } catch (e) { /* unparsable URL: try the next candidate */ }
      }
    }
    for (const a of args) {
      if (typeof a === "string" && /\.(db|sqlite|sqlite3)$/i.test(a)) return basename(a);
    }
    return name;
  }

  function fsPaths(server) {
    const args = Array.isArray(server.args) ? server.args : [];
    return args.filter((a) => typeof a === "string" && (a.startsWith("/") || a.startsWith("~") || /^[A-Za-z]:[\\/]/.test(a))).slice(0, 6);
  }
  function fsSensitivity(p) {
    if (/(\.ssh|\.aws|\.gnupg|\/etc\b|\.kube)/.test(p)) return 5;
    if (BROAD_FS.test(p)) return 4;
    return 3;
  }

  /* docs: {label: parsedJson}. opts: {target:"auto"|"a,b", minSensitivity:4, keep:["github"]} */
  function buildSpec(docs, opts = {}) {
    const target = opts.target === undefined ? "auto" : opts.target;
    const minSensitivity = opts.minSensitivity === undefined ? 4 : opts.minSensitivity;
    const keep = new Set((opts.keep || []).map((k) => k.toLowerCase()));
    const nodes = new Map();           // id -> {label, props}
    const edges = [];                  // {source, rel, target, props}
    const edgeMeta = new Map();        // "src|rel|dst" -> meta
    const configs = [];
    let hardcoded = 0, serversTotal = 0;

    const addNode = (id, label, props) => {
      if (!nodes.has(id)) {
        const { name, ...rest } = props;
        nodes.set(id, { label, props: { name: name === undefined ? id : name, ...rest } });
      } else if (label === "Resource") {
        const old = nodes.get(id).props;
        old.sensitivity = Math.max(old.sensitivity || 0, props.sensitivity || 0);
      }
    };
    const addEdge = (src, rel, dst, cost, meta = {}) => {
      meta = { ...meta };
      if (meta.action === "remove_server" && keep.has(String(meta.server || "").toLowerCase())) {
        cost = NOT_CONFIGURABLE; meta.kept = true;
      }
      edges.push({ source: src, rel, target: dst, props: { cost, ...meta } });
      edgeMeta.set(`${src}|${rel}|${dst}`, { cost, ...meta });
    };

    for (const [label, doc] of Object.entries(docs)) {
      const servers = findServers(doc);
      if (servers === null) continue;
      configs.push(label);
      const agentId = `agent:${label}`;
      addNode(agentId, "Agent", { name: label, trust: "medium", framework: "mcp-client", source: "config" });
      const shellTools = [], allTools = [];

      for (const [sname, server] of Object.entries(servers)) {
        if (!isObj(server) || server.disabled === true) continue;
        serversTotal += 1;
        const toolId = `${label}:${sname}`;
        const cat = classify(sname, server);
        const cname = cat ? cat.cat : "service", resKey = cat ? cat.res : null, sens = cat ? cat.sens : 3;
        const untrusted = cat ? cat.untrusted : false, lateral = cat ? cat.lateral : false;
        const command = basename(String(server.command || server.url || ""));
        addNode(toolId, "Tool", { name: sname, kind: "mcp", category: cname, command, config: label });
        addEdge(agentId, "CAN_INVOKE", toolId, COST_REMOVE_SERVER,
          { action: "remove_server", config: label, server: sname, inferred: false });
        allTools.push(toolId);
        if (lateral) shellTools.push(toolId);

        if (untrusted) {
          const dsId = `untrusted:${label}:${sname}`;
          addNode(dsId, "DataSource", { name: `${sname} content`, trusted: false, kind: cname, via: sname });
          addEdge(dsId, "FEEDS", agentId, COST_QUARANTINE, {
            action: "remove_server", config: label, server: sname, inferred: true,
            note: `${sname} returns content an outsider can write (prompt-injection entry)`,
          });
        }

        const secrets = collectSecrets(server);
        const resources = [];
        if (cname === "filesystem") {
          const ps = fsPaths(server);
          for (const p of (ps.length ? ps : ["(configured roots)"])) resources.push([`res:fs:${p}`, fsSensitivity(p)]);
        } else if (cname === "database") {
          resources.push([`res:database:${dbTarget(server, secrets, sname)}`, sens]);
        } else if (resKey) {
          resources.push([`res:${resKey}`, sens]);
        } else if (secrets.length) {
          resources.push([`res:svc:${sname}`, cname === "web" ? 2 : 3]);
        }
        for (const [rid, rsens] of resources) {
          addNode(rid, "Resource", { name: rid.split(":").slice(1).join(":"), kind: cname, sensitivity: rsens });
        }

        for (const sec of secrets) {
          if (sec.literal) hardcoded += 1;
          const credId = `cred:${slug(sec.key)}:${fp(sec.value)}`;
          addNode(credId, "Credential", {
            name: `${sec.key} (${fp(sec.value)})`, kind: `${sec.where}_secret`,
            env_key: sec.key, fingerprint: fp(sec.value), hardcoded: sec.literal,
          });
          addEdge(toolId, "USES", credId, COST_REMOVE_SERVER, {
            action: "remove_server", config: label, server: sname, key: sec.key, inferred: false,
            note: `${sec.where} secret ${sec.key}`,
          });
          for (const [rid] of resources) {
            if (!edgeMeta.has(`${credId}|GRANTS|${rid}`)) {
              addEdge(credId, "GRANTS", rid, NOT_CONFIGURABLE, {
                action: "advisory", config: label, server: sname, inferred: true,
                note: "what a token may do is enforced server-side; scope it down there",
              });
            }
          }
        }

        if (cname === "shell" || cname === "filesystem" || (cname === "database" && !secrets.length)) {
          for (const [rid] of resources) {
            addEdge(toolId, "HAS_ACCESS", rid, NOT_CONFIGURABLE, {
              action: "advisory", config: label, server: sname, inferred: true,
              note: "local access granted by the server process itself",
            });
          }
        }
      }

      for (const sh of shellTools) {
        for (const other of allTools) {
          if (other !== sh) {
            addEdge(sh, "CALLS", other, NOT_CONFIGURABLE, {
              action: "remove_server", config: label, server: sh.split(":").slice(1).join(":"), inferred: true,
              note: "shell access can read this config's secrets and invoke every other tool",
            });
          }
        }
      }
    }

    // crown jewels: a virtual sink so ONE min-cut seals them all at once
    const resourceIds = [...nodes.entries()].filter(([, v]) => v.label === "Resource").map(([id, v]) => [id, v.props]);
    let chosen;
    if (target === "" || target === "auto" || target === null) {
      chosen = resourceIds.filter(([, p]) => (p.sensitivity || 0) >= minSensitivity).map(([id]) => id);
    } else {
      const wanted = target.split(",").map((t) => t.trim()).filter(Boolean);
      chosen = resourceIds.map(([id]) => id).filter((r) => wanted.some((w) => r === w || r === `res:${w}` || r.startsWith(`res:${w}`)));
    }
    let specTarget = null;
    if (chosen.length === 1) {
      specTarget = chosen[0];
      nodes.get(chosen[0]).props.crown_jewel = true;
    } else if (chosen.length > 1) {
      addNode(SINK_ID, "Resource", { name: "all crown-jewel resources", kind: "virtual_sink", sensitivity: 9, crown_jewel: true, synthetic: true });
      for (const r of chosen) {
        nodes.get(r).props.crown_jewel = true;
        addEdge(r, "GRANTS", SINK_ID, SINK_COST, { action: "synthetic", synthetic: true });
      }
      specTarget = SINK_ID;
    }

    const graph = {
      nodes: [...nodes.entries()].map(([id, { label, props }]) => ({
        id, name: props.name === undefined ? id : props.name, label,
        trust: props.trust || "", kind: props.kind || "",
        trusted: props.trusted === undefined ? null : props.trusted,
      })),
      edges: edges.map((e) => ({ source: e.source, target: e.target, rel: e.rel, cap: 1, cost: e.props.cost })),
    };
    return {
      graph, target: specTarget, edgeMeta,
      stats: { configs: configs.length, servers: serversTotal, hardcoded_secrets: hardcoded, crown_jewels: [...chosen].sort() },
    };
  }

  /* Plain-English fix for one cut edge (mirrors what remediate.py will patch). */
  function describeFix(spec, c) {
    const m = spec.edgeMeta.get(`${c.src}|${c.rel}|${c.dst}`) || {};
    if (m.action === "remove_server") {
      return m.rel === "FEEDS" || c.rel === "FEEDS"
        ? `In \`${m.config}\`: stop the \`${m.server}\` server from feeding untrusted content to the agent (remove it, or disable it for this agent).`
        : `In \`${m.config}\`: remove the \`${m.server}\` MCP server.`;
    }
    if (m.action === "advisory") return `Outside the config file: ${m.note || "scope this permission down server-side"} (${c.src} -> ${c.dst}).`;
    return `Revoke ${c.src} -[${c.rel}]-> ${c.dst}.`;
  }

  return { buildSpec, describeFix, findServers, classify, sha256hex, SINK_ID };
})();

if (typeof window !== "undefined") window.SunderIngest = SunderIngest;   // same convention as engine.js / agent.js
if (typeof module !== "undefined" && module.exports) module.exports = SunderIngest;
