"""Real-data ingest: MCP client configs  ->  the SUNDER capability graph.

Point SUNDER at the files you already have (Claude Desktop's
``claude_desktop_config.json``, Cursor's ``mcp.json``, a VS Code ``mcp.json`` ...)
and it builds the agent-mesh graph from them:

    config file        -> Agent       (the MCP client / the agent it hosts)
    mcpServers entry   -> Tool        (Agent --CAN_INVOKE--> Tool)
    secret env / arg   -> Credential  (Tool  --USES-------> Credential)
    what it unlocks    -> Resource    (Credential --GRANTS--> Resource)
    web / mail / issue -> DataSource  (untrusted --FEEDS--> Agent)   = prompt-injection entry

Honest scope: a config file says *which servers an agent can call and with what
secrets*; it does not say what each server can reach. That second half is
inferred from the server's name / package (``server-postgres`` -> a database,
``server-github`` -> source repos and attacker-writable issue text, a shell
server -> the host and every other credential on it). Every inferred edge is
tagged ``inferred=true`` and the rules live in ``CATEGORIES`` below so they can
be audited and extended.

Secrets are never stored: only the env-var *name* and a short SHA-256
fingerprint of the value (so the same token reused across clients collapses
into one Credential node).

Edge costs reflect what a *config-level* remediation really is. Every fix SUNDER
can apply by editing a config is the same operation — remove an MCP server — so
all of them cost the same (5). Cutting at the untrusted-input side costs one
more (6): it blinds the agent rather than removing the dangerous capability, so on
an otherwise-tied cut SUNDER prefers to remove the capability. Edges that live
outside the file (what a token may do server-side) cost 100, so the minimum cut
only ever picks fixes SUNDER can really apply and then re-verify by re-ingesting
the patched config. ``keep`` lets you veto removing servers you cannot live
without; the cut then routes around them or reports that it cannot seal.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from . import schema as S
from .db import GraphDB
from .seed import load_spec

SINK_ID = "crown-jewels"
NOT_CONFIGURABLE = 100  # cost of an edge that cannot be changed from the config file
SINK_COST = 1000
COST_REMOVE_SERVER = 5   # remove a server (CAN_INVOKE / USES)
COST_QUARANTINE = 6      # blind the agent to an untrusted input (FEEDS)

# ---------------------------------------------------------------------------
# inference rules (ordered: most dangerous category wins)
# ---------------------------------------------------------------------------
# (category, resource id, sensitivity, content is attacker-writable?, lateral?, keywords)
CATEGORIES: list[tuple[str, str | None, int, bool, bool, set[str]]] = [
    ("shell", "host-shell", 5, False, True,
     {"shell", "terminal", "commander", "bash", "powershell", "exec", "ssh", "cmd"}),
    ("cloud", "cloud-account", 5, False, False,
     {"aws", "gcp", "gcloud", "azure", "kubernetes", "k8s", "kubectl", "terraform",
      "cloudflare", "vercel", "netlify", "pulumi"}),
    ("database", "database", 5, False, False,
     {"postgres", "postgresql", "mysql", "mariadb", "mongodb", "mongo", "redis", "sqlite",
      "supabase", "neon", "bigquery", "snowflake", "clickhouse", "dynamodb", "pg"}),
    ("payments", "payments-api", 4, False, False,
     {"stripe", "paypal", "square", "payments", "billing"}),
    ("mail", "mailbox", 4, True, False,
     {"gmail", "imap", "smtp", "outlook", "email", "mail"}),
    ("vcs", "source-repos", 4, True, False,
     {"github", "gitlab", "bitbucket", "git"}),
    ("messaging", "chat-workspace", 3, True, False,
     {"slack", "discord", "teams", "telegram", "whatsapp"}),
    ("workspace", "work-tracker", 3, True, False,
     {"notion", "jira", "linear", "confluence", "asana", "trello", "airtable", "gdrive",
      "drive", "sheets", "zendesk", "intercom", "hubspot", "salesforce"}),
    ("web", None, 1, True, False,
     {"fetch", "puppeteer", "playwright", "browser", "brave", "search", "firecrawl",
      "scrape", "crawl", "tavily", "exa", "selenium", "web", "http", "browserbase"}),
    ("filesystem", "filesystem", 3, False, False,
     {"filesystem", "fs", "files", "file"}),
]

_SECRET_KEY = re.compile(
    r"(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|BEARER|DSN|"
    r"CONNECTION_?STRING|DATABASE_?URL|(^|_)KEY($|_)|(^|_)PASS($|_)|(^|_)AUTH)",
    re.I,
)
_SECRET_VALUE = re.compile(r"^(ghp_|gho_|ghs_|github_pat_|xox[abprs]-|sk-|AKIA|ASIA|AIza|ya29\.)")
_URL_USERINFO = re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@", re.I)
_SERVER_KEYS = ("mcpServers", "servers", "context_servers")
_BROAD_FS = re.compile(r"^(/|~|[A-Za-z]:[\\/]?|/(Users|home)/[^/]+/?)$")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _fp(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:8]


def _slug(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", text).strip("-") or "x"


def find_servers(doc: Any) -> dict[str, Any] | None:
    """Return the *live* ``{name: server}`` dict inside a parsed config (or None)."""
    if not isinstance(doc, dict):
        return None
    for key in _SERVER_KEYS:
        if isinstance(doc.get(key), dict):
            return doc[key]
    mcp = doc.get("mcp")
    if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
        return mcp["servers"]
    return None


def _tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


def _package_args(args: list[Any]) -> list[str]:
    """Args that look like package names (not flags, paths or URLs)."""
    out = []
    for a in args:
        if not isinstance(a, str) or a.startswith("-") or "://" in a:
            continue
        if a.startswith(("/", "~", ".")) or "\\" in a:
            continue
        out.append(a)
    return out


def _match(tokens: list[str]):
    for cat in CATEGORIES:
        kws = cat[5]
        for t in tokens:
            if t in kws or any(len(k) >= 6 and t.startswith(k) for k in kws):
                return cat
    return None


def classify(name: str, server: dict[str, Any]):
    """Pick the inference category for one server (name first, then package)."""
    args = server.get("args") if isinstance(server.get("args"), list) else []
    cat = _match(_tokens(name))
    if cat is None:
        extra = [str(server.get("command", ""))] + _package_args(args)
        if isinstance(server.get("url"), str):
            extra.append(urlparse(server["url"]).hostname or "")
        cat = _match(_tokens(" ".join(extra)))
    return cat


def _is_secret_env(key: str, value: str) -> bool:
    if _URL_USERINFO.search(value) or _SECRET_VALUE.match(value):
        return True
    if not _SECRET_KEY.search(key):
        return False
    # Don't treat bare paths / booleans / tiny numbers as secrets
    return value not in ("", "true", "false") and not value.isdigit()


@dataclass
class _Secret:
    key: str          # env var / header / flag name
    value: str
    where: str        # "env" | "header" | "arg"

    @property
    def literal(self) -> bool:
        v = self.value.strip()
        return not (v.startswith("${") or v.startswith("$") or v.startswith("env:") or v == "")


def _collect_secrets(server: dict[str, Any]) -> list[_Secret]:
    found: list[_Secret] = []
    env = server.get("env")
    if isinstance(env, dict):
        for k, v in env.items():
            v = "" if v is None else str(v)
            if _is_secret_env(str(k), v):
                found.append(_Secret(str(k), v, "env"))
    headers = server.get("headers")
    if isinstance(headers, dict):
        for k, v in headers.items():
            v = "" if v is None else str(v)
            if re.search(r"(auth|token|key|secret)", str(k), re.I):
                found.append(_Secret(str(k), v, "header"))
    args = server.get("args") if isinstance(server.get("args"), list) else []
    for i, a in enumerate(args):
        if not isinstance(a, str):
            continue
        if _URL_USERINFO.search(a):
            found.append(_Secret(f"arg{i}:url-credentials", a, "arg"))
        elif a.startswith("--") and "=" in a and _SECRET_KEY.search(a.split("=", 1)[0]):
            found.append(_Secret(a.split("=", 1)[0].lstrip("-"), a.split("=", 1)[1], "arg"))
        elif a.startswith("--") and _SECRET_KEY.search(a) and i + 1 < len(args) and isinstance(args[i + 1], str):
            found.append(_Secret(a.lstrip("-"), args[i + 1], "arg"))
    return found


def _db_target(server: dict[str, Any], secrets: list[_Secret], name: str) -> str:
    """Name the database a server points at (host/db only — never the password)."""
    candidates = [s.value for s in secrets]
    args = server.get("args") if isinstance(server.get("args"), list) else []
    candidates += [a for a in args if isinstance(a, str) and "://" in a]
    for c in candidates:
        m = re.search(r"[a-z][a-z0-9+.-]*://", c, re.I)
        if m:
            try:
                u = urlparse(c[m.start():])
                if u.hostname:
                    return f"{u.hostname}{u.path or ''}"
            except ValueError:
                pass
    for a in args:
        if isinstance(a, str) and a.lower().endswith((".db", ".sqlite", ".sqlite3")):
            return os.path.basename(a)
    return name


def _fs_paths(server: dict[str, Any]) -> list[str]:
    args = server.get("args") if isinstance(server.get("args"), list) else []
    paths = [a for a in args if isinstance(a, str) and (a.startswith(("/", "~")) or re.match(r"^[A-Za-z]:[\\/]", a))]
    return paths[:6]


def _fs_sensitivity(path: str) -> int:
    if re.search(r"(\.ssh|\.aws|\.gnupg|/etc\b|\.kube)", path):
        return 5
    if _BROAD_FS.match(path):
        return 4
    return 3


# ---------------------------------------------------------------------------
# the spec builder
# ---------------------------------------------------------------------------
@dataclass
class Spec:
    nodes: list[tuple[str, str, dict[str, Any]]] = field(default_factory=list)
    edges: list[tuple[str, str, str, dict[str, Any]]] = field(default_factory=list)
    target: str | None = None
    # (src, rel, dst) -> how to fix it in the config file
    edge_meta: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    configs: list[str] = field(default_factory=list)       # labels, in load order
    stats: dict[str, Any] = field(default_factory=dict)

    def node_ids(self) -> set[str]:
        return {n[0] for n in self.nodes}


def build_spec(
    docs: dict[str, Any],
    target: str = "auto",
    min_sensitivity: int = 4,
    keep: set[str] | None = None,
) -> Spec:
    """Turn parsed config documents (``{label: json}``) into a graph spec.

    ``target`` is ``"auto"`` (every resource with sensitivity >= ``min_sensitivity``,
    sealed *together* in one globally-minimal cut) or a comma-separated list of
    resource ids / id prefixes (e.g. ``"database,cloud-account"``). ``keep`` is a
    set of server names that must not be removed.
    """
    keep = {k.lower() for k in (keep or set())}
    spec = Spec()
    nodes: dict[str, tuple[str, dict[str, Any]]] = {}
    edges: list[tuple[str, str, str, dict[str, Any]]] = []
    hardcoded = 0
    servers_total = 0

    def add_node(nid: str, label: str, **props: Any) -> None:
        if nid not in nodes:
            nodes[nid] = (label, {"name": props.pop("name", nid), **props})
        elif label == S.RESOURCE:  # keep the highest sensitivity seen
            old = nodes[nid][1]
            old["sensitivity"] = max(old.get("sensitivity", 0), props.get("sensitivity", 0))

    def add_edge(src: str, rel: str, dst: str, cost: int, **meta: Any) -> None:
        if meta.get("action") == "remove_server" and str(meta.get("server", "")).lower() in keep:
            cost = NOT_CONFIGURABLE  # vetoed: SUNDER will route around this server if it can
            meta["kept"] = True
        props = {"cost": cost, **{k: v for k, v in meta.items() if v is not None}}
        edges.append((src, rel, dst, props))
        spec.edge_meta[(src, rel, dst)] = {"cost": cost, **meta}

    for label, doc in docs.items():
        servers = find_servers(doc)
        if servers is None:
            continue
        spec.configs.append(label)
        agent_id = f"agent:{label}"
        add_node(agent_id, S.AGENT, name=label, trust=S.TRUST_MEDIUM, framework="mcp-client", source="config")
        shell_tools: list[str] = []
        all_tools: list[str] = []

        for sname, server in servers.items():
            if not isinstance(server, dict) or server.get("disabled") is True:
                continue
            servers_total += 1
            tool_id = f"{label}:{sname}"
            cat = classify(sname, server)
            cname, res_key, sens, untrusted, lateral, _ = cat if cat else ("service", None, 3, False, False, set())
            command = os.path.basename(str(server.get("command") or server.get("url") or ""))
            add_node(tool_id, S.TOOL, name=sname, kind="mcp", category=cname, command=command, config=label)
            add_edge(agent_id, S.CAN_INVOKE, tool_id, COST_REMOVE_SERVER,
                     action="remove_server", config=label, server=sname, inferred=False)
            all_tools.append(tool_id)
            if lateral:
                shell_tools.append(tool_id)

            if untrusted:
                ds_id = f"untrusted:{label}:{sname}"
                add_node(ds_id, S.DATA_SOURCE, name=f"{sname} content", trusted=False, kind=cname, via=sname)
                add_edge(ds_id, S.FEEDS, agent_id, COST_QUARANTINE, action="remove_server", config=label, server=sname,
                         inferred=True, note=f"{sname} returns content an outsider can write (prompt-injection entry)")

            secrets = _collect_secrets(server)

            # --- resources this server unlocks
            resources: list[tuple[str, int]] = []
            if cname == "filesystem":
                for p in _fs_paths(server) or ["(configured roots)"]:
                    resources.append((f"res:fs:{p}", _fs_sensitivity(p)))
            elif cname == "database":
                resources.append((f"res:database:{_db_target(server, secrets, sname)}", sens))
            elif res_key:
                resources.append((f"res:{res_key}", sens))
            elif secrets:  # unknown/web service holding a secret
                resources.append((f"res:svc:{sname}", 2 if cname == "web" else 3))
            for rid, rsens in resources:
                add_node(rid, S.RESOURCE, name=rid.split(":", 1)[1], kind=cname, sensitivity=rsens)

            # --- credentials
            for sec in secrets:
                hardcoded += 1 if sec.literal else 0
                cred_id = f"cred:{_slug(sec.key)}:{_fp(sec.value)}"
                add_node(cred_id, S.CREDENTIAL, name=f"{sec.key} ({_fp(sec.value)})", kind=f"{sec.where}_secret",
                         env_key=sec.key, fingerprint=_fp(sec.value), hardcoded=sec.literal)
                add_edge(tool_id, S.USES, cred_id, COST_REMOVE_SERVER,
                         action="remove_server", config=label, server=sname, key=sec.key, inferred=False,
                         note=f"{sec.where} secret {sec.key}")
                for rid, _ in resources:
                    if (cred_id, S.GRANTS, rid) not in spec.edge_meta:
                        add_edge(cred_id, S.GRANTS, rid, NOT_CONFIGURABLE,
                                 action="advisory", config=label, server=sname, inferred=True,
                                 note="what a token may do is enforced server-side; scope it down there")

            # --- direct access (no credential involved): only for servers that need none
            if cname in ("shell", "filesystem") or (cname == "database" and not secrets):
                for rid, _ in resources:
                    add_edge(tool_id, S.HAS_ACCESS, rid, NOT_CONFIGURABLE,
                             action="advisory", config=label, server=sname, inferred=True,
                             note="local access granted by the server process itself")

        # a shell on the host can read this config (and its env) => lateral movement to every other tool
        for sh in shell_tools:
            for other in all_tools:
                if other != sh:
                    add_edge(sh, S.CALLS, other, NOT_CONFIGURABLE,
                             action="remove_server", config=label, server=sh.split(":", 1)[1], inferred=True,
                             note="shell access can read this config's secrets and invoke every other tool")

    # --- crown jewels (virtual sink so ONE min-cut seals them all at once)
    resources = {nid: p for nid, (lab, p) in nodes.items() if lab == S.RESOURCE}
    if target in ("", "auto", None):
        chosen = [r for r, p in resources.items() if p.get("sensitivity", 0) >= min_sensitivity]
    else:
        wanted = [t.strip() for t in target.split(",") if t.strip()]
        chosen = [r for r in resources if any(r == w or r == f"res:{w}" or r.startswith(f"res:{w}") for w in wanted)]
    if len(chosen) == 1:
        spec.target = chosen[0]
        nodes[chosen[0]][1]["crown_jewel"] = True
    elif chosen:
        add_node(SINK_ID, S.RESOURCE, name="all crown-jewel resources", kind="virtual_sink",
                 sensitivity=9, crown_jewel=True, synthetic=True)
        for r in chosen:
            nodes[r][1]["crown_jewel"] = True
            add_edge(r, S.GRANTS, SINK_ID, SINK_COST, action="synthetic", synthetic=True)
        spec.target = SINK_ID

    for nid, (lab, props) in nodes.items():
        if lab == S.RESOURCE:
            props.setdefault("crown_jewel", False)
        spec.nodes.append((nid, lab, props))
    spec.edges = edges
    spec.stats = {
        "configs": len(spec.configs),
        "servers": servers_total,
        "hardcoded_secrets": hardcoded,
        "crown_jewels": sorted(chosen),
    }
    return spec


# ---------------------------------------------------------------------------
# file handling
# ---------------------------------------------------------------------------
def _label_for(path: str, used: set[str]) -> str:
    base = _slug(os.path.splitext(os.path.basename(path))[0].replace("_config", ""))
    label, n = base, 2
    while label in used:
        label, n = f"{base}-{n}", n + 1
    used.add(label)
    return label


def discover(paths: list[str]) -> list[str]:
    """Expand files/directories into config files that contain an MCP server map."""
    found: list[str] = []
    for p in paths:
        p = os.path.expanduser(p)
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                if any(part in (".git", "node_modules", "sunder-out") for part in root.split(os.sep)):
                    continue
                for f in sorted(files):
                    if f.endswith(".json"):
                        found.append(os.path.join(root, f))
        else:
            found.append(p)
    out = []
    for f in found:
        try:
            with open(f, encoding="utf-8") as fh:
                if find_servers(json.load(fh)) is not None:
                    out.append(f)
        except (OSError, ValueError):
            continue
    return out


def load_docs(paths: list[str]) -> tuple[dict[str, Any], dict[str, str]]:
    """Return ``({label: parsed_json}, {label: source_path})``."""
    files = discover(paths)
    if not files:
        raise FileNotFoundError(
            "no MCP client config found (expected JSON with an 'mcpServers' / 'servers' map) in: " + ", ".join(paths)
        )
    used: set[str] = set()
    docs, origin = {}, {}
    for f in files:
        label = _label_for(f, used)
        with open(f, encoding="utf-8") as fh:
            docs[label] = json.load(fh)
        origin[label] = f
    return docs, origin


def ingest_docs(
    db: GraphDB, docs: dict[str, Any], target: str = "auto", min_sensitivity: int = 4, keep: set[str] | None = None
) -> Spec:
    """Build the spec from parsed docs and load it into FalkorDB."""
    spec = build_spec(copy.deepcopy(docs), target=target, min_sensitivity=min_sensitivity, keep=keep)
    load_spec(db, spec.nodes, spec.edges)
    return spec


def ingest_paths(db: GraphDB, paths: list[str], target: str = "auto", min_sensitivity: int = 4, keep: set[str] | None = None):
    docs, origin = load_docs(paths)
    return ingest_docs(db, docs, target, min_sensitivity, keep), docs, origin
