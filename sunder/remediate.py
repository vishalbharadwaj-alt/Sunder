"""From a minimum cut to a *real* fix.

The agent's ``apply_cut`` edits SUNDER's own graph. This module turns that same
cut into changes you can ship:

  * patched copies of your MCP client configs (a server removed, a secret unset)
  * a unified diff
  * a plain-English plan, including the steps that live outside the file
    (e.g. "scope the GitHub token down") which SUNDER cannot apply for you
  * an independent proof: the patched configs are *re-ingested from scratch* and
    the attack paths recounted, so the verification does not rely on SUNDER's
    in-graph edit having been correct.

Originals are never modified.
"""
from __future__ import annotations

import copy
import difflib
import json
import os
from dataclasses import dataclass, field
from typing import Any

from . import schema as S
from .agent import SunderAgent, ScriptedPlanner
from .db import GraphDB, get_db
from .ingest import Spec, find_servers, ingest_docs, load_docs
from .tools import graph_tools as T

# ---------------------------------------------------------------------------
# plain-English actions
# ---------------------------------------------------------------------------
_GENERIC = {
    S.FEEDS: "Quarantine untrusted source `{src}`: sanitize its content and require human approval before `{dst}` acts on it.",
    S.CAN_INVOKE: "Remove `{dst}` from `{src}`'s tool allow-list.",
    S.USES: "Detach credential `{dst}` from `{src}`; give the tool a narrower, purpose-scoped credential.",
    S.GRANTS: "Revoke the grant of `{dst}` to `{src}` (role binding / IAM policy).",
    S.HAS_ACCESS: "Drop `{src}`'s access binding to `{dst}`.",
    S.DELEGATES: "Remove `{src}` -> `{dst}` delegation (or require an approval step on it).",
    S.CALLS: "Break tool chaining `{src}` -> `{dst}`.",
    S.HAS_CREDENTIAL: "Strip credential `{dst}` from agent `{src}`.",
}


@dataclass
class Action:
    edge: dict[str, str]
    kind: str                 # remove_server | blocked | advisory | generic
    config: str | None
    server: str | None
    key: str | None
    text: str
    cost: int
    applied_to_config: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "edge": self.edge, "kind": self.kind, "config": self.config, "server": self.server,
            "key": self.key, "text": self.text, "cost": self.cost,
            "applied_to_config": self.applied_to_config,
        }


def plan_actions(
    cut: list[dict[str, str]],
    edge_meta: dict[tuple[str, str, str], dict[str, Any]] | None = None,
    keep: set[str] | None = None,
) -> list[Action]:
    edge_meta = edge_meta or {}
    keep = {k.lower() for k in (keep or set())}
    actions: list[Action] = []
    for e in cut:
        key = (e["src"], e["rel"], e["dst"])
        meta = edge_meta.get(key)
        if not meta:
            actions.append(Action(e, "generic", None, None, None,
                                  _GENERIC.get(e["rel"], "Revoke `{src}` -> `{dst}`.").format(src=e["src"], dst=e["dst"]),
                                  S.REL_COST.get(e["rel"], 1)))
            continue
        kind, cfg, srv, k = meta.get("action", "advisory"), meta.get("config"), meta.get("server"), meta.get("key")
        if kind == "remove_server" and str(srv).lower() in keep:
            kind = "blocked"
            text = (f"BLOCKED: sealing needs `{srv}` removed from `{cfg}`, but you marked it keep. "
                    f"Run it in a separate, unprivileged agent (no other tools, no crown-jewel access) or accept this residual risk.")
        elif kind == "remove_server":
            text = f"In `{cfg}`: remove the `{srv}` MCP server (or move it into a separate, unprivileged agent)."
        else:
            text = f"Outside the config file: {meta.get('note') or 'tighten this permission'} ({e['src']} -> {e['dst']})."
        actions.append(Action(e, kind, cfg, srv, k, text, int(meta.get("cost", 1))))
    return actions


# ---------------------------------------------------------------------------
# patching
# ---------------------------------------------------------------------------
def apply_to_docs(docs: dict[str, Any], actions: list[Action]) -> dict[str, Any]:
    """Return patched deep copies of ``docs``; mark which actions touched a config."""
    patched = copy.deepcopy(docs)
    for a in actions:
        if a.kind != "remove_server" or a.config not in patched:
            continue
        servers = find_servers(patched[a.config])
        if servers is not None and a.server in servers:
            del servers[a.server]
        a.applied_to_config = True  # removed now, or already gone via an earlier action
    return patched


def redact_docs(docs: dict[str, Any]) -> dict[str, Any]:
    """Replace every secret *value* with a placeholder (safe to share/commit)."""
    from .ingest import _collect_secrets  # local import: private helper

    out = copy.deepcopy(docs)
    for doc in out.values():
        servers = find_servers(doc) or {}
        for srv in servers.values():
            if not isinstance(srv, dict):
                continue
            for sec in _collect_secrets(srv):
                if sec.where == "env":
                    srv["env"][sec.key] = "<REDACTED>"
                elif sec.where == "header":
                    srv["headers"][sec.key] = "<REDACTED>"
                elif sec.where == "arg":
                    srv["args"] = [("<REDACTED>" if sec.value in str(x) else x) for x in srv.get("args", [])]
    return out


def make_diff(before: Any, after: Any, label: str) -> str:
    a = json.dumps(before, indent=2, sort_keys=False).splitlines(keepends=True)
    b = json.dumps(after, indent=2, sort_keys=False).splitlines(keepends=True)
    return "".join(difflib.unified_diff(a, b, f"a/{label}.json", f"b/{label}.json"))


# ---------------------------------------------------------------------------
# the pipeline
# ---------------------------------------------------------------------------
@dataclass
class HardenResult:
    spec: Spec
    report: dict[str, Any]
    steps: list[Any]
    actions: list[Action]
    diffs: dict[str, str]
    patched: dict[str, Any]
    proof: dict[str, Any]
    files: list[str] = field(default_factory=list)


def _paths_to(db: GraphDB, target: str) -> int:
    return T.count_paths_to(target, db)


def harden(
    paths: list[str],
    out_dir: str = "sunder-out",
    target: str = "auto",
    min_sensitivity: int = 4,
    dry_run: bool = False,
    redact: bool = False,
    keep: set[str] | None = None,
    db: GraphDB | None = None,
    planner=None,
) -> HardenResult:
    """ingest -> reason -> cut -> patch -> re-ingest -> prove."""
    db = db or get_db()
    docs, origin = load_docs(paths)
    spec = ingest_docs(db, docs, target=target, min_sensitivity=min_sensitivity, keep=keep)
    if not spec.target:
        raise ValueError("no crown-jewel resource found at that sensitivity (try --min-sensitivity 3 or --target <id>)")

    agent = SunderAgent(target=spec.target, planner=planner or ScriptedPlanner(), allow_writes=not dry_run)
    steps, report = agent.run_to_completion()
    cut = report.get("cut", [])

    actions = plan_actions(cut, spec.edge_meta, keep)
    patched = apply_to_docs(docs, actions)

    # independent proof: rebuild the graph from the PATCHED files (same crown-jewel
    # set as before) and recount attack paths from scratch
    before = report["attack_paths_before_count"]
    jewels = ",".join(spec.stats["crown_jewels"])
    new_spec = ingest_docs(db, patched, target=jewels, min_sensitivity=min_sensitivity, keep=keep)
    after = _paths_to(db, new_spec.target) if new_spec.target else 0
    advisory = [a for a in actions if not a.applied_to_config]
    proof = {
        "method": "patched configs re-ingested into a fresh graph, attack paths recounted",
        "paths_before": before,
        "paths_after": after,
        "sealed": after == 0,
        "config_edits": sum(1 for a in actions if a.applied_to_config),
        "outside_config_steps": len(advisory),
    }

    # with --redact, diffs/plan are rendered from redacted copies so no output file carries a secret
    shown_before, shown_after = (redact_docs(docs), redact_docs(patched)) if redact else (docs, patched)
    diffs = {lab: make_diff(shown_before[lab], shown_after[lab], lab) for lab in docs if docs[lab] != patched[lab]}
    result = HardenResult(spec, report, steps, actions, diffs, patched, proof)

    if not dry_run:
        result.files = write_outputs(result, docs, origin, out_dir, redact)
    return result


# ---------------------------------------------------------------------------
# output
# ---------------------------------------------------------------------------
def render_markdown(res: HardenResult) -> str:
    r, p = res.report, res.proof
    lines = ["# SUNDER remediation plan", ""]
    lines.append(f"**Result:** {'SEALED' if p['sealed'] else 'NOT sealed'} — attack paths to crown jewels "
                 f"{p['paths_before']} → {p['paths_after']} "
                 f"(re-checked by re-ingesting the patched configs).")
    if not p["sealed"]:
        lines.append("")
        lines.append(f"> Config edits alone leave {p['paths_after']} path(s) open. "
                     f"Finish the {p['outside_config_steps']} step(s) marked manual/BLOCKED below to seal the rest.")
    lines.append("")
    lines.append(f"- Configs analysed: {res.spec.stats['configs']} · MCP servers: {res.spec.stats['servers']}")
    lines.append(f"- Crown-jewel resources: {', '.join(res.spec.stats['crown_jewels']) or '—'}")
    if res.spec.stats["hardcoded_secrets"]:
        lines.append(f"- ⚠ {res.spec.stats['hardcoded_secrets']} secret(s) are hard-coded in config files "
                     f"(value never stored by SUNDER; rotate them if these files were shared).")
    lines.append(f"- Entry points: {', '.join(r.get('entry_points', [])) or '—'}")
    lines.append(f"- Minimum cut: {len(r['cut'])} edge(s), business cost {r.get('cut_cost')}; "
                 f"max-flow {r.get('max_flow')} proves nothing cheaper exists.")
    if r.get("fewest_edge_cut_size") is not None:
        lines.append(f"- A fewest-edge cut would use {r['fewest_edge_cut_size']} edge(s) but cost "
                     f"{r.get('fewest_edge_cut_cost', '—')} — SUNDER minimises business impact, not edge count.")
    lines += ["", "## What to change", ""]
    for i, a in enumerate(res.actions, 1):
        tag = "auto-applied in patched config" if a.applied_to_config else ("BLOCKED by --keep" if a.kind == "blocked" else "manual")
        lines.append(f"{i}. {a.text}  _(cost {a.cost}, {tag})_")
    if res.diffs:
        lines += ["", "## Config diff", ""]
        for lab, d in res.diffs.items():
            lines += [f"### {lab}", "", "```diff", d.rstrip(), "```", ""]
    if r.get("attack_paths_before"):
        lines += ["## Example attack paths (before)", ""]
        for pth in r["attack_paths_before"][:5]:
            lines.append("- " + " → ".join(pth["nodes"]))
    return "\n".join(lines) + "\n"


def write_outputs(res: HardenResult, docs: dict[str, Any], origin: dict[str, str], out_dir: str, redact: bool) -> list[str]:
    os.makedirs(os.path.join(out_dir, "patched"), exist_ok=True)
    written = []
    to_write = redact_docs(res.patched) if redact else res.patched
    for lab, doc in to_write.items():
        dest = os.path.join(out_dir, "patched", os.path.basename(origin[lab]))
        if os.path.abspath(dest) == os.path.abspath(origin[lab]):
            raise ValueError("refusing to overwrite the original config; choose a different --out directory")
        # avoid clobbering when two sources share a filename
        if dest in written:
            dest = os.path.join(out_dir, "patched", f"{lab}-{os.path.basename(origin[lab])}")
        with open(dest, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
            fh.write("\n")
        written.append(dest)
    diff_path = os.path.join(out_dir, "patches.diff")
    with open(diff_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(res.diffs.values()))
    plan_path = os.path.join(out_dir, "remediation.md")
    with open(plan_path, "w", encoding="utf-8") as fh:
        fh.write(render_markdown(res))
    json_path = os.path.join(out_dir, "remediation.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump({
            "proof": res.proof,
            "actions": [a.as_dict() for a in res.actions],
            "report": {k: v for k, v in res.report.items() if k != "narrative"},
        }, fh, indent=2, default=str)
    return written + [diff_path, plan_path, json_path]
