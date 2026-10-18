"""SUNDER agent orchestrator.

The agent pursues a goal ("make the crown jewel safe from attacker-controlled
entry points") by *choosing tools*, each of which is a graph operation against
FalkorDB. Two planners are provided:

  * ``LoopPlanner``     — observe -> decide -> act: an OpenAI-compatible model sees
                          each real tool result and picks the next tool, inside
                          guardrails (the cut always comes from compute_min_cut;
                          apply needs a prior simulate; the run always ends verified).
                          Falls back to the scripted plan without an API key.
  * ``ScriptedPlanner`` — a deterministic, always-available plan. Every step is
                          annotated with the agent's reasoning, so the demo is
                          reproducible and offline-safe.

Whichever planner is used, the final act is the same and is the point of SUNDER:
compute the minimum edge cut, *apply* it, and verify zero attack paths remain.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator

from .config import CONFIG
from .tools import graph_tools as T


@dataclass
class Step:
    step: int
    tool: str
    args: dict[str, Any]
    reasoning: str
    summary: str = ""
    result: dict[str, Any] = field(default_factory=dict)
    ok: bool = True
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "tool": self.tool,
            "args": self.args,
            "reasoning": self.reasoning,
            "summary": self.summary,
            "result": self.result,
            "ok": self.ok,
            "error": self.error,
        }


# The catalogue shown to an LLM planner. Keep descriptions outcome-focused.
TOOL_CATALOG = [
    {"name": "describe_mesh", "args": {}, "desc": "Summarise the agent mesh: node/edge/label counts and available algorithms."},
    {"name": "find_entry_points", "args": {}, "desc": "List attacker-controlled entry points (low-trust agents, untrusted data sources)."},
    {"name": "all_attack_paths", "args": {"target": "resource id"}, "desc": "Enumerate every multi-hop capability path from any entry point to the target."},
    {"name": "rank_influential_nodes", "args": {}, "desc": "PageRank: rank nodes by influence."},
    {"name": "find_choke_points", "args": {}, "desc": "Betweenness: nodes many attack paths pass through."},
    {"name": "permission_communities", "args": {}, "desc": "Label-propagation permission clusters."},
    {"name": "compute_min_cut", "args": {"target": "resource id"}, "desc": "Minimum set of permission edges severing ALL entry points from the target."},
    {"name": "simulate_cut", "args": {"cut": "list of {src,rel,dst}", "target": "resource id"}, "desc": "Predict remaining attack paths if the cut is applied (no writes)."},
    {"name": "apply_cut", "args": {"cut": "list of {src,rel,dst}"}, "desc": "Revoke the cut edges from the graph (writes)."},
    {"name": "verify", "args": {"target": "resource id"}, "desc": "Re-check reachability and confirm the target is sealed."},
]


class SunderAgent:
    def __init__(self, target: str | None = None, planner: "Planner | None" = None, allow_writes: bool = True):
        self.target = target or CONFIG.crown_jewel
        self.planner = planner or make_planner()
        self.allow_writes = allow_writes
        self.state: dict[str, Any] = {"target": self.target, "results": {}, "cut": None, "log": []}

    # ---- execution -------------------------------------------------------
    def _call(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        fn = T.TOOL_REGISTRY.get(tool)
        if fn is None:
            raise ValueError(f"unknown tool: {tool}")
        if tool in T.WRITE_TOOLS and not self.allow_writes:
            return {"tool": tool, "skipped": True, "summary": f"write tool {tool} suppressed (read-only run)"}
        return fn(**args)

    def run(self) -> Iterator[Step]:
        """Yield each reasoning step as it happens (for streaming)."""
        step_no = 0
        for plan_item in self.planner.plan(self.target):
            step_no += 1
            tool, args, reasoning = plan_item.tool, plan_item.args, plan_item.reasoning
            args = self._resolve(args)
            step = Step(step=step_no, tool=tool, args=args, reasoning=reasoning)
            try:
                result = self._call(tool, args)
                step.result = result
                step.summary = result.get("summary", "")
                self.state["results"][tool] = result
                if tool == "compute_min_cut":
                    self.state["cut"] = result["cut"]
                    self.state["entry_points"] = result["entry_points"]
                    self.state["max_flow"] = result["max_flow"]
                self.state["log"].append(step.as_dict())
            except Exception as exc:  # keep the run alive, record the failure
                step.ok = False
                step.error = f"{type(exc).__name__}: {exc}"
                self.state["log"].append(step.as_dict())
            self.planner.observe(step)
            yield step

    def _resolve(self, args: dict[str, Any]) -> dict[str, Any]:
        out = dict(args)
        if "target" in out and out["target"] in (None, "", "TARGET"):
            out["target"] = self.target
        if "cut" in out and isinstance(out["cut"], str):
            out["cut"] = self.state.get("cut") or []
        return out

    def run_to_completion(self) -> tuple[list[Step], dict[str, Any]]:
        steps = list(self.run())
        from .report import build_report

        return steps, build_report(self.state)


# ---------------------------------------------------------------------------
# planners
# ---------------------------------------------------------------------------
@dataclass
class PlanItem:
    tool: str
    args: dict[str, Any]
    reasoning: str


class Planner:
    def plan(self, target: str) -> Iterator[PlanItem]:  # pragma: no cover - interface
        raise NotImplementedError

    def observe(self, step: "Step") -> None:
        """Called by the agent after each tool call, *before* the planner is asked
        for its next move. Scripted planners ignore it; the loop planner uses it
        to feed the real tool result back to the model."""
        return None


class ScriptedPlanner(Planner):
    """Deterministic, explainable plan — the offline-safe default."""

    def plan(self, target: str) -> Iterator[PlanItem]:
        yield PlanItem("describe_mesh", {}, "First, survey the terrain: how big is this agent mesh and what graph algorithms are available?")
        yield PlanItem("find_entry_points", {}, "Identify the attacker's footholds: agents with low trust and data sources we don't trust.")
        yield PlanItem("all_attack_paths", {"target": target}, "Enumerate every multi-hop chain of capability edges from those footholds to the crown jewel. This is the threat model.")
        yield PlanItem("rank_influential_nodes", {}, "PageRank tells me which nodes the mesh depends on most — useful context for where privilege concentrates.")
        yield PlanItem("find_choke_points", {}, "Betweenness highlights brokers that many attack paths traverse — candidate chokepoints.")
        yield PlanItem("permission_communities", {}, "Group tightly-coupled permissions so remediation respects real boundaries, not just single nodes.")
        yield PlanItem("compute_min_cut", {"target": target}, "Now the key move: find the MINIMUM-COST set of permission edges that severs every entry point from the target at once — minimising business impact, not just edge count.")
        yield PlanItem("simulate_cut", {"cut": "CUT", "target": target}, "Before touching anything, simulate the cut and predict the remaining attack paths.")
        yield PlanItem("apply_cut", {"cut": "CUT"}, "Apply the remediation: revoke exactly those permission edges.")
        yield PlanItem("verify", {"target": target}, "Prove the fix: re-run reachability. Zero attack paths means the jewel is sealed.")


READ_TOOLS = {"describe_mesh", "find_entry_points", "all_attack_paths", "rank_influential_nodes",
              "find_choke_points", "permission_communities"}
REQUIRED_TAIL = ["compute_min_cut", "simulate_cut", "apply_cut", "verify"]
_TARGET_TOOLS = {"all_attack_paths", "compute_min_cut", "simulate_cut", "verify"}


def _tool_schemas() -> list[dict[str, Any]]:
    """OpenAI-style function schemas built from TOOL_CATALOG (+ a ``finish`` tool)."""
    out = []
    for t in TOOL_CATALOG:
        props: dict[str, Any] = {
            "reasoning": {"type": "string", "description": "One sentence: why this tool, why now, given what you have seen so far."}
        }
        if t["name"] in _TARGET_TOOLS:
            props["target"] = {"type": "string", "description": "Resource id of the crown jewel (optional; defaults to the goal target)."}
        out.append({"type": "function", "function": {
            "name": t["name"], "description": t["desc"],
            "parameters": {"type": "object", "properties": props, "required": ["reasoning"]},
        }})
    out.append({"type": "function", "function": {
        "name": "finish", "description": "End the run. Only call this after verify has confirmed the outcome.",
        "parameters": {"type": "object", "properties": {"reasoning": {"type": "string"}}, "required": ["reasoning"]},
    }})
    return out


class LoopPlanner(Planner):
    """Observe -> decide -> act. The model sees each real tool result before it picks the next tool.

    Guardrails (enforced here, not left to the model):
      * the cut that gets simulated/applied always comes from ``compute_min_cut`` - the
        model cannot invent edges to revoke;
      * ``simulate_cut`` needs ``compute_min_cut`` first, ``apply_cut`` needs ``simulate_cut``,
        ``verify`` needs ``apply_cut``;
      * a read-only tool is not re-run if its result is already in hand;
      * a step budget bounds the run;
      * if the model stops early or the API fails, the missing required steps are completed
        deterministically and tagged as guardrail steps in the trace.
    Without an API key it falls back to the ScriptedPlanner.
    """

    def __init__(self, model: str | None = None, api_key: str | None = None, base_url: str | None = None,
                 client: Any = None, max_steps: int = 14):
        self.model = model or CONFIG.llm_model
        self.api_key = api_key or CONFIG.openai_api_key
        self.base_url = base_url or CONFIG.openai_base_url or None
        self._client_override = client
        self.max_steps = max_steps
        self.done: list[str] = []
        self._last: Step | None = None
        self.mode = "loop"

    # -- plumbing ---------------------------------------------------------
    def _client(self):
        if self._client_override is not None:
            return self._client_override
        if not self.api_key:
            return None
        try:
            from openai import OpenAI
        except Exception:
            return None
        kwargs: dict[str, Any] = {"api_key": self.api_key}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        return OpenAI(**kwargs)

    def observe(self, step: Step) -> None:
        self._last = step
        self.done.append(step.tool)

    @staticmethod
    def _compact(step: Step, limit: int = 1800) -> str:
        if not step.ok:
            return json.dumps({"error": step.error})
        body = json.dumps(step.result, default=str)
        if len(body) > limit:
            body = body[:limit] + "...(truncated)"
        return json.dumps({"summary": step.summary, "result": body})

    def _gate(self, tool: str) -> str | None:
        valid = {t["name"] for t in TOOL_CATALOG}
        if tool not in valid:
            return f"unknown tool '{tool}'. Choose one of: {sorted(valid)} or finish."
        if tool in READ_TOOLS and tool in self.done:
            return f"{tool} already ran; use its result above instead of re-running it."
        if tool == "simulate_cut" and "compute_min_cut" not in self.done:
            return "run compute_min_cut first: the cut to simulate comes from it."
        if tool == "apply_cut" and "simulate_cut" not in self.done:
            return "run simulate_cut first: never revoke permissions without predicting the effect."
        if tool == "verify" and "apply_cut" not in self.done:
            return "verify checks the outcome of apply_cut; apply the cut first."
        if tool in {"compute_min_cut", "simulate_cut", "apply_cut", "verify"} and tool in self.done:
            return f"{tool} already ran."
        return None

    def _system(self) -> str:
        return (
            "You are SUNDER, a security agent reasoning over an AI-agent-mesh graph stored in FalkorDB. "
            "You work one tool call at a time and you SEE each result before choosing the next tool. "
            "Goal: make the crown-jewel resource unreachable from every attacker-controlled entry point "
            "using the fewest, cheapest permission revocations, then prove it. "
            "Orient first, decide which analyses you actually need, then use compute_min_cut -> simulate_cut -> "
            "apply_cut -> verify. The cut is computed by compute_min_cut; you cannot choose edges yourself. "
            "If a result surprises you (e.g. verify still shows paths), say so in your reasoning and act on it. "
            "Call finish only after verify. Keep each reasoning to one sentence."
        )

    def _chat(self, client, messages):
        return client.chat.completions.create(
            model=self.model, messages=messages, tools=_tool_schemas(), tool_choice="auto", temperature=0.2,
        ).choices[0].message

    def _finish_required(self, target: str, why: str) -> Iterator[PlanItem]:
        for tool in REQUIRED_TAIL:
            if tool in self.done:
                continue
            args = {"target": target} if tool in _TARGET_TOOLS else {}
            if tool in {"simulate_cut", "apply_cut"}:
                args["cut"] = "CUT"
            yield PlanItem(tool, args, f"[guardrail] {why}; completing required step {tool}.")

    # -- the loop ---------------------------------------------------------
    def plan(self, target: str) -> Iterator[PlanItem]:
        self.done = []
        client = self._client()
        if client is None:
            self.mode = "scripted-fallback"
            yield from ScriptedPlanner().plan(target)
            return
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": self._system()},
            {"role": "user", "content": f"Crown jewel: '{target}'. Begin."},
        ]
        why_stop = "model ended the run before completing remediation"
        for _ in range(self.max_steps):
            try:
                msg = self._chat(client, messages)
            except Exception as exc:  # network/auth/etc: finish safely, deterministically
                self.mode = "loop+fallback"
                why_stop = f"LLM unavailable ({type(exc).__name__})"
                break
            calls = getattr(msg, "tool_calls", None) or []
            if not calls:
                break
            call = calls[0]
            tool = call.function.name
            try:
                raw = json.loads(call.function.arguments or "{}")
            except Exception:
                raw = {}
            reasoning = str(raw.get("reasoning") or getattr(msg, "content", "") or "").strip()
            messages.append({"role": "assistant", "content": getattr(msg, "content", None) or "", "tool_calls": [
                {"id": call.id, "type": "function", "function": {"name": tool, "arguments": call.function.arguments or "{}"}}]})
            if tool == "finish":
                if all(t in self.done for t in ("apply_cut", "verify")):
                    return
                messages.append({"role": "tool", "tool_call_id": call.id,
                                 "content": json.dumps({"refused": "finish only after apply_cut and verify"})})
                continue
            refusal = self._gate(tool)
            if refusal:
                messages.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps({"refused": refusal})})
                continue
            args: dict[str, Any] = {"target": target} if tool in _TARGET_TOOLS else {}
            if tool in {"simulate_cut", "apply_cut"}:
                args["cut"] = "CUT"
            self._last = None
            yield PlanItem(tool, args, reasoning or f"Model selected {tool}.")
            # the agent has now run the tool and called observe(): feed the real result back
            messages.append({"role": "tool", "tool_call_id": call.id,
                             "content": self._compact(self._last) if self._last else json.dumps({"error": "no result"})})
            if tool == "verify":
                return
        yield from self._finish_required(target, why_stop)


def make_planner() -> Planner:
    return LoopPlanner() if CONFIG.openai_api_key else ScriptedPlanner()
