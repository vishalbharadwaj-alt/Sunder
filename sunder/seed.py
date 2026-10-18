"""Synthetic AI-agent-mesh generator.

Builds a realistic enterprise agent deployment with *deliberately planted*
multi-hop privilege-escalation paths from untrusted entry points to a
crown-jewel secrets vault — plus benign noise so the agent has to reason.

The planted structure is designed so that the minimum edge cut is small and
lives at a choke point, not at the obvious final hop.
"""
from __future__ import annotations

from typing import Any

from . import schema as S
from .db import GraphDB

# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------
# (id, label, properties)
NODES: list[tuple[str, str, dict[str, Any]]] = [
    # --- crown-jewel & other resources ---
    ("prod-secrets-vault", S.RESOURCE, {"name": "prod-secrets-vault", "kind": "secret_vault", "sensitivity": 5, "crown_jewel": True}),
    ("prod-database", S.RESOURCE, {"name": "prod-database", "kind": "database", "sensitivity": 5, "crown_jewel": False}),
    ("customer-pii-bucket", S.RESOURCE, {"name": "customer-pii-bucket", "kind": "object_store", "sensitivity": 4, "crown_jewel": False}),
    ("billing-api", S.RESOURCE, {"name": "billing-api", "kind": "api", "sensitivity": 3, "crown_jewel": False}),
    ("audit-logs", S.RESOURCE, {"name": "audit-logs", "kind": "database", "sensitivity": 2, "crown_jewel": False}),
    ("marketing-assets", S.RESOURCE, {"name": "marketing-assets", "kind": "object_store", "sensitivity": 1, "crown_jewel": False}),

    # --- credentials ---
    ("vault-role", S.CREDENTIAL, {"name": "vault-role", "kind": "role", "scope": "secrets:read"}),
    ("jira-oauth", S.CREDENTIAL, {"name": "jira-oauth", "kind": "oauth", "scope": "tickets:*"}),
    ("deploy-role", S.CREDENTIAL, {"name": "deploy-role", "kind": "role", "scope": "prod:deploy"}),
    ("db-admin-role", S.CREDENTIAL, {"name": "db-admin-role", "kind": "role", "scope": "db:admin"}),
    ("bedrock-api-key", S.CREDENTIAL, {"name": "bedrock-api-key", "kind": "api_key", "scope": "llm:invoke"}),
    ("s3-readonly-key", S.CREDENTIAL, {"name": "s3-readonly-key", "kind": "api_key", "scope": "s3:read"}),
    ("payments-key", S.CREDENTIAL, {"name": "payments-key", "kind": "api_key", "scope": "billing:write"}),

    # --- tools / MCP servers ---
    ("ticket-tool", S.TOOL, {"name": "ticket-tool", "kind": "mcp", "scopes": ["tickets:read", "tickets:write"]}),
    ("email-tool", S.TOOL, {"name": "email-tool", "kind": "mcp", "scopes": ["email:send"]}),
    ("web-browser-tool", S.TOOL, {"name": "web-browser-tool", "kind": "mcp", "scopes": ["web:fetch"]}),
    ("doc-search-tool", S.TOOL, {"name": "doc-search-tool", "kind": "mcp", "scopes": ["docs:read"]}),
    ("code-exec-tool", S.TOOL, {"name": "code-exec-tool", "kind": "mcp", "scopes": ["code:run"]}),
    ("shell-tool", S.TOOL, {"name": "shell-tool", "kind": "cli", "scopes": ["shell:exec"]}),
    ("secrets-reader", S.TOOL, {"name": "secrets-reader", "kind": "cli", "scopes": ["secrets:read"]}),
    ("deploy-tool", S.TOOL, {"name": "deploy-tool", "kind": "cli", "scopes": ["prod:deploy"]}),
    ("db-query-tool", S.TOOL, {"name": "db-query-tool", "kind": "mcp", "scopes": ["db:query"]}),
    ("backup-tool", S.TOOL, {"name": "backup-tool", "kind": "cli", "scopes": ["db:backup"]}),
    ("billing-tool", S.TOOL, {"name": "billing-tool", "kind": "api", "scopes": ["billing:write"]}),

    # --- agents ---
    ("support-agent", S.AGENT, {"name": "support-agent", "trust": S.TRUST_LOW, "framework": "langgraph", "owner": "Customer Ops"}),
    ("sales-agent", S.AGENT, {"name": "sales-agent", "trust": S.TRUST_LOW, "framework": "crewai", "owner": "Revenue"}),
    ("research-agent", S.AGENT, {"name": "research-agent", "trust": S.TRUST_MEDIUM, "framework": "langgraph", "owner": "Research"}),
    ("data-agent", S.AGENT, {"name": "data-agent", "trust": S.TRUST_MEDIUM, "framework": "llamaindex", "owner": "Data"}),
    ("ops-agent", S.AGENT, {"name": "ops-agent", "trust": S.TRUST_MEDIUM, "framework": "langgraph", "owner": "SRE"}),
    ("deploy-agent", S.AGENT, {"name": "deploy-agent", "trust": S.TRUST_MEDIUM, "framework": "autogen", "owner": "SRE"}),
    ("billing-agent", S.AGENT, {"name": "billing-agent", "trust": S.TRUST_MEDIUM, "framework": "langgraph", "owner": "Finance"}),
    ("admin-agent", S.AGENT, {"name": "admin-agent", "trust": S.TRUST_HIGH, "framework": "langgraph", "owner": "Platform"}),

    # --- data sources (untrusted = attacker entry) ---
    ("untrusted-email", S.DATA_SOURCE, {"name": "untrusted-email", "trusted": False, "kind": "email_inbox"}),
    ("public-webpage", S.DATA_SOURCE, {"name": "public-webpage", "trusted": False, "kind": "web"}),
    ("customer-upload", S.DATA_SOURCE, {"name": "customer-upload", "trusted": False, "kind": "file_upload"}),
    ("internal-kb", S.DATA_SOURCE, {"name": "internal-kb", "trusted": True, "kind": "wiki"}),

    # --- humans ---
    ("alice", S.HUMAN, {"name": "alice", "role": "SRE"}),
    ("bob", S.HUMAN, {"name": "bob", "role": "CTO"}),
]

# ---------------------------------------------------------------------------
# Edges: (src, rel, dst, props)
# ---------------------------------------------------------------------------
E: list[tuple[str, str, str, dict[str, Any]]] = [
    # ===== benign business graph =====
    ("alice", S.OPERATES, "ops-agent", {}),
    ("bob", S.OPERATES, "admin-agent", {}),
    ("internal-kb", S.FEEDS, "support-agent", {}),
    ("internal-kb", S.FEEDS, "research-agent", {}),
    ("billing-agent", S.CAN_INVOKE, "billing-tool", {}),
    ("billing-tool", S.USES, "payments-key", {}),
    ("payments-key", S.GRANTS, "billing-api", {}),
    ("admin-agent", S.HAS_CREDENTIAL, "vault-role", {}),
    ("admin-agent", S.HAS_CREDENTIAL, "db-admin-role", {}),
    ("support-agent", S.CAN_INVOKE, "doc-search-tool", {}),
    ("doc-search-tool", S.HAS_ACCESS, "marketing-assets", {}),
    ("sales-agent", S.CAN_INVOKE, "doc-search-tool", {}),
    ("db-query-tool", S.HAS_ACCESS, "audit-logs", {}),
    ("backup-tool", S.USES, "s3-readonly-key", {}),
    ("backup-tool", S.HAS_ACCESS, "customer-pii-bucket", {}),
    ("s3-readonly-key", S.GRANTS, "customer-pii-bucket", {}),

    # ===== PLANTED ATTACK PATH FAMILY A -> jira-oauth -> vault-role -> vault =====
    ("untrusted-email", S.FEEDS, "support-agent", {}),
    ("support-agent", S.CAN_INVOKE, "ticket-tool", {}),
    ("support-agent", S.CAN_INVOKE, "email-tool", {}),
    ("support-agent", S.DELEGATES, "ops-agent", {}),
    ("ops-agent", S.CAN_INVOKE, "ticket-tool", {}),
    ("ticket-tool", S.USES, "jira-oauth", {}),
    ("email-tool", S.USES, "jira-oauth", {}),
    ("sales-agent", S.CAN_INVOKE, "email-tool", {}),
    ("jira-oauth", S.GRANTS, "vault-role", {}),
    ("vault-role", S.GRANTS, "prod-secrets-vault", {}),

    # ===== PLANTED ATTACK PATH FAMILY B -> secrets-reader -> vault =====
    ("public-webpage", S.FEEDS, "research-agent", {}),
    ("research-agent", S.CAN_INVOKE, "web-browser-tool", {}),
    ("research-agent", S.CAN_INVOKE, "secrets-reader", {}),
    ("web-browser-tool", S.CALLS, "code-exec-tool", {}),
    ("code-exec-tool", S.CALLS, "shell-tool", {}),
    ("shell-tool", S.CALLS, "secrets-reader", {}),
    ("secrets-reader", S.HAS_ACCESS, "prod-secrets-vault", {}),

    # ===== PLANTED ATTACK PATH FAMILY C -> deploy-role -> vault =====
    ("ops-agent", S.CAN_INVOKE, "deploy-tool", {}),
    ("deploy-agent", S.CAN_INVOKE, "deploy-tool", {}),
    ("deploy-tool", S.USES, "deploy-role", {}),
    ("deploy-role", S.GRANTS, "prod-secrets-vault", {}),

    # ===== PLANTED PATH to a SECOND high-sensitivity asset (prod-database) =====
    ("customer-upload", S.FEEDS, "data-agent", {}),
    ("data-agent", S.HAS_CREDENTIAL, "bedrock-api-key", {}),
    ("data-agent", S.CAN_INVOKE, "db-query-tool", {}),
    ("db-query-tool", S.USES, "db-admin-role", {}),
    ("db-admin-role", S.GRANTS, "prod-database", {}),
]


def _cypher_str(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        escaped = (
            value.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n").replace("\r", "\\r")
        )
        return f"'{escaped}'"
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_cypher_str(v) for v in value) + "]"
    raise TypeError(f"Unsupported property type: {type(value)}")


def _props(props: dict[str, Any]) -> str:
    if not props:
        return ""
    inner = ", ".join(f"{k}: {_cypher_str(v)}" for k, v in props.items())
    return " {" + inner + "}"


def reset_graph(db: GraphDB) -> None:
    db.query("MATCH (n) DETACH DELETE n")


def load_spec(
    db: GraphDB,
    nodes: list[tuple[str, str, dict[str, Any]]],
    edges: list[tuple[str, str, str, dict[str, Any]]],
) -> dict[str, int]:
    """(Re)build the graph from an arbitrary node/edge spec. Returns counts.

    Used by the synthetic seed *and* by the real-data ingesters. Edge ``props``
    may override the default ``cap`` / ``cost``.
    """
    reset_graph(db)

    for node_id, label, props in nodes:
        all_props = {"id": node_id, **props, "cap": 1}
        db.query(f"CREATE (n:{label}{_props(all_props)})")

    for src, rel, dst, props in edges:
        all_props = {
            "cap": props.get("cap", 1),
            "cost": props.get("cost", S.REL_COST.get(rel, 1)),
            **props,
        }
        db.query(
            "MATCH (a {id: $src}), (b {id: $dst}) "
            f"CREATE (a)-[:{rel}{_props(all_props)}]->(b)",
            {"src": src, "dst": dst},
        )

    # index for fast lookups by id
    for label in ("Agent", "Resource", "Tool"):
        try:
            db.query(f"CREATE INDEX FOR (n:{label}) ON (n.id)")
        except Exception:
            pass

    return {"nodes": len(nodes), "edges": len(edges)}


def load_graph(db: GraphDB) -> dict[str, int]:
    """(Re)build the synthetic agent-mesh graph. Returns node/edge counts."""
    return load_spec(db, NODES, E)
