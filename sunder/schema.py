"""The agent-mesh graph schema.

Nodes model an enterprise's AI agent deployment; directed edges model the
*capabilities* an attacker could chain together.

    Agent   --CAN_INVOKE-->  Tool        --HAS_ACCESS-->  Resource
    Tool    --USES-------->  Credential  --GRANTS------>  Resource
    Agent   --HAS_CREDENTIAL-> Credential
    Agent   --DELEGATES-----> Agent
    Tool    --CALLS---------> Tool
    DataSource --FEEDS------> Agent        (untrusted input => injection entry)
    Human   --OPERATES------> Agent

Every edge carries a numeric ``cap`` (capacity) so the flow/min-cut layer can
reason about how many independent paths an edge represents, and a ``cost`` — the
business impact of revoking that edge — so SUNDER can minimise remediation cost.
"""
from __future__ import annotations

# Node labels
AGENT = "Agent"
TOOL = "Tool"
RESOURCE = "Resource"
CREDENTIAL = "Credential"
DATA_SOURCE = "DataSource"
HUMAN = "Human"

NODE_LABELS = [AGENT, TOOL, RESOURCE, CREDENTIAL, DATA_SOURCE, HUMAN]

# Relationship types
CAN_INVOKE = "CAN_INVOKE"      # Agent -> Tool
HAS_ACCESS = "HAS_ACCESS"      # Tool   -> Resource
USES = "USES"                  # Tool   -> Credential
GRANTS = "GRANTS"              # Credential -> Resource
HAS_CREDENTIAL = "HAS_CREDENTIAL"  # Agent -> Credential
DELEGATES = "DELEGATES"        # Agent -> Agent
CALLS = "CALLS"                # Tool -> Tool
FEEDS = "FEEDS"                # DataSource -> Agent
OPERATES = "OPERATES"          # Human -> Agent

REL_TYPES = [
    CAN_INVOKE,
    HAS_ACCESS,
    USES,
    GRANTS,
    HAS_CREDENTIAL,
    DELEGATES,
    CALLS,
    FEEDS,
    OPERATES,
]

# Edges that represent an attacker-usable capability (used for path finding).
CAPABILITY_EDGES = [
    FEEDS,
    CAN_INVOKE,
    CALLS,
    DELEGATES,
    HAS_CREDENTIAL,
    USES,
    HAS_ACCESS,
    GRANTS,
]

# Business-impact cost of *revoking* one edge (the price of remediation).
# Cheapest fixes first: cutting an untrusted input or a role grant is a config
# change; cutting CAN_INVOKE breaks a working agent↔tool integration, so it
# costs more. The cost-aware min-cut minimises total business impact, not merely
# the number of edges removed.
REL_COST = {
    FEEDS: 1,           # quarantine an untrusted data source
    GRANTS: 1,          # revoke a role/permission grant
    HAS_ACCESS: 1,      # drop a resource access binding
    USES: 3,            # detach a tool from its credential
    DELEGATES: 4,       # break agent-to-agent delegation
    CAN_INVOKE: 5,      # break an agent's ability to call a tool
    CALLS: 5,           # break tool-to-tool chaining
    HAS_CREDENTIAL: 6,  # strip an agent's credential
    OPERATES: 9,        # (not a capability edge) disturb human ownership
}

# Trust tiers
TRUST_HIGH = "high"
TRUST_MEDIUM = "medium"
TRUST_LOW = "low"
