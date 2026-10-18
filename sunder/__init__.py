"""SUNDER — autonomous attack-path remediation for the AI agent mesh.

Given a mesh of AI agents, MCP tools, credentials and data resources, SUNDER
finds every multi-hop privilege-escalation path an attacker could take to reach
a crown-jewel resource, then computes and applies the *minimum* set of
permission edges that severs all of them — and proves it.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
