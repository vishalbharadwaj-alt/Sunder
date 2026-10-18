# SUNDER remediation plan

**Result:** SEALED — attack paths to crown jewels 34 → 0 (re-checked by re-ingesting the patched configs).

- Configs analysed: 2 · MCP servers: 10
- Crown-jewel resources: res:cloud-account, res:database:db.internal/prod, res:fs:/Users/dev/.ssh, res:host-shell, res:source-repos
- ⚠ 7 secret(s) are hard-coded in config files (value never stored by SUNDER; rotate them if these files were shared).
- Entry points: untrusted:claude_desktop:brave-search, untrusted:claude_desktop:fetch, untrusted:claude_desktop:github, untrusted:claude_desktop:slack, untrusted:cursor_mcp:github, untrusted:cursor_mcp:puppeteer
- Minimum cut: 6 edge(s), business cost 30; max-flow 30 proves nothing cheaper exists.
- A fewest-edge cut would use 5 edge(s) but cost 120 — SUNDER minimises business impact, not edge count.

## What to change

1. In `cursor_mcp`: remove the `aws` MCP server (or move it into a separate, unprivileged agent).  _(cost 5, auto-applied in patched config)_
2. In `cursor_mcp`: remove the `github` MCP server (or move it into a separate, unprivileged agent).  _(cost 5, auto-applied in patched config)_
3. In `claude_desktop`: remove the `desktop-commander` MCP server (or move it into a separate, unprivileged agent).  _(cost 5, auto-applied in patched config)_
4. In `claude_desktop`: remove the `postgres` MCP server (or move it into a separate, unprivileged agent).  _(cost 5, auto-applied in patched config)_
5. In `claude_desktop`: remove the `github` MCP server (or move it into a separate, unprivileged agent).  _(cost 5, auto-applied in patched config)_
6. In `claude_desktop`: remove the `filesystem` MCP server (or move it into a separate, unprivileged agent).  _(cost 5, auto-applied in patched config)_

## Config diff

### claude_desktop

```diff
--- a/claude_desktop.json
+++ b/claude_desktop.json
@@ -1,24 +1,5 @@
 {
   "mcpServers": {
-    "filesystem": {
-      "command": "npx",
-      "args": [
-        "-y",
-        "@modelcontextprotocol/server-filesystem",
-        "/Users/dev/projects",
-        "/Users/dev/.ssh"
-      ]
-    },
-    "github": {
-      "command": "npx",
-      "args": [
-        "-y",
-        "@modelcontextprotocol/server-github"
-      ],
-      "env": {
-        "GITHUB_PERSONAL_ACCESS_TOKEN": "<REDACTED>"
-      }
-    },
     "fetch": {
       "command": "uvx",
       "args": [
@@ -35,14 +16,6 @@
         "BRAVE_API_KEY": "<REDACTED>"
       }
     },
-    "postgres": {
-      "command": "npx",
-      "args": [
-        "-y",
-        "@modelcontextprotocol/server-postgres",
-        "<REDACTED>"
-      ]
-    },
     "slack": {
       "command": "npx",
       "args": [
@@ -53,13 +26,6 @@
         "SLACK_BOT_TOKEN": "<REDACTED>",
         "SLACK_TEAM_ID": "T0EXAMPLE"
       }
-    },
-    "desktop-commander": {
-      "command": "npx",
-      "args": [
-        "-y",
-        "@wonderwhy-er/desktop-commander"
-      ]
     }
   }
 }
```

### cursor_mcp

```diff
--- a/cursor_mcp.json
+++ b/cursor_mcp.json
@@ -1,32 +1,11 @@
 {
   "mcpServers": {
-    "github": {
-      "command": "npx",
-      "args": [
-        "-y",
-        "@modelcontextprotocol/server-github"
-      ],
-      "env": {
-        "GITHUB_PERSONAL_ACCESS_TOKEN": "<REDACTED>"
-      }
-    },
     "puppeteer": {
       "command": "npx",
       "args": [
         "-y",
         "@modelcontextprotocol/server-puppeteer"
       ]
-    },
-    "aws": {
-      "command": "uvx",
-      "args": [
-        "aws-mcp-server"
-      ],
-      "env": {
-        "AWS_ACCESS_KEY_ID": "<REDACTED>",
-        "AWS_SECRET_ACCESS_KEY": "<REDACTED>",
-        "AWS_REGION": "ap-south-1"
-      }
     }
   }
 }
```

## Example attack paths (before)

- untrusted:claude_desktop:fetch → agent:claude_desktop → claude_desktop:desktop-commander → res:host-shell → crown-jewels
- untrusted:claude_desktop:brave-search → agent:claude_desktop → claude_desktop:desktop-commander → res:host-shell → crown-jewels
- untrusted:claude_desktop:github → agent:claude_desktop → claude_desktop:filesystem → res:fs:/Users/dev/.ssh → crown-jewels
- untrusted:claude_desktop:slack → agent:claude_desktop → claude_desktop:filesystem → res:fs:/Users/dev/.ssh → crown-jewels
- untrusted:claude_desktop:brave-search → agent:claude_desktop → claude_desktop:filesystem → res:fs:/Users/dev/.ssh → crown-jewels
