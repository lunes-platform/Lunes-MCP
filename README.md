# Lunes MCP Server

[![CI](https://github.com/lunes-platform/Lunes-MCP/actions/workflows/ci.yml/badge.svg)](https://github.com/lunes-platform/Lunes-MCP/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/Rust-1.85%2B-b7410e)
![Transport](https://img.shields.io/badge/MCP-HTTP-2f6fed)
![Status](https://img.shields.io/badge/status-early%20access-f5a623)

<p align="center">
  <img src="assets/lunes-mcp-hero.png" alt="Lunes MCP Server secure gateway" width="100%">
</p>

Secure MCP access to Lunes Network tooling.

Lunes MCP Server is a local-first gateway that exposes Lunes account, transaction,
wallet delegation, and transaction preparation tools to MCP-compatible agents.
It runs as a small JSON-RPC HTTP service with conservative defaults: localhost
binding, prepare-only mode, API-key protection for public binds, rate limiting,
and policy checks before any local signing path is reached.

The current release is ready for local evaluation, agent integration, and
operator review. It does not yet broadcast final Lunes Network transactions.

## Contents

- [Overview](#overview)
- [Agent Capabilities](#agent-capabilities)
- [Use Cases](#use-cases)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Client Setup](#client-setup)
- [Tools](#tools)
- [Operations](#operations)
- [Development](#development)
- [Security](#security)

## Overview

| Area | Details |
| --- | --- |
| Protocol | MCP-style `initialize`, `tools/list`, and `tools/call` over JSON-RPC HTTP |
| Default bind | `127.0.0.1:9950` |
| Default mode | `prepare_only` |
| Authentication | `Authorization: Bearer <token>` or `x-lunes-mcp-api-key: <token>` |
| Guardrails | allowed extrinsics, destination whitelist, TTL, daily spend limit |
| Runtime checks | request size limit, response size limit, connection cap, rate limiting |
| Network status | local intent signing only; Lunes Network submission is not enabled yet |

### Safety Model

The server is built to fail closed.

- Public bind addresses are refused unless `LUNES_MCP_API_KEY` is configured.
- Empty extrinsic allowlists block all write tools.
- Empty destination whitelists block all write destinations.
- Autonomous signing requires explicit local opt-in with `LUNES_MCP_ALLOW_AUTONOMOUS_STUB=1`.
- Contract calls in autonomous mode remain disabled until message-level allowlists are available.

## Agent Capabilities

Lunes MCP Server gives connected agents a controlled interface to Lunes Network
workflows. It does not hand over unrestricted wallet access; every write-capable
action passes through explicit server-side policy.

| Capability | What the agent can do |
| --- | --- |
| Account visibility | Read LUNES and PSP22 balance information for approved workflows |
| Network awareness | Read live Lunes Network metadata, token settings, address format, and runtime version |
| Address safety | Validate Lunes Network SS58 addresses before a transfer or contract action is prepared |
| Transaction awareness | Check transaction status and return structured information to the user |
| Contract discovery | Look up ink! contract metadata through the Lunes tooling surface |
| Transfer preparation | Build human-reviewable payloads for native LUNES and PSP22 transfers |
| Local agent wallet lifecycle | Request creation or revocation of a local agent key |
| Policy-bounded signing | Sign local intent payloads only when autonomous mode, allowlists, TTL, and spend limits permit it |
| Operational visibility | Report health, status, active key state, spend usage, permissions, and audit entries |

The practical result is narrow, auditable agency: an assistant can help prepare,
explain, and route Lunes Network actions without bypassing human control or the
configured permission model.

## Use Cases

- Wallet operations inside agent tools without exposing private keys to the agent.
- Address validation and permission checks before an agent proposes an irreversible action.
- Human-reviewed transfer preparation for support, treasury, or operations teams.
- Read-only account and transaction assistance in Claude Code, Codex, Cursor, Windsurf, and similar environments.
- Bounded local automation for test flows where destination, extrinsic, TTL, and spend limits are explicitly configured.
- Operator dashboards or internal tools that need a small HTTP gateway for Lunes Network status and agent-wallet state.

## Quick Start

```bash
git clone https://github.com/lunes-platform/Lunes-MCP.git
cd Lunes-MCP
cargo run --release
```

The server listens on:

```text
http://127.0.0.1:9950
```

Check readiness:

```bash
curl -s http://127.0.0.1:9950 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"mcp_health","params":{}}'
```

Expected response shape:

```json
{
  "jsonrpc": "2.0",
  "result": {
    "status": "ok",
    "server": "lunes-mcp-server"
  },
  "id": 1
}
```

## Configuration

Edit `agent_config.toml` before exposing write-capable tools.

The checked-in configuration is intentionally restrictive:

```toml
[agent.wallet]
mode = "prepare_only"

[agent.permissions]
allowed_extrinsics = []
whitelisted_addresses = []
daily_limit_lunes = 0
ttl_hours = 168

[server]
bind_address = "127.0.0.1"
port = 9950
rate_limit_per_second = 10
rate_limit_burst = 20
```

For a protected remote or container deployment:

```bash
export LUNES_MCP_BIND="0.0.0.0:9950"
export LUNES_MCP_API_KEY="$(openssl rand -hex 32)"
cargo run --release
```

Send the token with either header:

```text
Authorization: Bearer <token>
x-lunes-mcp-api-key: <token>
```

Autonomous signing is intentionally gated:

```bash
export LUNES_MCP_ALLOW_AUTONOMOUS_STUB=1
```

Use that flag only for local stub testing. Production autonomous execution needs
real Lunes Network transaction construction, signing, submission, and finality
tracking.

## Client Setup

Start Lunes MCP Server first, then connect your client to the HTTP endpoint.
For local development without `LUNES_MCP_API_KEY`, omit the `headers` block.

| Client | Configuration style |
| --- | --- |
| Claude Code | `claude mcp add-json` |
| Codex | `codex mcp add` or MCP config |
| Cursor | `.cursor/mcp.json` or `~/.cursor/mcp.json` |
| OpenClaw | `openclaw mcp set` |
| Hermes Agent | `~/.hermes/config.yaml` |
| Windsurf | Cascade MCP raw config |
| Google Antigravity | MCP manager raw config |
| Claude Cowork | Connectors, developer settings, or managed remote MCP |

### Claude Code

```bash
claude mcp add-json lunes '{
  "type": "http",
  "url": "http://127.0.0.1:9950",
  "headers": {
    "Authorization": "Bearer '"$LUNES_MCP_API_KEY"'"
  }
}'

claude mcp list
```

Run `/mcp` inside Claude Code to confirm the connection.

### Codex

```bash
codex mcp add lunes --url http://127.0.0.1:9950
codex mcp list
```

For protected deployments, add the same authorization header in your Codex MCP
configuration or keep the server bound to localhost.

### Cursor

Create `.cursor/mcp.json` in the project or `~/.cursor/mcp.json` globally:

```json
{
  "mcpServers": {
    "lunes": {
      "url": "http://127.0.0.1:9950",
      "headers": {
        "Authorization": "Bearer ${env:LUNES_MCP_API_KEY}"
      }
    }
  }
}
```

Restart Cursor and enable the tools from Agent mode.

### OpenClaw

```bash
openclaw mcp set lunes '{
  "url": "http://127.0.0.1:9950",
  "headers": {
    "Authorization": "Bearer '"$LUNES_MCP_API_KEY"'"
  }
}'

openclaw mcp list
```

### Hermes Agent

Add the server to `~/.hermes/config.yaml`:

```yaml
mcp_servers:
  lunes:
    url: "http://127.0.0.1:9950"
    headers:
      Authorization: "Bearer ${LUNES_MCP_API_KEY}"
```

Hermes exposes MCP tools with a server prefix, for example
`mcp_lunes_lunes_get_chain_info` or `mcp_lunes_lunes_get_balance`.

### Windsurf

Open Windsurf settings, go to Cascade MCP servers, and edit the raw config:

```json
{
  "mcpServers": {
    "lunes": {
      "serverUrl": "http://127.0.0.1:9950",
      "headers": {
        "Authorization": "Bearer ${env:LUNES_MCP_API_KEY}"
      }
    }
  }
}
```

Refresh MCP servers after saving.

### Google Antigravity

Open the MCP manager, choose raw configuration, and add:

```json
{
  "mcpServers": {
    "lunes": {
      "url": "http://127.0.0.1:9950",
      "headers": {
        "Authorization": "Bearer ${env:LUNES_MCP_API_KEY}"
      }
    }
  }
}
```

Restart the agent session after updating the config.

### Claude Cowork

For individual use, add Lunes through the connector or developer settings where
local MCP servers are enabled.

For managed deployments, configure it as a remote MCP server:

```json
[
  {
    "name": "lunes",
    "url": "https://your-gateway.example.com",
    "headers": {
      "Authorization": "Bearer <managed-token>"
    },
    "toolPolicy": {
      "lunes_get_balance": "allow",
      "lunes_transfer_native": "ask",
      "lunes_revoke_agent_wallet": "blocked"
    }
  }
]
```

### Other MCP Clients

Use these connection details:

```text
Transport: HTTP
URL:       http://127.0.0.1:9950
Header:    Authorization: Bearer <token>
```

If a client only supports stdio servers, run Lunes MCP through an HTTP bridge or
use a client with HTTP MCP transport support.

## Tools

| Tool | Type | Description |
| --- | --- | --- |
| `lunes_get_balance` | Read | Reads native LUNES or PSP22 balance data |
| `lunes_get_chain_info` | Read | Reads live Lunes Network metadata, token settings, address format, and runtime version |
| `lunes_validate_address` | Read | Validates that an address uses the Lunes Network SS58 format |
| `lunes_get_permissions` | Read | Summarizes the active agent mode, guardrails, and allowed write scope |
| `lunes_get_transaction_status` | Read | Reads transaction status by hash |
| `lunes_search_contract` | Read | Looks up ink! contract metadata |
| `lunes_transfer_native` | Write | Prepares or signs a native LUNES transfer |
| `lunes_transfer_psp22` | Write | Prepares or signs a PSP22 transfer |
| `lunes_call_contract` | Write | Prepares or signs an ink! contract call |
| `lunes_provision_agent_wallet` | Lifecycle | Creates a local agent key for approval |
| `lunes_revoke_agent_wallet` | Lifecycle | Revokes the current local agent key |

Write tools are checked against policy before signing. Responses include
`broadcasted: false` until Lunes Network submission is implemented.

## Operations

### Health

```bash
curl -s http://127.0.0.1:9950 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"mcp_health","params":{}}'
```

### Status

```bash
curl -s http://127.0.0.1:9950 \
  -H 'content-type: application/json' \
  -H "Authorization: Bearer $LUNES_MCP_API_KEY" \
  -d '{"jsonrpc":"2.0","id":2,"method":"mcp_status","params":{}}'
```

### Public Exposure Checklist

Before binding to `0.0.0.0`:

- Set a strong `LUNES_MCP_API_KEY`.
- Terminate TLS at a reverse proxy or ingress.
- Keep production config files outside the repository.
- Use explicit destination whitelists for every write-capable setup.
- Keep autonomous mode disabled outside controlled local testing.

## Development

```bash
cargo fmt --check
cargo check --locked
cargo test --locked
cargo clippy --all-targets -- -D warnings
```

Security checks:

```bash
cargo audit
cargo deny check
```

The GitHub Actions workflow runs format, check, tests, clippy, audit, and
dependency policy checks on pushes and pull requests.

## Security

Read [SECURITY.md](SECURITY.md) before deploying outside localhost.

Key points:

- Keep `LUNES_MCP_API_KEY` out of source control.
- Do not expose the server publicly without authentication and TLS termination.
- Treat autonomous signing as experimental until real Lunes Network submission is complete.
- Review `agent_config.toml` carefully before enabling any write tool.
