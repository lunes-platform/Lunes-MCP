# Lunes MCP Server

Lunes MCP Server is a local-first Model Context Protocol gateway for Lunes Network tooling.
It exposes Lunes account, transaction, wallet delegation, and transaction-preparation tools
to MCP-compatible agents through a small JSON-RPC HTTP service.

The server is designed to be conservative by default. It starts in read/prepare mode, binds
to localhost, rejects public exposure without an API key, and does not broadcast blockchain
transactions until a real Substrate client is wired in.

## What It Provides

- MCP-compatible tool discovery through `initialize`, `tools/list`, and `tools/call`
- Local KMS lifecycle for an agent wallet key
- Safe transaction preparation for human review
- Guardrails for allowed extrinsics, destination whitelists, TTL, and daily spend
- HTTP API key authentication for protected deployments
- Request rate limiting and request/response size limits
- Health and status endpoints for operators

## Current Status

This repository is ready for local evaluation and agent integration work.

Autonomous on-chain execution is intentionally disabled unless explicitly enabled for local
stub testing. The current implementation signs local intent payloads only; it does not yet
submit SCALE-encoded Substrate extrinsics to Lunes.

## Requirements

- Rust 1.85 or newer
- A local checkout of this repository
- An MCP client that supports HTTP MCP servers

## Quick Start

```bash
git clone https://github.com/lunes-platform/Lunes-MCP.git
cd Lunes-MCP
cargo run --release
```

The default server listens on:

```text
http://127.0.0.1:9950
```

Check that it is running:

```bash
curl -s http://127.0.0.1:9950 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"mcp_health","params":{}}'
```

## Configuration

Edit `agent_config.toml` before starting the server.

The default file is safe:

- `mode = "prepare_only"`
- no write extrinsics are allowed
- no destination addresses are whitelisted
- daily spend is zero
- bind address is `127.0.0.1`

For a protected HTTP deployment:

```bash
export LUNES_MCP_BIND="0.0.0.0:9950"
export LUNES_MCP_API_KEY="$(openssl rand -hex 32)"
cargo run --release
```

Requests can authenticate with either header:

```text
Authorization: Bearer <token>
x-lunes-mcp-api-key: <token>
```

Autonomous signing is blocked unless this environment variable is present:

```bash
export LUNES_MCP_ALLOW_AUTONOMOUS_STUB=1
```

Use that only for local testing. Production autonomous execution requires real Substrate
transaction construction, signing, submission, and finality tracking.

## MCP Client Setup

Start the server first, then connect your client to the HTTP endpoint. For local development
without `LUNES_MCP_API_KEY`, omit the headers shown below.

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

Inside Claude Code, run `/mcp` to confirm the server is connected.

### Codex

```bash
codex mcp add lunes --url http://127.0.0.1:9950
codex mcp list
```

For protected remote deployments, configure the same URL and authorization header in your
Codex MCP configuration, or keep the server bound to localhost and let Codex connect locally.

### Cursor

Create `.cursor/mcp.json` in your project or `~/.cursor/mcp.json` globally:

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

Then restart Cursor and check the MCP tools list in Agent mode.

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

Hermes registers MCP tools with a server prefix, for example `mcp_lunes_lunes_get_balance`.

### Windsurf

Open Windsurf Settings, go to Cascade MCP Servers, and edit the raw MCP config:

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

Open the MCP manager, choose the raw config view, and add:

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

For individual desktop use, add Lunes from the Connectors or Developer settings where local
MCP servers are enabled.

For managed deployments, provision it as a remote MCP server:

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

Use the same connection details:

```text
Transport: HTTP
URL:       http://127.0.0.1:9950
Header:    Authorization: Bearer <token>
```

If your client only supports stdio servers, run Lunes MCP behind a local MCP HTTP bridge or keep
the server running separately and connect through a client that supports HTTP transport.

## Available Tools

- `lunes_get_balance`
- `lunes_get_transaction_status`
- `lunes_search_contract`
- `lunes_transfer_native`
- `lunes_transfer_psp22`
- `lunes_call_contract`
- `lunes_provision_agent_wallet`
- `lunes_revoke_agent_wallet`

Write tools are policy-checked before any local signing happens. The server returns
`broadcasted: false` until real chain submission is implemented.

## Operations

Health:

```bash
curl -s http://127.0.0.1:9950 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"mcp_health","params":{}}'
```

Status:

```bash
curl -s http://127.0.0.1:9950 \
  -H 'content-type: application/json' \
  -H "Authorization: Bearer $LUNES_MCP_API_KEY" \
  -d '{"jsonrpc":"2.0","id":2,"method":"mcp_status","params":{}}'
```

## Development

```bash
cargo fmt --check
cargo check --locked
cargo test --locked
cargo clippy --all-targets -- -D warnings
```

Optional security checks:

```bash
cargo audit
cargo deny check
```

## Security Notes

- Keep `LUNES_MCP_API_KEY` out of source control.
- Do not expose the server publicly without TLS termination and authentication.
- Keep production configs outside the repository.
- Use destination whitelists for every write-capable agent configuration.
- Treat autonomous mode as experimental until real Lunes chain submission is complete.
