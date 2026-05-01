# Lunes MCP Server

[![CI](https://github.com/lunes-platform/Lunes-MCP/actions/workflows/ci.yml/badge.svg)](https://github.com/lunes-platform/Lunes-MCP/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/Rust-1.88%2B-b7410e)
![Transport](https://img.shields.io/badge/MCP-HTTP-2f6fed)
![Status](https://img.shields.io/badge/status-early%20access-f5a623)

<p align="center">
  <img src="assets/lunes-mcp-hero.png" alt="Lunes MCP Server secure gateway" width="100%">
</p>

Secure MCP access to the Lunes Blockchain.

The Lunes Blockchain is the network where LUNES accounts, assets, staking,
validators, contracts, and transaction workflows live. Lunes MCP Server gives
MCP-compatible agents a controlled gateway into that environment: they can read
live chain state, inspect balances and validators, prepare actions for human
review, and relay explicitly approved transactions without receiving unrestricted
wallet authority.

It runs as a small JSON-RPC HTTP service with conservative defaults: localhost
binding, prepare-only mode, API-key protection for public binds, rate limiting,
and policy checks before any local signing path is reached.

The current release is ready for local evaluation, agent integration, and
operator review. It can relay externally signed transaction payloads and can
build, KMS-sign, submit, and track native LUNES transfers only when the operator
enables every broadcast guardrail explicitly.

## Contents

- [Overview](#overview)
- [Agent Capabilities](#agent-capabilities)
- [Use Cases](#use-cases)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Client Setup](#client-setup)
- [Tools](#tools)
- [Specifications](#specifications)
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
| Network status | live metadata, health, native balances, validator set, archive-assisted transaction lookup, guarded relay of externally signed payloads, and guarded native LUNES transfer submission |

### Safety Model

The server is built to fail closed.

- Public bind addresses are refused unless `LUNES_MCP_API_KEY` is configured.
- Empty extrinsic allowlists block all write tools.
- Empty destination whitelists block all write destinations.
- Staking tools require the `staking` policy target in the whitelist; validator and reward-account addresses must also be whitelisted.
- Governance tools are read/prepare-only: they can read bounded referendum storage and prepare human-review vote payloads, but they never sign or broadcast final votes.
- Autonomous signing requires explicit local opt-in with `LUNES_MCP_ALLOW_AUTONOMOUS=1`.
- Broadcasting a human-signed extrinsic requires `LUNES_MCP_ENABLE_BROADCAST=1`, a pre-approved signed payload hash, `confirm_broadcast=true`, and agent policy allowing `author.submit_extrinsic` to the `broadcast` target.
- Broadcasting an internally signed native LUNES transfer additionally requires `LUNES_MCP_ENABLE_INTERNAL_SIGNING=1`, `LUNES_MCP_AUDIT_LOG_PATH`, an active KMS key, `balances.transfer` policy for the recipient, and `author.submit_extrinsic` policy for `broadcast`.
- Read-only contract simulation requires message-level allowlists; autonomous generic contract calls are blocked, and PSP22 transfers require contract/message, recipient, and asset-specific base-unit limits.

## Agent Capabilities

Lunes MCP Server gives connected agents a controlled interface to Lunes Network
workflows. It does not hand over unrestricted wallet access; every write-capable
action passes through explicit server-side policy.

| Capability | What the agent can do |
| --- | --- |
| Account visibility | Read native LUNES balances, nonce, spendable amount, and policy context through live Lunes Network RPC |
| Asset visibility | List native LUNES plus allowlisted PSP22 contracts, local metadata, transfer limits, and dry-run token balance reads through live RPC |
| Network awareness | Read live Lunes Network metadata, health, peers, finality lag, token settings, address format, and runtime version |
| Address safety | Validate Lunes Network SS58 addresses before a transfer or contract action is prepared |
| Transaction awareness | Check pending pool, current heads, recent finalized block summaries, raw block events, and account activity timelines |
| Human-signed transaction submission | Broadcast an externally signed Lunes extrinsic and poll for inclusion/finality when explicitly enabled |
| Native transfer submission | Build, KMS-sign, broadcast, and track a native LUNES transfer when all internal-signing guardrails pass |
| Validator visibility | Read the current validator set and expose bounded samples to agents |
| Validator profiles | Inspect active-set status, commission, blocked state, and nomination eligibility hints |
| Staking account state | Read bond, ledger, unlocking schedule, reward destination, nominations, and validator preferences for a Lunes account |
| Investment planning | Summarize liquid and reserved/locked LUNES for conservative staking or treasury planning |
| Staking management | Prepare bond, unbond, withdraw, nominate, chill, and reward-destination updates |
| Governance visibility | Read bounded raw referendum storage and current prepare-only governance policy |
| Governance preparation | Prepare human-review vote, remove-vote, delegation, and undelegation payloads without MCP signing or broadcast |
| Contract discovery | Look up Lunes contract interface metadata, message allowlists, and local asset policy through the tooling surface |
| Transfer preparation | Build human-reviewable payloads for native LUNES and policy-limited PSP22 transfers |
| Local agent wallet lifecycle | Request creation or revocation of a local agent key |
| Policy-bounded signing | Sign local intent payloads only when autonomous mode, allowlists, TTL, and spend limits permit it |
| Operational visibility | Report health, status, transport metrics, active key state, spend usage, permissions, and audit entries |

The practical result is narrow, auditable agency: an assistant can help prepare,
explain, and route Lunes Network actions without bypassing human control or the
configured permission model.

## Use Cases

- Wallet operations inside agent tools without exposing private keys to the agent.
- Address validation and permission checks before an agent proposes an irreversible action.
- Staking and investment workflows where every operation is bounded by allowlists and review.
- Validator discovery and account liquidity checks before a staking plan is proposed.
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

### Docker

Build the production image locally:

```bash
docker build -t lunes-mcp-server:local .
```

Run it with an API key because container deployments bind to all interfaces:

```bash
docker run --rm -p 9950:9950 \
  -e LUNES_MCP_API_KEY="$(openssl rand -hex 32)" \
  lunes-mcp-server:local
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
allowlist_contracts = {}
ttl_hours = 168

# Optional PSP22 policy:
# [agent.permissions.asset_policies."6contract..."]
# name = "Example Token"
# symbol = "EXT"
# decimals = 12
# max_transfer_base_units = "1000000000000"
# allowed_recipients = ["5recipient..."]

[agent.permissions.governance]
allow_prepare_votes = false
allow_prepare_delegations = false
allowed_referenda = []
allowed_delegation_tracks = []
allowed_delegates = []
allowed_vote_directions = []
allowed_convictions = []
max_vote_lunes = 0
max_delegation_lunes = 0

[server]
bind_address = "127.0.0.1"
port = 9950
rate_limit_per_second = 10
rate_limit_burst = 20
```

For staking workflows, the allowlist should be explicit. Include `staking` in
`whitelisted_addresses`, and include each validator or reward-account address
the agent may use:

```toml
[agent.permissions]
allowed_extrinsics = [
  "staking.bond",
  "staking.unbond",
  "staking.rebond",
  "staking.withdraw_unbonded",
  "staking.nominate",
  "staking.payout_stakers",
  "staking.chill",
  "staking.set_payee"
]
whitelisted_addresses = [
  "staking",
  "6validator_or_reward_account..."
]
daily_limit_lunes = 100
ttl_hours = 168
```

For PSP22 assets, reads and transfers are separated. `allowlist_contracts`
grants methods for a contract, while `asset_policies` supplies local metadata,
a per-transfer token limit in base units, and the recipients allowed for that
token. Metadata is local policy data; it is not automatic on-chain token
metadata discovery.

```toml
[agent.permissions]
allowed_extrinsics = ["contracts.call"]
whitelisted_addresses = ["6psp22_contract..."]
daily_limit_lunes = 1

[agent.permissions.allowlist_contracts]
"6psp22_contract..." = ["PSP22::balance_of", "PSP22::transfer"]

[agent.permissions.asset_policies."6psp22_contract..."]
name = "Example Token"
symbol = "EXT"
decimals = 12
max_transfer_base_units = "1000000000000"
allowed_recipients = ["5recipient..."]
```

For governance workflows, use the dedicated prepare-only policy. This policy
does not authorize final votes or delegations; it only lets the MCP server
build explicit payloads for human review in an external wallet:

```toml
[agent.permissions.governance]
allow_prepare_votes = true
allow_prepare_delegations = true
allowed_referenda = [12]
allowed_delegation_tracks = [0]
allowed_delegates = ["6delegate..."]
allowed_vote_directions = ["aye"]
allowed_convictions = ["locked1x"]
max_vote_lunes = 50
max_delegation_lunes = 25
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
export LUNES_MCP_ALLOW_AUTONOMOUS=1
```

The legacy `LUNES_MCP_ALLOW_AUTONOMOUS_STUB=1` variable is still accepted for
older local setups, but new deployments should use `LUNES_MCP_ALLOW_AUTONOMOUS`.

Broadcasting an extrinsic already signed by an external wallet is separately
gated:

```bash
export LUNES_MCP_ENABLE_BROADCAST=1
export LUNES_MCP_ALLOWED_BROADCAST_HASHES="0x..."
```

Only enable this in an operator-controlled environment. The server computes the
signed payload hash and requires it to be pre-approved in
`LUNES_MCP_ALLOWED_BROADCAST_HASHES`. Agent policy must also include
`author.submit_extrinsic` in `allowed_extrinsics` and `broadcast` in
`whitelisted_addresses`. The relay still does not decode or verify the contents
of a raw signed payload before submitting it.

Internally signed native LUNES transfer broadcast is narrower and has an extra
gate:

```bash
export LUNES_MCP_ENABLE_BROADCAST=1
export LUNES_MCP_ENABLE_INTERNAL_SIGNING=1
export LUNES_MCP_AUDIT_LOG_PATH="/var/log/lunes-mcp/audit.jsonl"
```

The request must include `confirm_broadcast=true`. Agent policy must allow
`balances.transfer` to the recipient address and `author.submit_extrinsic` to
the synthetic `broadcast` target. The response returns transaction hash,
final status, block details, raw event storage when available, and `final_error`
when the transaction finalizes with a runtime dispatch failure.

Optional persistent audit logging can be enabled with:

```bash
export LUNES_MCP_AUDIT_LOG_PATH="/var/log/lunes-mcp/audit.jsonl"
```

Each JSONL entry stores action metadata, destination, result, and a payload hash;
raw signing payload bytes are not written to the log. When this path is
configured, successful local KMS signing fails closed if the persistent audit
entry cannot be written.

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
| `lunes_get_balance` | Read | Reads native LUNES balance data or delegates allowlisted PSP22 balance checks to the asset balance tool |
| `lunes_get_assets` | Read | Lists native LUNES plus PSP22 contracts allowed by local policy, including configured metadata and transfer limits |
| `lunes_get_asset_balance` | Read | Reads native LUNES balances or dry-runs `PSP22::balance_of` for an allowlisted contract |
| `lunes_get_network_health` | Read | Reads live peer count, sync status, head/finality lag, pending pool size, and RPC surface size |
| `lunes_get_account_overview` | Read | Reads account nonce, native balances, spendable amount, and active agent policy |
| `lunes_get_investment_position` | Read | Summarizes liquid and reserved/locked LUNES for staking or treasury planning |
| `lunes_get_validator_set` | Read | Reads the current validator set from live Lunes Network state |
| `lunes_get_staking_overview` | Read | Summarizes validator visibility and the staking actions this agent is allowed to prepare |
| `lunes_get_validator_profiles` | Read | Reads validator active-set status, commission, blocked state, and nomination eligibility |
| `lunes_get_validator_scores` | Read | Scores validators from observable profile data; exposure and reward history are explicitly marked as not decoded |
| `lunes_get_staking_account` | Read | Reads live staking state for one account, including bond, ledger, unlocking schedule, rewards destination, nominations, and validator preferences when present |
| `lunes_get_governance_overview` | Read | Summarizes raw referendum visibility and prepare-only governance policy |
| `lunes_get_referenda` | Read | Reads bounded raw referendum storage entries from live Lunes governance state |
| `lunes_get_chain_info` | Read | Reads live Lunes Network metadata, token settings, address format, and runtime version |
| `lunes_validate_address` | Read | Validates that an address uses the Lunes Network SS58 format |
| `lunes_get_permissions` | Read | Summarizes the active agent mode, guardrails, and allowed write scope |
| `lunes_get_transaction_status` | Read | Checks pending pool, current heads, and archive endpoint for a transaction hash; `archive_lookback_blocks` can widen the bounded archive search |
| `lunes_submit_signed_extrinsic` | Write | Broadcasts an externally signed Lunes extrinsic when env opt-in, signed hash preapproval, `confirm_broadcast=true`, and `author.submit_extrinsic` -> `broadcast` policy all pass, then polls for inclusion/finality |
| `lunes_get_recent_blocks` | Read | Lists recent finalized block summaries without returning raw extrinsics |
| `lunes_get_block_events` | Read | Reads raw event storage for a block by hash, number, or finalized head |
| `lunes_search_account_activity` | Read | Searches pending transactions and recent finalized blocks for bounded account activity, including timeline entries |
| `lunes_read_contract` | Read | Simulates a read-only Lunes contract call through live RPC when allowed by contract message policy |
| `lunes_search_contract` | Read | Looks up Lunes contract interface metadata plus configured message allowlists and local PSP22 policy |
| `lunes_transfer_native` | Write | Prepares, locally signs, or guarded-broadcasts a native LUNES transfer |
| `lunes_transfer_psp22` | Write | Prepares or signs a PSP22 transfer only when contract/message, recipient, and asset-specific base-unit limits pass |
| `lunes_call_contract` | Write | Prepares a Lunes contract call; autonomous generic calls are blocked in favor of specialized policy-checked tools |
| `lunes_stake_bond` | Write | Prepares or signs a staking bond operation |
| `lunes_stake_unbond` | Write | Prepares or signs a staking unbond operation |
| `lunes_stake_rebond` | Write | Prepares or signs a staking rebond operation |
| `lunes_stake_withdraw_unbonded` | Write | Prepares or signs withdrawal of unlocked staking funds |
| `lunes_stake_nominate` | Write | Prepares or signs validator nominations |
| `lunes_stake_payout` | Write | Prepares or signs `staking.payout_stakers` for a whitelisted validator stash and era |
| `lunes_stake_chill` | Write | Prepares or signs a pause of active nominations |
| `lunes_stake_set_payee` | Write | Prepares or signs staking reward destination updates |
| `lunes_prepare_governance_vote` | Prepare | Builds a human-review governance vote payload without signing or broadcasting |
| `lunes_prepare_governance_remove_vote` | Prepare | Builds a human-review remove-vote payload without signing or broadcasting |
| `lunes_prepare_governance_delegate` | Prepare | Builds a human-review governance delegation payload without signing or broadcasting |
| `lunes_prepare_governance_undelegate` | Prepare | Builds a human-review governance undelegation payload without signing or broadcasting |
| `lunes_provision_agent_wallet` | Lifecycle | Creates a local agent key for approval |
| `lunes_revoke_agent_wallet` | Lifecycle | Revokes the current local agent key |

Write tools are checked against policy before signing. Local intent-signing
responses still include `broadcasted: false`. Native LUNES transfer is the only
KMS-built final transaction path currently enabled, and only with the internal
signing guardrails above. `lunes_submit_signed_extrinsic` remains the relay path
for payloads that were already signed outside this server. Contract write tools
require explicit contract/message allowlists; an empty method list does not
grant wildcard contract access. Governance prepare tools are stricter: they
never sign in autonomous mode, reject `confirm_broadcast=true`, and require
dedicated policy fields before returning a pending approval payload. Vote
preparation is bounded by referendum, direction, conviction, and amount;
delegation preparation is bounded by track, delegate, conviction, and amount.

## Specifications

The public tool contract for agent-facing Lunes Network reads is documented in
[`docs/agent-tools-spec.md`](docs/agent-tools-spec.md).

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

### Metrics

```bash
curl -s http://127.0.0.1:9950 \
  -H 'content-type: application/json' \
  -H "Authorization: Bearer $LUNES_MCP_API_KEY" \
  -d '{"jsonrpc":"2.0","id":3,"method":"mcp_metrics","params":{}}'
```

`mcp_metrics` reports transport accept/reject counters, rate-limit settings,
KMS audit count, spend usage, and basic network configuration without exposing
API keys, payload bytes, or raw audit entries.

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
- Treat autonomous signing as experimental and enable internal native transfer broadcast only in operator-controlled environments.
- Review `agent_config.toml` carefully before enabling any write tool.
- Pre-approve only exact signed extrinsic hashes for relay, and rotate the
  allowlist after use.
- Set `LUNES_MCP_AUDIT_LOG_PATH` to an append-only location owned by the server
  user when persistent audit retention is required.
