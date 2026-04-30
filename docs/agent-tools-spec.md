# Lunes Agent Tools Specification

This document defines the public contract for the read-only Lunes Network tools
used by MCP-compatible agents.

## Objective

Give agents enough live network context to inspect accounts, reason about
staking, and prepare investment workflows without receiving unrestricted wallet
authority.

The server must keep the same safety boundary across all tools:

- read tools can query live Lunes Network RPC;
- write tools can only prepare payloads or sign local intent payloads after
  policy checks;
- final Lunes Network transaction construction, submission, and finality
  tracking are not enabled in this release.

## Commands

```bash
cargo fmt --check
cargo test --locked
cargo clippy --all-targets -- -D warnings
cargo audit
cargo deny check
```

Local manual verification:

```bash
LUNES_MCP_BIND=127.0.0.1:9964 cargo run
curl -s http://127.0.0.1:9964 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

## Tool Contracts

| Tool | Access | Purpose |
| --- | --- | --- |
| `lunes_get_network_health` | Read | Inspect live peer count, sync status, best/finalized blocks, pending pool size, and RPC surface size |
| `lunes_get_account_overview` | Read | Inspect account nonce, native LUNES balances, spendable amount, and active agent policy |
| `lunes_get_investment_position` | Read | Summarize liquid and reserved/locked LUNES for staking or treasury planning |
| `lunes_get_validator_set` | Read | Read the current validator set from live Lunes Network state |
| `lunes_get_validator_profiles` | Read | Read active-set status, commission, blocked state, and nomination eligibility for validators |
| `lunes_get_staking_overview` | Read | Summarize validator visibility and the staking actions this agent is allowed to prepare |
| `lunes_get_staking_account` | Read | Read bond, ledger, unlocking schedule, reward destination, nominations, and validator preferences for one Lunes account |
| `lunes_search_account_activity` | Read | Search pending transactions and recent finalized blocks for bounded account activity |
| `lunes_read_contract` | Read | Simulate an allowed read-only Lunes contract call through live RPC |

## Project Structure

```text
src/lunes_client.rs  Live Lunes Network RPC client and state decoding helpers
src/tools.rs         MCP tool schemas, validation, and response formatting
README.md            User-facing setup and tool documentation
SECURITY.md          Security model and current limitations
docs/                Public technical specifications
tests/               HTTP integration tests
```

## Code Style

Read tools return MCP-compatible content blocks whose text is pretty JSON:

```json
{
  "content": [
    {
      "type": "text",
      "text": "{...}"
    }
  ],
  "isError": false
}
```

Handlers validate input at the boundary and map RPC or decoding failures to
tool errors with `isError: true`.

## Testing Strategy

- Unit tests cover tool response shape, policy summaries, validator limit
  handling, contract guardrails, account activity caps, and low-level state
  decoding.
- Existing HTTP integration tests continue to cover authentication and rate
  limiting.
- Manual RPC checks verify the server can query the public Lunes endpoints.

## Boundaries

Always:

- validate SS58 addresses before account-specific reads;
- keep read-only tools free of signing or budget mutation;
- cap user-controlled limits such as validator list size and archive lookup
  depth;
- keep write tools behind allowlists, TTL, and daily spend limits.

Ask first:

- adding dependencies;
- changing public tool names or response fields;
- enabling final Lunes Network transaction submission;
- expanding staking reads into reward payout history, performance scoring, or
  automated validator selection.

Never:

- commit private keys, API keys, mnemonics, or production configs;
- broadcast transactions from these read-only tools;
- let an agent pick validators outside the configured whitelist for write
  operations.

## Success Criteria

- `tools/list` exposes the read-only tools above.
- `lunes_get_network_health` reads live Lunes Network status.
- `lunes_get_account_overview` returns balance and nonce for a valid Lunes
  address.
- `lunes_get_investment_position` gives agents a conservative liquidity and
  policy summary.
- `lunes_get_validator_set` reads validator addresses from live network state.
- `lunes_get_validator_profiles` returns bounded validator profile and
  nomination eligibility hints without making recommendations.
- `lunes_get_staking_overview` combines validator visibility with local policy
  boundaries.
- `lunes_get_staking_account` returns live staking state, including unlocking
  chunks, for bonded, nominator, validator, and idle accounts without signing
  or broadcasting.
- `lunes_search_account_activity` caps account activity scans.
- `lunes_read_contract` requires contract message allowlists before live reads.
- All verification commands pass before publishing.
