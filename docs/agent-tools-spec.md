# Lunes Agent Tools Specification

This document defines the public contract for MCP-compatible agents that inspect
and prepare actions on the Lunes Blockchain.

## Objective

Give agents enough live network context to inspect accounts, reason about
staking, prepare investment workflows, and relay human-signed payloads without
receiving unrestricted wallet authority.

The server must keep the same safety boundary across all tools:

- read tools can query live Lunes Network RPC;
- write tools can prepare payloads or sign local intent payloads after policy
  checks;
- `lunes_transfer_native` can also build, KMS-sign, submit, and track a final
  native transfer when `confirm_broadcast=true`,
  `LUNES_MCP_ENABLE_BROADCAST=1`, `LUNES_MCP_ENABLE_INTERNAL_SIGNING=1`,
  `LUNES_MCP_AUDIT_LOG_PATH`, transfer policy, broadcast policy, active KMS,
  TTL, whitelist, and spend limits all pass;
- externally signed transaction payloads can be submitted only when
  `LUNES_MCP_ENABLE_BROADCAST=1`, their computed signed extrinsic hash is
  present in `LUNES_MCP_ALLOWED_BROADCAST_HASHES`, and the request includes
  `confirm_broadcast=true`; agent policy must also allow
  `author.submit_extrinsic` and whitelist `broadcast`;
- other KMS-built final Lunes Network transaction categories are not enabled in
  this release.
- governance tools are limited to live raw reads and prepare-only payloads for
  human review; they reject broadcast requests and never call the local KMS.

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
| `lunes_get_assets` | Read | List native LUNES and PSP22 contracts, local metadata, and transfer limits exposed by the active agent policy |
| `lunes_get_asset_balance` | Read | Read native LUNES or dry-run PSP22 balance reads for allowlisted token contracts |
| `lunes_get_network_health` | Read | Inspect live peer count, sync status, best/finalized blocks, pending pool size, and RPC surface size |
| `lunes_get_account_overview` | Read | Inspect account nonce, native LUNES balances, spendable amount, and active agent policy |
| `lunes_get_investment_position` | Read | Summarize liquid and reserved/locked LUNES for staking or treasury planning |
| `lunes_get_validator_set` | Read | Read the current validator set from live Lunes Network state |
| `lunes_get_validator_profiles` | Read | Read active-set status, commission, blocked state, and nomination eligibility for validators |
| `lunes_get_validator_scores` | Read | Score validators from observable profile data while marking exposure and reward history as not decoded |
| `lunes_get_staking_overview` | Read | Summarize validator visibility and the staking actions this agent is allowed to prepare |
| `lunes_get_staking_account` | Read | Read bond, ledger, unlocking schedule, reward destination, nominations, and validator preferences for one Lunes account |
| `lunes_get_governance_overview` | Read | Summarize raw referendum storage visibility and prepare-only governance policy |
| `lunes_get_referenda` | Read | Read bounded raw referendum storage entries from live governance state |
| `lunes_get_recent_blocks` | Read | List recent finalized block summaries without returning raw extrinsics |
| `lunes_get_block_events` | Read | Read raw event storage for a block by hash, number, or the finalized head |
| `lunes_search_account_activity` | Read | Search pending transactions and recent finalized blocks for bounded account activity timelines |
| `lunes_submit_signed_extrinsic` | Write | Relay an externally signed Lunes transaction payload, then poll for inclusion/finality |
| `lunes_transfer_native` | Write | Prepare, locally sign, or guarded-broadcast a native LUNES transfer |
| `lunes_transfer_psp22` | Write | Prepare or locally sign a PSP22 transfer after contract/message, recipient, and asset-limit checks |
| `lunes_call_contract` | Write | Prepare generic contract calls; autonomous generic signing is disabled |
| `lunes_stake_rebond` | Write | Prepare or locally sign a staking rebond operation |
| `lunes_stake_payout` | Write | Prepare or locally sign `staking.payout_stakers` for a whitelisted validator stash and era |
| `lunes_prepare_governance_vote` | Prepare | Prepare a human-review governance vote payload without signing or broadcasting |
| `lunes_prepare_governance_remove_vote` | Prepare | Prepare a human-review remove-vote payload without signing or broadcasting |
| `lunes_prepare_governance_delegate` | Prepare | Prepare a human-review governance delegation payload without signing or broadcasting |
| `lunes_prepare_governance_undelegate` | Prepare | Prepare a human-review governance undelegation payload without signing or broadcasting |
| `lunes_read_contract` | Read | Simulate an allowed read-only Lunes contract call through live RPC |
| `lunes_search_contract` | Read | Look up local interface metadata, configured message allowlists, and PSP22 asset policy |

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
- require contract/message allowlists before PSP22 balance dry-runs;
- require PSP22 asset policies with local metadata, `max_transfer_base_units`,
  and `allowed_recipients` before PSP22 transfer signing;
- require contract/message allowlists before contract write preparation;
- cap user-controlled limits such as validator list size and archive lookup
  depth;
- keep block history tools bounded and avoid returning raw extrinsics from block
  summary responses;
- keep write tools behind allowlists, TTL, daily native spend limits, and
  asset-specific PSP22 transfer limits;
- keep governance tools behind dedicated prepare-only policy fields and reject
  `confirm_broadcast=true`;
- never sign governance payloads with the local KMS, even in autonomous mode;
- require `LUNES_MCP_ENABLE_BROADCAST=1`, `confirm_broadcast=true`, and a
  pre-approved signed extrinsic hash before relaying an externally signed
  payload;
- require `author.submit_extrinsic` plus the `broadcast` policy target before
  relaying an externally signed payload;
- require `LUNES_MCP_ENABLE_INTERNAL_SIGNING=1`, persistent audit logging, and
  both transfer and broadcast policy before internally signing and broadcasting
  a native transfer;
- reject unsafe runtime RPC configuration, including public `ws://` endpoints,
  userinfo credentials, query strings, and fragments.

Ask first:

- adding dependencies;
- changing public tool names or response fields;
- enabling additional internal final Lunes Network transaction categories such
  as staking, generic contracts, or governance;
- expanding staking reads into reward payout history, decoded exposure, or
  automated validator selection.

Never:

- commit private keys, API keys, mnemonics, or production configs;
- broadcast transactions from read-only tools;
- construct or sign final network transactions from the local KMS outside the
  audited native transfer path;
- let an agent pick validators outside the configured whitelist for write
  operations.

## Success Criteria

- `tools/list` exposes the read-only tools above.
- `lunes_get_network_health` reads live Lunes Network status.
- `lunes_get_account_overview` returns balance and nonce for a valid Lunes
  address.
- `lunes_get_assets` exposes only native LUNES plus contracts from local policy,
  including configured PSP22 metadata and transfer limits.
- `lunes_get_asset_balance` rejects non-allowlisted PSP22 contracts and returns
  raw live dry-run results for allowed token balances.
- `lunes_get_investment_position` gives agents a conservative liquidity and
  policy summary.
- `lunes_get_validator_set` reads validator addresses from live network state.
- `lunes_get_validator_profiles` returns bounded validator profile and
  nomination eligibility hints without making recommendations.
- `lunes_get_validator_scores` returns a bounded partial score from observable
  validator profile data and explicitly marks exposure/reward history as not
  decoded.
- `lunes_get_staking_overview` combines validator visibility with local policy
  boundaries.
- `lunes_get_staking_account` returns live staking state, including unlocking
  chunks, for bonded, nominator, validator, and idle accounts without signing
  or broadcasting.
- `lunes_get_governance_overview` reports raw referendum visibility and makes
  the prepare-only governance policy explicit.
- `lunes_get_referenda` returns bounded raw referendum storage without
  pretending to decode referendum metadata.
- Governance prepare tools return pending human approval payloads with
  `broadcasted=false`, no transaction hash, and no local KMS signature. Votes
  are bounded by referendum/direction/conviction/amount policy; delegation and
  undelegation are bounded by track/delegate/conviction/amount policy.
- `lunes_get_recent_blocks` returns only block hash, number, and extrinsic count
  for bounded recent finalized block windows.
- `lunes_get_block_events` returns raw event storage for an explicitly selected
  block or finalized head without pretending to decode events.
- `lunes_search_account_activity` caps account activity scans and returns
  pending/finalized timeline entries using an explicit raw account-id substring
  match strategy.
- `lunes_submit_signed_extrinsic` rejects calls without explicit confirmation
  broadcast opt-in, and hash preapproval, and returns hash, status, block
  details, and raw event storage for accepted payloads when the network exposes
  them.
- `lunes_transfer_native` preserves prepare/local-intent responses by default
  and only broadcasts when every internal-signing guardrail passes.
- `lunes_transfer_psp22` rejects transfers without contract/message allowlists,
  an asset-specific base-unit limit, and an allowed recipient; it does not
  consume the native LUNES daily budget for token amounts.
- `lunes_stake_rebond` and `lunes_stake_payout` return policy-bound staking
  payloads without final network submission; payout requires a whitelisted
  validator stash.
- `lunes_read_contract` requires contract message allowlists before live reads.
- `lunes_search_contract` exposes the local interface registry together with
  configured contract/message policy; it does not claim live ABI discovery.
- All verification commands pass before publishing.
