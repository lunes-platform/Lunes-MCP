# Spec: Lunes Network MCP Write Integration

## Objective
Implement the MCP server as a guarded Lunes Network gateway that can read live state, prepare writes, and, when explicitly authorized, build, sign, submit, and track real network transactions.

The first implementation slice is native LUNES transfer finalization through `lunes_transfer_native`. Existing prepare-only and local-intent signing behavior must remain available when live broadcast guardrails are not satisfied.

The next safe slice is governance visibility and preparation: read bounded raw
referendum storage, expose the explicit governance policy, and prepare vote,
remove-vote, delegation, and undelegation payloads for human review without
local signing or broadcast.

The current staking slice adds policy-bound rebond and payout preparation plus
partial validator scoring from observable profile data. It does not decode
validator exposure, reward payout history, or choose validators automatically.

## Tech Stack
- Rust 1.88, Tokio async runtime, jsonrpsee HTTP/WebSocket RPC.
- `ed25519-dalek` remains the local KMS signer.
- `subxt` is used for dynamic transaction construction from live runtime metadata.
- MCP results remain JSON text blocks in the existing `McpToolResult` shape.

## Commands
- Format: `cargo fmt --check`
- Unit and integration tests: `cargo test --locked`
- Lint: `cargo clippy --all-targets -- -D warnings`
- Release build: `cargo build --release --locked`
- Docker build: `docker --context lima-docker-ubuntu22 build -t lunes-mcp-server:local .`

## Project Structure
- `src/tools.rs` owns MCP argument validation, policy checks, guardrails, and response shape.
- `src/lunes_client.rs` owns Lunes RPC access, transaction submission, chain lookups, and dynamic transaction construction.
- `src/kms.rs` owns key lifecycle, signing, spend accounting, and audit logging.
- `src/config.rs` owns runtime safety validation.
- `docs/` contains public specs and operational documentation.
- `tests/` contains HTTP-level integration tests.

## Code Style
Keep network-specific logic out of tool handlers when it can live in `LunesClient`; keep security policy decisions visible at the tool boundary.

```rust
if !confirm_broadcast {
    return Ok(LocalIntent);
}
require_env_opt_in()?;
kms.preflight_write("balances.transfer", to, amount_lunes)?;
kms.preflight_write("author.submit_extrinsic", "broadcast", 0)?;
```

Use typed structs for internal chain results. Keep `serde_json::Value` only at MCP and raw RPC boundaries.

## Testing Strategy
- Unit tests for argument conversion, guardrails, policy denial, and response shape.
- Static client fixtures for transaction submission success without touching the live network.
- Live RPC tests are not part of default CI; they require explicit operator credentials and funds.
- Security tests must prove broadcast is blocked unless request confirmation, broadcast env, internal signing env, KMS policy, active key, and destination policy all pass.

## Boundaries
- Always: require explicit write policies, destination whitelist, TTL, daily limit, audit logging, and caller confirmation before real broadcast.
- Always: preserve prepare-only behavior as the default safe path.
- Ask first: adding funded live-network tests, enabling autonomous production configs, or widening contract/governance write scopes.
- Never: commit secrets, private keys, seed phrases, or funded test credentials.
- Never: silently broadcast because autonomous mode is enabled.

## Success Criteria
- `lunes_transfer_native` can return prepare-only payloads without live broadcast.
- `lunes_transfer_native` can build a final native transfer extrinsic, sign it with the local KMS key, submit it to Lunes RPC, and return hash, block, events, final status, and any final failure.
- Broadcast requires `confirm_broadcast=true`, `LUNES_MCP_ENABLE_BROADCAST=1`, `LUNES_MCP_ENABLE_INTERNAL_SIGNING=1`, `LUNES_MCP_AUDIT_LOG_PATH`, active autonomous KMS, transfer policy, broadcast policy, destination whitelist, and spend limit.
- Existing external signed extrinsic relay remains unchanged.
- `lunes_get_governance_overview` and `lunes_get_referenda` expose bounded raw
  governance storage reads.
- `lunes_prepare_governance_vote` and
  `lunes_prepare_governance_remove_vote` require dedicated governance policy.
  `lunes_prepare_governance_delegate` and
  `lunes_prepare_governance_undelegate` require dedicated delegation track and
  delegate policy. All governance prepare tools reject `confirm_broadcast=true`,
  return `pending_human_approval`, and never call KMS signing.
- `lunes_stake_rebond` and `lunes_stake_payout` prepare or locally sign intent
  payloads only; payout requires a whitelisted validator stash.
- `lunes_get_validator_scores` returns bounded partial scores using active-set
  status, commission, blocked state, and nomination eligibility, while marking
  exposure and reward history as not decoded.
- `cargo fmt --check`, `cargo test --locked`, `cargo clippy --all-targets -- -D warnings`, and `cargo build --release --locked` pass.

## Open Questions
- Whether Lunes production runtime accepts Ed25519 `MultiSignature` for funded accounts; the client implementation is guarded, but a funded live test is needed before production use.
- Whether `Balances.transfer_allow_death` or `Balances.transfer_keep_alive` should be the default operator policy; this slice defaults to allow-death unless `keep_alive=true`.
- Asset-aware, staking-write, contract-write, and final governance-write broadcasts need separate policies and specs before being enabled.
- Validator exposure, reward payout history, and slash/performance history need
  explicit runtime/indexer-backed decoding before they can influence scores.
- Governance reads currently expose raw referendum storage. Metadata-aware
  decoding, track details, account voting history, and proposal preimage
  resolution remain future network/indexer work.
