# Security Policy

## Supported Status

The server is an early access implementation. Public internet exposure is only supported behind the
built-in API key requirement and a TLS-terminating reverse proxy.

## Required Public Settings

Set both variables for non-local binds:

```bash
LUNES_MCP_BIND=0.0.0.0:9950
LUNES_MCP_API_KEY=<strong-random-token>
```

The process refuses public bind addresses without an API key and enabled rate limit.
Autonomous mode also refuses startup unless `LUNES_MCP_ALLOW_AUTONOMOUS=1`
is set explicitly. The legacy `LUNES_MCP_ALLOW_AUTONOMOUS_STUB=1` variable is
still accepted for older local setups.
Broadcast of an externally signed extrinsic is separately disabled unless
`LUNES_MCP_ENABLE_BROADCAST=1` is set, the computed signed extrinsic hash is
listed in `LUNES_MCP_ALLOWED_BROADCAST_HASHES`, and the request includes
`confirm_broadcast=true`. The agent policy must also allow
`author.submit_extrinsic` and whitelist the `broadcast` policy target.
Broadcast of an internally signed native LUNES transfer additionally requires
`LUNES_MCP_ENABLE_INTERNAL_SIGNING=1`, `LUNES_MCP_AUDIT_LOG_PATH`, an active KMS
key, `balances.transfer` policy for the recipient, and `author.submit_extrinsic`
policy for `broadcast`.
Governance tools are deliberately read/prepare-only. They expose bounded raw
referendum storage and prepare explicit human-review payloads, but reject
`confirm_broadcast=true` and never sign or submit final votes.

## Sensitive Files

Do not commit:

- `.env*`
- private keys, seeds or exported wallets
- production agent configs
- audit logs

The `.gitignore` blocks these patterns by default.

## Current Security Limitations

- Lunes Network metadata, health, native balances, allowlisted PSP22 balance dry-runs, account nonce, validator set, validator profiles, bounded validator scoring from profile data, account staking state, bounded account activity scans, recent block summaries, raw block event lookup, bounded raw governance referendum reads, read-only contract simulation, externally signed extrinsic submission, guarded native LUNES transfer submission, and bounded archive-assisted transaction lookup use live RPC.
- PSP22 decoded balance values, automatic token metadata discovery, governance metadata decoding, account voting history, decoded validator exposure, reward payout history, indexed full-history transaction search, and KMS-built staking/generic-contract/governance transaction signing still need full network-backed implementations.
- Recent block summaries intentionally omit raw extrinsics; account activity timelines use raw account-id substring matching and can miss encoded relationships that require a full indexer or metadata-aware decoding.
- Staking write tools prepare or locally sign intent payloads only; validator, payout, and reward-account choices must be explicitly whitelisted.
- Governance preparation requires dedicated vote or delegation policy and never signs locally, even when autonomous mode is active.
- SS58 validation checks the Lunes Network prefix and checksum, but it does not prove account ownership.
- Autonomous signatures are local intent payload signatures except for guarded native LUNES transfer broadcast, which builds and signs a final network transaction only after all internal signing guardrails pass.
- Raw signed extrinsic submission still does not decode transaction contents before broadcast; it is hash-preapproved and policy-gated to prevent arbitrary relay, but only enable it in an operator-controlled environment.
- Read-only contract simulation and contract write preparation require explicit message allowlists. PSP22 transfer signing additionally requires local asset metadata, `max_transfer_base_units`, and `allowed_recipients`; autonomous generic `contracts.call` signing is blocked.
- Audit logs are bounded in memory by default. Set `LUNES_MCP_AUDIT_LOG_PATH` to append JSONL entries with action metadata and payload hashes for persistent retention; successful local KMS signing fails closed if that persistent write fails.
- Runtime config rejects public `ws://` RPC URLs and RPC URLs containing credentials, query strings, or fragments; use `wss://` for non-local endpoints.

Report vulnerabilities privately to the project maintainers before public disclosure.
