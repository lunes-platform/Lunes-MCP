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
Autonomous mode also refuses startup unless `LUNES_MCP_ALLOW_AUTONOMOUS_STUB=1`
is set; this is for local testing only until real Lunes Network transaction signing
exists.
Broadcast of an externally signed extrinsic is separately disabled unless
`LUNES_MCP_ENABLE_BROADCAST=1` is set, the computed signed extrinsic hash is
listed in `LUNES_MCP_ALLOWED_BROADCAST_HASHES`, and the request includes
`confirm_broadcast=true`. The agent policy must also allow
`author.submit_extrinsic` and whitelist the `broadcast` policy target.

## Sensitive Files

Do not commit:

- `.env*`
- private keys, seeds or exported wallets
- production agent configs
- audit logs

The `.gitignore` blocks these patterns by default.

## Current Security Limitations

- Lunes Network metadata, health, native balances, allowlisted PSP22 balance dry-runs, account nonce, validator set, validator profiles, account staking state, bounded account activity scans, recent block summaries, raw block event lookup, read-only contract simulation, externally signed extrinsic submission, and bounded archive-assisted transaction lookup use live RPC.
- PSP22 decoded balance values, token metadata discovery, performance scoring, indexed full-history transaction search, and KMS-built final transaction signing still need full network-backed implementations.
- Recent block summaries intentionally omit raw extrinsics; account activity timelines use raw account-id substring matching and can miss encoded relationships that require a full indexer or metadata-aware decoding.
- Staking write tools prepare or locally sign intent payloads only; validator and reward-account choices must be explicitly whitelisted.
- SS58 validation checks the Lunes Network prefix and checksum, but it does not prove account ownership.
- Autonomous signatures are local intent payload signatures, not final Lunes Network transaction signatures.
- Raw signed extrinsic submission still does not decode transaction contents before broadcast; it is hash-preapproved and policy-gated to prevent arbitrary relay, but only enable it in an operator-controlled environment.
- Read-only contract simulation and contract write preparation require explicit message allowlists; autonomous `contracts.call` writes remain disabled until asset-specific limits exist.
- Audit logs are bounded in memory by default. Set `LUNES_MCP_AUDIT_LOG_PATH` to append JSONL entries with action metadata and payload hashes for persistent retention; successful local KMS signing fails closed if that persistent write fails.
- Runtime config rejects public `ws://` RPC URLs and RPC URLs containing credentials, query strings, or fragments; use `wss://` for non-local endpoints.

Report vulnerabilities privately to the project maintainers before public disclosure.
