# Changelog

## 0.2.0

- Added live Lunes Network reads for balances, account overview, validator state,
  staking account state, transaction status, and contract simulations.
- Added asset inventory and allowlisted PSP22 balance dry-runs.
- Added local PSP22 asset policies with metadata, recipient allowlists, and
  per-contract base-unit transfer limits; PSP22 token amounts no longer consume
  the native LUNES daily budget.
- Added guarded relay for externally signed Lunes transaction payloads.
- Added guarded native LUNES transfer submission with dynamic transaction
  construction, KMS Ed25519 signing, finality tracking, raw event lookup, dual
  broadcast env gates, transfer/broadcast policy checks, and mandatory
  persistent audit logging.
- Hardened relay so signed extrinsic hashes must be pre-approved before
  broadcast, with explicit `author.submit_extrinsic` -> `broadcast` agent
  policy required.
- Required explicit contract/message allowlists for PSP22 and generic contract
  write preparation, and blocked autonomous generic contract-call signing.
- Added raw event storage to transaction status responses when available.
- Added bounded recent block summaries, raw block event lookup, and account
  activity timeline entries without returning raw extrinsics from block summary
  responses.
- Bounded in-memory audit logs and redacted RPC endpoint credentials in status
  and connection errors.
- Added optional JSONL audit persistence with payload hashes instead of raw
  payload bytes.
- Rejected unsafe RPC endpoint config such as public `ws://`, credentials, query
  strings, and fragments.
- Added staking preparation tools for bond, unbond, withdraw, nominate, chill,
  and reward destination updates.
- Added staking rebond and payout preparation tools, with payout constrained to
  whitelisted validator stash addresses.
- Added bounded validator scoring from observable validator profile data, while
  explicitly marking exposure and reward history as not decoded.
- Added governance read/preparation tools for bounded raw referendum storage,
  explicit prepare-only vote policy, and human-review vote/remove-vote payloads
  that never sign or broadcast.
- Blocked autonomous high-risk governance and indirection extrinsics such as
  referendum voting, batching, proxy, multisig, scheduler, and preimage calls
  until dedicated safe policies exist.
- Added production guardrails for public binds, API keys, rate limiting,
  request limits, and graceful shutdown.
- Added Docker packaging and release-build CI coverage.
