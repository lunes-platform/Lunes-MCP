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

## Sensitive Files

Do not commit:

- `.env*`
- private keys, seeds or exported wallets
- production agent configs
- audit logs

The `.gitignore` blocks these patterns by default.

## Current Security Limitations

- Lunes Network metadata reads use live RPC, but balances, status checks, and submissions still need full network-backed implementations.
- SS58 validation checks the Lunes Network prefix and checksum, but it does not prove account ownership.
- Autonomous signatures are local intent payload signatures, not final Lunes Network transaction signatures.
- Autonomous `contracts.call` is disabled until message allowlists and asset-specific limits exist.
- Audit logs are in memory only.

Report vulnerabilities privately to the project maintainers before public disclosure.
