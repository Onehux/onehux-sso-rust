# Changelog

All notable changes to `github.com/Onehux/onehux-sso-rust` are documented here.

## v0.1.0

- **Added** `ResourceServerVerifier` (`resource_server` module) — verifies a Bearer token's
  RS256 signature against OneHux Accounts' real, live JWKS (`/.well-known/jwks.json`), with
  automatic caching and re-fetch on key rotation. No session, no redirect, no client secret —
  resource-server only, deliberately; see README for why.
- **Added** `AuthenticatedClaims`, a real axum `FromRequestParts` extractor (`axum_support`
  module, on by default) — rejects a missing/invalid/expired token automatically, before a
  handler body runs, with a response body matching this platform's flat
  `{code, message, details?}` error convention.
- **Verified**: every rejection path (expired, wrong `token_type`, untrusted `client_id`, a
  forged signature) against real, locally generated RSA keys and real RS256-signed JWTs — no
  mocked signature verification. JWK parsing also verified directly against the live
  `api-accounts.onehux.com` JWKS endpoint.
