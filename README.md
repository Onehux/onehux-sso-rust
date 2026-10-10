# onehux-sso-rust

A real, installable Rust SDK for OneHux Accounts SSO — **resource-server only**, unlike this
project's Django/Node.js/Go/Laravel SDKs, which each also support an OAuth-client/BFF role.

## Why resource-server only — this is deliberate, not a placeholder

Every Rust/axum backend in the OneHux product family (`onehux-pos-backend`,
`onehux-forge-backend-axum`) is a pure JSON API sitting behind a *separate* SvelteKit frontend
that owns its own BFF role via `@onehux/sso` — login redirects, the session cookie, the token
exchange all happen in that Node/SvelteKit layer, never in Rust. Mobile apps
(`onehux-sso-android`, and any future `onehux-sso-ios`) are direct OAuth clients holding their
own tokens. So a Rust backend's only real job is: receive a Bearer token (forwarded by a
frontend's BFF, or sent directly by a mobile app) and verify it's genuinely signed by OneHux
Accounts. It never redirects a browser, never exchanges an authorization code, and never holds
a client secret.

If a real Rust-as-its-own-BFF use case ever shows up, that's a clean, separate addition to this
crate later — not a reason to build unused OAuth-client scope into it now.

## Install

Not on crates.io — add as a git dependency:

```toml
[dependencies]
onehux-sso = { git = "https://github.com/Onehux/onehux-sso-rust", tag = "v0.1.1" }
```

## Two hosts — don't mix them up

`accounts.onehux.com` serves the hosted login pages a browser is redirected to (not used by
this crate at all). `api-accounts.onehux.com` serves the actual OAuth API, including
`/.well-known/jwks.json` — this crate's `issuer` option defaults to that host. Never point it
at a custom domain: JWKS has no per-Organization customization, and collapsing the two hosts
was a real, confirmed integration bug documented in this family's other packages.

## Usage

```rust
use onehux_sso::{ResourceServerOptions, ResourceServerVerifier};

let verifier = ResourceServerVerifier::new(ResourceServerOptions {
    trusted_client_ids: Some(vec!["onehux_client_pos_xxx".to_string()]),
    ..Default::default()
});

let token = onehux_sso::extract_bearer_token(authorization_header)
    .ok_or(/* 401 */)?;
let claims = verifier.verify_access_token(token).await
    .map_err(|_| /* 401 */)?;

// claims.sub, claims.email, claims.org_id, claims.scope, claims.has_scope("invoices:read")
```

`verify_access_token()` fetches and caches the platform's real, live JWKS, matched by `kid`,
re-fetching automatically on a `kid` it hasn't seen — key rotation on the platform side needs
zero action here. `trusted_client_ids` is optional but recommended: it restricts acceptance to
tokens issued to specific Application(s) — real tenant isolation on a shared identity
platform, not just "is this token valid at all." `ResourceServerVerifier` is cheap to clone
(an `Arc` internally) — construct once per process and share it.

`token_type` is checked too: a refresh token or `id_token` presented as a Bearer credential is
always rejected, never silently accepted.

## Axum integration (on by default)

```rust
use axum::{Router, routing::get};
use axum::extract::FromRef;
use onehux_sso::{AuthenticatedClaims, ResourceServerVerifier};

#[derive(Clone, FromRef)]
struct AppState {
    sso: ResourceServerVerifier,
    // ...your other shared state
}

async fn me(AuthenticatedClaims(claims): AuthenticatedClaims) -> String {
    format!("Hello, {}", claims.email.unwrap_or(claims.sub))
}

let state = AppState {
    sso: ResourceServerVerifier::new(ResourceServerOptions::default()),
    // ...
};
let app = Router::new().route("/v1/me", get(me)).with_state(state);
```

`AuthenticatedClaims` is a real `FromRequestParts` extractor — take it as a handler parameter
and a missing/invalid/expired token is rejected automatically, before your handler body ever
runs. The rejection body matches this platform's own flat error convention,
`{"code": "unauthenticated", "message": "..."}` — not Django REST Framework's `{"detail": ...}`
shape the Go/Django packages use, since this crate's only known consumers are built against
that convention.

Disable the extractor (and the `axum` dependency entirely) for a non-axum consumer:

```toml
onehux-sso = { git = "...", tag = "v0.1.1", default-features = false }
```

## What's been verified

Every rejection path (expired, wrong `token_type`, untrusted `client_id`, a signature from a
key not in the real JWKS) is tested against a real, locally generated 2048-bit RSA keypair and
real RS256-signed JWTs — nothing about signature verification is mocked. JWK parsing is also
verified directly against the live `api-accounts.onehux.com` JWKS endpoint, not just synthetic
test data.

## License

Apache License 2.0 — see `LICENSE`.
