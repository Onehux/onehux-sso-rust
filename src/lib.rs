//! `onehux-sso` — Rust SDK for OneHux Accounts SSO.
//!
//! Resource-server only: verifies OneHux-issued access tokens (RS256/JWKS) for a Rust API
//! sitting behind a separate frontend BFF (a SvelteKit app using `@onehux/sso`, a mobile app,
//! another service). This crate never redirects a browser, never exchanges an authorization
//! code, and never holds a client secret — if you need that role (an app that IS the OAuth
//! client), see the Node.js/Django/Go/Laravel packages in the `onehux_sso_client` family
//! instead. See the README for why this scope was chosen deliberately, not as a placeholder.

pub mod resource_server;

#[cfg(feature = "axum")]
pub mod axum_support;

pub use resource_server::{
    ResourceServerOptions, ResourceServerVerifier, TokenClaims, VerifyError, extract_bearer_token,
};

#[cfg(feature = "axum")]
pub use axum_support::{AuthRejection, AuthenticatedClaims};
