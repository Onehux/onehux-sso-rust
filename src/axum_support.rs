//! Axum `FromRequestParts` extractor — pulls a verified [`TokenClaims`] straight out of a
//! request's `Authorization: Bearer` header. Requires [`ResourceServerVerifier`] to be
//! reachable from the app's `State` via axum's [`FromRef`] mechanism (the standard way to
//! share one slice of typed state across extractors) — see the crate README for a full
//! example.
//!
//! Error body shape matches `platform/AGENTS.md` §4's flat `{code, message, details?}`
//! convention (not DRF's `{"detail": ...}` the Django/Go packages use) — this crate's only
//! known consumers are axum backends built against that same platform convention.

use axum::Json;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::{StatusCode, header, request::Parts};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::resource_server::{ResourceServerVerifier, TokenClaims, extract_bearer_token};

/// Extractor wrapping a verified [`TokenClaims`]. Add `ResourceServerVerifier` to your app's
/// state (and implement `FromRef` for it, or derive it via `#[derive(Clone)]` + axum's
/// `#[from_ref]` pattern on a composite state struct), then take `AuthenticatedClaims` as a
/// handler parameter — rejection is automatic on a missing/invalid/expired token.
pub struct AuthenticatedClaims(pub TokenClaims);

/// Why [`AuthenticatedClaims`] extraction failed — both variants respond `401` with the
/// platform's flat error body; this crate deliberately doesn't distinguish "missing header"
/// from "invalid token" in the response body (same posture as this package family's other
/// resource-server implementations — nothing more specific to offer a caller than "not valid
/// anymore").
pub enum AuthRejection {
    /// No (or malformed) `Authorization: Bearer` header was present.
    Missing,
    /// A token was present but [`ResourceServerVerifier::verify_access_token`] rejected it.
    Invalid,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        let message = match self {
            AuthRejection::Missing => "Not authenticated.",
            AuthRejection::Invalid => "Invalid or expired token.",
        };
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                code: "unauthenticated",
                message,
            }),
        )
            .into_response()
    }
}

impl<S> FromRequestParts<S> for AuthenticatedClaims
where
    ResourceServerVerifier: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let verifier = ResourceServerVerifier::from_ref(state);
        let header_value = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AuthRejection::Missing)?;
        let token = extract_bearer_token(header_value).ok_or(AuthRejection::Missing)?;
        let claims = verifier
            .verify_access_token(token)
            .await
            .map_err(|_| AuthRejection::Invalid)?;
        Ok(AuthenticatedClaims(claims))
    }
}
