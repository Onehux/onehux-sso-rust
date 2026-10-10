//! Resource-server verification of OneHux-issued access tokens.
//!
//! For a Rust API sitting behind a *separate* frontend BFF (a SvelteKit app using
//! `@onehux/sso`, a mobile app holding its own tokens, another service) rather than this app
//! itself being the OAuth client. No session, no redirect, no client secret involved — mirrors
//! `@onehux/sso/resource-server` (Node), `onehux_sso.resource_server` (Django), the Go
//! package's `ResourceServerVerifier`, and `OneHuxResourceServerVerifier` (Android).
//!
//! Claim shape matches what `onehux-accounts-backend`'s `oauth/services.py` `build_jwt()`
//! actually signs — `sub`/`aud`/`iss`/`iat`/`exp`/`token_type` are always present;
//! `email`/`org_id`/`sid`/`scope` are present on every token the platform currently issues.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::RwLock;

const DEFAULT_ISSUER: &str = "https://api-accounts.onehux.com";
const DEFAULT_JWKS_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// Every way [`ResourceServerVerifier::verify_access_token`] can reject a token — expired, bad
/// signature, unrecognized `kid`, wrong issuer, not a real access token, or (when
/// `trusted_client_ids` is set) issued to an untrusted Application. Mirrors this package
/// family's own established posture: deliberately generic messages here, since the platform's
/// client packages document having "nothing more specific to offer a caller than invalid or
/// expired." A genuine network/transport failure reaching the JWKS endpoint is NOT this error
/// — see [`VerifyError::Jwks`].
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The token itself is unusable — see the message for which real reason.
    #[error("{0}")]
    Token(String),
    /// The JWKS endpoint could not be reached or returned something unparseable — distinct
    /// from a rejected token, since this means "OneHux Accounts was unreachable," not "this
    /// credential is dead."
    #[error("failed to fetch or parse OneHux Accounts' JWKS: {0}")]
    Jwks(String),
}

/// The real, verified claims from a OneHux access token. `raw` carries every claim, including
/// any not promoted to a named field, so a caller reading a claim this struct doesn't expose
/// isn't blocked.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub aud: String,
    pub iss: String,
    pub iat: i64,
    pub exp: i64,
    pub token_type: String,
    pub email: Option<String>,
    pub org_id: Option<String>,
    pub sid: Option<String>,
    pub scope: Option<String>,
    #[serde(flatten)]
    pub raw: Value,
}

impl TokenClaims {
    /// `true` if `scope` (space-delimited, per this platform's own token shape) contains
    /// `required`.
    #[must_use]
    pub fn has_scope(&self, required: &str) -> bool {
        self.scope
            .as_deref()
            .is_some_and(|scope| scope.split_whitespace().any(|s| s == required))
    }
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kty: String,
    kid: String,
    n: String,
    e: String,
}

#[derive(Debug, Deserialize)]
struct JwksDocument {
    keys: Vec<Jwk>,
}

struct JwksCache {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Instant,
}

/// Configures a [`ResourceServerVerifier`]. Every field defaults to this platform's own
/// production values when left `None`.
#[derive(Default)]
pub struct ResourceServerOptions {
    /// The OneHux Accounts issuer this API trusts. Default: `https://api-accounts.onehux.com`.
    /// Never point this at a custom domain — JWKS has no per-Organization customization.
    pub issuer: Option<String>,
    /// Restricts acceptance to tokens issued to specific Application(s) — the token's `aud`
    /// claim — real tenant isolation on a shared identity platform, not just "is this token
    /// valid at all." Leave `None` to accept a valid token issued to any Application on
    /// `issuer`.
    pub trusted_client_ids: Option<Vec<String>>,
    /// The HTTP client used for JWKS fetches. Default: a client with a 10s timeout.
    pub http_client: Option<reqwest::Client>,
    /// How long a fetched JWKS is trusted before being re-fetched, even for a `kid` already
    /// seen. Default: 5 minutes. A `kid` NOT in the current cache always triggers an immediate
    /// re-fetch regardless of this TTL — covers key rotation with zero action needed by a
    /// caller.
    pub jwks_cache_ttl: Option<Duration>,
}

/// Verifies OneHux-issued access tokens against the platform's real, live JWKS. Cheap to
/// clone (an `Arc` internally) — construct once per process and share it, e.g. via axum state.
#[derive(Clone)]
pub struct ResourceServerVerifier {
    inner: Arc<Inner>,
}

struct Inner {
    issuer: String,
    trusted_client_ids: Option<Vec<String>>,
    http_client: reqwest::Client,
    cache_ttl: Duration,
    cache: RwLock<Option<JwksCache>>,
}

impl ResourceServerVerifier {
    /// Constructs a verifier, applying the defaults documented on [`ResourceServerOptions`].
    #[must_use]
    pub fn new(options: ResourceServerOptions) -> Self {
        let issuer = options
            .issuer
            .unwrap_or_else(|| DEFAULT_ISSUER.to_string())
            .trim_end_matches('/')
            .to_string();
        let http_client = options.http_client.unwrap_or_else(|| {
            reqwest::Client::builder()
                .timeout(DEFAULT_HTTP_TIMEOUT)
                .build()
                .unwrap_or_default()
        });
        Self {
            inner: Arc::new(Inner {
                issuer,
                trusted_client_ids: options.trusted_client_ids,
                http_client,
                cache_ttl: options.jwks_cache_ttl.unwrap_or(DEFAULT_JWKS_CACHE_TTL),
                cache: RwLock::new(None),
            }),
        }
    }

    /// Verifies `token`'s RS256 signature against the issuer's real, live JWKS (auto-fetched/
    /// cached, re-fetched on a `kid` it hasn't seen — covers key rotation with zero action
    /// needed here), plus issuer/expiry and, when `trusted_client_ids` is set, audience. Also
    /// rejects anything that isn't a real access token (`token_type` must be `"access"` — an
    /// `id_token` or refresh token presented here is always a caller mistake, never a valid
    /// Bearer credential).
    ///
    /// # Errors
    /// [`VerifyError::Token`] for a real rejection (expired, bad signature, unrecognized `kid`,
    /// untrusted issuer/client_id, not an access token). [`VerifyError::Jwks`] if the JWKS
    /// endpoint itself could not be reached or parsed.
    pub async fn verify_access_token(&self, token: &str) -> Result<TokenClaims, VerifyError> {
        let header = decode_header(token)
            .map_err(|e| VerifyError::Token(format!("Token is not a well-formed JWT: {e}")))?;
        if header.alg != Algorithm::RS256 {
            return Err(VerifyError::Token(format!(
                "Unsupported token alg: {:?}",
                header.alg
            )));
        }
        let kid = header
            .kid
            .ok_or_else(|| VerifyError::Token("Token has no kid header.".to_string()))?;

        let key = self.get_key(&kid).await?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.inner.issuer.as_str()]);
        // Audience is checked manually below (trusted_client_ids is optional; an empty/unset
        // validation.aud would otherwise reject every token outright).
        validation.validate_aud = false;

        let data = decode::<TokenClaims>(token, &key, &validation)
            .map_err(|e| VerifyError::Token(format!("Token signature/claims rejected: {e}")))?;
        let claims = data.claims;

        if claims.token_type != "access" {
            return Err(VerifyError::Token(format!(
                "Token is not an access token (token_type={}).",
                claims.token_type
            )));
        }
        if let Some(trusted) = &self.inner.trusted_client_ids
            && !trusted.iter().any(|id| id == &claims.aud)
        {
            return Err(VerifyError::Token(format!(
                "Token was issued to an untrusted client_id: {}",
                claims.aud
            )));
        }

        Ok(claims)
    }

    async fn get_key(&self, kid: &str) -> Result<DecodingKey, VerifyError> {
        {
            let cache = self.inner.cache.read().await;
            if let Some(entry) = cache.as_ref()
                && entry.fetched_at.elapsed() < self.inner.cache_ttl
                && let Some(key) = entry.keys.get(kid)
            {
                return Ok(key.clone());
            }
        }

        let keys = self.fetch_jwks().await?;
        let key = keys.get(kid).cloned().ok_or_else(|| {
            VerifyError::Token("Token was signed by an unrecognized key.".to_string())
        })?;
        Ok(key)
    }

    /// Fetches and parses the issuer's real `/.well-known/jwks.json`, replacing the cache
    /// outright (a key removed on the platform side — real rotation, not just addition — must
    /// stop being trusted here too, not linger from a stale partial merge).
    async fn fetch_jwks(&self) -> Result<HashMap<String, DecodingKey>, VerifyError> {
        let url = format!("{}/.well-known/jwks.json", self.inner.issuer);
        let response = self
            .inner
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| VerifyError::Jwks(e.to_string()))?;
        if !response.status().is_success() {
            return Err(VerifyError::Jwks(format!(
                "jwks endpoint returned status {}",
                response.status()
            )));
        }
        let doc: JwksDocument = response
            .json()
            .await
            .map_err(|e| VerifyError::Jwks(e.to_string()))?;

        let mut keys = HashMap::with_capacity(doc.keys.len());
        for jwk in doc.keys {
            if jwk.kty != "RSA" {
                continue;
            }
            let Ok(key) = DecodingKey::from_rsa_components(&jwk.n, &jwk.e) else {
                continue;
            };
            keys.insert(jwk.kid, key);
        }

        let mut cache = self.inner.cache.write().await;
        *cache = Some(JwksCache {
            keys: keys.clone(),
            fetched_at: Instant::now(),
        });
        Ok(keys)
    }
}

/// Extracts the bearer token from an `Authorization` header value, or `None` if it isn't one.
#[must_use]
pub fn extract_bearer_token(header_value: &str) -> Option<&str> {
    header_value.strip_prefix("Bearer ")
}
