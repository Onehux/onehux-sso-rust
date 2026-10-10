//! Real tests for `ResourceServerVerifier` — a real 2048-bit RSA keypair generated once per
//! test, real RS256-signed JWTs (hand-signed the same way `verify_access_token` verifies them,
//! not round-tripped through the same encoder), and a real local axum server serving a real
//! JWKS document. Nothing about signature verification is mocked.
//!
//! `unwrap`/`expect`/`panic` are the lib crate's own denied lints (src-level correctness
//! rules) — test code legitimately uses them to fail loudly on setup errors and assertion
//! failures, which is exactly what `#[test]` relies on.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::routing::get;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use onehux_sso::{ResourceServerOptions, ResourceServerVerifier, VerifyError};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{Value, json};
use tokio::net::TcpListener;

const TEST_KID: &str = "test-key-1";

struct TestJwks {
    issuer: String,
    private_key_pem: String,
}

/// Generates a real RSA keypair and serves it as a real JWKS document on a local axum server
/// bound to an OS-assigned port. Returns the issuer base URL to configure
/// `ResourceServerOptions::issuer` with, plus the PEM private key to sign test tokens with.
async fn start_test_jwks_server() -> TestJwks {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate test RSA key");
    let public_key = RsaPublicKey::from(&private_key);

    let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

    let jwks_doc = json!({
        "keys": [{
            "kty": "RSA",
            "kid": TEST_KID,
            "n": n,
            "e": e,
        }]
    });

    let app = Router::new().route(
        "/.well-known/jwks.json",
        get(move || {
            let body = jwks_doc.clone();
            async move { axum::Json(body) }
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test listener");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve test jwks");
    });

    TestJwks {
        issuer: format!("http://{addr}"),
        private_key_pem: private_key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .expect("encode private key pem")
            .to_string(),
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs()
        .cast_signed()
}

fn sign_test_token(private_key_pem: &str, issuer: &str, claims: &Value) -> String {
    let encoding_key =
        EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).expect("load test signing key");
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(TEST_KID.to_string());
    let mut claims = claims.clone();
    claims["iss"] = json!(issuer);
    encode(&header, &claims, &encoding_key).expect("sign test token")
}

#[tokio::test]
async fn accepts_a_real_valid_access_token() {
    let jwks = start_test_jwks_server().await;
    let token = sign_test_token(
        &jwks.private_key_pem,
        &jwks.issuer,
        &json!({
            "sub": "user-123",
            "aud": "onehux_client_test",
            "iat": now(),
            "exp": now() + 900,
            "token_type": "access",
            "email": "a@b.com",
            "org_id": "org-456",
            "sid": "session-789",
            "scope": "openid profile email",
        }),
    );

    let verifier = ResourceServerVerifier::new(ResourceServerOptions {
        issuer: Some(jwks.issuer.clone()),
        ..Default::default()
    });

    let claims = verifier
        .verify_access_token(&token)
        .await
        .expect("token should verify");
    assert_eq!(claims.sub, "user-123");
    assert_eq!(claims.org_id.as_deref(), Some("org-456"));
    assert!(claims.has_scope("profile"));
    assert!(!claims.has_scope("admin"));
}

#[tokio::test]
async fn rejects_an_expired_token() {
    let jwks = start_test_jwks_server().await;
    let token = sign_test_token(
        &jwks.private_key_pem,
        &jwks.issuer,
        &json!({
            "sub": "user-123",
            "aud": "onehux_client_test",
            "iat": now() - 1_000,
            "exp": now() - 500,
            "token_type": "access",
        }),
    );

    let verifier = ResourceServerVerifier::new(ResourceServerOptions {
        issuer: Some(jwks.issuer.clone()),
        ..Default::default()
    });

    let err = verifier
        .verify_access_token(&token)
        .await
        .expect_err("expired token must be rejected");
    assert!(matches!(err, VerifyError::Token(_)));
}

#[tokio::test]
async fn rejects_a_token_not_of_type_access() {
    let jwks = start_test_jwks_server().await;
    let token = sign_test_token(
        &jwks.private_key_pem,
        &jwks.issuer,
        &json!({
            "sub": "user-123",
            "aud": "onehux_client_test",
            "iat": now(),
            "exp": now() + 900,
            "token_type": "refresh",
        }),
    );

    let verifier = ResourceServerVerifier::new(ResourceServerOptions {
        issuer: Some(jwks.issuer.clone()),
        ..Default::default()
    });

    let err = verifier
        .verify_access_token(&token)
        .await
        .expect_err("a refresh token presented as Bearer must be rejected");
    assert!(matches!(err, VerifyError::Token(msg) if msg.contains("not an access token")));
}

#[tokio::test]
async fn rejects_a_token_issued_to_an_untrusted_client_id() {
    let jwks = start_test_jwks_server().await;
    let token = sign_test_token(
        &jwks.private_key_pem,
        &jwks.issuer,
        &json!({
            "sub": "user-123",
            "aud": "onehux_client_someone_else",
            "iat": now(),
            "exp": now() + 900,
            "token_type": "access",
        }),
    );

    let verifier = ResourceServerVerifier::new(ResourceServerOptions {
        issuer: Some(jwks.issuer.clone()),
        trusted_client_ids: Some(vec!["onehux_client_pos".to_string()]),
        ..Default::default()
    });

    let err = verifier
        .verify_access_token(&token)
        .await
        .expect_err("an untrusted client_id must be rejected");
    assert!(matches!(err, VerifyError::Token(msg) if msg.contains("untrusted client_id")));
}

#[tokio::test]
async fn rejects_a_token_signed_by_a_different_key() {
    let jwks = start_test_jwks_server().await;

    // Sign with a SECOND, never-published key — the JWKS endpoint above only serves the
    // first key's public half, so this must fail signature verification, not merely an
    // unrecognized-kid lookup (the kid header below still names the real, published kid,
    // simulating a forged signature rather than key rotation).
    let mut rng = rand::thread_rng();
    let forged_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate forged key");
    let forged_pem = forged_key
        .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
        .expect("encode forged key pem")
        .to_string();

    let token = sign_test_token(
        &forged_pem,
        &jwks.issuer,
        &json!({
            "sub": "user-123",
            "aud": "onehux_client_test",
            "iat": now(),
            "exp": now() + 900,
            "token_type": "access",
        }),
    );

    let verifier = ResourceServerVerifier::new(ResourceServerOptions {
        issuer: Some(jwks.issuer.clone()),
        ..Default::default()
    });

    let err = verifier
        .verify_access_token(&token)
        .await
        .expect_err("a token signed by a key not in the real JWKS must be rejected");
    assert!(matches!(err, VerifyError::Token(_)));
}

/// Confirms this crate's JWK parsing actually works against the REAL, live
/// `api-accounts.onehux.com` JWKS — not just the synthetic key pairs the tests above generate.
/// Uses the default issuer (no override), sending a syntactically valid JWT with a `kid` that
/// can't be in the real JWKS; the only way `verify_access_token` rejects it as "unrecognized
/// key" rather than `VerifyError::Jwks(...)` is if the real endpoint was actually reached and
/// its real key material actually parsed without error — the production equivalent of the
/// Android SDK's own "verified directly against the live platform" standard.
#[tokio::test]
async fn parses_the_real_live_jwks_endpoint() {
    let verifier = ResourceServerVerifier::new(ResourceServerOptions::default());

    // A syntactically well-formed, unsigned-but-irrelevant JWT: header names a kid that is
    // real-looking but guaranteed absent from the live JWKS, so the only way to reach
    // "unrecognized key" is a successful fetch+parse of the real document.
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"definitely-not-a-real-kid"}"#);
    let payload = URL_SAFE_NO_PAD.encode(br#"{"sub":"x"}"#);
    let fake_token = format!("{header}.{payload}.fake-signature");

    let err = verifier
        .verify_access_token(&fake_token)
        .await
        .expect_err("a nonexistent kid must be rejected");
    match err {
        VerifyError::Token(msg) => assert!(
            msg.contains("unrecognized key"),
            "expected an unrecognized-key rejection, got: {msg}"
        ),
        VerifyError::Jwks(msg) => panic!("live JWKS endpoint was not reachable/parseable: {msg}"),
    }
}

#[test]
fn extract_bearer_token_parses_a_real_header_value() {
    assert_eq!(
        onehux_sso::extract_bearer_token("Bearer abc.def.ghi"),
        Some("abc.def.ghi")
    );
    assert_eq!(onehux_sso::extract_bearer_token("Basic xyz"), None);
    assert_eq!(onehux_sso::extract_bearer_token(""), None);
}
