use once_cell::sync::Lazy;
use rand::thread_rng;
use rsa::{pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
use base64::Engine as _;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct RsaKeyMaterial {
    pub kid: String,
    pub private_der: Arc<Vec<u8>>, // PKCS1 DER
    pub public_jwk: serde_json::Value,
}

static ACTIVE_KEYS: Lazy<RwLock<Vec<RsaKeyMaterial>>> = Lazy::new(|| RwLock::new(Vec::new()));

fn base64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn bigint_to_bytes_be(n: &rsa::BigUint) -> Vec<u8> {
    let mut bytes = n.to_bytes_be();
    // Ensure there's no leading zero trimming issue for positive integers (JWK expects unsigned big-endian)
    while bytes.first().is_some_and(|b| *b == 0) {
        bytes.remove(0);
    }
    bytes
}

async fn generate_rsa_key() -> RsaKeyMaterial {
    let mut rng = thread_rng();
    let private = RsaPrivateKey::new(&mut rng, 2048).expect("RSA key generation failed");
    let public: RsaPublicKey = private.to_public_key();

    let n_b = bigint_to_bytes_be(public.n());
    let e_b = bigint_to_bytes_be(public.e());
    let n = base64url(&n_b);
    let e = base64url(&e_b);

    let kid = uuid::Uuid::new_v4().to_string();
    let public_jwk = serde_json::json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": n,
        "e": e,
    });

    let der = private
        .to_pkcs1_der()
        .expect("encode pkcs1 der")
        .as_bytes()
        .to_vec();

    RsaKeyMaterial {
        kid,
        private_der: Arc::new(der),
        public_jwk,
    }
}

pub async fn ensure_initialized() {
    let mut guard = ACTIVE_KEYS.write().await;
    if guard.is_empty() {
        guard.push(generate_rsa_key().await);
    }
}

pub async fn current_signing_key() -> (String, jsonwebtoken::EncodingKey) {
    ensure_initialized().await;
    let guard = ACTIVE_KEYS.read().await;
    let key = guard.first().expect("signing key present").clone();
    (
        key.kid.clone(),
        jsonwebtoken::EncodingKey::from_rsa_der(&key.private_der),
    )
}

pub async fn jwks_document() -> serde_json::Value {
    ensure_initialized().await;
    let guard = ACTIVE_KEYS.read().await;
    let keys: Vec<serde_json::Value> = guard.iter().map(|k| k.public_jwk.clone()).collect();
    serde_json::json!({ "keys": keys })
}
