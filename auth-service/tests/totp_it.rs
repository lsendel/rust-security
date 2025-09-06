#![cfg(all(
    feature = "full-integration",
    feature = "api-keys",
    feature = "redis-sessions",
    feature = "crypto"
))]
// cfg moved to top of file
use auth_service::jwks_rotation::{InMemoryKeyStorage, JwksManager};
use auth_service::storage::session::store::RedisSessionStore;
use auth_service::storage::store::hybrid::HybridStore;
use auth_service::{api_key_store::ApiKeyStore, app, AppState};
use common::TokenRecord;
use data_encoding::BASE32;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256; // Use sha2::Sha256 instead of sha1::Sha1
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
// Removed unused import: use tokio::sync::RwLock;

type HmacSha256 = Hmac<Sha256>; // Change to Sha256

async fn spawn_app() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let api_key_store = ApiKeyStore::new("sqlite::memory:").await.unwrap();

    let store = Arc::new(HybridStore::new().await);
    let session_store = Arc::new(RedisSessionStore::new(None));
    let jwks_manager = Arc::new(
        JwksManager::new(
            auth_service::jwks_rotation::KeyRotationConfig::default(),
            Arc::new(InMemoryKeyStorage::new()),
        )
        .await
        .unwrap(),
    );

    let app = app(AppState {
        store,
        session_store,
        token_store: Arc::new(std::sync::RwLock::new(HashMap::<String, TokenRecord>::new())),
        client_credentials: Arc::new(std::sync::RwLock::new(HashMap::new())),
        allowed_scopes: Arc::new(std::sync::RwLock::new(std::collections::HashSet::new())),
        authorization_codes: Arc::new(std::sync::RwLock::new(HashMap::<String, String>::new())),
        policy_cache: std::sync::Arc::new(
            auth_service::storage::cache::policy_cache::PolicyCache::new(
                auth_service::storage::cache::policy_cache::PolicyCacheConfig::default(),
            ),
        ),
        backpressure_state: Arc::new(std::sync::RwLock::new(false)),
        api_key_store: Arc::new(api_key_store),
        jwks_manager,
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

#[derive(Serialize, Deserialize, Debug)]
struct TotpRegisterRequest {
    user_id: String,
}
#[derive(Serialize, Deserialize, Debug)]
struct TotpRegisterResponse {
    secret_base32: String,
    otpauth_url: String,
}
#[derive(Serialize, Deserialize, Debug)]
struct TotpVerifyRequest {
    user_id: String,
    code: String,
}
#[derive(Serialize, Deserialize, Debug)]
struct TotpVerifyResponse {
    verified: bool,
}
#[derive(Serialize, Deserialize, Debug)]
struct BackupCodesResponse {
    codes: Vec<String>,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut msg = [0u8; 8];
    msg.copy_from_slice(&counter.to_be_bytes());
    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(&msg);
    let hash = mac.finalize().into_bytes();
    let offset = (hash[19] & 0x0f) as usize;
    let bin_code: u32 = ((u32::from(hash[offset]) & 0x7f) << 24)
        | (u32::from(hash[offset + 1]) << 16)
        | (u32::from(hash[offset + 2]) << 8)
        | u32::from(hash[offset + 3]);
    bin_code
}

fn totp(secret: &[u8], time: u64, period: u64, digits: u32) -> String {
    let counter = time / period;
    let modulo = 10u32.pow(digits);
    let code = hotp(secret, counter) % modulo;
    let mut s = code.to_string();
    while s.len() < digits as usize {
        s = format!("0{s}");
    }
    s
}

#[tokio::test]
async fn totp_register_and_verify() {
    let base = spawn_app().await;
    let user_id = format!("u-{}", uuid::Uuid::new_v4());
    let client = reqwest::Client::new();

    let reg: TotpRegisterResponse = client
        .post(format!("{base}/mfa/totp/register"))
        .json(&TotpRegisterRequest {
            user_id: user_id.clone(),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(!reg.secret_base32.is_empty());
    assert!(reg.otpauth_url.starts_with("otpauth://totp/"));
    let secret = BASE32
        .decode(reg.secret_base32.as_bytes())
        .expect("decode base32");

    let code = totp(&secret, now_unix(), 30, 6);
    let verified: TotpVerifyResponse = client
        .post(format!("{base}/mfa/totp/verify"))
        .json(&TotpVerifyRequest {
            user_id: user_id.clone(),
            code,
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(verified.verified);
}

#[tokio::test]
async fn totp_backup_codes_flow() {
    let base = spawn_app().await;
    let user_id = format!("u-{}", uuid::Uuid::new_v4());
    let client = reqwest::Client::new();

    // register to create entry
    let _ = client
        .post(format!("{base}/mfa/totp/register"))
        .json(&TotpRegisterRequest {
            user_id: user_id.clone(),
        })
        .send()
        .await
        .unwrap();

    // generate backup codes
    let codes: BackupCodesResponse = client
        .post(format!("{base}/mfa/totp/backup-codes/generate"))
        .json(&TotpRegisterRequest {
            user_id: user_id.clone(),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(codes.codes.len(), 8);
    let code = codes.codes[0].clone();

    // verify using backup code should succeed once
    let res: TotpVerifyResponse = client
        .post(format!("{base}/mfa/totp/verify"))
        .json(&TotpVerifyRequest {
            user_id: user_id.clone(),
            code: code.clone(),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(res.verified);

    // reusing same backup code should fail
    let res2: TotpVerifyResponse = client
        .post(format!("{base}/mfa/totp/verify"))
        .json(&TotpVerifyRequest { user_id, code })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!res2.verified);
}
// removed stray cfg
