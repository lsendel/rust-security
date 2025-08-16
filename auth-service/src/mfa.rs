use axum::{extract::State, Json};
use data_encoding::BASE32;
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use redis;

use crate::AppState;

type HmacSha1 = Hmac<Sha1>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpRegisterRequest {
    pub user_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpRegisterResponse {
    pub secret_base32: String,
    pub otpauth_url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpVerifyRequest {
    pub user_id: String,
    pub code: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpVerifyResponse {
    pub verified: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupCodesResponse {
    pub codes: Vec<String>,
}

#[derive(Clone, Debug)]
struct TotpRecord {
    secret: Vec<u8>,
    verified: bool,
    backup_codes: HashSet<String>,
}

static MFA_STORE: Lazy<RwLock<HashMap<String, TotpRecord>>> = Lazy::new(|| RwLock::new(HashMap::new()));

async fn redis_conn() -> Option<redis::aio::ConnectionManager> {
    let url = std::env::var("REDIS_URL").ok()?;
    let client = redis::Client::open(url).ok()?;
    (client.get_connection_manager().await).ok()
}

async fn persist_secret(user_id: &str, secret: &[u8]) {
    if let Some(mut conn) = redis_conn().await {
        let key = format!("mfa:totp:{}:secret", user_id);
        let _ = redis::cmd("SET")
            .arg(&key)
            .arg(BASE32.encode(secret))
            .query_async::<String>(&mut conn)
            .await
            .ok();
    }
}

#[allow(dead_code)]
async fn load_secret(user_id: &str) -> Option<Vec<u8>> {
    if let Some(mut conn) = redis_conn().await {
        let key = format!("mfa:totp:{}:secret", user_id);
        if let Ok(val) = redis::cmd("GET")
            .arg(&key)
            .query_async::<String>(&mut conn)
            .await
        {
            return BASE32.decode(val.as_bytes()).ok();
        }
    }
    None
}

async fn set_verified(user_id: &str) {
    if let Some(mut conn) = redis_conn().await {
        let key = format!("mfa:totp:{}:verified", user_id);
        let _ = redis::cmd("SET")
            .arg(&key)
            .arg("1")
            .query_async::<String>(&mut conn)
            .await
            .ok();
    }
}

#[allow(dead_code)]
async fn is_verified(user_id: &str) -> Option<bool> {
    if let Some(mut conn) = redis_conn().await {
        let key = format!("mfa:totp:{}:verified", user_id);
        if let Ok(v) = redis::cmd("GET")
            .arg(&key)
            .query_async::<String>(&mut conn)
            .await
        {
            return Some(v == "1");
        }
    }
    None
}

async fn persist_backup_codes(user_id: &str, codes: &[String]) {
    if let Some(mut conn) = redis_conn().await {
        let key = format!("mfa:totp:{}:backup", user_id);
        let _ = redis::cmd("DEL")
            .arg(&key)
            .query_async::<i64>(&mut conn)
            .await
            .ok();
        let _ = redis::cmd("SADD")
            .arg(&key)
            .arg(codes)
            .query_async::<i64>(&mut conn)
            .await
            .ok();
    }
}

async fn consume_backup_code(user_id: &str, code: &str) -> bool {
    if let Some(mut conn) = redis_conn().await {
        let key = format!("mfa:totp:{}:backup", user_id);
        if let Ok(removed) = redis::cmd("SREM")
            .arg(&key)
            .arg(code)
            .query_async::<i64>(&mut conn)
            .await
        {
            return removed > 0;
        }
    }
    false
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut msg = [0u8; 8];
    msg.copy_from_slice(&counter.to_be_bytes());
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(&msg);
    let hash = mac.finalize().into_bytes();
    let offset = (hash[19] & 0x0f) as usize;
    let bin_code: u32 = ((hash[offset] as u32 & 0x7f) << 24)
        | ((hash[offset + 1] as u32) << 16)
        | ((hash[offset + 2] as u32) << 8)
        | (hash[offset + 3] as u32);
    bin_code
}

fn totp(secret: &[u8], time: u64, period: u64, digits: u32) -> u32 {
    let counter = time / period;
    let code = hotp(secret, counter);
    let modulo = 10u32.pow(digits);
    code % modulo
}

fn format_code(code: u32, digits: u32) -> String {
    let mut s = code.to_string();
    while s.len() < digits as usize {
        s = format!("0{}", s);
    }
    s
}

pub async fn totp_register(State(_state): State<AppState>, Json(req): Json<TotpRegisterRequest>) -> Json<TotpRegisterResponse> {
    // 20-byte random secret
    let secret = {
        let mut bytes = vec![0u8; 20];
        getrandom::getrandom(&mut bytes).expect("random");
        bytes
    };
    let secret_b32 = BASE32.encode(&secret);
    let issuer = std::env::var("TOTP_ISSUER").unwrap_or_else(|_| "auth-service".to_string());
    let label = format!("{}:{}", &issuer, &req.user_id);
    let uri = format!(
        "otpauth://totp/{}?secret={}&issuer={}",
        urlencoding::encode(&label),
        secret_b32,
        urlencoding::encode(&issuer)
    );

    persist_secret(&req.user_id, &secret).await;
    let mut store = MFA_STORE.write().await;
    store.insert(req.user_id.clone(), TotpRecord { secret, verified: false, backup_codes: HashSet::new() });

    Json(TotpRegisterResponse {
        secret_base32: secret_b32,
        otpauth_url: uri,
    })
}

pub async fn totp_verify(State(_state): State<AppState>, Json(req): Json<TotpVerifyRequest>) -> Json<TotpVerifyResponse> {
    // Check backup code in Redis first
    if consume_backup_code(&req.user_id, &req.code).await {
        set_verified(&req.user_id).await;
        let mut w = MFA_STORE.write().await;
        if let Some(rec_w) = w.get_mut(&req.user_id) { rec_w.backup_codes.remove(&req.code); rec_w.verified = true; }
        return Json(TotpVerifyResponse { verified: true });
    }
    let store = MFA_STORE.read().await;
    if let Some(rec) = store.get(&req.user_id) {
        // check backup code first
        if rec.backup_codes.contains(&req.code) {
            drop(store);
            let mut w = MFA_STORE.write().await;
            if let Some(rec_w) = w.get_mut(&req.user_id) {
                rec_w.backup_codes.remove(&req.code);
                rec_w.verified = true;
            }
            return Json(TotpVerifyResponse { verified: true });
        }
        let time = now_unix();
        let digits = 6u32;
        for skew in [-1i64, 0, 1] {
            let t = if skew < 0 {
                time.saturating_sub(30)
            } else if skew > 0 {
                time.saturating_add(30)
            } else {
                time
            };
            let expected = format_code(totp(&rec.secret, t, 30, digits), digits);
            if expected == req.code {
                drop(store);
                let mut w = MFA_STORE.write().await;
                if let Some(rec_w) = w.get_mut(&req.user_id) { rec_w.verified = true; }
                set_verified(&req.user_id).await;
                return Json(TotpVerifyResponse { verified: true });
            }
        }
    }
    Json(TotpVerifyResponse { verified: false })
}

pub async fn totp_generate_backup_codes(State(_state): State<AppState>, Json(req): Json<TotpRegisterRequest>) -> Json<BackupCodesResponse> {
    // generate 8 codes, 10 chars each base32-like
    let mut codes = Vec::new();
    let alphabet = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no lookalikes
    for _ in 0..8 {
        let mut b = [0u8; 10];
        getrandom::getrandom(&mut b).expect("random");
        let code: String = b.iter().map(|x| alphabet[(*x as usize) % alphabet.len()] as char).collect();
        codes.push(code);
    }
    persist_backup_codes(&req.user_id, &codes).await;
    let mut w = MFA_STORE.write().await;
    let entry = w.entry(req.user_id).or_insert(TotpRecord { secret: vec![], verified: false, backup_codes: HashSet::new() });
    entry.backup_codes = codes.iter().cloned().collect();
    Json(BackupCodesResponse { codes })
}


