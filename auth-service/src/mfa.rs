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
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};

use crate::AppState;
use crate::security_logging::{SecurityEvent, SecurityEventType, SecurityLogger, SecuritySeverity};
use crate::otp_provider::{MockSender, OtpSender, TwilioSender};

// Declare the crypto module
pub mod crypto;
use crate::mfa::crypto::SecretManager;

// Re-export the comprehensive MFA modules
// Note: comprehensive MFA modules exist in src/mfa/* but are not compiled by default here to keep build lean

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
    backup_codes: HashSet<String>,  // Stores hashed backup codes
}

static MFA_STORE: Lazy<RwLock<HashMap<String, TotpRecord>>> = Lazy::new(|| RwLock::new(HashMap::new()));

async fn redis_conn() -> Option<redis::aio::ConnectionManager> {
    let url = std::env::var("REDIS_URL").ok()?;
    let client = redis::Client::open(url).ok()?;
    (client.get_connection_manager().await).ok()
}

async fn persist_secret(user_id: &str, secret: &[u8]) {
    // Encrypt secret before persisting
    let manager = SecretManager::from_env().unwrap_or_default();
    if let Ok(enc) = manager.encrypt_secret(secret).await {
        if let Some(mut conn) = redis_conn().await {
            let key = format!("mfa:totp:{}:secret", user_id);
            let ttl = std::env::var("MFA_TOTP_SECRET_TTL_SECS").ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
            let payload = serde_json::to_string(&enc).unwrap_or_default();
            if ttl > 0 {
                let _ = redis::cmd("SETEX")
                    .arg(&key)
                    .arg(ttl)
                    .arg(payload)
                    .query_async::<i64>(&mut conn)
                    .await
                    .ok();
            } else {
                let _ = redis::cmd("SET")
                    .arg(&key)
                    .arg(payload)
                    .query_async::<String>(&mut conn)
                    .await
                    .ok();
            }
        }
    }
}

// Removed unused load_secret function

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

async fn set_last_verified(user_id: &str) {
    if let Some(mut conn) = redis_conn().await {
        let key = format!("mfa:last_verified:{}", user_id);
        let now = now_unix() as i64;
        let _ = redis::cmd("SET")
            .arg(&key)
            .arg(now)
            .query_async::<String>(&mut conn)
            .await
            .ok();
    }
}

/// Track a used TOTP code to prevent replay attacks
async fn track_totp_nonce(user_id: &str, code: &str, _time_window: u64) -> bool {
    if let Some(mut conn) = redis_conn().await {
        // Create a unique key for this user's TOTP nonce tracking
        let nonce_key = format!("mfa:totp:nonce:{}:{}", user_id, code);

        // Try to set the nonce with a TTL of 120 seconds (4 TOTP windows)
        // This ensures codes can't be reused within the replay window
        match redis::cmd("SET")
            .arg(&nonce_key)
            .arg("used")
            .arg("EX")
            .arg(120) // 120 seconds TTL to cover 4 TOTP windows
            .arg("NX") // Only set if not exists
            .query_async::<String>(&mut conn)
            .await
        {
            Ok(_) => {
                // Successfully set the nonce, code hasn't been used
                true
            }
            Err(_) => {
                // Failed to set nonce (already exists), code has been used
                false
            }
        }
    } else {
        // No Redis connection, fallback to allowing the code
        // In production, this should log a warning
        tracing::warn!("No Redis connection available for TOTP nonce tracking");
        true
    }
}

/// Check if a TOTP code has already been used (replay attack detection)
async fn is_totp_code_used(user_id: &str, code: &str) -> bool {
    if let Some(mut conn) = redis_conn().await {
        let nonce_key = format!("mfa:totp:nonce:{}:{}", user_id, code);

        // Check if the nonce exists
        match redis::cmd("EXISTS")
            .arg(&nonce_key)
            .query_async::<i64>(&mut conn)
            .await
        {
            Ok(exists) => exists == 1,
            Err(_) => false, // If we can't check, assume not used
        }
    } else {
        false // No Redis, assume not used
    }
}

pub async fn is_recently_verified(user_id: &str, window_secs: u64) -> bool {
    if let Some(mut conn) = redis_conn().await {
        let key = format!("mfa:last_verified:{}", user_id);
        if let Ok(Some(ts)) = redis::cmd("GET")
            .arg(&key)
            .query_async::<Option<i64>>(&mut conn)
            .await
        {
            let now = now_unix() as i64;
            return now.saturating_sub(ts) <= window_secs as i64;
        }
    }
    false
}

// Removed unused is_verified function

fn hash_backup_code(code: &str) -> String {
    // Use Argon2 for secure password hashing with salt
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2.hash_password(code.as_bytes(), &salt)
        .expect("Failed to hash backup code")
        .to_string()
}

fn verify_backup_code(code: &str, hash: &str) -> bool {
    // Verify a backup code against its Argon2 hash
    if let Ok(parsed_hash) = PasswordHash::new(hash) {
        let argon2 = Argon2::default();
        argon2.verify_password(code.as_bytes(), &parsed_hash).is_ok()
    } else {
        false
    }
}

async fn persist_backup_codes(user_id: &str, codes: &[String]) {
    if let Some(mut conn) = redis_conn().await {
        let key = format!("mfa:totp:{}:backup", user_id);
        let hashed: Vec<String> = codes.iter().map(|c| hash_backup_code(c)).collect();
        let _ = redis::cmd("DEL")
            .arg(&key)
            .query_async::<i64>(&mut conn)
            .await
            .ok();
        let _ = redis::cmd("SADD")
            .arg(&key)
            .arg(hashed)
            .query_async::<i64>(&mut conn)
            .await
            .ok();
        let ttl = std::env::var("MFA_TOTP_BACKUP_TTL_SECS").ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
        if ttl > 0 {
            let _ = redis::cmd("EXPIRE")
                .arg(&key)
                .arg(ttl)
                .query_async::<i64>(&mut conn)
                .await
                .ok();
        }
    }
}

async fn consume_backup_code(user_id: &str, code: &str) -> bool {
    if let Some(mut conn) = redis_conn().await {
        let key = format!("mfa:totp:{}:backup", user_id);

        // Fetch all hashed backup codes from Redis
        if let Ok(stored_hashes) = redis::cmd("SMEMBERS")
            .arg(&key)
            .query_async::<Vec<String>>(&mut conn)
            .await
        {
            // Find matching hash by verifying against each stored hash
            for stored_hash in stored_hashes {
                if verify_backup_code(code, &stored_hash) {
                    // Remove the matching hash
                    if let Ok(removed) = redis::cmd("SREM")
                        .arg(&key)
                        .arg(&stored_hash)
                        .query_async::<i64>(&mut conn)
                        .await
                    {
                        return removed > 0;
                    }
                }
            }
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
        if let Some(rec_w) = w.get_mut(&req.user_id) {
            // Find and remove the matching hashed backup code
            rec_w.backup_codes.retain(|hash| !verify_backup_code(&req.code, hash));
            rec_w.verified = true;
        }
        return Json(TotpVerifyResponse { verified: true });
    }
    let snapshot = { MFA_STORE.read().await.get(&req.user_id).cloned() };
    if let Some(rec) = snapshot.as_ref() {
        // Check backup codes in memory by verifying against hashes
        for hash in &rec.backup_codes {
            if verify_backup_code(&req.code, hash) {
                let mut w = MFA_STORE.write().await;
                if let Some(rec_w) = w.get_mut(&req.user_id) {
                    rec_w.backup_codes.remove(hash);
                    rec_w.verified = true;
                }
                return Json(TotpVerifyResponse { verified: true });
            }
        }
        // First check if this code has already been used (replay attack detection)
        if is_totp_code_used(&req.user_id, &req.code).await {
            // Log potential replay attack
            SecurityLogger::log_event(&SecurityEvent::new(
                SecurityEventType::MfaFailure,
                SecuritySeverity::High,
                "auth-service".to_string(),
                "TOTP replay attack detected".to_string(),
            )
            .with_actor("user".to_string())
            .with_action("mfa_verify".to_string())
            .with_target("mfa_token".to_string())
            .with_outcome("blocked".to_string())
            .with_reason("TOTP code already used - replay attack detected".to_string())
            .with_user_id(req.user_id.clone())
            .with_detail("code".to_string(), "REDACTED")
            .with_detail("attack_type".to_string(), "replay"));

            return Json(TotpVerifyResponse { verified: false });
        }

        let time = now_unix();
        let digits = 6u32;
        let mut code_is_valid = false;

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
                code_is_valid = true;
                break;
            }
        }

        if code_is_valid {
            // Track this code as used to prevent replay attacks
            if track_totp_nonce(&req.user_id, &req.code, 120).await {
                let mut w = MFA_STORE.write().await;
                if let Some(rec_w) = w.get_mut(&req.user_id) { rec_w.verified = true; }
                set_verified(&req.user_id).await;
                set_last_verified(&req.user_id).await;

                // Log successful TOTP verification
                SecurityLogger::log_event(&SecurityEvent::new(
                    SecurityEventType::MfaAttempt,
                    SecuritySeverity::Low,
                    "auth-service".to_string(),
                    "TOTP verification successful".to_string(),
                )
                .with_actor("user".to_string())
                .with_action("mfa_verify".to_string())
                .with_target("mfa_token".to_string())
                .with_outcome("success".to_string())
                .with_reason("TOTP code validated successfully".to_string())
                .with_user_id(req.user_id));

                return Json(TotpVerifyResponse { verified: true });
            } else {
                // Failed to track nonce (Redis issue or code already used)
                // Log this as a potential issue
                SecurityLogger::log_event(&SecurityEvent::new(
                    SecurityEventType::MfaFailure,
                    SecuritySeverity::Medium,
                    "auth-service".to_string(),
                    "TOTP nonce tracking failed".to_string(),
                )
                .with_actor("system".to_string())
                .with_action("mfa_verify".to_string())
                .with_target("mfa_token".to_string())
                .with_outcome("error".to_string())
                .with_reason("Redis nonce tracking failed - unable to prevent replay attacks".to_string())
                .with_user_id(req.user_id)
                .with_detail("reason".to_string(), "nonce_tracking_failed"));

                return Json(TotpVerifyResponse { verified: false });
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
    // Store hashed versions in memory
    entry.backup_codes = codes.iter().map(|c| hash_backup_code(c)).collect();
    Json(BackupCodesResponse { codes })
}


// --- SMS/Email OTP (mock delivery) ---
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OtpSendRequest {
    pub user_id: String,
    pub channel: String,      // "sms" | "email"
    pub destination: String,  // phone or email
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OtpSendResponse { pub sent: bool }

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OtpVerifyRequest {
    pub user_id: String,
    pub code: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OtpVerifyResponse { pub verified: bool }

fn hash_otp(code: &str) -> String { hash_backup_code(code) }
fn verify_otp(code: &str, hash: &str) -> bool { verify_backup_code(code, hash) }

fn generate_otp_code() -> String {
    let mut bytes = [0u8; 4];
    getrandom::getrandom(&mut bytes).expect("random");
    let num = u32::from_be_bytes(bytes) % 1_000_000; // 6 digits
    format!("{:06}", num)
}

pub async fn otp_send(State(_state): State<AppState>, Json(req): Json<OtpSendRequest>) -> Json<OtpSendResponse> {
    // simple rate limit: N sends per hour per user
    if let Some(mut conn) = redis_conn().await {
        let rl_key = format!("mfa:otp:rate:{}", req.user_id);
        let sends_per_hour: i64 = std::env::var("MFA_OTP_SENDS_PER_HOUR").ok().and_then(|s| s.parse::<i64>().ok()).unwrap_or(5);
        if let Ok(count) = redis::cmd("INCR").arg(&rl_key).query_async::<i64>(&mut conn).await {
            if count == 1 {
                let _ : Result<i64, _> = redis::cmd("EXPIRE").arg(&rl_key).arg(3600).query_async(&mut conn).await;
            }
            if count > sends_per_hour {
                tracing::warn!(target = "mfa", user = %req.user_id, "OTP rate limit exceeded");
                return Json(OtpSendResponse { sent: false });
            }
        }
    }
    let code = generate_otp_code();
    // persist hash with TTL
    if let Some(mut conn) = redis_conn().await {
        let key = format!("mfa:otp:{}", req.user_id);
        let ttl = std::env::var("MFA_OTP_TTL_SECS").ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(300);
        let _ = redis::cmd("SETEX")
            .arg(&key)
            .arg(ttl)
            .arg(hash_otp(&code))
            .query_async::<i64>(&mut conn)
            .await
            .ok();
    }
    // delivery via provider (mock or Twilio skeleton)
    let provider: Box<dyn OtpSender> = match std::env::var("OTP_SMS_PROVIDER").ok().as_deref() {
        Some("twilio") if req.channel.eq_ignore_ascii_case("sms") => {
            Box::new(TwilioSender {
                account_sid: std::env::var("TWILIO_ACCOUNT_SID").unwrap_or_default(),
                auth_token: std::env::var("TWILIO_AUTH_TOKEN").unwrap_or_default(),
                from: std::env::var("TWILIO_FROM_NUMBER").unwrap_or_default(),
            })
        }
        _ => Box::new(MockSender),
    };
    let send_res = if req.channel.eq_ignore_ascii_case("sms") {
        provider.send_sms(&req.destination, &format!("Your code is {}", code)).await
    } else {
        provider.send_email(&req.destination, "Your verification code", &format!("Code: {}", code)).await
    };
    if send_res.is_err() {
        tracing::warn!(target = "mfa", channel = %req.channel, destination = %req.destination, "OTP send failed");
        let event = SecurityEvent::new(
            SecurityEventType::MfaFailure,
            SecuritySeverity::Medium,
            "auth-service".to_string(),
            "OTP send failed".to_string(),
        )
        .with_actor("system".to_string())
        .with_action("mfa_generate".to_string())
        .with_target("otp_code".to_string())
        .with_outcome("failure".to_string())
        .with_reason("Failed to send OTP via delivery provider".to_string())
        .with_detail("channel".to_string(), req.channel.clone())
        .with_detail("destination".to_string(), "masked");
        SecurityLogger::log_event(&event);
        return Json(OtpSendResponse { sent: false });
    }
    let event = SecurityEvent::new(
        SecurityEventType::MfaAttempt,
        SecuritySeverity::Low,
        "auth-service".to_string(),
        "OTP sent".to_string(),
    )
    .with_actor("system".to_string())
    .with_action("mfa_generate".to_string())
    .with_target("otp_code".to_string())
    .with_outcome("success".to_string())
    .with_reason("OTP code generated and sent successfully".to_string())
    .with_detail("channel".to_string(), req.channel.clone())
    .with_detail("destination".to_string(), "masked");
    SecurityLogger::log_event(&event);
    Json(OtpSendResponse { sent: true })
}

pub async fn otp_verify(State(_state): State<AppState>, Json(req): Json<OtpVerifyRequest>) -> Json<OtpVerifyResponse> {
    if let Some(mut conn) = redis_conn().await {
        let key = format!("mfa:otp:{}", req.user_id);
        if let Ok(Some(stored)) = redis::cmd("GET").arg(&key).query_async::<Option<String>>(&mut conn).await {
            if verify_otp(&req.code, &stored) {
                let _ : Result<i64, _> = redis::cmd("DEL").arg(&key).query_async(&mut conn).await;
                set_verified(&req.user_id).await;
                set_last_verified(&req.user_id).await;
                let event = SecurityEvent::new(
                    SecurityEventType::MfaAttempt,
                    SecuritySeverity::Low,
                    "auth-service".to_string(),
                    "OTP verified".to_string(),
                )
                .with_actor("user".to_string())
                .with_action("mfa_verify".to_string())
                .with_target("otp_code".to_string())
                .with_outcome("success".to_string())
                .with_reason("OTP code verified successfully".to_string())
                .with_user_id(req.user_id.clone());
                SecurityLogger::log_event(&event);
                return Json(OtpVerifyResponse { verified: true });
            }
        }
    }
    let event = SecurityEvent::new(
        SecurityEventType::MfaFailure,
        SecuritySeverity::Medium,
        "auth-service".to_string(),
        "OTP verification failed".to_string(),
    )
    .with_actor("user".to_string())
    .with_action("mfa_verify".to_string())
    .with_target("otp_code".to_string())
    .with_outcome("failure".to_string())
    .with_reason("OTP code validation failed - invalid or expired code".to_string())
    .with_user_id(req.user_id);
    SecurityLogger::log_event(&event);
    Json(OtpVerifyResponse { verified: false })
}

// Mark current session/token as MFA-verified for a window; also record per-user last verified
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MfaSessionVerifyRequest { pub user_id: String }

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MfaSessionVerifyResponse { pub acknowledged: bool }

pub async fn mfa_session_verify(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<MfaSessionVerifyRequest>,
) -> Json<MfaSessionVerifyResponse> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = auth.strip_prefix("Bearer ").unwrap_or("");
    if !token.is_empty() {
        let window = std::env::var("MFA_VERIFIED_WINDOW_SECS").ok().and_then(|s| s.parse::<u64>().ok()).unwrap_or(300);
        let _ = state.token_store.set_mfa_verified(token, true, Some(window)).await;
    }
    set_last_verified(&body.user_id).await;
    let event = SecurityEvent::new(
        SecurityEventType::MfaAttempt,
        SecuritySeverity::Low,
        "auth-service".to_string(),
        "Session marked MFA-verified".to_string(),
    )
    .with_actor("user".to_string())
    .with_action("mfa_session_verify".to_string())
    .with_target("user_session".to_string())
    .with_outcome("success".to_string())
    .with_reason("Session MFA verification window established".to_string())
    .with_user_id(body.user_id);
    SecurityLogger::log_event(&event);
    Json(MfaSessionVerifyResponse { acknowledged: true })
}


