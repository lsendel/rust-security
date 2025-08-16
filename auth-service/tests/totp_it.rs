use auth_service::{app, store::TokenStore, AppState};
use data_encoding::BASE32;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

type HmacSha1 = Hmac<Sha1>;

async fn spawn_app() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();

    let app = app(AppState {
        token_store: TokenStore::InMemory(Arc::new(RwLock::new(HashMap::new()))),
        client_credentials: HashMap::new(),
        allowed_scopes: vec![],
        authorization_codes: Arc::new(RwLock::new(HashMap::new())),
    });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{}", addr)
}

#[derive(Serialize, Deserialize, Debug)]
struct TotpRegisterRequest { user_id: String }
#[derive(Serialize, Deserialize, Debug)]
struct TotpRegisterResponse { secret_base32: String, otpauth_url: String }
#[derive(Serialize, Deserialize, Debug)]
struct TotpVerifyRequest { user_id: String, code: String }
#[derive(Serialize, Deserialize, Debug)]
struct TotpVerifyResponse { verified: bool }
#[derive(Serialize, Deserialize, Debug)]
struct BackupCodesResponse { codes: Vec<String> }

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut msg = [0u8; 8];
    msg.copy_from_slice(&counter.to_be_bytes());
    let mut mac = HmacSha1::new_from_slice(secret).unwrap();
    mac.update(&msg);
    let hash = mac.finalize().into_bytes();
    let offset = (hash[19] & 0x0f) as usize;
    let bin_code: u32 = ((hash[offset] as u32 & 0x7f) << 24)
        | ((hash[offset + 1] as u32) << 16)
        | ((hash[offset + 2] as u32) << 8)
        | (hash[offset + 3] as u32);
    bin_code
}

fn totp(secret: &[u8], time: u64, period: u64, digits: u32) -> String {
    let counter = time / period;
    let modulo = 10u32.pow(digits);
    let code = hotp(secret, counter) % modulo;
    let mut s = code.to_string();
    while s.len() < digits as usize {
        s = format!("0{}", s);
    }
    s
}

#[tokio::test]
async fn totp_register_and_verify() {
    let base = spawn_app().await;
    let user_id = format!("u-{}", uuid::Uuid::new_v4());
    let client = reqwest::Client::new();

    let reg: TotpRegisterResponse = client
        .post(format!("{}/mfa/totp/register", base))
        .json(&TotpRegisterRequest { user_id: user_id.clone() })
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
        .post(format!("{}/mfa/totp/verify", base))
        .json(&TotpVerifyRequest { user_id: user_id.clone(), code })
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
        .post(format!("{}/mfa/totp/register", base))
        .json(&TotpRegisterRequest { user_id: user_id.clone() })
        .send()
        .await
        .unwrap();

    // generate backup codes
    let codes: BackupCodesResponse = client
        .post(format!("{}/mfa/totp/backup-codes/generate", base))
        .json(&TotpRegisterRequest { user_id: user_id.clone() })
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
        .post(format!("{}/mfa/totp/verify", base))
        .json(&TotpVerifyRequest { user_id: user_id.clone(), code: code.clone() })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(res.verified);

    // reusing same backup code should fail
    let res2: TotpVerifyResponse = client
        .post(format!("{}/mfa/totp/verify", base))
        .json(&TotpVerifyRequest { user_id, code })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!res2.verified);
}


