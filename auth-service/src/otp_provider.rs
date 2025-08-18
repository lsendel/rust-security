use async_trait::async_trait;

#[async_trait]
pub trait OtpSender: Send + Sync {
    async fn send_sms(&self, to: &str, msg: &str) -> anyhow::Result<()>;
    async fn send_email(&self, to: &str, subject: &str, body: &str) -> anyhow::Result<()>;
}

pub struct MockSender;

#[async_trait]
impl OtpSender for MockSender {
    async fn send_sms(&self, to: &str, _msg: &str) -> anyhow::Result<()> {
        tracing::info!(target="mfa", sms_to=%mask(to), "Mock SMS sent");
        Ok(())
    }
    async fn send_email(&self, to: &str, subject: &str, _body: &str) -> anyhow::Result<()> {
        tracing::info!(target="mfa", email_to=%mask(to), subject=%subject, "Mock Email sent");
        Ok(())
    }
}

fn mask(s: &str) -> String {
    let len = s.len();
    if len <= 4 {
        return "***".to_string();
    }
    format!("{}***{}", &s[..2], &s[len - 2..])
}

// Skeletons for real providers
pub struct TwilioSender {
    pub account_sid: String,
    pub auth_token: String,
    pub from: String,
}
#[async_trait]
impl OtpSender for TwilioSender {
    async fn send_sms(&self, to: &str, msg: &str) -> anyhow::Result<()> {
        let client = reqwest::Client::new();
        let url = format!(
            "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json",
            self.account_sid
        );
        let params = [("To", to), ("From", self.from.as_str()), ("Body", msg)];
        let _ = client
            .post(url)
            .basic_auth(&self.account_sid, Some(&self.auth_token))
            .form(&params)
            .send()
            .await?;
        Ok(())
    }
    async fn send_email(&self, _to: &str, _subject: &str, _body: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

pub struct SesSender {/* add AWS SDK client here */}
#[async_trait]
impl OtpSender for SesSender {
    async fn send_sms(&self, _to: &str, _msg: &str) -> anyhow::Result<()> {
        Ok(())
    }
    async fn send_email(&self, _to: &str, _subject: &str, _body: &str) -> anyhow::Result<()> {
        Ok(())
    }
}
