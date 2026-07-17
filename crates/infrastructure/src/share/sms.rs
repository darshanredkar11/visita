//! SMS delivery via MSG91's Flow API (India transactional SMS, DLT-template
//! based -- matches the `+91` phone numbers used throughout this codebase).
//!
//! Gated by `AppConfig.sms_enabled`; see [`SmsShareChannel::share`] for
//! where and why that check lives.

use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use visitorpass_application::ports::share_channel::{ShareChannel, SharePassInput, ShareResult};
use visitorpass_domain::DomainError;

/// Seam between `SmsShareChannel` and the actual wire call to the SMS
/// vendor. Nothing outside this file knows MSG91's request/response shape;
/// tests substitute a capturing fake here instead of touching the network.
/// Returns the vendor's message id on success.
#[async_trait]
pub trait SmsHttpClient: Send + Sync + 'static {
    async fn send_sms(&self, to_e164: &str, body: &str) -> Result<String, DomainError>;
}

/// Real MSG91 "Flow" API client (`POST https://api.msg91.com/api/v5/flow/`).
///
/// India requires a DLT-registered template for transactional SMS, so this
/// isn't a raw free-text send: `flow_id` identifies the pre-approved
/// template, whose single free-text variable (conventionally named `VAR1`)
/// carries the message body `SmsShareChannel` builds. This keeps the
/// `SmsHttpClient` trait's `(to, body)` contract simple while still being a
/// realistic, deployable MSG91 integration.
pub struct Msg91HttpClient {
    http:      reqwest::Client,
    auth_key:  String,
    sender_id: String,
    flow_id:   String,
}

impl Msg91HttpClient {
    pub fn new(auth_key: String, sender_id: String, flow_id: String) -> Self {
        Self { http: reqwest::Client::new(), auth_key, sender_id, flow_id }
    }
}

#[derive(Debug, Deserialize)]
struct Msg91Response {
    #[serde(rename = "type")]
    kind:    String,
    message: String,
}

#[async_trait]
impl SmsHttpClient for Msg91HttpClient {
    async fn send_sms(&self, to_e164: &str, body: &str) -> Result<String, DomainError> {
        // MSG91 mobiles are digits-only, country code first, no leading '+'.
        let mobile = to_e164.trim_start_matches('+');
        let payload = serde_json::json!({
            "flow_id": self.flow_id,
            "sender": self.sender_id,
            "recipients": [{ "mobiles": mobile, "VAR1": body }],
        });

        let resp = self
            .http
            .post("https://api.msg91.com/api/v5/flow/")
            .header("authkey", &self.auth_key)
            .json(&payload)
            .send()
            .await
            .map_err(|e| DomainError::ExternalServiceError(format!("MSG91 request failed: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(DomainError::ExternalServiceError(format!(
                "MSG91 returned HTTP {status}: {text}"
            )));
        }

        let parsed: Msg91Response = resp
            .json()
            .await
            .map_err(|e| DomainError::ExternalServiceError(format!("MSG91 response parse failed: {e}")))?;

        if parsed.kind != "success" {
            return Err(DomainError::ExternalServiceError(format!(
                "MSG91 rejected the request: {}",
                parsed.message
            )));
        }

        // On success, `message` carries MSG91's request id.
        Ok(parsed.message)
    }
}

fn build_message(input: &SharePassInput) -> String {
    format!(
        "{name}, {org} shared a visitor pass with you: {url} (valid until {until}).",
        name = input.visitor_name,
        org = input.org_name,
        url = input.share_url,
        until = input.valid_until.format("%d %b %Y %H:%M"),
    )
}

/// SMS `ShareChannel`.
///
/// The `sms_enabled` feature flag is checked HERE, inside `share()`, rather
/// than at each call site: this is the one place that owns "is SMS on"
/// semantics, so every caller (today: the `/passes/:pass_id/share` handler;
/// tomorrow: anything else) gets the documented no-op for free instead of
/// having to remember to gate the call themselves.
pub struct SmsShareChannel {
    enabled: bool,
    client:  Arc<dyn SmsHttpClient>,
}

impl SmsShareChannel {
    pub fn new(enabled: bool, client: Arc<dyn SmsHttpClient>) -> Self {
        Self { enabled, client }
    }

    /// Production constructor: wires the real MSG91 client.
    pub fn msg91(enabled: bool, auth_key: String, sender_id: String, flow_id: String) -> Self {
        Self::new(enabled, Arc::new(Msg91HttpClient::new(auth_key, sender_id, flow_id)))
    }

    /// Convenience for callers with no MSG91 credentials configured (yet) --
    /// test wiring, or a deployment that hasn't turned SMS on. Equivalent to
    /// `Self::new(false, ..)` with a client that can never actually be
    /// reached (the disabled check in `share()` always short-circuits
    /// first), so nothing needs to hand-roll a dummy `SmsHttpClient`.
    pub fn disabled() -> Self {
        Self::new(false, Arc::new(UnreachableSmsClient))
    }
}

struct UnreachableSmsClient;

#[async_trait]
impl SmsHttpClient for UnreachableSmsClient {
    async fn send_sms(&self, _to_e164: &str, _body: &str) -> Result<String, DomainError> {
        unreachable!("SmsShareChannel::disabled() must never invoke the underlying client")
    }
}

/// Harmless stand-in `SmsHttpClient` for test/dev wiring that needs
/// `enabled: true` (e.g. to mirror `AppConfig.sms_enabled` elsewhere in the
/// same test state) but must still never touch a real provider. Succeeds
/// immediately, no network call. Use `SmsShareChannel::disabled()` instead
/// when `enabled` should also be `false`.
pub struct NoopSmsHttpClient;

#[async_trait]
impl SmsHttpClient for NoopSmsHttpClient {
    async fn send_sms(&self, _to_e164: &str, _body: &str) -> Result<String, DomainError> {
        Ok("noop-test-message-id".to_string())
    }
}

#[async_trait]
impl ShareChannel for SmsShareChannel {
    fn channel_name(&self) -> &'static str {
        "sms"
    }

    async fn share(&self, input: SharePassInput) -> Result<ShareResult, DomainError> {
        if !self.enabled {
            tracing::debug!(
                to = %input.recipient_phone,
                "SMS_ENABLED=false: skipping SMS share (documented no-op)"
            );
            return Ok(ShareResult { channel: "sms", delivered: false, detail: None });
        }

        let body = build_message(&input);
        let message_id = self.client.send_sms(&input.recipient_phone, &body).await?;
        Ok(ShareResult { channel: "sms", delivered: true, detail: Some(message_id) })
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use parking_lot::Mutex;

    use super::*;

    #[derive(Default)]
    struct CapturingSmsClient {
        calls: Mutex<Vec<(String, String)>>,
    }

    #[async_trait]
    impl SmsHttpClient for CapturingSmsClient {
        async fn send_sms(&self, to_e164: &str, body: &str) -> Result<String, DomainError> {
            self.calls.lock().push((to_e164.to_string(), body.to_string()));
            Ok("fake-msg91-id-123".to_string())
        }
    }

    fn sample_input() -> SharePassInput {
        SharePassInput {
            recipient_phone: "+919876543210".to_string(),
            visitor_name:    "Asha".to_string(),
            share_url:       "https://visitorpass.app/v/VP-DEADBEEF".to_string(),
            org_name:        "Skyline Towers".to_string(),
            valid_until:     chrono::Utc.with_ymd_and_hms(2026, 7, 20, 18, 0, 0).unwrap(),
        }
    }

    #[tokio::test]
    async fn enabled_channel_invokes_the_client_with_correct_phone_and_body() {
        let client = Arc::new(CapturingSmsClient::default());
        let channel = SmsShareChannel::new(true, client.clone());

        let result = channel.share(sample_input()).await.unwrap();

        assert!(result.delivered);
        assert_eq!(result.channel, "sms");
        assert_eq!(result.detail.as_deref(), Some("fake-msg91-id-123"));

        let calls = client.calls.lock();
        assert_eq!(calls.len(), 1, "underlying client must be invoked exactly once");
        let (to, body) = &calls[0];
        assert_eq!(to, "+919876543210");
        assert!(body.contains("Asha"), "body must contain visitor name: {body}");
        assert!(body.contains("Skyline Towers"), "body must contain org name: {body}");
        assert!(
            body.contains("https://visitorpass.app/v/VP-DEADBEEF"),
            "body must contain the share url: {body}"
        );
    }

    #[tokio::test]
    async fn disabled_channel_is_a_documented_noop_and_never_calls_the_client() {
        let client = Arc::new(CapturingSmsClient::default());
        let channel = SmsShareChannel::new(false, client.clone());

        let result = channel.share(sample_input()).await.unwrap();

        assert!(!result.delivered);
        assert_eq!(result.channel, "sms");
        assert!(result.detail.is_none());
        assert!(
            client.calls.lock().is_empty(),
            "disabled SMS channel must never invoke the underlying HTTP client"
        );
    }

    #[test]
    fn channel_name_is_sms() {
        let client = Arc::new(CapturingSmsClient::default());
        assert_eq!(SmsShareChannel::new(true, client).channel_name(), "sms");
    }
}
