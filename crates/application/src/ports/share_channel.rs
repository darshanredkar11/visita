use async_trait::async_trait;
use chrono::{DateTime, Utc};
use visitorpass_domain::DomainError;

/// Abstraction over a channel that distributes an already-created pass's
/// share link to its visitor -- WhatsApp deep link, SMS, (future: email).
///
/// This is deliberately separate from `NotificationProvider`:
/// `NotificationProvider` is for server-initiated account/system messages
/// (invites, password reset). `ShareChannel` is specifically "hand this
/// pass's `share_url` to the visitor" and is invoked on demand from the
/// pass-share endpoint, never automatically.
///
/// Not a plugin system -- there are two implementations (WhatsApp, SMS) and
/// that is expected to stay true for the foreseeable future.
#[async_trait]
pub trait ShareChannel: Send + Sync + 'static {
    /// Machine-readable identifier matching the `channel` field the client
    /// sends to `POST .../passes/:pass_id/share`, e.g. `"whatsapp"`, `"sms"`.
    fn channel_name(&self) -> &'static str;

    /// Distribute `input.share_url` to `input.recipient_phone` over this
    /// channel. Implementations that are feature-flagged off (e.g. SMS when
    /// `sms_enabled=false`) MUST return `Ok(ShareResult { delivered: false, .. })`
    /// rather than an `Err` -- a disabled channel is a documented no-op, not
    /// a failure.
    async fn share(&self, input: SharePassInput) -> Result<ShareResult, DomainError>;
}

/// Everything a `ShareChannel` needs to build its message. Assembled by the
/// handler from the looked-up `VisitorPass` + `Organization`, so channel
/// implementations never touch a repository directly.
#[derive(Debug, Clone)]
pub struct SharePassInput {
    /// E.164 phone number (e.g. `+919876543210`).
    pub recipient_phone: String,
    pub visitor_name:    String,
    /// The public `/v/:pass_number` share page URL (see `CreatePassOutput::share_url`).
    pub share_url:       String,
    pub org_name:        String,
    pub valid_until:     DateTime<Utc>,
}

/// Result of a `ShareChannel::share` call.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareResult {
    pub channel: &'static str,
    /// True if the channel actually produced/dispatched something; false
    /// when it deliberately no-op'd (e.g. SMS disabled via config).
    pub delivered: bool,
    /// Channel-specific payload for the caller: the `https://wa.me/...`
    /// link for WhatsApp, the provider message id for SMS. `None` when
    /// `delivered` is false.
    pub detail: Option<String>,
}
