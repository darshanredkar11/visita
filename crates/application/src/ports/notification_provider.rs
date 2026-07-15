use async_trait::async_trait;
use visitorpass_domain::DomainError;

/// Abstraction over notification delivery.
///
/// Native mobile sharing via OS share sheet is the primary mechanism.
/// This provider is used for server-initiated notifications:
/// - Invitations
/// - Password reset
/// - Optional automated pass notifications
#[async_trait]
pub trait NotificationProvider: Send + Sync + 'static {
    /// Send an SMS message.
    async fn send_sms(&self, to_e164: &str, body: &str) -> Result<(), DomainError>;

    /// Send an email.
    async fn send_email(&self, input: EmailInput) -> Result<(), DomainError>;
}

pub struct EmailInput {
    pub to:      String,
    pub subject: String,
    pub html:    String,
    pub text:    String,
}

/// A no-op provider for development and testing.
pub struct NoopNotificationProvider;

#[async_trait]
impl NotificationProvider for NoopNotificationProvider {
    async fn send_sms(&self, to: &str, body: &str) -> Result<(), DomainError> {
        tracing::debug!(to, body_len = body.len(), "NOOP: send_sms");
        Ok(())
    }

    async fn send_email(&self, input: EmailInput) -> Result<(), DomainError> {
        tracing::debug!(to = input.to, subject = input.subject, "NOOP: send_email");
        Ok(())
    }
}
