//! WhatsApp "click to chat" deep-link generator.
//!
//! Pure string building -- there is no WhatsApp Business API call here, no
//! network I/O, nothing to mock. The backend hands the resulting
//! `https://wa.me/...` URL back to the client (web/mobile), which opens it;
//! WhatsApp itself (installed app or web.whatsapp.com) takes over from there.

use async_trait::async_trait;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use visitorpass_application::ports::share_channel::{ShareChannel, SharePassInput, ShareResult};
use visitorpass_domain::DomainError;

/// Keep digits only: wa.me requires `<countrycode><number>` with no `+`,
/// spaces, or punctuation (e.g. `+91 98765-43210` -> `919876543210`).
fn digits_only(phone: &str) -> String {
    phone.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// The human-readable message embedded in the link's `text` param.
fn build_message(input: &SharePassInput) -> String {
    format!(
        "Hi {name}, {org} has shared a visitor pass with you. \
         View your pass here: {url} (valid until {until}).",
        name = input.visitor_name,
        org = input.org_name,
        url = input.share_url,
        until = input.valid_until.format("%d %b %Y, %I:%M %p UTC"),
    )
}

/// Builds a `https://wa.me/<digits>?text=<url-encoded message>` deep link.
///
/// Pure function, no I/O -- exposed standalone (rather than only through
/// `ShareChannel::share`) so it is directly unit-testable. The entire
/// `message` is percent-encoded as one opaque query-parameter value (per
/// RFC 3986 `query` component rules), including any URL embedded inside it
/// -- that inner URL is payload of `text=`, not part of the wa.me link's
/// own path/query structure, so its `/` and `:` must be encoded too.
pub fn build_whatsapp_link(phone: &str, message: &str) -> String {
    let digits = digits_only(phone);
    let encoded = utf8_percent_encode(message, NON_ALPHANUMERIC).to_string();
    format!("https://wa.me/{digits}?text={encoded}")
}

pub struct WhatsAppShareChannel;

impl WhatsAppShareChannel {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WhatsAppShareChannel {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ShareChannel for WhatsAppShareChannel {
    fn channel_name(&self) -> &'static str {
        "whatsapp"
    }

    async fn share(&self, input: SharePassInput) -> Result<ShareResult, DomainError> {
        let message = build_message(&input);
        let link = build_whatsapp_link(&input.recipient_phone, &message);
        Ok(ShareResult {
            channel:   "whatsapp",
            delivered: true,
            detail:    Some(link),
        })
    }
}

#[cfg(test)]
mod tests {
    use percent_encoding::percent_decode_str;

    use super::*;

    #[test]
    fn digits_only_strips_plus_spaces_and_dashes() {
        assert_eq!(digits_only("+91 98765-43210"), "919876543210");
    }

    #[test]
    fn link_decodes_back_to_the_exact_message() {
        let message = "Hi Alice, Acme Corp has shared a visitor pass: https://visitorpass.app/v/VP-ABC123 (valid until 16 Jul 2026).";
        let link = build_whatsapp_link("+919876543210", message);

        assert!(link.starts_with("https://wa.me/919876543210?text="));

        let encoded = link.strip_prefix("https://wa.me/919876543210?text=").unwrap();
        let decoded = percent_decode_str(encoded).decode_utf8().unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn special_characters_in_names_do_not_break_the_url() {
        // Ampersands, question marks, and unicode are exactly the characters
        // that corrupt a query string if left unencoded.
        let input = SharePassInput {
            recipient_phone: "+91 98765 43210".to_string(),
            visitor_name:    "O'Brien & Söns? <script>".to_string(),
            share_url:       "https://visitorpass.app/v/VP-XYZ789".to_string(),
            org_name:        "Café Résidences & Co.".to_string(),
            valid_until:     chrono::Utc::now(),
        };
        let message = build_message(&input);
        let link = build_whatsapp_link(&input.recipient_phone, &message);

        // No raw reserved/unsafe characters may leak into the query value.
        let query = link.strip_prefix("https://wa.me/919876543210?text=").unwrap();
        for forbidden in ['&', '?', '<', '>', ' ', '\''] {
            assert!(
                !query.contains(forbidden),
                "unencoded '{forbidden}' leaked into query string: {query}"
            );
        }

        // And the link is still exactly recoverable.
        let decoded = percent_decode_str(query).decode_utf8().unwrap();
        assert_eq!(decoded, message);
        assert!(decoded.contains("O'Brien & Söns? <script>"));
        assert!(decoded.contains("Café Résidences & Co."));
    }

    #[test]
    fn channel_name_is_whatsapp() {
        assert_eq!(WhatsAppShareChannel::new().channel_name(), "whatsapp");
    }

    #[tokio::test]
    async fn share_always_delivers_a_link() {
        let channel = WhatsAppShareChannel::new();
        let input = SharePassInput {
            recipient_phone: "+919876543210".to_string(),
            visitor_name:    "Bob".to_string(),
            share_url:       "https://visitorpass.app/v/VP-AAAA1111".to_string(),
            org_name:        "Test Org".to_string(),
            valid_until:     chrono::Utc::now(),
        };
        let result = channel.share(input).await.unwrap();
        assert!(result.delivered);
        assert_eq!(result.channel, "whatsapp");
        let detail = result.detail.expect("whatsapp share must return a link");
        assert!(detail.starts_with("https://wa.me/919876543210?text="));
    }
}
