//! Pass-sharing channels: distributing an existing pass's share link over
//! WhatsApp/SMS, plus a standalone PDF pass-card generator.
//!
//! `whatsapp` and `sms` implement `visitorpass_application::ports::ShareChannel`.
//! `pdf` is a plain function -- a PDF is a document to download, not a
//! delivery channel.

pub mod pdf;
pub mod sms;
pub mod whatsapp;

pub use pdf::generate_pass_pdf;
pub use sms::{Msg91HttpClient, NoopSmsHttpClient, SmsHttpClient, SmsShareChannel};
pub use whatsapp::{build_whatsapp_link, WhatsAppShareChannel};
