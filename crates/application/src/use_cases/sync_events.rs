use std::sync::Arc;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use visitorpass_domain::{
    entities::{DenialReason, VisitorPass},
    value_objects::OrgContext,
    DomainError,
};

use crate::ports::{
    crypto_service::CryptoService,
    notification_provider::NotificationProvider,
    repositories::{AuditEventInput, AuditRepository, CreateEntryInput, DeviceRepository,
                   EntryRepository, OrgRepository, PassRepository, UserRepository},
};

// ── Push event (device → server) ─────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct SyncPushEvent {
    pub client_event_id: Uuid,
    pub event_type:      String,
    pub pass_id:         Uuid,
    pub action:          String,
    pub occurred_at:     chrono::DateTime<Utc>,
    pub location_id:     Uuid,
    pub denial_reason:   Option<String>,
    pub guard_note:      Option<String>,
}

// ── Pull event (server → device) ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event_type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SyncPullEvent {
    PassRevoked {
        seq:        i64,
        pass_id:    Uuid,
        revoked_at: chrono::DateTime<Utc>,
    },
    PassCreated {
        seq:        i64,
        pass_id:    Uuid,
        qr_payload: String,
    },
    DeviceRevoked {
        seq:       i64,
        device_id: Uuid,
    },
    KeyRotated {
        seq:                   i64,
        key_version:           i32,
        signing_public_key_b64: String,
    },
}

impl SyncPullEvent {
    pub fn seq(&self) -> i64 {
        match self {
            SyncPullEvent::PassRevoked  { seq, .. } => *seq,
            SyncPullEvent::PassCreated  { seq, .. } => *seq,
            SyncPullEvent::DeviceRevoked{ seq, .. } => *seq,
            SyncPullEvent::KeyRotated   { seq, .. } => *seq,
        }
    }
}

// ── Request / Response ────────────────────────────────────────────────────────

pub struct SyncRequest {
    pub device_id:     Uuid,
    pub last_sync_seq: i64,
    pub events:        Vec<SyncPushEvent>,
}

pub struct SyncResult {
    pub new_sync_seq:      i64,
    pub pull_events:       Vec<SyncPullEvent>,
    pub accepted:          u32,
    pub rejected:          u32,
    pub rejection_details: Vec<RejectionDetail>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RejectionDetail {
    pub client_event_id: Uuid,
    pub reason:          String,
}

// ── Use Case ─────────────────────────────────────────────────────────────────

pub struct SyncEventsUseCase {
    devices:     Arc<dyn DeviceRepository>,
    passes:      Arc<dyn PassRepository>,
    entries:     Arc<dyn EntryRepository>,
    orgs:        Arc<dyn OrgRepository>,
    users:       Arc<dyn UserRepository>,
    crypto:      Arc<dyn CryptoService>,
    audit:       Arc<dyn AuditRepository>,
    notifier:    Arc<dyn NotificationProvider>,
    /// Mirrors `AppConfig::sms_enabled`. Gates the SMS fallback in
    /// `notify_resident_of_entry` -- consistent with how the rest of the
    /// codebase gates SMS sends off this same flag.
    sms_enabled: bool,
}

impl SyncEventsUseCase {
    pub fn new(
        devices:     Arc<dyn DeviceRepository>,
        passes:      Arc<dyn PassRepository>,
        entries:     Arc<dyn EntryRepository>,
        orgs:        Arc<dyn OrgRepository>,
        users:       Arc<dyn UserRepository>,
        crypto:      Arc<dyn CryptoService>,
        audit:       Arc<dyn AuditRepository>,
        notifier:    Arc<dyn NotificationProvider>,
        sms_enabled: bool,
    ) -> Self {
        Self { devices, passes, entries, orgs, users, crypto, audit, notifier, sms_enabled }
    }

    pub async fn execute(
        &self,
        ctx: &OrgContext,
        request: SyncRequest,
    ) -> Result<SyncResult, DomainError> {
        // ── 1. Verify device is active ─────────────────────────────────────
        let device = self.devices.find_by_id(ctx, request.device_id).await?;
        device.assert_active()?;

        // ── 2. Process PUSH events (entry/exit logs) ───────────────────────
        let mut accepted = 0u32;
        let mut rejected = 0u32;
        let mut rejection_details = Vec::new();

        for event in &request.events {
            match self.process_push_event(ctx, &device, event).await {
                Ok(true)  => accepted += 1,
                Ok(false) => {
                    // Idempotent duplicate — count as accepted
                    accepted += 1;
                }
                Err(e) => {
                    rejected += 1;
                    rejection_details.push(RejectionDetail {
                        client_event_id: event.client_event_id,
                        reason:          e.to_string(),
                    });
                    tracing::warn!(
                        device_id = %request.device_id,
                        client_event_id = %event.client_event_id,
                        error = %e,
                        "sync event rejected"
                    );
                }
            }
        }

        // ── 3. Fetch PULL events since last_sync_seq ───────────────────────
        let pull_events = self
            .build_pull_events(ctx, &device, request.last_sync_seq)
            .await?;

        // ── 4. Get the new sync_seq ────────────────────────────────────────
        let org = self.orgs.find_by_id(ctx, ctx.org_id).await?;
        let new_sync_seq = org.sync_seq;

        // ── 5. Update device sync checkpoint ──────────────────────────────
        self.devices
            .update_sync_checkpoint(request.device_id, ctx.org_id, new_sync_seq)
            .await?;
        self.devices.update_last_seen(request.device_id, ctx.org_id).await?;

        // ── 6. Audit ───────────────────────────────────────────────────────
        let _ = self.audit.append(AuditEventInput {
            org_id:             ctx.org_id,
            event_type:         "SYNC_COMPLETED".into(),
            actor_user_id:      Some(ctx.user_id),
            actor_device_id:    Some(request.device_id),
            target_entity_type: None,
            target_entity_id:   None,
            metadata:           serde_json::json!({
                "pushed":          accepted + rejected,
                "accepted":        accepted,
                "rejected":        rejected,
                "pulled":          pull_events.len(),
                "last_sync_seq":   request.last_sync_seq,
                "new_sync_seq":    new_sync_seq,
            }),
            ip_address: None,
        }).await;

        Ok(SyncResult {
            new_sync_seq,
            pull_events,
            accepted,
            rejected,
            rejection_details,
        })
    }

    async fn process_push_event(
        &self,
        ctx: &OrgContext,
        device: &visitorpass_domain::entities::Device,
        event: &SyncPushEvent,
    ) -> Result<bool, DomainError> {
        // Validate occurred_at is not in the future (allow 5-min clock skew)
        let max_future = Utc::now() + chrono::Duration::minutes(5);
        if event.occurred_at > max_future {
            return Err(DomainError::ValidationFailed {
                field:   "occurred_at".into(),
                message: "timestamp is in the future".into(),
            });
        }

        // Validate the client-supplied denial reason against the closed
        // enum (migration 027). The API handler already rejects the whole
        // HTTP request with 400 before any event reaches here (see
        // crates/api/src/handlers/sync.rs::sync) -- this is defense in
        // depth for any other caller of this use case.
        let denial_reason = match &event.denial_reason {
            Some(s) => Some(DenialReason::try_from(s.as_str())?),
            None => None,
        };

        // Check that the pass exists and belongs to this org
        let pass = self.passes.find_by_id(ctx, event.pass_id).await?;

        // Validate that the pass is still ACTIVE (not revoked or expired) --
        // except for DENIED events. A DENIED event's entire point is
        // recording that access was refused, often *because* the pass is no
        // longer valid; previously this check ran unconditionally, so a
        // legitimate "denied: pass expired" event from a guard device could
        // never be persisted -- check_valid() returned Err before
        // entries.create() ever ran, silently dropping it into the
        // rejected-events bucket (never durably recorded anywhere) instead
        // of the entry_logs audit trail.
        if event.action != "DENIED" {
            pass.check_valid(Utc::now())?;
        }
        // Check that the event's location matches device assignment
        if let Some(dev_loc) = device.location_id {
            if dev_loc != event.location_id {
                return Err(DomainError::LocationOrgMismatch);
            }
        }

        let entry = self.entries.create(ctx, CreateEntryInput {
            org_id:          ctx.org_id,
            location_id:     event.location_id,
            pass_id:         event.pass_id,
            device_id:       Some(device.id),
            guard_user_id:   Some(ctx.user_id),
            action:          event.action.clone(),
            denial_reason,
            guard_note:      event.guard_note.clone(),
            occurred_at:     event.occurred_at,
            client_event_id: event.client_event_id,
        }).await?;

        // `None` means idempotent duplicate; `Some(_)` means new entry
        if entry.is_some() && event.action == "ENTRY" {
            self.passes.increment_use_count(ctx, event.pass_id).await?;

            // Notification decision (v1): ENTRY only.
            // - EXIT: no clear "your visitor left" value for a resident;
            //   revisit if residents actually ask for exit confirmations.
            // - DENIED: the guard is standing at the gate when a pass is
            //   denied, so a push notification adds no real-time value the
            //   guard's own kiosk display doesn't already give -- and a
            //   denial "flood" (e.g. someone repeatedly retrying an expired
            //   pass) would spam the resident on every retry. A digest/
            //   summary notification would be the right shape for that, not
            //   a per-event push. Explicitly deferred, not an oversight.
            self.notify_resident_of_entry(ctx, &pass).await;
        }

        Ok(entry.is_some())
    }

    /// Best-effort notification to the resident who created `pass` that
    /// their visitor has arrived. Never fails the sync event: all errors
    /// are logged and swallowed, matching this file's existing
    /// `let _ = self.audit.append(..)` pattern for non-critical side effects.
    async fn notify_resident_of_entry(&self, ctx: &OrgContext, pass: &VisitorPass) {
        let devices = match self.devices.find_by_owner(ctx, pass.created_by).await {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(error = %e, pass_id = %pass.id, "failed to look up resident devices for entry notification");
                return;
            }
        };

        let title = "Visitor arrived";
        let message = format!("Your visitor {} has arrived", pass.visitor_name);

        if let Some(token) = devices.iter().find_map(|d| {
            d.push_token.as_deref().filter(|t| !t.is_empty())
        }) {
            if let Err(e) = self.notifier.send_push(token, title, &message).await {
                tracing::warn!(error = %e, pass_id = %pass.id, "push notification failed");
            }
            return;
        }

        if !self.sms_enabled {
            tracing::debug!(
                pass_id = %pass.id,
                resident_id = %pass.created_by,
                "no push token on any resident device and SMS disabled; skipping entry notification"
            );
            return;
        }

        // SMS fallback. NOTE: as of this writing, app.org_memberships.
        // phone_enc is never WRITTEN by any code path in this repo (no
        // invite/join-org flow captures+encrypts a member's phone yet), so
        // this will typically resolve to `Ok(None)` today. It's wired
        // correctly end-to-end (including decryption, keyed the same way
        // CreatePassUseCase keys visitor_phone_enc -- by the row's own
        // durable id) so it activates the moment a future phase populates
        // that column; see the final report for this phase's writeup of
        // the gap.
        match self.users.find_membership_phone_enc(pass.created_by, ctx.org_id).await {
            Ok(Some(phone_enc)) => {
                match self.crypto.decrypt_phone(pass.created_by, &phone_enc) {
                    Ok(phone) => {
                        if let Err(e) = self.notifier.send_sms(&phone, &message).await {
                            tracing::warn!(error = %e, pass_id = %pass.id, "SMS fallback notification failed");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, pass_id = %pass.id, "failed to decrypt resident phone for SMS fallback");
                    }
                }
            }
            Ok(None) => {
                tracing::debug!(
                    pass_id = %pass.id,
                    resident_id = %pass.created_by,
                    "no push token and no membership phone on file; entry notification not sent"
                );
            }
            Err(e) => {
                tracing::warn!(error = %e, pass_id = %pass.id, "failed to look up resident membership phone for SMS fallback");
            }
        }
    }

    async fn build_pull_events(
        &self,
        ctx: &OrgContext,
        device: &visitorpass_domain::entities::Device,
        since_seq: i64,
    ) -> Result<Vec<SyncPullEvent>, DomainError> {
        let mut events: Vec<SyncPullEvent> = Vec::new();

        // ── Revoked passes since last sync ─────────────────────────────────
        let revoked = self.passes.list_revoked_since(ctx.org_id, since_seq).await?;
        for (pass_id, revoked_at) in revoked {
            events.push(SyncPullEvent::PassRevoked {
                seq: since_seq + 1, // Simplified; real seq from DB
                pass_id,
                revoked_at,
            });
        }

        // ── New/updated passes for this location ───────────────────────────
        if let Some(location_id) = device.location_id {
            let new_passes = self.passes
                .list_for_sync(ctx.org_id, location_id, since_seq)
                .await?;
            for pass in new_passes {
                events.push(SyncPullEvent::PassCreated {
                    seq:        pass.sync_seq.unwrap_or(since_seq + 1),
                    pass_id:    pass.id,
                    qr_payload: pass.qr_payload,
                });
            }
        }

        // Sort by seq for deterministic ordering
        events.sort_by_key(|e| e.seq());

        Ok(events)
    }
}
