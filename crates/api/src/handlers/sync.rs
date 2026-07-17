use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    Extension,
};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use visitorpass_domain::{entities::DenialReason, value_objects::{OrgContext, Role}};
use visitorpass_application::ports::repositories::AuditEventInput;
use visitorpass_application::use_cases::sync_events::{SyncPushEvent, SyncRequest};
use visitorpass_infrastructure::db::postgres::rls::org_scoped_tx;

use crate::{errors::ApiError, state::{AppState, RealtimeEvent}};

#[derive(Debug, Deserialize)]
pub struct SyncRequestBody {
    pub device_id:     Uuid,
    pub last_sync_seq: i64,
    pub events:        Vec<SyncPushEventBody>,
}

#[derive(Debug, Deserialize)]
pub struct SyncPushEventBody {
    pub client_event_id: Uuid,
    pub event_type:      String,
    pub pass_id:         Uuid,
    pub action:          String,
    pub occurred_at:     chrono::DateTime<chrono::Utc>,
    pub location_id:     Uuid,
    pub denial_reason:   Option<String>,
    pub guard_note:      Option<String>,
}

/// POST /api/v1/sync
pub async fn sync(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgContext>,
    Json(body): Json<SyncRequestBody>,
) -> Result<impl IntoResponse, ApiError> {
    if body.events.len() > 500 {
        return Err(ApiError::validation("events", "maximum 500 events per sync request"));
    }

    // Validate denial_reason up front, for the WHOLE batch, before any
    // event is processed: an unrecognized value must reject the request
    // with 400 (and write zero rows), not get silently absorbed into
    // SyncEventsUseCase's per-event rejected-events bucket (which returns
    // 200 with a rejection_details entry -- correct for event-level
    // business errors, but not for a malformed request body).
    for event in &body.events {
        if let Some(reason) = &event.denial_reason {
            DenialReason::try_from(reason.as_str()).map_err(|_| {
                ApiError::validation(
                    "denial_reason",
                    &format!("unrecognized denial reason: {reason}"),
                )
            })?;
        }
    }

    let events: Vec<SyncPushEvent> = body.events.into_iter().map(|e| SyncPushEvent {
        client_event_id: e.client_event_id,
        event_type:      e.event_type,
        pass_id:         e.pass_id,
        action:          e.action,
        occurred_at:     e.occurred_at,
        location_id:     e.location_id,
        denial_reason:   e.denial_reason,
        guard_note:      e.guard_note,
    }).collect();

    let result = state.sync_events.execute(&ctx, SyncRequest {
        device_id:     body.device_id,
        last_sync_seq: body.last_sync_seq,
        events,
    }).await?;

    // Deliver the org's current active Ed25519 public key so guard devices
    // can verify pass signatures fully offline -- previously never sent,
    // forcing the mobile client to hardcode a mock key (see
    // GuardKioskDashboard.kt). Devices cache this locally and refresh it on
    // every sync; a key rotation propagates on the device's next sync.
    let org_key = state.orgs.find_active_key(ctx.org_id).await?;

    Ok(Json(serde_json::json!({
        "new_sync_seq":      result.new_sync_seq,
        "events":            result.pull_events,
        "accepted":          result.accepted,
        "rejected":          result.rejected,
        "rejection_details": result.rejection_details,
        "org_public_key":    hex::encode(&org_key.signing_public_key),
        "org_key_version":   org_key.version,
    })))
}

#[derive(Debug, Deserialize, validator::Validate)]
pub struct RequestApprovalRequest {
    #[validate(length(max = 200), custom(function = "crate::validation::validate_non_empty_trimmed"))]
    pub visitor_name:    String,
    #[validate(custom(function = "crate::validation::validate_e164_phone"))]
    pub visitor_phone:   String,
    pub location_id:     Uuid,
    #[validate(length(max = 100), custom(function = "crate::validation::validate_non_empty_trimmed"))]
    pub unit_identifier: String,
}

#[derive(Debug, Deserialize)]
pub struct ApproveEntryRequest {
    pub approved: bool,
}

/// GET /api/v1/sync/ws
/// Establishes a persistent, real-time WebSocket connection scoped to the caller's organization.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgContext>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state, ctx))
}


/// Verify org_id is properly scoped (not nil)
fn validate_org_context(ctx: &OrgContext) -> Result<(), ()> {
    if ctx.org_id.is_nil() {
        tracing::warn!("WebSocket connection attempted with unscoped org_id (nil)");
        return Err(());
    }
    Ok(())
}
async fn handle_socket(socket: WebSocket, state: AppState, ctx: OrgContext) {
    let (mut sender, mut receiver) = socket.split();
    
    // Validate that org_id is properly scoped (not nil)
    if validate_org_context(&ctx).is_err() {
        return;
    }
    
    let mut rx = state.broadcast_tx.subscribe();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));

    loop {
        tokio::select! {
            // 1. Receive broadcast event from memory
            res = rx.recv() => {
                match res {
                    Ok(event) => {
                        // Multi-tenant isolation boundary: only send events matching this client's org_id
                        if event.org_id == ctx.org_id {
                            let text = serde_json::to_string(&event.payload).unwrap_or_default();
                            if sender.send(Message::Text(text)).await.is_err() {
                                break; // Connection closed
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        tracing::warn!("WebSocket client lagged on broadcast queue");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break; // Channel closed
                    }
                }
            }

            // 2. Read messages from client (handle Ping/Pong or Close)
            msg_res = receiver.next() => {
                match msg_res {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(payload))) => {
                        if sender.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    _ => {}
                }
            }

            // 3. Keepalive ping
            _ = interval.tick() => {
                if sender.send(Message::Ping(Vec::new())).await.is_err() {
                    break;
                }
            }
        }
    }

    tracing::info!(user_id = %ctx.user_id, "WebSocket connection closed cleanly");
}

/// POST /api/v1/organizations/:org_id/entries/request-approval
/// Guard initiates an ad-hoc unexpected visitor approval request.
pub async fn request_approval(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgContext>,
    Json(req): Json<RequestApprovalRequest>,
) -> Result<impl IntoResponse, ApiError> {
    use validator::Validate;
    req.validate().map_err(crate::validation::validation_errors_to_api_error)?;

    let approval_id = Uuid::now_v7();

    // Hash (for lookup/dedup) + encrypt (for storage) the visitor phone,
    // mirroring app.visitor_passes' pattern exactly. The encryption key is
    // derived from `approval_id` itself (persisted as the row's own primary
    // key), so it can always be re-derived later to decrypt -- unlike
    // CreatePassUseCase's phone_enc, which is (separately, pre-existing)
    // derived from a throwaway UUID that's never stored anywhere.
    let visitor_phone_hmac = state.crypto.hmac_phone(&req.visitor_phone)?;
    let visitor_phone_enc = state.crypto.encrypt_phone(approval_id, &req.visitor_phone)?;

    let mut tx = org_scoped_tx(&state.db_pool, ctx.org_id).await?;
    sqlx::query(
        r#"
        INSERT INTO app.ad_hoc_approvals (id, org_id, location_id, visitor_name, visitor_phone_hmac, visitor_phone_enc, unit_identifier, status, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'PENDING', NOW(), NOW())
        "#
    )
    .bind(approval_id)
    .bind(ctx.org_id)
    .bind(req.location_id)
    .bind(&req.visitor_name)
    .bind(&visitor_phone_hmac)
    .bind(&visitor_phone_enc)
    .bind(&req.unit_identifier)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to create ad-hoc approval request");
        ApiError::internal()
    })?;
    tx.commit().await.map_err(|_| ApiError::internal())?;

    let payload = serde_json::json!({
        "event": "entry_pending",
        "approval_id": approval_id,
        "org_id": ctx.org_id,
        "visitor_name": req.visitor_name,
        "visitor_phone": req.visitor_phone,
        "unit_identifier": req.unit_identifier,
        "location_id": req.location_id,
    });

    let _ = state.broadcast_tx.send(RealtimeEvent {
        org_id: ctx.org_id,
        payload,
    });

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "status": "PENDING",
            "approval_id": approval_id,
        })),
    ))
}

/// POST /api/v1/organizations/:org_id/entries/:entry_id/approve
/// Resident approves or denies the pending unexpected visitor request.
pub async fn approve_entry(
    State(state): State<AppState>,
    Extension(ctx): Extension<OrgContext>,
    axum::extract::Path((_org_id, approval_id)): axum::extract::Path<(Uuid, Uuid)>,
    Json(req): Json<ApproveEntryRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let mut tx = org_scoped_tx(&state.db_pool, ctx.org_id).await?;

    // 1. Lookup approval request to get unit_identifier
    let approval: (Uuid, String) = sqlx::query_as(
        r#"
        SELECT id, unit_identifier
        FROM app.ad_hoc_approvals
        WHERE id = $1 AND org_id = $2 AND status = 'PENDING'
        "#
    )
    .bind(approval_id)
    .bind(ctx.org_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| ApiError::internal())?
    .ok_or_else(|| ApiError::validation("approval_id", "Pending approval request not found or already processed"))?;
    
    let (_approval_id, unit_identifier) = approval;
    
    // 2. Check if approver is OrgAdmin (role-based override)
    let is_admin_or_owner = ctx.role == Role::OrgAdmin;
    
    if !is_admin_or_owner {
        // 3. Verify approver's unit ownership
        let approver_unit: Option<String> = sqlx::query_scalar(
            r#"
            SELECT unit_identifier
            FROM app.org_memberships
            WHERE org_id = $1 AND user_id = $2
            "#
        )
        .bind(ctx.org_id)
        .bind(ctx.user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::internal())?;
        
        // Verify the approver manages this unit
        if approver_unit.as_ref() != Some(&unit_identifier) {
            return Err(ApiError::forbidden("Cannot approve visits for units you don't manage"));
        }
    }
    
    let status = if req.approved { "APPROVED" } else { "DENIED" };

    let rows_affected = sqlx::query(
        r#"
        UPDATE app.ad_hoc_approvals
        SET status = $1, updated_at = NOW()
        WHERE id = $2 AND org_id = $3 AND status = 'PENDING'
        "#
    )
    .bind(status)
    .bind(approval_id)
    .bind(ctx.org_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to update ad-hoc approval status");
        ApiError::internal()
    })?
    .rows_affected();
    tx.commit().await.map_err(|_| ApiError::internal())?;

    if rows_affected == 0 {
        return Err(ApiError::internal()); // Should not happen given earlier check
    }

    // 4. Create audit event
    let _ = state.audit.append(AuditEventInput {
        org_id: ctx.org_id,
        event_type: format!("entry_{}", if req.approved { "approved" } else { "denied" }),
        actor_user_id: Some(ctx.user_id),
        actor_device_id: None,
        target_entity_type: Some("ad_hoc_approval".to_string()),
        target_entity_id: Some(approval_id),
        metadata: serde_json::json!({
            "unit_identifier": unit_identifier,
        }),
        ip_address: None,
    }).await;

    let payload = serde_json::json!({
        "event": if req.approved { "entry_approved" } else { "entry_denied" },
        "approval_id": approval_id,
        "org_id": ctx.org_id,
    });

    let _ = state.broadcast_tx.send(RealtimeEvent {
        org_id: ctx.org_id,
        payload,
    });

    Ok(Json(serde_json::json!({
        "status": status,
        "approval_id": approval_id,
    })))
}
