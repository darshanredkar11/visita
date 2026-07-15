#[cfg(test)]
mod e2e_tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use serde_json::json;
    use std::sync::Arc;
    use uuid::Uuid;
    use chrono::{Utc, Duration};

    use crate::{
        config::AppConfig,
        router::build_router,
        state::AppState,
    };

    // Helper: setup mock environment and seed data
    async fn setup_test_env() -> Option<(axum::Router, sqlx::PgPool, Uuid, Uuid, Uuid, String)> {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://visitorpass:CHANGEME@localhost:5432/visitorpass".to_string());

        let db_pool = sqlx::PgPool::connect(&database_url).await.map_err(|e| {
            eprintln!("Failed to connect to DB at '{}': {:?}", database_url, e);
            e
        }).ok()?;

        let org_id = Uuid::now_v7();
        let location_id = Uuid::now_v7();
        let user_id = Uuid::now_v7();
        let org_slug = format!("e2e-test-org-{}", Uuid::new_v4());
        let user_email = format!("mock_e2e_test_{}@visitorpass.app", Uuid::new_v4());

        // Seed Organization
        sqlx::query("INSERT INTO app.organizations (id, name, slug) VALUES ($1, 'E2E Test Org', $2)")
            .bind(org_id)
            .bind(&org_slug)
            .execute(&db_pool)
            .await
            .map_err(|e| { eprintln!("Seed Org DB Error: {:?}", e); e })
            .ok()?;

        // Seed Location
        sqlx::query("INSERT INTO app.locations (id, org_id, name, status) VALUES ($1, $2, 'Test Location', 'ACTIVE')")
            .bind(location_id)
            .bind(org_id)
            .execute(&db_pool)
            .await
            .map_err(|e| { eprintln!("Seed Location DB Error: {:?}", e); e })
            .ok()?;

        // Seed User
        sqlx::query("INSERT INTO app.users (id, email, full_name, role) VALUES ($1, $2, 'E2E User', 'RESIDENT')")
            .bind(user_id)
            .bind(&user_email)
            .execute(&db_pool)
            .await
            .map_err(|e| { eprintln!("Seed User DB Error: {:?}", e); e })
            .ok()?;

        // Seed Membership
        sqlx::query("INSERT INTO app.memberships (org_id, user_id, role, unit_identifier, status) VALUES ($1, $2, 'RESIDENT', 'Flat 101', 'ACTIVE')")
            .bind(org_id)
            .bind(user_id)
            .execute(&db_pool)
            .await
            .map_err(|e| { eprintln!("Seed Membership DB Error: {:?}", e); e })
            .ok()?;

        let config = AppConfig {
            host: "0.0.0.0".to_string(),
            port: 8080,
            database_url: database_url.clone(),
            database_max_connections: 5,
            database_min_connections: 1,
            master_key_hex: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string(),
            base_url: "http://localhost:8080".to_string(),
            env: "development".to_string(),
            default_retention_days: 90,
            sms_enabled: false,
            email_enabled: false,
            google_client_id: "test-google-client-id.apps.googleusercontent.com".to_string(),
        };

        std::env::set_var("MASTER_KEY_HEX", &config.master_key_hex);
        let key_provider: Arc<dyn visitorpass_application::ports::KeyProvider> = Arc::new(
            visitorpass_infrastructure::key_provider::env_key_provider::EnvKeyProvider::from_env()
        );

        let crypto: Arc<dyn visitorpass_application::ports::CryptoService> = Arc::new(
            visitorpass_infrastructure::crypto::service::DefaultCryptoService::new(Arc::clone(&key_provider))
        );

        let orgs: Arc<dyn visitorpass_application::ports::OrgRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgOrgRepository::new(db_pool.clone()));
        let users: Arc<dyn visitorpass_application::ports::UserRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgUserRepository::new(db_pool.clone()));
        let passes: Arc<dyn visitorpass_application::ports::PassRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgPassRepository::new(db_pool.clone()));
        let entries: Arc<dyn visitorpass_application::ports::EntryRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgEntryRepository::new(db_pool.clone()));
        let devices: Arc<dyn visitorpass_application::ports::DeviceRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgDeviceRepository::new(db_pool.clone()));
        let locations: Arc<dyn visitorpass_application::ports::LocationRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgLocationRepository::new(db_pool.clone()));
        let audit: Arc<dyn visitorpass_application::ports::AuditRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgAuditRepository::new(db_pool.clone()));

        let create_pass = Arc::new(visitorpass_application::use_cases::CreatePassUseCase::new(
            Arc::clone(&passes),
            Arc::clone(&orgs),
            Arc::clone(&crypto),
            Arc::clone(&audit),
            config.base_url.clone(),
        ));
        let verify_pass = Arc::new(visitorpass_application::use_cases::VerifyPassUseCase::new(
            Arc::clone(&passes),
            Arc::clone(&orgs),
            Arc::clone(&crypto),
            Arc::clone(&audit),
        ));
        let revoke_pass = Arc::new(visitorpass_application::use_cases::RevokePassUseCase::new(
            Arc::clone(&passes),
            Arc::clone(&orgs),
            Arc::clone(&audit),
        ));
        let register_org = Arc::new(visitorpass_application::use_cases::RegisterOrganizationUseCase::new(
            Arc::clone(&orgs),
            Arc::clone(&users),
            Arc::clone(&crypto),
            Arc::clone(&audit),
        ));
        let register_device = Arc::new(visitorpass_application::use_cases::RegisterDeviceUseCase::new(
            Arc::clone(&devices),
            Arc::clone(&orgs),
            Arc::clone(&audit),
        ));
        let revoke_device = Arc::new(visitorpass_application::use_cases::RevokeDeviceUseCase::new(
            Arc::clone(&devices),
            Arc::clone(&audit),
        ));
        let sync_events = Arc::new(visitorpass_application::use_cases::SyncEventsUseCase::new(
            Arc::clone(&devices),
            Arc::clone(&passes),
            Arc::clone(&entries),
            Arc::clone(&orgs),
            Arc::clone(&audit),
        ));

        let (broadcast_tx, _) = tokio::sync::broadcast::channel(1024);

        let state = AppState {
            config,
            db_pool: db_pool.clone(),
            key_provider,
            crypto,
            create_pass,
            verify_pass,
            revoke_pass,
            register_org,
            register_device,
            revoke_device,
            sync_events,
            orgs,
            users,
            passes,
            entries,
            devices,
            locations,
            audit,
            broadcast_tx,
            rate_limiter: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        };

        let app = build_router(state);

        // Get Global Token
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/google")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&json!({
                    "id_token": "mock_mock_e2e_test@visitorpass.app"
                })).unwrap()
            ))
            .unwrap();

        let response = app.clone().oneshot(req).await.ok()?;
        let body_bytes = axum::body::to_bytes(response.into_body(), 10000).await.ok()?;
        let auth_res: serde_json::Value = serde_json::from_slice(&body_bytes).ok()?;
        let global_token = auth_res["access_token"].as_str()?;

        // Exchange for scoped token
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/select-org")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", global_token))
            .body(Body::from(
                serde_json::to_string(&json!({
                    "org_id": org_id
                })).unwrap()
            ))
            .unwrap();

        let response = app.clone().oneshot(req).await.ok()?;
        let body_bytes = axum::body::to_bytes(response.into_body(), 10000).await.ok()?;
        let select_res: serde_json::Value = serde_json::from_slice(&body_bytes).ok()?;
        let scoped_token = select_res["access_token"].as_str()?.to_string();

        Some((app, db_pool, org_id, location_id, user_id, scoped_token))
    }

    async fn teardown_test_env(db_pool: &sqlx::PgPool, org_id: Uuid, user_id: Uuid, location_id: Uuid) {
        sqlx::query("DELETE FROM app.memberships WHERE org_id = $1").bind(org_id).execute(db_pool).await.ok();
        sqlx::query("DELETE FROM app.users WHERE id = $1").bind(user_id).execute(db_pool).await.ok();
        sqlx::query("DELETE FROM app.locations WHERE id = $1").bind(location_id).execute(db_pool).await.ok();
        sqlx::query("DELETE FROM app.organizations WHERE id = $1").bind(org_id).execute(db_pool).await.ok();
    }

    // SCENARIO 1: Standard End-To-End Pass Flow (Creation & Token parsing)
    #[tokio::test]
    async fn test_e2e_pass_lifecycle() {
        let (app, db_pool, org_id, location_id, user_id, scoped_token) = match setup_test_env().await {
            Some(res) => res,
            None => return,
        };

        // Create pass
        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/organizations/{}/passes", org_id))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", scoped_token))
            .body(Body::from(
                serde_json::to_string(&json!({
                    "visitor_name": "E2E Guest",
                    "visitor_phone": "+91 99999 99999",
                    "valid_from": "2026-07-10T12:00:00Z",
                    "valid_until": "2026-07-10T18:00:00Z"
                })).unwrap()
            ))
            .unwrap();

        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let body_bytes = axum::body::to_bytes(response.into_body(), 10000).await.unwrap();
        let pass_res: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let pass_number = pass_res["pass_number"].as_str().expect("Pass number should exist");
        assert!(pass_number.starts_with("VP-"));

        teardown_test_env(&db_pool, org_id, user_id, location_id).await;
    }

    // SCENARIO 2: Input Combinations & Validity Validation Check
    #[tokio::test]
    async fn test_pass_creation_invalid_times() {
        let (app, db_pool, org_id, location_id, user_id, scoped_token) = match setup_test_env().await {
            Some(res) => res,
            None => return,
        };

        // valid_until set in the past relative to valid_from
        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/organizations/{}/passes", org_id))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", scoped_token))
            .body(Body::from(
                serde_json::to_string(&json!({
                    "visitor_name": "Error Guest",
                    "visitor_phone": "+91 99999 99999",
                    "valid_from": "2026-07-10T12:00:00Z",
                    "valid_until": "2026-07-09T12:00:00Z" 
                })).unwrap()
            ))
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert!(response.status().is_client_error());

        teardown_test_env(&db_pool, org_id, user_id, location_id).await;
    }

    // SCENARIO 3: Ad-Hoc Visitor Real-time Approval State Loop
    #[tokio::test]
    async fn test_ad_hoc_approval_lifecycle() {
        let (app, db_pool, org_id, location_id, user_id, scoped_token) = match setup_test_env().await {
            Some(res) => res,
            None => return,
        };

        // Guard requests approval
        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/organizations/{}/entries/request-approval", org_id))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", scoped_token))
            .body(Body::from(
                serde_json::to_string(&json!({
                    "visitor_name": "Ad-Hoc Guest",
                    "visitor_phone": "+91 88888 88888",
                    "location_id": location_id,
                    "unit_identifier": "Flat 402"
                })).unwrap()
            ))
            .unwrap();

        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let body_bytes = axum::body::to_bytes(response.into_body(), 10000).await.unwrap();
        let res: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let approval_id_str = res["approval_id"].as_str().unwrap();
        let approval_id = Uuid::parse_str(approval_id_str).unwrap();

        // Confirm DB status is PENDING
        let status: String = sqlx::query_scalar("SELECT status FROM app.ad_hoc_approvals WHERE id = $1")
            .bind(approval_id)
            .fetch_one(&db_pool)
            .await
            .unwrap();
        assert_eq!(status, "PENDING");

        // Resident approves
        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/organizations/{}/entries/{}/approve", org_id, approval_id))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", scoped_token))
            .body(Body::from(
                serde_json::to_string(&json!({
                    "approved": true
                })).unwrap()
            ))
            .unwrap();

        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Confirm DB status is APPROVED
        let status: String = sqlx::query_scalar("SELECT status FROM app.ad_hoc_approvals WHERE id = $1")
            .bind(approval_id)
            .fetch_one(&db_pool)
            .await
            .unwrap();
        assert_eq!(status, "APPROVED");

        // Re-approving should fail
        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/organizations/{}/entries/{}/approve", org_id, approval_id))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", scoped_token))
            .body(Body::from(
                serde_json::to_string(&json!({
                    "approved": true
                })).unwrap()
            ))
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert!(response.status().is_client_error());

        teardown_test_env(&db_pool, org_id, user_id, location_id).await;
    }

    #[tokio::test]
    async fn test_idempotency_key_replay() {
        let (app, db_pool, org_id, location_id, user_id, scoped_token) =
            setup_test_env().await.expect("Failed to setup test environment");

        let idempotency_key = Uuid::new_v4().to_string();

        let create_pass_payload = json!({
            "visitor_name": "Idempotent Guest",
            "visitor_phone": "9876543210",
            "valid_from": (Utc::now() + Duration::minutes(5)).to_rfc3339(),
            "valid_to": (Utc::now() + Duration::hours(2)).to_rfc3339(),
            "location_ids": [location_id],
        });

        // 1. First POST request
        let req1 = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/organizations/{}/passes", org_id))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", scoped_token))
            .header("Idempotency-Key", &idempotency_key)
            .body(Body::from(serde_json::to_string(&create_pass_payload).unwrap()))
            .unwrap();

        let response1 = app.clone().oneshot(req1).await.unwrap();
        assert_eq!(response1.status(), StatusCode::CREATED);
        assert!(response1.headers().get("Idempotent-Replay").is_none());

        let body_bytes1 = axum::body::to_bytes(response1.into_body(), 10_000_000).await.unwrap();
        let body1: serde_json::Value = serde_json::from_slice(&body_bytes1).unwrap();

        // 2. Second POST request (replay)
        let req2 = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/organizations/{}/passes", org_id))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", scoped_token))
            .header("Idempotency-Key", &idempotency_key)
            .body(Body::from(serde_json::to_string(&create_pass_payload).unwrap()))
            .unwrap();

        let response2 = app.oneshot(req2).await.unwrap();
        assert_eq!(response2.status(), StatusCode::CREATED);
        
        // Assert cache header hit
        let replay_header = response2.headers().get("Idempotent-Replay");
        assert!(replay_header.is_some());
        assert_eq!(replay_header.unwrap().to_str().unwrap(), "true");

        let body_bytes2 = axum::body::to_bytes(response2.into_body(), 10_000_000).await.unwrap();
        let body2: serde_json::Value = serde_json::from_slice(&body_bytes2).unwrap();

        // Verify body contains the exact same data
        assert_eq!(body1, body2);

        // Verify DB only has 1 pass created
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM app.visitor_passes WHERE visitor_name = 'Idempotent Guest'")
            .fetch_one(&db_pool)
            .await
            .unwrap();
        assert_eq!(count, 1);

        teardown_test_env(&db_pool, org_id, user_id, location_id).await;
    }
}
