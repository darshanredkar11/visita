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
        // The pool actually wired into AppState/repositories -- MUST be the
        // least-privilege `visitorpass_app` role (migration 024), not the
        // superuser `database_url` above, or these tests would "pass"
        // while silently exercising the RLS superuser-bypass path instead
        // of proving RLS (migration 023) holds for the real runtime
        // connection. `database_url` above is still used directly for test
        // fixture seed/teardown, which legitimately needs to write rows
        // across arbitrary orgs.
        let app_database_url = std::env::var("APP_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://visitorpass_app:CHANGEME_APP_ROLE_PASSWORD@localhost:5432/visitorpass".to_string());

        let db_pool = sqlx::PgPool::connect(&database_url).await.map_err(|e| {
            eprintln!("Failed to connect to DB at '{}': {:?}", database_url, e);
            e
        }).ok()?;
        let app_db_pool = sqlx::PgPool::connect(&app_database_url).await.map_err(|e| {
            eprintln!("Failed to connect to DB at '{}': {:?}", app_database_url, e);
            e
        }).ok()?;

        let org_id = Uuid::now_v7();
        let location_id = Uuid::now_v7();
        let user_id = Uuid::now_v7();
        let org_slug = format!("e2e-test-org-{}", Uuid::new_v4());
        let user_email = format!("mock_e2e_test_{}@visitorpass.app", Uuid::new_v4());

        // Build key provider + crypto service FIRST: needed to generate the org's
        // Ed25519 signing key below, which CreatePassUseCase requires (find_active_key).
        let master_key_hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string();
        std::env::set_var("MASTER_KEY_HEX", &master_key_hex);
        let key_provider: Arc<dyn visitorpass_application::ports::KeyProvider> = Arc::new(
            visitorpass_infrastructure::key_provider::env_key_provider::EnvKeyProvider::from_env()
        );
        let crypto: Arc<dyn visitorpass_application::ports::CryptoService> = Arc::new(
            visitorpass_infrastructure::crypto::service::DefaultCryptoService::new(Arc::clone(&key_provider))
        );

        // Seed Organization. org_type is NOT NULL with no default (app.org_type enum).
        sqlx::query("INSERT INTO app.organizations (id, name, org_type, slug) VALUES ($1, 'E2E Test Org', 'OFFICE', $2)")
            .bind(org_id)
            .bind(&org_slug)
            .execute(&db_pool)
            .await
            .map_err(|e| { eprintln!("Seed Org DB Error: {:?}", e); e })
            .ok()?;

        // Seed the org's active signing key. Without this, CreatePassUseCase::execute's
        // `self.orgs.find_active_key(ctx.org_id)` call returns Err(UnknownKeyVersion) and
        // every pass-creation request fails before ever reaching the idempotency/DB layer.
        let keypair = crypto.generate_org_keypair(org_id, 1).ok()?;
        sqlx::query(
            "INSERT INTO app.org_keys (id, org_id, version, signing_public_key, signing_private_key_enc, key_derivation_nonce, enc_algorithm) \
             VALUES ($1, $2, 1, $3, $4, $5, 'CHACHA20_POLY1305')"
        )
            .bind(Uuid::now_v7())
            .bind(org_id)
            .bind(&keypair.public_key_bytes)
            .bind(&keypair.encrypted_private_key)
            .bind(&keypair.nonce)
            .execute(&db_pool)
            .await
            .map_err(|e| { eprintln!("Seed OrgKey DB Error: {:?}", e); e })
            .ok()?;

        // Seed Location
        sqlx::query("INSERT INTO app.locations (id, org_id, name, status) VALUES ($1, $2, 'Test Location', 'ACTIVE')")
            .bind(location_id)
            .bind(org_id)
            .execute(&db_pool)
            .await
            .map_err(|e| { eprintln!("Seed Location DB Error: {:?}", e); e })
            .ok()?;

        // Seed User. app.users has no `role` column (role is per-org, lives on
        // org_memberships) and password_hash is NOT NULL with no default.
        sqlx::query("INSERT INTO app.users (id, email, password_hash, full_name) VALUES ($1, $2, 'unused-e2e-test-hash', 'E2E User')")
            .bind(user_id)
            .bind(&user_email)
            .execute(&db_pool)
            .await
            .map_err(|e| { eprintln!("Seed User DB Error: {:?}", e); e })
            .ok()?;

        // Seed Membership. The table is app.org_memberships, not app.memberships.
        sqlx::query("INSERT INTO app.org_memberships (org_id, user_id, role, unit_identifier, status) VALUES ($1, $2, 'RESIDENT', 'Flat 101', 'ACTIVE')")
            .bind(org_id)
            .bind(user_id)
            .execute(&db_pool)
            .await
            .map_err(|e| { eprintln!("Seed Membership DB Error: {:?}", e); e })
            .ok()?;

        let config = AppConfig {
            host: "0.0.0.0".to_string(),
            port: 8080,
            database_url: app_database_url.clone(),
            migration_database_url: None,
            database_max_connections: 5,
            database_min_connections: 1,
            master_key_hex: master_key_hex.clone(),
            base_url: "http://localhost:8080".to_string(),
            env: "development".to_string(),
            default_retention_days: 90,
            sms_enabled: false,
            sms_provider_api_key: None,
            sms_sender_id: None,
            sms_flow_id: None,
            email_enabled: false,
            google_client_id: "test-google-client-id.apps.googleusercontent.com".to_string(),
        };

        let orgs: Arc<dyn visitorpass_application::ports::OrgRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgOrgRepository::new(app_db_pool.clone()));
        let users: Arc<dyn visitorpass_application::ports::UserRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgUserRepository::new(app_db_pool.clone()));
        let passes: Arc<dyn visitorpass_application::ports::PassRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgPassRepository::new(app_db_pool.clone()));
        let entries: Arc<dyn visitorpass_application::ports::EntryRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgEntryRepository::new(app_db_pool.clone()));
        let devices: Arc<dyn visitorpass_application::ports::DeviceRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgDeviceRepository::new(app_db_pool.clone()));
        let locations: Arc<dyn visitorpass_application::ports::LocationRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgLocationRepository::new(app_db_pool.clone()));
        let audit: Arc<dyn visitorpass_application::ports::AuditRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgAuditRepository::new(app_db_pool.clone()));
        let platform_admins: Arc<dyn visitorpass_application::ports::PlatformAdminRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgPlatformAdminRepository::new(app_db_pool.clone()));

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
        let notifier: Arc<dyn visitorpass_application::ports::NotificationProvider> = Arc::new(
            visitorpass_application::ports::notification_provider::NoopNotificationProvider
        );
        let sync_events = Arc::new(visitorpass_application::use_cases::SyncEventsUseCase::new(
            Arc::clone(&devices),
            Arc::clone(&passes),
            Arc::clone(&entries),
            Arc::clone(&orgs),
            Arc::clone(&users),
            Arc::clone(&crypto),
            Arc::clone(&audit),
            Arc::clone(&notifier),
            config.sms_enabled,
        ));

        let (broadcast_tx, _) = tokio::sync::broadcast::channel(1024);

        let state = AppState {
            config,
            db_pool: app_db_pool.clone(),
            key_provider,
            crypto,
            notifier,
            whatsapp_channel: Arc::new(visitorpass_infrastructure::share::WhatsAppShareChannel::new()),
            sms_channel: Arc::new(visitorpass_infrastructure::share::SmsShareChannel::disabled()),
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
            platform_admins,
            broadcast_tx,
            rate_limiter: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            jwks_cache: Arc::new(crate::handlers::google_auth::JwksCache::new()),
        };

        let app = build_router(state);

        // Get Global Token
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/google")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&json!({
                    "id_token": format!("mock_{}", user_email)
                })).unwrap()
            ))
            .unwrap();

        let response = app.clone().oneshot(req).await.ok()?;
        let s1 = response.status();
        let body_bytes = axum::body::to_bytes(response.into_body(), 10000).await.ok()?;
        if !s1.is_success() { eprintln!("AUTH-GOOGLE status={} body={}", s1, String::from_utf8_lossy(&body_bytes)); }
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
        let s2 = response.status();
        let body_bytes = axum::body::to_bytes(response.into_body(), 10000).await.ok()?;
        if !s2.is_success() { eprintln!("SELECT-ORG status={} body={}", s2, String::from_utf8_lossy(&body_bytes)); }
        let select_res: serde_json::Value = serde_json::from_slice(&body_bytes).ok()?;
        let scoped_token = select_res["access_token"].as_str()?.to_string();

        Some((app, db_pool, org_id, location_id, user_id, scoped_token))
    }

    async fn teardown_test_env(db_pool: &sqlx::PgPool, org_id: Uuid, user_id: Uuid, location_id: Uuid) {
        // Delete in FK dependency order. None of these tables cascade on
        // delete (app.visitor_passes.org_id etc. are plain REFERENCES with no
        // ON DELETE clause), so deleting organizations first would always
        // fail silently (errors here are `.ok()`-swallowed) and leave every
        // test run's fixtures permanently orphaned in the test database.
        sqlx::query("DELETE FROM app.entry_logs WHERE org_id = $1").bind(org_id).execute(db_pool).await.ok();
        sqlx::query("DELETE FROM sync.device_checkpoints WHERE org_id = $1").bind(org_id).execute(db_pool).await.ok();
        sqlx::query("DELETE FROM app.devices WHERE org_id = $1").bind(org_id).execute(db_pool).await.ok();
        sqlx::query("DELETE FROM app.ad_hoc_approvals WHERE org_id = $1").bind(org_id).execute(db_pool).await.ok();
        sqlx::query("DELETE FROM app.visitor_passes WHERE org_id = $1").bind(org_id).execute(db_pool).await.ok();
        sqlx::query("DELETE FROM app.org_keys WHERE org_id = $1").bind(org_id).execute(db_pool).await.ok();
        sqlx::query("DELETE FROM app.sessions WHERE user_id = $1").bind(user_id).execute(db_pool).await.ok();
        sqlx::query("DELETE FROM app.org_memberships WHERE org_id = $1").bind(org_id).execute(db_pool).await.ok();
        sqlx::query("DELETE FROM app.users WHERE id = $1").bind(user_id).execute(db_pool).await.ok();
        sqlx::query("DELETE FROM app.locations WHERE id = $1").bind(location_id).execute(db_pool).await.ok();
        sqlx::query("DELETE FROM app.organizations WHERE id = $1").bind(org_id).execute(db_pool).await.ok();
    }

    // Helper: seed a platform-admin user and log them in through the real
    // /auth/google mock path, returning (user_id, PLATFORM_ADMIN token).
    // Mirrors the seeding steps in
    // `test_platform_admin_rbac_boundary_is_bidirectional`.
    async fn seed_platform_admin(app: &axum::Router, db_pool: &sqlx::PgPool) -> (Uuid, String) {
        let admin_user_id = Uuid::now_v7();
        let admin_email = format!("platform_admin_test_{}@visitorpass.app", Uuid::new_v4());
        sqlx::query("INSERT INTO app.users (id, email, password_hash, full_name) VALUES ($1, $2, 'unused-e2e-test-hash', 'Platform Admin')")
            .bind(admin_user_id)
            .bind(&admin_email)
            .execute(db_pool)
            .await
            .expect("seed platform admin user");
        sqlx::query("INSERT INTO app.platform_admins (user_id, granted_by) VALUES ($1, NULL)")
            .bind(admin_user_id)
            .execute(db_pool)
            .await
            .expect("seed platform_admins row");

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/google")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&json!({
                "id_token": format!("mock_{}", admin_email)
            })).unwrap()))
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 10_000).await.unwrap()
        ).unwrap();
        let token = body["access_token"].as_str().expect("platform admin must get a token").to_string();
        (admin_user_id, token)
    }

    async fn teardown_platform_admin(db_pool: &sqlx::PgPool, admin_user_id: Uuid) {
        sqlx::query("DELETE FROM app.platform_admins WHERE user_id = $1").bind(admin_user_id).execute(db_pool).await.ok();
        sqlx::query("DELETE FROM app.users WHERE id = $1").bind(admin_user_id).execute(db_pool).await.ok();
    }

    // Helper: seed a second user with an ADMIN (-> OrgAdmin, read-compat)
    // membership on `org_id` and log them in through the real
    // /auth/google mock path. Since this is their only membership, the
    // single-membership auto-login branch hands back an org-scoped token
    // directly (no /auth/select-org round trip needed). Returns
    // (user_id, ORG_ADMIN-scoped token).
    async fn seed_org_admin_token(app: &axum::Router, db_pool: &sqlx::PgPool, org_id: Uuid) -> (Uuid, String) {
        let admin_user_id = Uuid::now_v7();
        let admin_email = format!("org_admin_test_{}@visitorpass.app", Uuid::new_v4());
        sqlx::query("INSERT INTO app.users (id, email, password_hash, full_name) VALUES ($1, $2, 'unused-e2e-test-hash', 'Org Admin')")
            .bind(admin_user_id)
            .bind(&admin_email)
            .execute(db_pool)
            .await
            .expect("seed org admin user");
        sqlx::query("INSERT INTO app.org_memberships (org_id, user_id, role, unit_identifier, status) VALUES ($1, $2, 'ADMIN', 'HQ', 'ACTIVE')")
            .bind(org_id)
            .bind(admin_user_id)
            .execute(db_pool)
            .await
            .expect("seed org admin membership");

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/google")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&json!({
                "id_token": format!("mock_{}", admin_email)
            })).unwrap()))
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 10_000).await.unwrap()
        ).unwrap();
        assert_eq!(body["role"].as_str(), Some("ORG_ADMIN"), "single-membership auto-login must resolve the ADMIN row to ORG_ADMIN");
        let token = body["access_token"].as_str().expect("org admin must get an org-scoped token").to_string();
        (admin_user_id, token)
    }

    // Helper: setup a login-capable environment (password-based /auth/login,
    // needed for refresh/logout tests) distinct from setup_test_env's
    // Google-mock flow, which never sets a verifiable password hash.
    async fn setup_login_test_env() -> Option<(axum::Router, sqlx::PgPool, Uuid, Uuid, String, String, String)> {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://visitorpass:CHANGEME@localhost:5432/visitorpass".to_string());
        let app_database_url = std::env::var("APP_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://visitorpass_app:CHANGEME_APP_ROLE_PASSWORD@localhost:5432/visitorpass".to_string());
        let db_pool = sqlx::PgPool::connect(&database_url).await.ok()?;
        let app_db_pool = sqlx::PgPool::connect(&app_database_url).await.ok()?;

        let org_id = Uuid::now_v7();
        let user_id = Uuid::now_v7();
        let org_slug = format!("login-test-org-{}", Uuid::new_v4());
        let user_email = format!("login_test_{}@visitorpass.app", Uuid::new_v4());
        let password = "correct-horse-battery-staple";

        let master_key_hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string();
        std::env::set_var("MASTER_KEY_HEX", &master_key_hex);
        let key_provider: Arc<dyn visitorpass_application::ports::KeyProvider> = Arc::new(
            visitorpass_infrastructure::key_provider::env_key_provider::EnvKeyProvider::from_env()
        );
        let crypto: Arc<dyn visitorpass_application::ports::CryptoService> = Arc::new(
            visitorpass_infrastructure::crypto::service::DefaultCryptoService::new(Arc::clone(&key_provider))
        );
        let password_hash = crypto.hash_password(password).await.ok()?;

        sqlx::query("INSERT INTO app.organizations (id, name, org_type, slug) VALUES ($1, 'Login Test Org', 'OFFICE', $2)")
            .bind(org_id).bind(&org_slug).execute(&db_pool).await.ok()?;
        sqlx::query("INSERT INTO app.users (id, email, password_hash, full_name) VALUES ($1, $2, $3, 'Login User')")
            .bind(user_id).bind(&user_email).bind(&password_hash).execute(&db_pool).await.ok()?;
        sqlx::query("INSERT INTO app.org_memberships (org_id, user_id, role, unit_identifier, status) VALUES ($1, $2, 'RESIDENT', 'Flat 101', 'ACTIVE')")
            .bind(org_id).bind(user_id).execute(&db_pool).await.ok()?;

        let config = AppConfig {
            host: "0.0.0.0".to_string(),
            port: 8080,
            database_url: app_database_url.clone(),
            migration_database_url: None,
            database_max_connections: 5,
            database_min_connections: 1,
            master_key_hex: master_key_hex.clone(),
            base_url: "http://localhost:8080".to_string(),
            env: "development".to_string(),
            default_retention_days: 90,
            sms_enabled: false,
            sms_provider_api_key: None,
            sms_sender_id: None,
            sms_flow_id: None,
            email_enabled: false,
            google_client_id: "test-google-client-id.apps.googleusercontent.com".to_string(),
        };

        let orgs: Arc<dyn visitorpass_application::ports::OrgRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgOrgRepository::new(app_db_pool.clone()));
        let users: Arc<dyn visitorpass_application::ports::UserRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgUserRepository::new(app_db_pool.clone()));
        let passes: Arc<dyn visitorpass_application::ports::PassRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgPassRepository::new(app_db_pool.clone()));
        let entries: Arc<dyn visitorpass_application::ports::EntryRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgEntryRepository::new(app_db_pool.clone()));
        let devices: Arc<dyn visitorpass_application::ports::DeviceRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgDeviceRepository::new(app_db_pool.clone()));
        let locations: Arc<dyn visitorpass_application::ports::LocationRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgLocationRepository::new(app_db_pool.clone()));
        let audit: Arc<dyn visitorpass_application::ports::AuditRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgAuditRepository::new(app_db_pool.clone()));
        let platform_admins: Arc<dyn visitorpass_application::ports::PlatformAdminRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgPlatformAdminRepository::new(app_db_pool.clone()));

        let create_pass = Arc::new(visitorpass_application::use_cases::CreatePassUseCase::new(
            Arc::clone(&passes), Arc::clone(&orgs), Arc::clone(&crypto), Arc::clone(&audit), config.base_url.clone(),
        ));
        let verify_pass = Arc::new(visitorpass_application::use_cases::VerifyPassUseCase::new(
            Arc::clone(&passes), Arc::clone(&orgs), Arc::clone(&crypto), Arc::clone(&audit),
        ));
        let revoke_pass = Arc::new(visitorpass_application::use_cases::RevokePassUseCase::new(
            Arc::clone(&passes), Arc::clone(&orgs), Arc::clone(&audit),
        ));
        let register_org = Arc::new(visitorpass_application::use_cases::RegisterOrganizationUseCase::new(
            Arc::clone(&orgs), Arc::clone(&users), Arc::clone(&crypto), Arc::clone(&audit),
        ));
        let register_device = Arc::new(visitorpass_application::use_cases::RegisterDeviceUseCase::new(
            Arc::clone(&devices), Arc::clone(&orgs), Arc::clone(&audit),
        ));
        let revoke_device = Arc::new(visitorpass_application::use_cases::RevokeDeviceUseCase::new(
            Arc::clone(&devices), Arc::clone(&audit),
        ));
        let notifier: Arc<dyn visitorpass_application::ports::NotificationProvider> = Arc::new(
            visitorpass_application::ports::notification_provider::NoopNotificationProvider
        );
        let sync_events = Arc::new(visitorpass_application::use_cases::SyncEventsUseCase::new(
            Arc::clone(&devices), Arc::clone(&passes), Arc::clone(&entries), Arc::clone(&orgs),
            Arc::clone(&users), Arc::clone(&crypto), Arc::clone(&audit), Arc::clone(&notifier), config.sms_enabled,
        ));
        let (broadcast_tx, _) = tokio::sync::broadcast::channel(1024);

        let state = AppState {
            config,
            db_pool: app_db_pool.clone(),
            key_provider,
            crypto,
            notifier,
            whatsapp_channel: Arc::new(visitorpass_infrastructure::share::WhatsAppShareChannel::new()),
            sms_channel: Arc::new(visitorpass_infrastructure::share::SmsShareChannel::disabled()),
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
            platform_admins,
            broadcast_tx,
            rate_limiter: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            jwks_cache: Arc::new(crate::handlers::google_auth::JwksCache::new()),
        };

        let app = build_router(state);
        Some((app, db_pool, org_id, user_id, org_slug, user_email, password.to_string()))
    }

    async fn teardown_login_test_env(db_pool: &sqlx::PgPool, org_id: Uuid, user_id: Uuid) {
        sqlx::query("DELETE FROM app.sessions WHERE user_id = $1").bind(user_id).execute(db_pool).await.ok();
        sqlx::query("DELETE FROM app.org_memberships WHERE org_id = $1").bind(org_id).execute(db_pool).await.ok();
        sqlx::query("DELETE FROM app.users WHERE id = $1").bind(user_id).execute(db_pool).await.ok();
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
                    "location_id": location_id,
                    "visitor_name": "E2E Guest",
                    "visitor_phone": "+919999999999",
                    "purpose": "E2E test visit",
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
                    "visitor_phone": "+918888888888",
                    "location_id": location_id,
                    "unit_identifier": "Flat 101"
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
            "location_id": location_id,
            "visitor_name": "Idempotent Guest",
            "visitor_phone": "+919876543210",
            "purpose": "Idempotency replay test",
            "valid_from": (Utc::now() + Duration::minutes(5)).to_rfc3339(),
            "valid_until": (Utc::now() + Duration::hours(2)).to_rfc3339(),
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

        // Verify DB only has 1 pass created for THIS org. Scoped by org_id, not
        // just visitor_name, so this assertion is self-contained and doesn't
        // depend on every other test run's fixtures having been cleaned up.
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM app.visitor_passes WHERE visitor_name = 'Idempotent Guest' AND org_id = $1")
            .bind(org_id)
            .fetch_one(&db_pool)
            .await
            .unwrap();
        assert_eq!(count, 1);

        teardown_test_env(&db_pool, org_id, user_id, location_id).await;
    }

    // Regression test for the middleware-ordering bug: idempotency_middleware
    // was previously layered OUTSIDE (before) auth_middleware, so it ran on
    // every protected request before `Extension<OrgContext>` existed. This
    // test proves the fix by going through the REAL router + a REAL HTTP
    // request (not calling either middleware function directly, which could
    // never observe an ordering bug): a POST that reuses an Idempotency-Key
    // already cached from a legitimately authenticated request, but this time
    // sent with an invalid Authorization header, must be rejected by auth
    // (401) -- never served from the idempotency cache, and never a 500 from
    // a missing-extension panic.
    #[tokio::test]
    async fn test_idempotency_replay_requires_valid_auth() {
        let (app, db_pool, org_id, location_id, user_id, scoped_token) =
            setup_test_env().await.expect("Failed to setup test environment");

        let idempotency_key = Uuid::new_v4().to_string();
        let create_pass_payload = json!({
            "location_id": location_id,
            "visitor_name": "Auth Ordering Guest",
            "visitor_phone": "+919876500000",
            "purpose": "Auth-before-idempotency regression test",
            "valid_from": (Utc::now() + Duration::minutes(5)).to_rfc3339(),
            "valid_until": (Utc::now() + Duration::hours(2)).to_rfc3339(),
        });

        // 1. Legitimate, authenticated request: creates the pass and caches
        //    the 201 response under (org_id, path, idempotency_key).
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

        // 2. Attacker (or a buggy client) replays the SAME path + SAME
        //    Idempotency-Key, but with an invalid Authorization header.
        //    Must be rejected by auth BEFORE idempotency ever looks at the
        //    cache -- asserting 401, not a replayed 201/200, and not a 500.
        let req2 = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/organizations/{}/passes", org_id))
            .header("content-type", "application/json")
            .header("authorization", "Bearer not-a-real-token")
            .header("Idempotency-Key", &idempotency_key)
            .body(Body::from(serde_json::to_string(&create_pass_payload).unwrap()))
            .unwrap();

        let response2 = app.clone().oneshot(req2).await.unwrap();
        assert_eq!(
            response2.status(),
            StatusCode::UNAUTHORIZED,
            "an invalid Authorization header must be rejected by auth, not replayed from the idempotency cache and not a 500"
        );
        assert!(
            response2.headers().get("Idempotent-Replay").is_none(),
            "an unauthenticated request must never be served from the idempotency cache"
        );
        let body_bytes2 = axum::body::to_bytes(response2.into_body(), 10_000).await.unwrap();
        let body2: serde_json::Value = serde_json::from_slice(&body_bytes2).unwrap();
        assert!(
            body2.get("pass_number").is_none(),
            "the rejected request must not leak the cached pass payload"
        );

        // 3. Same check with the header omitted entirely.
        let req3 = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/organizations/{}/passes", org_id))
            .header("content-type", "application/json")
            .header("Idempotency-Key", &idempotency_key)
            .body(Body::from(serde_json::to_string(&create_pass_payload).unwrap()))
            .unwrap();

        let response3 = app.clone().oneshot(req3).await.unwrap();
        assert_eq!(response3.status(), StatusCode::UNAUTHORIZED);

        // 4. No second pass was ever created by the rejected replay attempts.
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM app.visitor_passes WHERE visitor_name = 'Auth Ordering Guest' AND org_id = $1"
        )
            .bind(org_id)
            .fetch_one(&db_pool)
            .await
            .unwrap();
        assert_eq!(count, 1);

        teardown_test_env(&db_pool, org_id, user_id, location_id).await;
    }

    // A2: app.ad_hoc_approvals.visitor_phone used to be stored in plaintext.
    // This test goes through the real HTTP handler (request_approval), then
    // reads the raw row back with a direct SQL query -- proving (a) the
    // plaintext number is not recoverable from either stored column by
    // inspection, and (b) the ciphertext genuinely decrypts back to the
    // original number using the same key-derivation the handler used.
    #[tokio::test]
    async fn test_ad_hoc_approval_phone_encrypted_at_rest() {
        let (app, db_pool, org_id, location_id, user_id, scoped_token) =
            setup_test_env().await.expect("Failed to setup test environment");

        let visitor_phone = "+919812345678";

        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/organizations/{}/entries/request-approval", org_id))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", scoped_token))
            .body(Body::from(
                serde_json::to_string(&json!({
                    "visitor_name": "Plaintext Check Guest",
                    "visitor_phone": visitor_phone,
                    "location_id": location_id,
                    "unit_identifier": "Flat 101"
                })).unwrap()
            ))
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body_bytes = axum::body::to_bytes(response.into_body(), 10_000).await.unwrap();
        let res: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let approval_id = Uuid::parse_str(res["approval_id"].as_str().unwrap()).unwrap();

        // Read the raw row directly via SQL -- bypassing the application layer
        // entirely -- to prove what is ACTUALLY persisted, not what a Rust
        // struct claims is persisted.
        let row: (String, Vec<u8>) = sqlx::query_as(
            "SELECT visitor_phone_hmac, visitor_phone_enc FROM app.ad_hoc_approvals WHERE id = $1"
        )
            .bind(approval_id)
            .fetch_one(&db_pool)
            .await
            .unwrap();
        let (visitor_phone_hmac, visitor_phone_enc) = row;

        // 1. The plaintext phone number must not appear verbatim anywhere in
        //    either stored column.
        assert!(
            !visitor_phone_hmac.contains(visitor_phone),
            "HMAC column must not contain the plaintext phone number"
        );
        let enc_as_lossy_string = String::from_utf8_lossy(&visitor_phone_enc);
        assert!(
            !enc_as_lossy_string.contains(visitor_phone),
            "encrypted column must not contain the plaintext phone number"
        );
        // The old plaintext column no longer exists at all (dropped in the
        // same migration that added the encrypted columns).
        let plaintext_col_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'app' AND table_name = 'ad_hoc_approvals' AND column_name = 'visitor_phone')"
        )
            .fetch_one(&db_pool)
            .await
            .unwrap();
        assert!(!plaintext_col_exists, "plaintext visitor_phone column must have been dropped");

        // 2. Decrypting visitor_phone_enc with the correct per-record key
        //    reproduces the original phone number exactly.
        std::env::set_var("MASTER_KEY_HEX", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        let key_provider: Arc<dyn visitorpass_application::ports::KeyProvider> = Arc::new(
            visitorpass_infrastructure::key_provider::env_key_provider::EnvKeyProvider::from_env()
        );
        let crypto: Arc<dyn visitorpass_application::ports::CryptoService> = Arc::new(
            visitorpass_infrastructure::crypto::service::DefaultCryptoService::new(key_provider)
        );
        let decrypted = crypto.decrypt_phone(approval_id, &visitor_phone_enc)
            .expect("decryption with the correct record id must succeed");
        assert_eq!(decrypted, visitor_phone);

        // 3. Decrypting with the WRONG record id must fail (proves the key is
        //    actually derived per-record, not a fixed/global key).
        let wrong_id = Uuid::now_v7();
        assert!(crypto.decrypt_phone(wrong_id, &visitor_phone_enc).is_err());

        teardown_test_env(&db_pool, org_id, user_id, location_id).await;
    }

    // Helper: POST /api/v1/auth/login, returning (access_token, refresh_token).
    async fn do_login(app: &axum::Router, slug: &str, email: &str, password: &str) -> (String, String) {
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&json!({
                "email": email,
                "password": password,
                "slug": slug,
            })).unwrap()))
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        let status = response.status();
        if status != StatusCode::OK {
            let body_bytes = axum::body::to_bytes(response.into_body(), 10_000).await.unwrap();
            panic!("do_login failed: status={} body={}", status, String::from_utf8_lossy(&body_bytes));
        }
        let body_bytes = axum::body::to_bytes(response.into_body(), 10_000).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        (
            body["access_token"].as_str().unwrap().to_string(),
            body["refresh_token"].as_str().unwrap().to_string(),
        )
    }

    // Helper: POST /api/v1/auth/refresh, returning the raw response for the
    // caller to assert status/body on.
    async fn do_refresh(app: &axum::Router, refresh_token: &str) -> axum::response::Response {
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/refresh")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&json!({
                "refresh_token": refresh_token,
            })).unwrap()))
            .unwrap();
        app.clone().oneshot(req).await.unwrap()
    }

    // B2, scenario 1: rotation succeeds; the just-rotated-away token still
    // works within the 5-minute grace window; the SAME token fails once that
    // window has passed (simulated by backdating previous_token_rotated_at
    // directly in the DB rather than sleeping 5 real minutes).
    #[tokio::test]
    async fn test_refresh_rotation_and_grace_window() {
        let (app, db_pool, org_id, user_id, org_slug, user_email, password) =
            setup_login_test_env().await.expect("Failed to setup login test environment");

        let (_access1, refresh1) = do_login(&app, &org_slug, &user_email, &password).await;

        // Rotate: refresh1 (current) -> refresh2. Must succeed.
        let resp2 = do_refresh(&app, &refresh1).await;
        assert_eq!(resp2.status(), StatusCode::OK);
        let body2: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp2.into_body(), 10_000).await.unwrap()
        ).unwrap();
        let refresh2 = body2["refresh_token"].as_str().unwrap().to_string();
        assert_ne!(refresh1, refresh2, "rotation must issue a genuinely new token");

        // refresh1 is now the PREVIOUS token; presenting it again immediately
        // (well within 5 minutes) must still succeed (grace window).
        let resp3 = do_refresh(&app, &refresh1).await;
        assert_eq!(resp3.status(), StatusCode::OK, "previous token must be accepted within the grace window");
        let body3: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp3.into_body(), 10_000).await.unwrap()
        ).unwrap();
        let refresh3 = body3["refresh_token"].as_str().unwrap().to_string();

        // Backdate previous_token_rotated_at for this session past the grace
        // window, simulating ">5 minutes have passed" without a real sleep.
        sqlx::query(
            "UPDATE app.sessions SET previous_token_rotated_at = NOW() - INTERVAL '10 minutes' WHERE user_id = $1"
        )
            .bind(user_id)
            .execute(&db_pool)
            .await
            .unwrap();

        // refresh1 (previous-of-previous by now) presented again, outside
        // the grace window, must fail as reuse/theft -- and per the theft
        // response, the family is revoked, so the CURRENT token (refresh3)
        // must ALSO stop working afterwards.
        let resp4 = do_refresh(&app, &refresh1).await;
        assert_eq!(resp4.status(), StatusCode::UNAUTHORIZED, "reused previous token outside the grace window must be rejected");

        let resp5 = do_refresh(&app, &refresh3).await;
        assert_eq!(resp5.status(), StatusCode::UNAUTHORIZED, "the entire family must be revoked once theft is detected, including the newest token");

        teardown_login_test_env(&db_pool, org_id, user_id).await;
    }

    // B2, scenario 2: an explicit theft simulation matching the exact
    // wording of the requirement -- after a valid rotation, replay the
    // PRE-rotation token outside the grace window and confirm the family is
    // revoked, including the newest (legitimately rotated-to) token.
    #[tokio::test]
    async fn test_refresh_theft_detection_revokes_family() {
        let (app, db_pool, org_id, user_id, org_slug, user_email, password) =
            setup_login_test_env().await.expect("Failed to setup login test environment");

        let (_access1, token_a) = do_login(&app, &org_slug, &user_email, &password).await;

        // Legitimate rotation: token_a -> token_b.
        let resp_rotate = do_refresh(&app, &token_a).await;
        assert_eq!(resp_rotate.status(), StatusCode::OK);
        let body_rotate: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(resp_rotate.into_body(), 10_000).await.unwrap()
        ).unwrap();
        let token_b = body_rotate["refresh_token"].as_str().unwrap().to_string();

        // Force the grace window closed for token_a (simulating an attacker
        // replaying a long-stolen token, not a fast network retry).
        sqlx::query(
            "UPDATE app.sessions SET previous_token_rotated_at = NOW() - INTERVAL '1 hour' WHERE user_id = $1"
        )
            .bind(user_id)
            .execute(&db_pool)
            .await
            .unwrap();

        // Attacker (or a stolen-token replay) presents the PRE-rotation
        // token_a. Must be rejected AND revoke the whole family.
        let resp_theft = do_refresh(&app, &token_a).await;
        assert_eq!(resp_theft.status(), StatusCode::UNAUTHORIZED);

        // The legitimate holder's current, valid, never-abused token_b must
        // ALSO now be rejected -- proving the full family was revoked, not
        // just the abused token.
        let resp_legit = do_refresh(&app, &token_b).await;
        assert_eq!(
            resp_legit.status(),
            StatusCode::UNAUTHORIZED,
            "theft detection must revoke the entire session family, not just the replayed token"
        );

        // Confirm at the DB level too: every session row for this user must
        // now be revoked.
        let unrevoked_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM app.sessions WHERE user_id = $1 AND revoked_at IS NULL"
        )
            .bind(user_id)
            .fetch_one(&db_pool)
            .await
            .unwrap();
        assert_eq!(unrevoked_count, 0);

        teardown_login_test_env(&db_pool, org_id, user_id).await;
    }

    // B2, scenario 3: logout revokes the session; a subsequent refresh with
    // that session's token must fail.
    #[tokio::test]
    async fn test_logout_revokes_session() {
        let (app, db_pool, org_id, user_id, org_slug, user_email, password) =
            setup_login_test_env().await.expect("Failed to setup login test environment");

        let (_access, refresh) = do_login(&app, &org_slug, &user_email, &password).await;

        let logout_req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/logout")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&json!({
                "refresh_token": refresh,
            })).unwrap()))
            .unwrap();
        let logout_resp = app.clone().oneshot(logout_req).await.unwrap();
        assert_eq!(logout_resp.status(), StatusCode::OK);

        // Subsequent refresh with the now-revoked session's token must fail.
        let resp_after_logout = do_refresh(&app, &refresh).await;
        assert_eq!(
            resp_after_logout.status(),
            StatusCode::UNAUTHORIZED,
            "refreshing with a logged-out session's token must fail"
        );

        teardown_login_test_env(&db_pool, org_id, user_id).await;
    }

    // ── B4: validator-crate wiring ──────────────────────────────────────────

    #[tokio::test]
    async fn test_create_pass_rejects_malformed_phone_before_db_write() {
        let (app, db_pool, org_id, location_id, user_id, scoped_token) =
            setup_test_env().await.expect("Failed to setup test environment");

        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/organizations/{}/passes", org_id))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", scoped_token))
            .body(Body::from(serde_json::to_string(&json!({
                "location_id": location_id,
                "visitor_name": "Bad Phone Guest",
                "visitor_phone": "not-a-phone-number",
                "purpose": "Validator test",
                "valid_from": (Utc::now() + Duration::minutes(5)).to_rfc3339(),
                "valid_until": (Utc::now() + Duration::hours(2)).to_rfc3339(),
            })).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM app.visitor_passes WHERE visitor_name = 'Bad Phone Guest' AND org_id = $1"
        ).bind(org_id).fetch_one(&db_pool).await.unwrap();
        assert_eq!(count, 0, "malformed input must be rejected before any DB write");

        teardown_test_env(&db_pool, org_id, user_id, location_id).await;
    }

    #[tokio::test]
    async fn test_create_pass_accepts_valid_input() {
        let (app, db_pool, org_id, location_id, user_id, scoped_token) =
            setup_test_env().await.expect("Failed to setup test environment");

        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/organizations/{}/passes", org_id))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", scoped_token))
            .body(Body::from(serde_json::to_string(&json!({
                "location_id": location_id,
                "visitor_name": "Good Phone Guest",
                "visitor_phone": "+14155552671",
                "purpose": "Validator test",
                "valid_from": (Utc::now() + Duration::minutes(5)).to_rfc3339(),
                "valid_until": (Utc::now() + Duration::hours(2)).to_rfc3339(),
            })).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        teardown_test_env(&db_pool, org_id, user_id, location_id).await;
    }

    #[tokio::test]
    async fn test_request_approval_rejects_malformed_phone_before_db_write() {
        let (app, db_pool, org_id, location_id, user_id, scoped_token) =
            setup_test_env().await.expect("Failed to setup test environment");

        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/organizations/{}/entries/request-approval", org_id))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", scoped_token))
            .body(Body::from(serde_json::to_string(&json!({
                "visitor_name": "Bad Phone Approval Guest",
                "visitor_phone": "12345",
                "location_id": location_id,
                "unit_identifier": "Flat 101",
            })).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM app.ad_hoc_approvals WHERE org_id = $1"
        ).bind(org_id).fetch_one(&db_pool).await.unwrap();
        assert_eq!(count, 0, "malformed input must be rejected before any DB write");

        teardown_test_env(&db_pool, org_id, user_id, location_id).await;
    }

    #[tokio::test]
    async fn test_request_approval_accepts_valid_input() {
        let (app, db_pool, org_id, location_id, user_id, scoped_token) =
            setup_test_env().await.expect("Failed to setup test environment");

        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/organizations/{}/entries/request-approval", org_id))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", scoped_token))
            .body(Body::from(serde_json::to_string(&json!({
                "visitor_name": "Good Phone Approval Guest",
                "visitor_phone": "+14155552671",
                "location_id": location_id,
                "unit_identifier": "Flat 101",
            })).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        teardown_test_env(&db_pool, org_id, user_id, location_id).await;
    }

    #[tokio::test]
    async fn test_join_by_token_rejects_empty_unit_identifier_before_db_write() {
        let (app, db_pool, org_id, location_id, user_id, scoped_token) =
            setup_test_env().await.expect("Failed to setup test environment");

        let token = state_orgs_generate_join_token(&db_pool, org_id, user_id).await;
        let membership_count_before: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM app.org_memberships WHERE org_id = $1"
        ).bind(org_id).fetch_one(&db_pool).await.unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/organizations/join-by-token")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", scoped_token))
            .body(Body::from(serde_json::to_string(&json!({
                "token": token,
                "unit_identifier": "   ",
            })).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let membership_count_after: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM app.org_memberships WHERE org_id = $1"
        ).bind(org_id).fetch_one(&db_pool).await.unwrap();
        assert_eq!(membership_count_before, membership_count_after, "malformed input must be rejected before any DB write");

        teardown_test_env(&db_pool, org_id, user_id, location_id).await;
    }

    #[tokio::test]
    async fn test_join_by_token_accepts_valid_input() {
        let (app, db_pool, org_id, location_id, user_id, scoped_token) =
            setup_test_env().await.expect("Failed to setup test environment");

        // A second, distinct org for the caller to join via token (the
        // setup_test_env user is already a member of `org_id`, so reusing
        // it would hit the org_memberships unique (org_id, user_id) index).
        let target_org_id = Uuid::now_v7();
        sqlx::query("INSERT INTO app.organizations (id, name, org_type, slug) VALUES ($1, 'Join Target Org', 'OFFICE', $2)")
            .bind(target_org_id).bind(format!("join-target-{}", Uuid::new_v4()))
            .execute(&db_pool).await.unwrap();

        let token = state_orgs_generate_join_token(&db_pool, target_org_id, user_id).await;

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/organizations/join-by-token")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", scoped_token))
            .body(Body::from(serde_json::to_string(&json!({
                "token": token,
                "unit_identifier": "Flat 202",
            })).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let joined: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM app.org_memberships WHERE org_id = $1 AND user_id = $2"
        ).bind(target_org_id).bind(user_id).fetch_one(&db_pool).await.unwrap();
        assert_eq!(joined, 1);

        sqlx::query("DELETE FROM app.org_memberships WHERE org_id = $1").bind(target_org_id).execute(&db_pool).await.ok();
        sqlx::query("DELETE FROM app.organizations WHERE id = $1").bind(target_org_id).execute(&db_pool).await.ok();
        teardown_test_env(&db_pool, org_id, user_id, location_id).await;
    }

    // Helper: generate a join token directly via the repository (bypassing
    // the HTTP endpoint's ADMIN/OWNER authorization check, which is
    // orthogonal to what these tests exercise).
    async fn state_orgs_generate_join_token(db_pool: &sqlx::PgPool, org_id: Uuid, user_id: Uuid) -> String {
        let orgs: Arc<dyn visitorpass_application::ports::OrgRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgOrgRepository::new(db_pool.clone()));
        orgs.generate_join_token(org_id, user_id).await.expect("join token generation must succeed")
    }

    // Mobile C1 depends on this: guard kiosks previously hardcoded a mock
    // Ed25519 public key because /api/v1/sync never delivered the org's
    // real one. Proves the real, unmodified sync handler now includes it,
    // and that it matches what's actually in app.org_keys for this org.
    #[tokio::test]
    async fn test_sync_response_includes_org_public_key() {
        let (app, db_pool, org_id, location_id, user_id, scoped_token) =
            setup_test_env().await.expect("Failed to setup test environment");

        let expected_pubkey_hex: String = sqlx::query_scalar(
            "SELECT encode(signing_public_key, 'hex') FROM app.org_keys WHERE org_id = $1 AND retired_at IS NULL"
        ).bind(org_id).fetch_one(&db_pool).await.unwrap();

        let device_id = Uuid::now_v7();
        let device_public_key: Vec<u8> = Uuid::new_v4().as_bytes().iter().chain(Uuid::new_v4().as_bytes().iter()).copied().collect();
        sqlx::query("INSERT INTO app.devices (id, org_id, location_id, device_type, name, public_key, status) VALUES ($1, $2, $3, 'GUARD_KIOSK', 'Test Kiosk', $4, 'ACTIVE')")
            .bind(device_id).bind(org_id).bind(location_id).bind(&device_public_key)
            .execute(&db_pool).await.unwrap();
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/sync")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", scoped_token))
            .body(Body::from(serde_json::to_string(&json!({
                "device_id": device_id,
                "last_sync_seq": 0,
                "events": [],
            })).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 10_000).await.unwrap()
        ).unwrap();

        assert_eq!(body["org_public_key"].as_str().unwrap(), expected_pubkey_hex);
        assert_eq!(body["org_key_version"].as_i64().unwrap(), 1);

        teardown_test_env(&db_pool, org_id, user_id, location_id).await;
    }

    // Follow-up fix, found while implementing A2's phone-encryption pattern
    // for create_pass.rs: the use case generated `pass_id` for the signed
    // QR payload, but PgPassRepository::create generated ITS OWN,
    // independent `Uuid::now_v7()` for the actual database row -- so the
    // pass_id embedded in every QR code never matched its own row, AND
    // visitor_phone_enc was keyed by a THIRD, fully-discarded UUID that was
    // never stored anywhere at all (permanently undecryptable, worse than
    // the ad-hoc-approval bug A2 fixed, since this is the primary path).
    //
    // This test proves, through the real HTTP handler and the real
    // signature-verification path (`verify_qr_payload`, the same function
    // `/api/v1/passes/verify` uses), that all three are now the same id:
    // the API response's `id`, the database row's `id`, and the pass_id
    // recoverable by scanning and verifying the pass's own QR code -- and
    // that the phone is decryptable using that id.
    #[tokio::test]
    async fn test_pass_id_consistent_across_api_response_db_row_and_qr_payload() {
        let (app, db_pool, org_id, location_id, user_id, scoped_token) =
            setup_test_env().await.expect("Failed to setup test environment");

        let visitor_phone = "+14155552671";
        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/organizations/{}/passes", org_id))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", scoped_token))
            .body(Body::from(serde_json::to_string(&json!({
                "location_id": location_id,
                "visitor_name": "Pass Id Consistency Guest",
                "visitor_phone": visitor_phone,
                "purpose": "Pass id consistency test",
                "valid_from": (Utc::now() + Duration::minutes(5)).to_rfc3339(),
                "valid_until": (Utc::now() + Duration::hours(2)).to_rfc3339(),
            })).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 10_000).await.unwrap()
        ).unwrap();
        let api_response_id = Uuid::parse_str(body["id"].as_str().expect("response must include id")).unwrap();
        let qr_payload = body["qr_payload"].as_str().expect("response must include qr_payload").to_string();

        // 1. The database row's own primary key must equal the id the API
        //    just returned (previously: a different, independently
        //    generated id, since the repository ignored the use case's id).
        let row: (Uuid, Vec<u8>) = sqlx::query_as(
            "SELECT id, visitor_phone_enc FROM app.visitor_passes WHERE id = $1"
        )
            .bind(api_response_id)
            .fetch_one(&db_pool)
            .await
            .expect("the API response's id must be the row's actual primary key");
        let (db_row_id, visitor_phone_enc) = row;
        assert_eq!(db_row_id, api_response_id);

        // 2. Decrypting visitor_phone_enc using that SAME id must reproduce
        //    the original phone number (previously: encrypted with a
        //    fully-discarded third UUID, permanently undecryptable by any
        //    id you could ever look up).
        std::env::set_var("MASTER_KEY_HEX", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        let key_provider: Arc<dyn visitorpass_application::ports::KeyProvider> = Arc::new(
            visitorpass_infrastructure::key_provider::env_key_provider::EnvKeyProvider::from_env()
        );
        let crypto: Arc<dyn visitorpass_application::ports::CryptoService> = Arc::new(
            visitorpass_infrastructure::crypto::service::DefaultCryptoService::new(Arc::clone(&key_provider))
        );
        let decrypted_phone = crypto.decrypt_phone(api_response_id, &visitor_phone_enc)
            .expect("visitor_phone_enc must be decryptable using the pass's own (real, persisted) id");
        assert_eq!(decrypted_phone, visitor_phone);

        // 3. Scanning and verifying this pass's own QR code through the
        //    REAL production verification path must recover pass_id ==
        //    api_response_id -- previously a different, unrelated id.
        let org_public_key: Vec<u8> = sqlx::query_scalar(
            "SELECT signing_public_key FROM app.org_keys WHERE org_id = $1 AND retired_at IS NULL"
        )
            .bind(org_id)
            .fetch_one(&db_pool)
            .await
            .unwrap();
        let verified = crypto.verify_qr_payload(&qr_payload, &org_public_key)
            .expect("the pass's own QR code must verify against its own org's public key");
        assert_eq!(
            verified.pass_id, api_response_id,
            "the pass_id signed into the QR code must match the actual database row's id"
        );

        teardown_test_env(&db_pool, org_id, user_id, location_id).await;
    }

    // Proves the platform-admin / org-scoped RBAC boundary is bidirectional
    // and mutually exclusive, end to end through the real router:
    //   1. A user in app.platform_admins logs in via the SAME /auth/google
    //      endpoint everyone else uses, and gets a token with NO org claim
    //      and role=PLATFORM_ADMIN (not routed into the membership-based
    //      single-org-auto-login / multi-org-selector branches).
    //   2. That token can call the new cross-tenant route
    //      (/api/v1/platform/organizations) and sees orgs it is not a
    //      member of.
    //   3. That SAME token gets 403 PLATFORM_ADMIN_FORBIDDEN -- not a
    //      generic auth failure -- on an existing org-scoped route.
    //   4. A normal org-scoped token (RESIDENT, from setup_test_env) gets
    //      403 PLATFORM_ADMIN_REQUIRED on the platform-only route.
    #[tokio::test]
    async fn test_platform_admin_rbac_boundary_is_bidirectional() {
        let (app, db_pool, org_id, location_id, user_id, scoped_token) =
            setup_test_env().await.expect("Failed to setup test environment");

        let admin_user_id = Uuid::now_v7();
        let admin_email = format!("platform_admin_test_{}@visitorpass.app", Uuid::new_v4());
        sqlx::query("INSERT INTO app.users (id, email, password_hash, full_name) VALUES ($1, $2, 'unused-e2e-test-hash', 'Platform Admin')")
            .bind(admin_user_id)
            .bind(&admin_email)
            .execute(&db_pool)
            .await
            .expect("seed platform admin user");
        sqlx::query("INSERT INTO app.platform_admins (user_id, granted_by) VALUES ($1, NULL)")
            .bind(admin_user_id)
            .execute(&db_pool)
            .await
            .expect("seed platform_admins row");

        // 1. Login as the platform admin through the real /auth/google mock path.
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/google")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&json!({
                "id_token": format!("mock_{}", admin_email)
            })).unwrap()))
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 10_000).await.unwrap()
        ).unwrap();
        assert_eq!(body["role"].as_str(), Some("PLATFORM_ADMIN"));
        assert_eq!(body["memberships"].as_array().map(|a| a.len()), Some(0));
        let platform_token = body["access_token"].as_str().expect("platform admin must get a token").to_string();

        // 2. Platform token CAN list all organizations, including one it is
        // not (and cannot be) a member of.
        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/platform/organizations")
            .header("authorization", format!("Bearer {}", platform_token))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // 1_000_000, not the usual 10_000: this response's size scales
        // with the TOTAL org count across every concurrently-running test
        // run sharing this database, not just this test's own fixtures.
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1_000_000).await.unwrap()
        ).unwrap();
        let orgs = body["organizations"].as_array().expect("organizations array");
        assert!(
            orgs.iter().any(|o| o["id"].as_str() == Some(org_id.to_string().as_str())),
            "platform admin must see the org seeded by setup_test_env even though it has no membership in it"
        );

        // 3. Platform token gets 403 PLATFORM_ADMIN_FORBIDDEN on an
        // existing org-scoped route -- not 401, not silently OrgContext'd
        // with a bogus org.
        let req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/organizations/{}", org_id))
            .header("authorization", format!("Bearer {}", platform_token))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 10_000).await.unwrap()
        ).unwrap();
        assert_eq!(body["error"]["code"].as_str(), Some("PLATFORM_ADMIN_FORBIDDEN"));

        // 4. Vice versa: a normal org-scoped (RESIDENT) token gets 403
        // PLATFORM_ADMIN_REQUIRED on the platform-only route.
        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/platform/organizations")
            .header("authorization", format!("Bearer {}", scoped_token))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 10_000).await.unwrap()
        ).unwrap();
        assert_eq!(body["error"]["code"].as_str(), Some("PLATFORM_ADMIN_REQUIRED"));

        sqlx::query("DELETE FROM app.platform_admins WHERE user_id = $1").bind(admin_user_id).execute(&db_pool).await.ok();
        sqlx::query("DELETE FROM app.users WHERE id = $1").bind(admin_user_id).execute(&db_pool).await.ok();
        teardown_test_env(&db_pool, org_id, user_id, location_id).await;
    }

    // Definitive proof RLS (migration 023) is a REAL second layer, not
    // documentation: connects DIRECTLY as `visitorpass_app` (the runtime
    // role) with a raw `PgPool` -- no repository, no use case, no handler,
    // no `WHERE org_id = ...` anywhere in this test's own queries -- and
    // shows Postgres itself, not application code, decides which rows are
    // visible. This is what would catch a future bug where a new query
    // forgets the app-layer WHERE clause; the app-layer scoping tested
    // everywhere else in this file could not.
    #[tokio::test]
    async fn test_rls_blocks_cross_org_rows_even_without_app_layer_where_clause() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://visitorpass:CHANGEME@localhost:5432/visitorpass".to_string());
        let app_database_url = std::env::var("APP_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://visitorpass_app:CHANGEME_APP_ROLE_PASSWORD@localhost:5432/visitorpass".to_string());
        let Ok(owner_pool) = sqlx::PgPool::connect(&database_url).await else { return };
        let Ok(app_pool) = sqlx::PgPool::connect(&app_database_url).await else { return };

        // Seed two independent orgs, each with exactly one visitor pass, as
        // the owner role (bypasses RLS by being superuser -- fine, this is
        // fixture setup, not the thing under test).
        let org_a = Uuid::now_v7();
        let org_b = Uuid::now_v7();
        let loc_a = Uuid::now_v7();
        let loc_b = Uuid::now_v7();
        let user_a = Uuid::now_v7();
        let pass_a = Uuid::now_v7();
        let pass_b = Uuid::now_v7();

        for (org_id, slug_prefix) in [(org_a, "rls-a"), (org_b, "rls-b")] {
            sqlx::query("INSERT INTO app.organizations (id, name, org_type, slug) VALUES ($1, 'RLS Test Org', 'OFFICE', $2)")
                .bind(org_id).bind(format!("{}-{}", slug_prefix, Uuid::new_v4()))
                .execute(&owner_pool).await.expect("seed org");
        }
        sqlx::query("INSERT INTO app.locations (id, org_id, name, status) VALUES ($1, $2, 'Loc', 'ACTIVE')")
            .bind(loc_a).bind(org_a).execute(&owner_pool).await.expect("seed location a");
        sqlx::query("INSERT INTO app.locations (id, org_id, name, status) VALUES ($1, $2, 'Loc', 'ACTIVE')")
            .bind(loc_b).bind(org_b).execute(&owner_pool).await.expect("seed location b");
        sqlx::query("INSERT INTO app.users (id, email, password_hash, full_name) VALUES ($1, $2, 'x', 'User')")
            .bind(user_a).bind(format!("rls-test-{}@visitorpass.app", Uuid::new_v4())).execute(&owner_pool).await.expect("seed user");

        for (pid, org_id, loc_id) in [(pass_a, org_a, loc_a), (pass_b, org_b, loc_b)] {
            sqlx::query(
                "INSERT INTO app.visitor_passes (id, org_id, location_id, created_by, pass_number, visitor_name, visitor_phone_hmac, purpose, valid_from, valid_until, qr_payload, qr_nonce, key_version)
                 VALUES ($1, $2, $3, $4, $5, 'Guest', 'hmac', 'rls-test', NOW(), NOW() + interval '1 hour', 'vp1.x', $6, 1)"
            )
                .bind(pid).bind(org_id).bind(loc_id).bind(user_a)
                .bind(format!("VP-{}", &Uuid::new_v4().simple().to_string()[..8].to_uppercase()))
                .bind(vec![0u8; 12])
                .execute(&owner_pool).await.expect("seed pass");
        }

        // 1. No GUC set at all: fails CLOSED, not open. Zero rows, even
        // though two exist and this query has no WHERE clause whatsoever.
        let mut tx = app_pool.begin().await.expect("begin tx");
        let unscoped_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM app.visitor_passes WHERE id = ANY($1)")
            .bind(vec![pass_a, pass_b])
            .fetch_one(&mut *tx)
            .await
            .expect("unscoped count query");
        assert_eq!(unscoped_count, 0, "with no app.current_org_id GUC set, RLS must deny ALL rows, not default open");
        tx.rollback().await.ok();

        // 2. GUC set to org A: a query with NO org_id predicate anywhere in
        // its own WHERE clause still returns ONLY org A's pass.
        let mut tx = app_pool.begin().await.expect("begin tx");
        sqlx::query("SELECT set_config('app.current_org_id', $1, true)")
            .bind(org_a.to_string())
            .execute(&mut *tx)
            .await
            .expect("set GUC to org A");
        let visible_ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM app.visitor_passes WHERE id = ANY($1)")
            .bind(vec![pass_a, pass_b])
            .fetch_all(&mut *tx)
            .await
            .expect("scoped query as org A");
        tx.rollback().await.ok();
        assert_eq!(visible_ids, vec![pass_a], "scoped to org A, RLS must return org A's row and NEVER org B's, despite no WHERE org_id clause in this query");

        // 3. Same query, GUC set to org B instead: proves the restriction
        // tracks the GUC, not some fixed property of the query text.
        let mut tx = app_pool.begin().await.expect("begin tx");
        sqlx::query("SELECT set_config('app.current_org_id', $1, true)")
            .bind(org_b.to_string())
            .execute(&mut *tx)
            .await
            .expect("set GUC to org B");
        let visible_ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM app.visitor_passes WHERE id = ANY($1)")
            .bind(vec![pass_a, pass_b])
            .fetch_all(&mut *tx)
            .await
            .expect("scoped query as org B");
        tx.rollback().await.ok();
        assert_eq!(visible_ids, vec![pass_b], "scoped to org B, RLS must return org B's row and NEVER org A's");

        // 4. Cross-org WRITE is blocked too: WITH CHECK, not just USING.
        // Attempt to UPDATE org B's row while the GUC is scoped to org A.
        let mut tx = app_pool.begin().await.expect("begin tx");
        sqlx::query("SELECT set_config('app.current_org_id', $1, true)")
            .bind(org_a.to_string())
            .execute(&mut *tx)
            .await
            .expect("set GUC to org A");
        let update_result = sqlx::query("UPDATE app.visitor_passes SET visitor_name = 'RLS Write Test' WHERE id = $1")
            .bind(pass_b)
            .execute(&mut *tx)
            .await
            .expect("update statement itself must not error");
        tx.commit().await.ok();
        assert_eq!(update_result.rows_affected(), 0, "scoped to org A, an UPDATE targeting org B's row by its real id must affect zero rows");

        sqlx::query("DELETE FROM app.visitor_passes WHERE id = ANY($1)").bind(vec![pass_a, pass_b]).execute(&owner_pool).await.ok();
        sqlx::query("DELETE FROM app.users WHERE id = $1").bind(user_a).execute(&owner_pool).await.ok();
        sqlx::query("DELETE FROM app.locations WHERE id = ANY($1)").bind(vec![loc_a, loc_b]).execute(&owner_pool).await.ok();
        sqlx::query("DELETE FROM app.organizations WHERE id = ANY($1)").bind(vec![org_a, org_b]).execute(&owner_pool).await.ok();
    }

    // Platform Super-Admin Portal (Phase 2) -- Organization Provisioning:
    // a platform admin can provision a brand-new org + its root OrgAdmin
    // account, and that admin can log in via the real /auth/google mock
    // flow immediately afterward with NO prior login of their own,
    // landing an org-scoped ORG_ADMIN token with exactly one membership.
    #[tokio::test]
    async fn test_platform_provision_organization_creates_org_admin_who_can_login() {
        let (app, db_pool, org_id, location_id, user_id, _scoped_token) =
            setup_test_env().await.expect("Failed to setup test environment");
        let (platform_admin_id, platform_token) = seed_platform_admin(&app, &db_pool).await;

        let new_slug = format!("provisioned-org-{}", Uuid::new_v4());
        let new_admin_email = format!("provisioned_admin_{}@visitorpass.app", Uuid::new_v4());

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/platform/organizations")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", platform_token))
            .body(Body::from(serde_json::to_string(&json!({
                "name": "Provisioned Test Org",
                "org_type": "OFFICE",
                "slug": new_slug,
                "timezone": "UTC",
                "admin_email": new_admin_email,
                "admin_name": "New Org Admin"
            })).unwrap()))
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 10_000).await.unwrap()
        ).unwrap();
        assert_eq!(body["subscription_tier"].as_str(), Some("FREE"), "new orgs default to the FREE tier");
        let new_org_id = Uuid::parse_str(body["org_id"].as_str().expect("org_id")).unwrap();

        // The new admin logs in via the real /auth/google mock path --
        // no pre-existing password, no prior login -- it must just work.
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/google")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&json!({
                "id_token": format!("mock_{}", new_admin_email)
            })).unwrap()))
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 10_000).await.unwrap()
        ).unwrap();
        assert_eq!(body["role"].as_str(), Some("ORG_ADMIN"));
        assert!(body["access_token"].as_str().is_some(), "must get a valid, org-scoped access token on first login");
        let memberships = body["memberships"].as_array().expect("memberships array");
        assert_eq!(memberships.len(), 1, "provisioned org admin must have exactly one membership");
        assert_eq!(memberships[0]["org_id"].as_str(), Some(new_org_id.to_string().as_str()));
        assert_eq!(memberships[0]["role"].as_str(), Some("ORG_ADMIN"));
        let new_admin_user_id = Uuid::parse_str(body["user"]["id"].as_str().unwrap()).unwrap();

        sqlx::query("DELETE FROM app.org_memberships WHERE org_id = $1").bind(new_org_id).execute(&db_pool).await.ok();
        sqlx::query("DELETE FROM app.org_keys WHERE org_id = $1").bind(new_org_id).execute(&db_pool).await.ok();
        sqlx::query("DELETE FROM app.organizations WHERE id = $1").bind(new_org_id).execute(&db_pool).await.ok();
        sqlx::query("DELETE FROM app.users WHERE id = $1").bind(new_admin_user_id).execute(&db_pool).await.ok();
        teardown_platform_admin(&db_pool, platform_admin_id).await;
        teardown_test_env(&db_pool, org_id, user_id, location_id).await;
    }

    // Platform Super-Admin Portal (Phase 2) -- Global Billing &
    // Subscriptions: a platform admin sets an org's tier/limits, and the
    // change is visible when the org list is re-fetched (not just in the
    // PUT response itself).
    #[tokio::test]
    async fn test_platform_set_subscription_tier_updates_and_persists() {
        let (app, db_pool, org_id, location_id, user_id, _scoped_token) =
            setup_test_env().await.expect("Failed to setup test environment");
        let (platform_admin_id, platform_token) = seed_platform_admin(&app, &db_pool).await;

        let req = Request::builder()
            .method("PUT")
            .uri(format!("/api/v1/platform/organizations/{}/tier", org_id))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", platform_token))
            .body(Body::from(serde_json::to_string(&json!({
                "tier": "PRO",
                "max_locations": 10,
                "max_daily_passes": 500
            })).unwrap()))
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 10_000).await.unwrap()
        ).unwrap();
        assert_eq!(body["subscription_tier"].as_str(), Some("PRO"));
        assert_eq!(body["max_locations"].as_i64(), Some(10));
        assert_eq!(body["max_daily_passes"].as_i64(), Some(500));

        // Re-fetch through the org list -- not just trusting the PUT's own echo.
        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/platform/organizations")
            .header("authorization", format!("Bearer {}", platform_token))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // 1_000_000, not the usual 10_000: see the comment on the same
        // pattern in test_platform_admin_rbac_boundary_is_bidirectional.
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1_000_000).await.unwrap()
        ).unwrap();
        let orgs = body["organizations"].as_array().expect("organizations array");
        let updated = orgs.iter().find(|o| o["id"].as_str() == Some(org_id.to_string().as_str()))
            .expect("updated org must appear in the re-fetched list");
        assert_eq!(updated["subscription_tier"].as_str(), Some("PRO"));
        assert_eq!(updated["max_locations"].as_i64(), Some(10));
        assert_eq!(updated["max_daily_passes"].as_i64(), Some(500));

        teardown_platform_admin(&db_pool, platform_admin_id).await;
        teardown_test_env(&db_pool, org_id, user_id, location_id).await;
    }

    // Platform Super-Admin Portal (Phase 2) -- Cross-Tenant Analytics:
    // the metrics endpoint returns non-error JSON matching the documented
    // shape, and the seeded org appears in the per-org breakdown.
    #[tokio::test]
    async fn test_platform_metrics_returns_documented_shape() {
        let (app, db_pool, org_id, location_id, user_id, _scoped_token) =
            setup_test_env().await.expect("Failed to setup test environment");
        let (platform_admin_id, platform_token) = seed_platform_admin(&app, &db_pool).await;

        let req = Request::builder()
            .method("GET")
            .uri("/api/v1/platform/metrics")
            .header("authorization", format!("Bearer {}", platform_token))
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 10_000).await.unwrap()
        ).unwrap();

        assert_eq!(body["window_days"].as_i64(), Some(30));
        assert!(body["total_check_ins"].as_i64().is_some(), "total_check_ins must be a number");
        assert!(body.get("avg_gate_sync_latency_seconds").is_some(), "avg_gate_sync_latency_seconds key must be present (null or a number)");
        let per_org = body["per_org"].as_array().expect("per_org array");
        let seeded = per_org.iter().find(|o| o["org_id"].as_str() == Some(org_id.to_string().as_str()))
            .expect("the org seeded by setup_test_env must appear in the per-org breakdown even with zero check-ins");
        assert_eq!(seeded["org_name"].as_str(), Some("E2E Test Org"));
        assert!(seeded["check_in_count"].as_i64().is_some());

        teardown_platform_admin(&db_pool, platform_admin_id).await;
        teardown_test_env(&db_pool, org_id, user_id, location_id).await;
    }

    // Platform Super-Admin Portal (Phase 2) -- Global Device Revocation:
    // a platform admin (who has no membership in the device's org at all)
    // can revoke it purely cross-tenant.
    #[tokio::test]
    async fn test_platform_revoke_device_works_across_orgs() {
        let (app, db_pool, org_id, location_id, user_id, _scoped_token) =
            setup_test_env().await.expect("Failed to setup test environment");
        let (platform_admin_id, platform_token) = seed_platform_admin(&app, &db_pool).await;

        let device_id = Uuid::now_v7();
        let public_key: Vec<u8> = Uuid::new_v4().as_bytes().iter().chain(Uuid::new_v4().as_bytes().iter()).cloned().collect();
        sqlx::query(
            "INSERT INTO app.devices (id, org_id, location_id, device_type, name, public_key, status) \
             VALUES ($1, $2, $3, 'GUARD_KIOSK', 'Cross-Tenant Test Kiosk', $4, 'ACTIVE')"
        )
            .bind(device_id)
            .bind(org_id)
            .bind(location_id)
            .bind(&public_key)
            .execute(&db_pool)
            .await
            .expect("seed device");

        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/platform/devices/{}/revoke", device_id))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", platform_token))
            .body(Body::from(serde_json::to_string(&json!({ "reason": "lost device" })).unwrap()))
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 10_000).await.unwrap()
        ).unwrap();
        assert_eq!(body["status"].as_str(), Some("REVOKED"));
        assert_eq!(body["org_id"].as_str(), Some(org_id.to_string().as_str()));

        // Confirm it actually persisted, not just echoed in the response.
        let status: String = sqlx::query_scalar("SELECT status::text FROM app.devices WHERE id = $1")
            .bind(device_id)
            .fetch_one(&db_pool)
            .await
            .expect("fetch device status");
        assert_eq!(status, "REVOKED");

        sqlx::query("DELETE FROM app.devices WHERE id = $1").bind(device_id).execute(&db_pool).await.ok();
        teardown_platform_admin(&db_pool, platform_admin_id).await;
        teardown_test_env(&db_pool, org_id, user_id, location_id).await;
    }

    // Platform Super-Admin Portal (Phase 2) -- an ORG_ADMIN-role token
    // (the highest org-scoped role) gets 403 PLATFORM_ADMIN_REQUIRED on
    // all 4 new platform routes, mirroring
    // `test_platform_admin_rbac_boundary_is_bidirectional`'s point 4.
    #[tokio::test]
    async fn test_platform_new_routes_reject_org_admin_token() {
        let (app, db_pool, org_id, location_id, user_id, _scoped_token) =
            setup_test_env().await.expect("Failed to setup test environment");
        let (org_admin_user_id, org_admin_token) = seed_org_admin_token(&app, &db_pool, org_id).await;

        async fn assert_platform_admin_required(app: axum::Router, req: Request<Body>) {
            let response = app.oneshot(req).await.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 10_000).await.unwrap()
            ).unwrap();
            assert_eq!(body["error"]["code"].as_str(), Some("PLATFORM_ADMIN_REQUIRED"));
        }

        assert_platform_admin_required(app.clone(), Request::builder()
            .method("POST")
            .uri("/api/v1/platform/organizations")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", org_admin_token))
            .body(Body::from(serde_json::to_string(&json!({
                "name": "Should Not Provision", "org_type": "OFFICE",
                "slug": format!("nope-{}", Uuid::new_v4()), "timezone": "UTC",
                "admin_email": format!("nope_{}@visitorpass.app", Uuid::new_v4()), "admin_name": "Nope"
            })).unwrap())).unwrap()).await;

        assert_platform_admin_required(app.clone(), Request::builder()
            .method("PUT")
            .uri(format!("/api/v1/platform/organizations/{}/tier", org_id))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", org_admin_token))
            .body(Body::from(serde_json::to_string(&json!({
                "tier": "PRO", "max_locations": 5, "max_daily_passes": 200
            })).unwrap())).unwrap()).await;

        assert_platform_admin_required(app.clone(), Request::builder()
            .method("GET")
            .uri("/api/v1/platform/metrics")
            .header("authorization", format!("Bearer {}", org_admin_token))
            .body(Body::empty()).unwrap()).await;

        assert_platform_admin_required(app.clone(), Request::builder()
            .method("POST")
            .uri(format!("/api/v1/platform/devices/{}/revoke", Uuid::now_v7()))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", org_admin_token))
            .body(Body::from(serde_json::to_string(&json!({ "reason": null })).unwrap())).unwrap()).await;

        sqlx::query("DELETE FROM app.org_memberships WHERE user_id = $1").bind(org_admin_user_id).execute(&db_pool).await.ok();
        sqlx::query("DELETE FROM app.users WHERE id = $1").bind(org_admin_user_id).execute(&db_pool).await.ok();
        teardown_test_env(&db_pool, org_id, user_id, location_id).await;
    }

    // ── Push notification + denial_reason enum test fixtures ──────────────

    /// Test double for `NotificationProvider` that records every call
    /// instead of sending anything, so tests can assert exactly what a
    /// use case tried to send and to whom. `parking_lot::Mutex` because
    /// every call site here locks-and-immediately-unwraps (no async
    /// hold-across-await, no poisoning boilerplate needed).
    #[derive(Default)]
    struct CapturingNotifier {
        push_calls: parking_lot::Mutex<Vec<(String, String, String)>>, // (token, title, body)
        sms_calls:  parking_lot::Mutex<Vec<(String, String)>>,         // (to_e164, body)
    }

    #[async_trait::async_trait]
    impl visitorpass_application::ports::NotificationProvider for CapturingNotifier {
        async fn send_sms(&self, to_e164: &str, body: &str) -> Result<(), visitorpass_domain::DomainError> {
            self.sms_calls.lock().push((to_e164.to_string(), body.to_string()));
            Ok(())
        }

        async fn send_email(
            &self,
            _input: visitorpass_application::ports::notification_provider::EmailInput,
        ) -> Result<(), visitorpass_domain::DomainError> {
            Ok(())
        }

        async fn send_push(&self, device_token: &str, title: &str, body: &str) -> Result<(), visitorpass_domain::DomainError> {
            self.push_calls.lock().push((device_token.to_string(), title.to_string(), body.to_string()));
            Ok(())
        }
    }

    /// Identical to `setup_test_env` except it takes an injected
    /// `NotificationProvider` instead of always wiring `NoopNotificationProvider`
    /// -- so notification tests can pass a `CapturingNotifier` and assert on
    /// it afterward. Duplicated rather than adding an optional parameter to
    /// `setup_test_env` itself: that function is called from dozens of
    /// existing tests (and possibly concurrently-edited by sibling work),
    /// so changing its signature is exactly the kind of wide, non-additive
    /// change the shared-file collision-avoidance guidance for this task
    /// warns against. Mirrors this file's own existing precedent of
    /// `setup_test_env` / `setup_login_test_env` being independent,
    /// mostly-duplicated helpers rather than one parameterized function.
    async fn setup_test_env_with_notifier(
        notifier: Arc<dyn visitorpass_application::ports::NotificationProvider>,
    ) -> Option<(axum::Router, sqlx::PgPool, Uuid, Uuid, Uuid, String)> {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://visitorpass:CHANGEME@localhost:5432/visitorpass".to_string());
        let app_database_url = std::env::var("APP_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://visitorpass_app:CHANGEME_APP_ROLE_PASSWORD@localhost:5432/visitorpass".to_string());

        let db_pool = sqlx::PgPool::connect(&database_url).await.ok()?;
        let app_db_pool = sqlx::PgPool::connect(&app_database_url).await.ok()?;

        let org_id = Uuid::now_v7();
        let location_id = Uuid::now_v7();
        let user_id = Uuid::now_v7();
        let org_slug = format!("e2e-notif-test-org-{}", Uuid::new_v4());
        let user_email = format!("mock_e2e_notif_test_{}@visitorpass.app", Uuid::new_v4());

        let master_key_hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string();
        std::env::set_var("MASTER_KEY_HEX", &master_key_hex);
        let key_provider: Arc<dyn visitorpass_application::ports::KeyProvider> = Arc::new(
            visitorpass_infrastructure::key_provider::env_key_provider::EnvKeyProvider::from_env()
        );
        let crypto: Arc<dyn visitorpass_application::ports::CryptoService> = Arc::new(
            visitorpass_infrastructure::crypto::service::DefaultCryptoService::new(Arc::clone(&key_provider))
        );

        sqlx::query("INSERT INTO app.organizations (id, name, org_type, slug) VALUES ($1, 'E2E Notif Test Org', 'OFFICE', $2)")
            .bind(org_id).bind(&org_slug).execute(&db_pool).await.ok()?;

        let keypair = crypto.generate_org_keypair(org_id, 1).ok()?;
        sqlx::query(
            "INSERT INTO app.org_keys (id, org_id, version, signing_public_key, signing_private_key_enc, key_derivation_nonce, enc_algorithm) \
             VALUES ($1, $2, 1, $3, $4, $5, 'CHACHA20_POLY1305')"
        )
            .bind(Uuid::now_v7()).bind(org_id).bind(&keypair.public_key_bytes)
            .bind(&keypair.encrypted_private_key).bind(&keypair.nonce)
            .execute(&db_pool).await.ok()?;

        sqlx::query("INSERT INTO app.locations (id, org_id, name, status) VALUES ($1, $2, 'Test Location', 'ACTIVE')")
            .bind(location_id).bind(org_id).execute(&db_pool).await.ok()?;

        sqlx::query("INSERT INTO app.users (id, email, password_hash, full_name) VALUES ($1, $2, 'unused-e2e-test-hash', 'E2E Notif User')")
            .bind(user_id).bind(&user_email).execute(&db_pool).await.ok()?;

        sqlx::query("INSERT INTO app.org_memberships (org_id, user_id, role, unit_identifier, status) VALUES ($1, $2, 'RESIDENT', 'Flat 101', 'ACTIVE')")
            .bind(org_id).bind(user_id).execute(&db_pool).await.ok()?;

        let config = AppConfig {
            host: "0.0.0.0".to_string(),
            port: 8080,
            database_url: app_database_url.clone(),
            migration_database_url: None,
            database_max_connections: 5,
            database_min_connections: 1,
            master_key_hex: master_key_hex.clone(),
            base_url: "http://localhost:8080".to_string(),
            env: "development".to_string(),
            default_retention_days: 90,
            sms_enabled: true,
            email_enabled: false,
            sms_provider_api_key: Some("test-api-key".to_string()),
            sms_sender_id: Some("test-sender".to_string()),
            sms_flow_id: Some("test-flow".to_string()),
            google_client_id: "test-google-client-id.apps.googleusercontent.com".to_string(),
        };

        let orgs: Arc<dyn visitorpass_application::ports::OrgRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgOrgRepository::new(app_db_pool.clone()));
        let users: Arc<dyn visitorpass_application::ports::UserRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgUserRepository::new(app_db_pool.clone()));
        let passes: Arc<dyn visitorpass_application::ports::PassRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgPassRepository::new(app_db_pool.clone()));
        let entries: Arc<dyn visitorpass_application::ports::EntryRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgEntryRepository::new(app_db_pool.clone()));
        let devices: Arc<dyn visitorpass_application::ports::DeviceRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgDeviceRepository::new(app_db_pool.clone()));
        let locations: Arc<dyn visitorpass_application::ports::LocationRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgLocationRepository::new(app_db_pool.clone()));
        let audit: Arc<dyn visitorpass_application::ports::AuditRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgAuditRepository::new(app_db_pool.clone()));
        let platform_admins: Arc<dyn visitorpass_application::ports::PlatformAdminRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgPlatformAdminRepository::new(app_db_pool.clone()));

        let create_pass = Arc::new(visitorpass_application::use_cases::CreatePassUseCase::new(
            Arc::clone(&passes), Arc::clone(&orgs), Arc::clone(&crypto), Arc::clone(&audit), config.base_url.clone(),
        ));
        let verify_pass = Arc::new(visitorpass_application::use_cases::VerifyPassUseCase::new(
            Arc::clone(&passes), Arc::clone(&orgs), Arc::clone(&crypto), Arc::clone(&audit),
        ));
        let revoke_pass = Arc::new(visitorpass_application::use_cases::RevokePassUseCase::new(
            Arc::clone(&passes), Arc::clone(&orgs), Arc::clone(&audit),
        ));
        let register_org = Arc::new(visitorpass_application::use_cases::RegisterOrganizationUseCase::new(
            Arc::clone(&orgs), Arc::clone(&users), Arc::clone(&crypto), Arc::clone(&audit),
        ));
        let register_device = Arc::new(visitorpass_application::use_cases::RegisterDeviceUseCase::new(
            Arc::clone(&devices), Arc::clone(&orgs), Arc::clone(&audit),
        ));
        let revoke_device = Arc::new(visitorpass_application::use_cases::RevokeDeviceUseCase::new(
            Arc::clone(&devices), Arc::clone(&audit),
        ));
        let sync_events = Arc::new(visitorpass_application::use_cases::SyncEventsUseCase::new(
            Arc::clone(&devices), Arc::clone(&passes), Arc::clone(&entries), Arc::clone(&orgs),
            Arc::clone(&users), Arc::clone(&crypto), Arc::clone(&audit), Arc::clone(&notifier), config.sms_enabled,
        ));
        let (broadcast_tx, _) = tokio::sync::broadcast::channel(1024);

        let state = AppState {
            config,
            db_pool: app_db_pool.clone(),
            key_provider,
            crypto,
            notifier,
            whatsapp_channel: Arc::new(visitorpass_infrastructure::share::whatsapp::WhatsAppShareChannel::default()),
            sms_channel: Arc::new(visitorpass_infrastructure::share::sms::SmsShareChannel::new(true, Arc::new(visitorpass_infrastructure::share::sms::NoopSmsHttpClient))),
            create_pass, verify_pass, revoke_pass, register_org, register_device, revoke_device, sync_events,
            orgs, users, passes, entries, devices, locations, audit, platform_admins,
            broadcast_tx,
            rate_limiter: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            jwks_cache: Arc::new(crate::handlers::google_auth::JwksCache::new()),
        };

        let app = build_router(state);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/google")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&json!({ "id_token": format!("mock_{}", user_email) })).unwrap()))
            .unwrap();
        let response = app.clone().oneshot(req).await.ok()?;
        let body_bytes = axum::body::to_bytes(response.into_body(), 10000).await.ok()?;
        let auth_res: serde_json::Value = serde_json::from_slice(&body_bytes).ok()?;
        let global_token = auth_res["access_token"].as_str()?;

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/select-org")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", global_token))
            .body(Body::from(serde_json::to_string(&json!({ "org_id": org_id })).unwrap()))
            .unwrap();
        let response = app.clone().oneshot(req).await.ok()?;
        let body_bytes = axum::body::to_bytes(response.into_body(), 10000).await.ok()?;
        let select_res: serde_json::Value = serde_json::from_slice(&body_bytes).ok()?;
        let scoped_token = select_res["access_token"].as_str()?.to_string();

        Some((app, db_pool, org_id, location_id, user_id, scoped_token))
    }

    /// Creates a resident-owned pass and a guard kiosk device via raw SQL
    /// (mirroring `test_sync_response_includes_org_public_key`'s existing
    /// convention for device fixtures), returning
    /// `(pass_id, guard_device_id)`.
    async fn seed_pass_and_guard_device(
        app: &axum::Router,
        db_pool: &sqlx::PgPool,
        org_id: Uuid,
        location_id: Uuid,
        scoped_token: &str,
        visitor_name: &str,
    ) -> (Uuid, Uuid) {
        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/organizations/{}/passes", org_id))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", scoped_token))
            .body(Body::from(serde_json::to_string(&json!({
                "location_id": location_id,
                "visitor_name": visitor_name,
                "visitor_phone": "+14155552673",
                "purpose": "Notification test",
                "valid_from": (Utc::now() - Duration::minutes(1)).to_rfc3339(),
                "valid_until": (Utc::now() + Duration::hours(2)).to_rfc3339(),
            })).unwrap())).unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 10_000).await.unwrap()
        ).unwrap();
        let pass_id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();

        let guard_device_id = Uuid::now_v7();
        let guard_device_pubkey: Vec<u8> = Uuid::new_v4().as_bytes().iter().chain(Uuid::new_v4().as_bytes().iter()).copied().collect();
        sqlx::query("INSERT INTO app.devices (id, org_id, location_id, device_type, name, public_key, status) VALUES ($1, $2, $3, 'GUARD_KIOSK', 'Test Kiosk', $4, 'ACTIVE')")
            .bind(guard_device_id).bind(org_id).bind(location_id).bind(&guard_device_pubkey)
            .execute(db_pool).await.unwrap();

        (pass_id, guard_device_id)
    }

    // Sub-phase A acceptance: creating an ENTRY entry_log (via the guard-
    // device sync path -- the ONLY EntryRepository::create call site in
    // this codebase; ad-hoc approvals never write entry_logs at all, see
    // this phase's final report) with a resident who owns a device with a
    // push_token fires exactly one send_push call, to that token, with a
    // message naming the visitor -- and does NOT fall back to SMS.
    #[tokio::test]
    async fn test_entry_sync_event_triggers_push_notification_to_resident_device() {
        let notifier = Arc::new(CapturingNotifier::default());
        let (app, db_pool, org_id, location_id, user_id, scoped_token) =
            setup_test_env_with_notifier(notifier.clone()).await.expect("Failed to setup test environment");

        let visitor_name = "Push Notification Guest";
        let (pass_id, guard_device_id) =
            seed_pass_and_guard_device(&app, &db_pool, org_id, location_id, &scoped_token, visitor_name).await;

        // Resident's own device, with a push_token on file.
        let resident_device_id = Uuid::now_v7();
        let resident_device_pubkey: Vec<u8> = Uuid::new_v4().as_bytes().iter().chain(Uuid::new_v4().as_bytes().iter()).copied().collect();
        sqlx::query("INSERT INTO app.devices (id, org_id, owner_user_id, device_type, name, public_key, push_token, status) VALUES ($1, $2, $3, 'RESIDENT_PHONE', 'Resident Phone', $4, $5, 'ACTIVE')")
            .bind(resident_device_id).bind(org_id).bind(user_id).bind(&resident_device_pubkey).bind("test-push-token-abc123")
            .execute(&db_pool).await.unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/sync")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", scoped_token))
            .body(Body::from(serde_json::to_string(&json!({
                "device_id": guard_device_id,
                "last_sync_seq": 0,
                "events": [{
                    "client_event_id": Uuid::now_v7(),
                    "event_type": "ENTRY_LOG",
                    "pass_id": pass_id,
                    "action": "ENTRY",
                    "occurred_at": Utc::now().to_rfc3339(),
                    "location_id": location_id,
                }],
            })).unwrap())).unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 10_000).await.unwrap()
        ).unwrap();
        assert_eq!(body["accepted"].as_u64().unwrap(), 1);
        assert_eq!(body["rejected"].as_u64().unwrap(), 0);

        let push_calls = notifier.push_calls.lock().clone();
        assert_eq!(push_calls.len(), 1, "expected exactly one push notification call, got {:?}", push_calls);
        assert_eq!(push_calls[0].0, "test-push-token-abc123");
        assert!(
            push_calls[0].2.contains(visitor_name),
            "notification body {:?} should mention the visitor's name",
            push_calls[0].2
        );
        assert_eq!(notifier.sms_calls.lock().len(), 0, "SMS fallback must not fire when a push token exists");

        teardown_test_env(&db_pool, org_id, user_id, location_id).await;
    }

    // Sub-phase A decision (stated in the final report): only ENTRY events
    // notify in v1. This proves EXIT and DENIED sync events -- even when the
    // resident has a perfectly good push token on file -- do NOT trigger
    // any notification call.
    #[tokio::test]
    async fn test_exit_and_denied_sync_events_do_not_trigger_notification() {
        let notifier = Arc::new(CapturingNotifier::default());
        let (app, db_pool, org_id, location_id, user_id, scoped_token) =
            setup_test_env_with_notifier(notifier.clone()).await.expect("Failed to setup test environment");

        let (pass_id, guard_device_id) =
            seed_pass_and_guard_device(&app, &db_pool, org_id, location_id, &scoped_token, "No Notify Guest").await;

        let resident_device_id = Uuid::now_v7();
        let resident_device_pubkey: Vec<u8> = Uuid::new_v4().as_bytes().iter().chain(Uuid::new_v4().as_bytes().iter()).copied().collect();
        sqlx::query("INSERT INTO app.devices (id, org_id, owner_user_id, device_type, name, public_key, push_token, status) VALUES ($1, $2, $3, 'RESIDENT_PHONE', 'Resident Phone', $4, $5, 'ACTIVE')")
            .bind(resident_device_id).bind(org_id).bind(user_id).bind(&resident_device_pubkey).bind("test-push-token-should-not-fire")
            .execute(&db_pool).await.unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/sync")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", scoped_token))
            .body(Body::from(serde_json::to_string(&json!({
                "device_id": guard_device_id,
                "last_sync_seq": 0,
                "events": [
                    {
                        "client_event_id": Uuid::now_v7(),
                        "event_type": "ENTRY_LOG",
                        "pass_id": pass_id,
                        "action": "EXIT",
                        "occurred_at": Utc::now().to_rfc3339(),
                        "location_id": location_id,
                    },
                    {
                        "client_event_id": Uuid::now_v7(),
                        "event_type": "ENTRY_LOG",
                        "pass_id": pass_id,
                        "action": "DENIED",
                        "denial_reason": "OTHER",
                        "occurred_at": Utc::now().to_rfc3339(),
                        "location_id": location_id,
                    },
                ],
            })).unwrap())).unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 10_000).await.unwrap()
        ).unwrap();
        assert_eq!(body["accepted"].as_u64().unwrap(), 2, "both EXIT and DENIED should be accepted (persisted)");

        assert_eq!(notifier.push_calls.lock().len(), 0, "EXIT/DENIED must not trigger a push notification");
        assert_eq!(notifier.sms_calls.lock().len(), 0, "EXIT/DENIED must not trigger an SMS notification");

        teardown_test_env(&db_pool, org_id, user_id, location_id).await;
    }

    // Sub-phase B acceptance: an unrecognized denial_reason string on a
    // DENIED sync event must be rejected with 400 at the real HTTP
    // endpoint (not silently absorbed into a 200-with-rejected-count
    // response, and not a 500 from a DB enum constraint violation), and
    // must write zero entry_logs rows for the WHOLE request.
    #[tokio::test]
    async fn test_sync_denied_event_with_invalid_reason_returns_400_and_writes_zero_rows() {
        let (app, db_pool, org_id, location_id, user_id, scoped_token) =
            setup_test_env().await.expect("Failed to setup test environment");

        let (pass_id, guard_device_id) =
            seed_pass_and_guard_device(&app, &db_pool, org_id, location_id, &scoped_token, "Invalid Reason Guest").await;

        let rows_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM app.entry_logs WHERE pass_id = $1")
            .bind(pass_id).fetch_one(&db_pool).await.unwrap();
        assert_eq!(rows_before, 0);

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/sync")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", scoped_token))
            .body(Body::from(serde_json::to_string(&json!({
                "device_id": guard_device_id,
                "last_sync_seq": 0,
                "events": [{
                    "client_event_id": Uuid::now_v7(),
                    "event_type": "ENTRY_LOG",
                    "pass_id": pass_id,
                    "action": "DENIED",
                    "denial_reason": "NOT_A_REAL_DENIAL_REASON",
                    "occurred_at": Utc::now().to_rfc3339(),
                    "location_id": location_id,
                }],
            })).unwrap())).unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "unrecognized denial_reason must be a 400, not 200-with-rejected or 500");

        let rows_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM app.entry_logs WHERE pass_id = $1")
            .bind(pass_id).fetch_one(&db_pool).await.unwrap();
        assert_eq!(rows_after, 0, "an invalid denial_reason must write zero rows");

        teardown_test_env(&db_pool, org_id, user_id, location_id).await;
    }

    // Sub-phase B acceptance: a valid enum denial_reason round-trips
    // correctly through the real HTTP endpoint, the real Postgres
    // app.denial_reason column (migration 027), and back out through the
    // entries listing API.
    #[tokio::test]
    async fn test_sync_denied_event_with_valid_reason_round_trips() {
        let (app, db_pool, org_id, location_id, user_id, scoped_token) =
            setup_test_env().await.expect("Failed to setup test environment");

        let (pass_id, guard_device_id) =
            seed_pass_and_guard_device(&app, &db_pool, org_id, location_id, &scoped_token, "Valid Reason Guest").await;

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/sync")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", scoped_token))
            .body(Body::from(serde_json::to_string(&json!({
                "device_id": guard_device_id,
                "last_sync_seq": 0,
                "events": [{
                    "client_event_id": Uuid::now_v7(),
                    "event_type": "ENTRY_LOG",
                    "pass_id": pass_id,
                    "action": "DENIED",
                    "denial_reason": "PASS_REVOKED",
                    "occurred_at": Utc::now().to_rfc3339(),
                    "location_id": location_id,
                }],
            })).unwrap())).unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 10_000).await.unwrap()
        ).unwrap();
        assert_eq!(body["accepted"].as_u64().unwrap(), 1);
        assert_eq!(body["rejected"].as_u64().unwrap(), 0);

        // Direct DB check: the column is genuinely `app.denial_reason`
        // (migration 027), not TEXT, and holds the exact value sent.
        let stored: String = sqlx::query_scalar(
            "SELECT denial_reason::text FROM app.entry_logs WHERE pass_id = $1 AND action = 'DENIED'::app.entry_action"
        ).bind(pass_id).fetch_one(&db_pool).await.expect("denied entry log must have been written");
        assert_eq!(stored, "PASS_REVOKED");

        // Round-trip through the real API too.
        let req = Request::builder()
            .method("GET")
            .uri(format!("/api/v1/organizations/{}/entries?pass_id={}", org_id, pass_id))
            .header("authorization", format!("Bearer {}", scoped_token))
            .body(Body::empty()).unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 10_000).await.unwrap()
        ).unwrap();
        let items = body["items"].as_array().expect("entries list must return items");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["denial_reason"].as_str().unwrap(), "PASS_REVOKED");

        teardown_test_env(&db_pool, org_id, user_id, location_id).await;
    }

    // ── TokenStorage phase: refresh token moved from JSON body to an
    // HttpOnly cookie for /auth/google and /auth/select-org ────────────────

    // Acceptance (a): /auth/google's mock login path (single membership,
    // auto-login branch) returns the refresh token via a Set-Cookie header
    // (HttpOnly; Secure; SameSite=Strict; scoped Path) and NEVER in the
    // JSON body -- closing the pre-existing gap where /auth/google minted
    // no refresh token at all.
    #[tokio::test]
    async fn test_google_auth_sets_refresh_cookie_and_omits_body_field() {
        let (app, db_pool, org_id, user_id, org_slug, user_email, _password) =
            setup_login_test_env().await.expect("Failed to setup login test environment");
        let _ = org_slug;

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/google")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&json!({
                "id_token": format!("mock_{}", user_email)
            })).unwrap()))
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let set_cookie = response
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .expect("google_auth (single membership) must set a refresh_token cookie")
            .to_str()
            .unwrap()
            .to_string();

        assert!(set_cookie.starts_with("refresh_token="), "cookie name must be refresh_token: {set_cookie}");
        assert!(set_cookie.contains("HttpOnly"), "missing HttpOnly: {set_cookie}");
        assert!(set_cookie.contains("Secure"), "missing Secure: {set_cookie}");
        assert!(set_cookie.contains("SameSite=Strict"), "missing SameSite=Strict: {set_cookie}");
        assert!(set_cookie.contains("Path=/api/v1/auth"), "missing scoped Path: {set_cookie}");
        assert!(set_cookie.contains("Max-Age="), "missing Max-Age: {set_cookie}");

        let body_bytes = axum::body::to_bytes(response.into_body(), 10_000).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert!(body.get("refresh_token").is_none(), "refresh_token must NOT appear in the JSON body: {body}");
        assert!(body["access_token"].as_str().is_some(), "access_token must still be in the body");

        teardown_login_test_env(&db_pool, org_id, user_id).await;
    }

    // Acceptance (b): /auth/refresh works when the refresh token arrives
    // ONLY via the cookie -- no refresh_token field in the request body at
    // all, proving the cookie-read path works standalone, not merely as a
    // fallback alongside a body value.
    #[tokio::test]
    async fn test_refresh_via_cookie_only_succeeds_and_rotates_cookie() {
        let (app, db_pool, org_id, user_id, _org_slug, user_email, _password) =
            setup_login_test_env().await.expect("Failed to setup login test environment");

        let google_req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/google")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&json!({
                "id_token": format!("mock_{}", user_email)
            })).unwrap()))
            .unwrap();
        let google_resp = app.clone().oneshot(google_req).await.unwrap();
        assert_eq!(google_resp.status(), StatusCode::OK);
        let set_cookie = google_resp
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        // Extract just the `name=value` pair (before the first `;`) to send
        // back as a request `Cookie` header, exactly like a real browser.
        let cookie_pair = set_cookie.split(';').next().unwrap().to_string();

        let refresh_req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/refresh")
            .header("content-type", "application/json")
            .header("cookie", &cookie_pair)
            .body(Body::from("{}"))
            .unwrap();
        let refresh_resp = app.clone().oneshot(refresh_req).await.unwrap();
        assert_eq!(refresh_resp.status(), StatusCode::OK, "refresh must succeed using only the cookie, no body field");

        let new_set_cookie = refresh_resp
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .expect("refresh must re-set a rotated refresh_token cookie")
            .to_str()
            .unwrap()
            .to_string();
        assert_ne!(
            cookie_pair,
            new_set_cookie.split(';').next().unwrap(),
            "rotation must issue a genuinely new cookie value"
        );

        let body_bytes = axum::body::to_bytes(refresh_resp.into_body(), 10_000).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert!(body["access_token"].as_str().is_some());

        teardown_login_test_env(&db_pool, org_id, user_id).await;
    }

    // select_org is the only place a refresh session is created for a
    // caller who did NOT have exactly one membership at /auth/google time --
    // verify it now issues a refresh cookie too. It never returned
    // refresh_token in its JSON body, so there is nothing to "stop
    // returning" there, just the new cookie to check for.
    #[tokio::test]
    async fn test_select_org_issues_refresh_cookie() {
        let (app, db_pool, org_id, user_id, org_slug, user_email, password) =
            setup_login_test_env().await.expect("Failed to setup login test environment");

        let (access_token, _refresh) = do_login(&app, &org_slug, &user_email, &password).await;

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/select-org")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", access_token))
            .body(Body::from(serde_json::to_string(&json!({ "org_id": org_id })).unwrap()))
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let set_cookie = response
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .expect("select_org must set a refresh_token cookie")
            .to_str()
            .unwrap()
            .to_string();
        assert!(set_cookie.starts_with("refresh_token="));
        assert!(set_cookie.contains("HttpOnly") && set_cookie.contains("Secure") && set_cookie.contains("SameSite=Strict"));

        let body_bytes = axum::body::to_bytes(response.into_body(), 10_000).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert!(body.get("refresh_token").is_none(), "select_org's JSON body must never carry the refresh token");

        teardown_login_test_env(&db_pool, org_id, user_id).await;
    }

    // Logout must clear the cookie (Max-Age=0) so the browser drops it
    // immediately instead of holding onto a revoked token for 30 days, and
    // must accept the token via the cookie alone, symmetric with refresh.
    #[tokio::test]
    async fn test_logout_clears_refresh_cookie() {
        let (app, db_pool, org_id, user_id, org_slug, user_email, password) =
            setup_login_test_env().await.expect("Failed to setup login test environment");

        let (_access, refresh) = do_login(&app, &org_slug, &user_email, &password).await;

        let logout_req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/logout")
            .header("content-type", "application/json")
            .header("cookie", format!("refresh_token={}", refresh))
            .body(Body::from("{}"))
            .unwrap();
        let logout_resp = app.clone().oneshot(logout_req).await.unwrap();
        assert_eq!(logout_resp.status(), StatusCode::OK);

        let clearing_cookie = logout_resp
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .expect("logout must clear the refresh_token cookie")
            .to_str()
            .unwrap()
            .to_string();
        assert!(clearing_cookie.contains("Max-Age=0"), "logout must expire the cookie immediately: {clearing_cookie}");

        // The session the cookie identified must actually be revoked --
        // refresh with the same (now logged-out) token must fail.
        let resp_after_logout = do_refresh(&app, &refresh).await;
        assert_eq!(resp_after_logout.status(), StatusCode::UNAUTHORIZED);

        teardown_login_test_env(&db_pool, org_id, user_id).await;
    }

    // Platform admins are never a row in app.org_memberships and
    // app.sessions.org_id is NOT NULL, so /auth/google must NOT attempt to
    // issue a refresh session (and therefore sets no Set-Cookie header) for
    // them -- see google_auth's doc comment on that branch.
    #[tokio::test]
    async fn test_platform_admin_google_auth_has_no_refresh_cookie() {
        let (app, db_pool, org_id, location_id, user_id, _scoped_token) =
            setup_test_env().await.expect("Failed to setup test environment");

        let admin_user_id = Uuid::now_v7();
        let admin_email = format!("platform_admin_cookie_test_{}@visitorpass.app", Uuid::new_v4());
        sqlx::query("INSERT INTO app.users (id, email, password_hash, full_name) VALUES ($1, $2, 'unused-e2e-test-hash', 'Platform Admin')")
            .bind(admin_user_id)
            .bind(&admin_email)
            .execute(&db_pool)
            .await
            .expect("seed platform admin user");
        sqlx::query("INSERT INTO app.platform_admins (user_id, granted_by) VALUES ($1, NULL)")
            .bind(admin_user_id)
            .execute(&db_pool)
            .await
            .expect("seed platform_admins row");

        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/google")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&json!({
                "id_token": format!("mock_{}", admin_email)
            })).unwrap()))
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers().get(axum::http::header::SET_COOKIE).is_none(),
            "platform admin google_auth must not set a refresh cookie (no org to scope a session to)"
        );

        sqlx::query("DELETE FROM app.platform_admins WHERE user_id = $1").bind(admin_user_id).execute(&db_pool).await.ok();
        sqlx::query("DELETE FROM app.users WHERE id = $1").bind(admin_user_id).execute(&db_pool).await.ok();
        teardown_test_env(&db_pool, org_id, user_id, location_id).await;
    }
}
