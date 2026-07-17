use axum::{extract::State, http::HeaderMap, response::IntoResponse, Json};
use std::future::Future;
use pasetors::{
    claims::Claims as PasetoClaims,
    keys::AsymmetricSecretKey,
    version4::V4,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use visitorpass_domain::{value_objects::Role, DomainError};
use visitorpass_application::ports::repositories::CreateUserInput;

use crate::{
    errors::ApiError,
    handlers::auth::{create_session, refresh_cookie_header},
    state::AppState,
};

// ── DTOs ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct GoogleLoginRequest {
    pub id_token: String,
}

#[derive(Debug, Serialize)]
pub struct MembershipSummary {
    pub org_id:          Uuid,
    pub org_name:        String,
    pub role:            String,
    pub unit_identifier: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GoogleLoginResponse {
    // Present only if user has exactly 1 membership
    pub access_token:   Option<String>,
    pub role:           Option<String>,
    pub expires_in:     Option<i64>,

    // Always returned for frontend routing
    pub user:           UserSummary,
    pub memberships:    Vec<MembershipSummary>,
}

#[derive(Debug, Serialize)]
pub struct UserSummary {
    pub id:        Uuid,
    pub email:     String,
    pub full_name: String,
}

#[derive(Debug, Deserialize)]
struct GoogleClaims {
    iss:   String,
    aud:   String,
    email: String,
    name:  Option<String>,
}

// ── Handler ───────────────────────────────────────────────────────────────────

/// POST /api/v1/auth/google
/// Authenticates the user using a Google Identity Services ID token.
/// Automatically creates a user profile if this is their first login.
pub async fn google_auth(
    State(state): State<AppState>,
    Json(req): Json<GoogleLoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // 1. Verify Google token and extract email/name
    let email_and_name = verify_google_token(&state, &req.id_token).await?;

    let email = email_and_name.0.to_lowercase();
    let full_name = email_and_name.1.unwrap_or_else(|| email.split('@').next().unwrap_or("User").to_string());

    // 2. Lookup or create User
    let user = match state.users.find_by_email(&email).await {
        Ok(u) => u,
        Err(_) => {
            // New user registration
            let dummy_pass = Uuid::new_v4().to_string(); // random password for OAuth accounts
            let password_hash = state.crypto.hash_password(&dummy_pass).await?;
            state.users.create(CreateUserInput {
                email:         email.clone(),
                password_hash,
                phone_hmac:     None,
                full_name:     full_name.clone(),
            }).await?
        }
    };

    user.check_not_locked(chrono::Utc::now())?;
    state.users.record_login_success(user.id).await?;

    // 3. Platform admins bypass the org-membership flow entirely -- they
    // are never a row in app.org_memberships (see migration 022 and
    // PlatformContext's doc comment), so there is no "membership" to
    // select. Check this BEFORE loading memberships: a platform admin may
    // also happen to hold org memberships (e.g. the SaaS owner also runs a
    // demo org), and if we loaded memberships first we could accidentally
    // route them into the single-membership auto-login branch below with
    // the wrong (org-scoped) role. Platform admin status always wins.
    if state.platform_admins.is_platform_admin(user.id).await? {
        let token = generate_paseto_token(&state, None, user.id, Role::PlatformAdmin, None, None)?;
        // No refresh session: app.sessions.org_id is NOT NULL (migration
        // 20240101000006) and platform admins are never a row in
        // app.org_memberships, so there is no org to scope a session to.
        // They re-authenticate via Google whenever their 15-minute access
        // token expires instead of holding a long-lived refresh session --
        // see the TokenStorage phase report for this tradeoff.
        return Ok((
            HeaderMap::new(),
            Json(GoogleLoginResponse {
                access_token: Some(token),
                role:         Some(Role::PlatformAdmin.as_str().to_string()),
                expires_in:   Some(900),
                user: UserSummary {
                    id:        user.id,
                    email:     user.email,
                    full_name: user.full_name,
                },
                memberships: Vec::new(),
            }),
        ));
    }

    // 4. Load all memberships for this user
    let memberships = load_user_memberships(&state, user.id).await?;

    // 5. Determine response: automatic login vs organization selector
    let mut access_token = None;
    let mut active_role = None;
    let mut expires_in = None;
    let mut refresh_headers = HeaderMap::new();

    if memberships.len() == 1 {
        let primary = &memberships[0];
        let role = Role::try_from(primary.role.as_str()).unwrap_or(Role::Resident);

        let token = generate_paseto_token(&state, Some(primary.org_id), user.id, role, None, None)?;
        access_token = Some(token);
        active_role = Some(primary.role.clone());
        expires_in = Some(900);

        // Exactly one membership means we already know which org to scope a
        // refresh session to, so issue one now (delivered as an HttpOnly
        // cookie) instead of forcing a redundant /auth/select-org round
        // trip just to obtain one -- mirrors the auto-login UX this branch
        // already gives the access token.
        let refresh_token = create_session(&state, primary.org_id, user.id, Uuid::new_v4()).await?;
        refresh_headers = refresh_cookie_header(&refresh_token);
    } else {
        // 0 or >1 memberships: no single org to scope a session to yet.
        // /auth/select-org is where the refresh session actually gets
        // created, once the client tells us which org.
        let token = generate_paseto_token(&state, Some(Uuid::nil()), user.id, Role::Resident, None, None)?;
        access_token = Some(token);
        expires_in = Some(900);
    }

    Ok((
        refresh_headers,
        Json(GoogleLoginResponse {
            access_token,
            role: active_role,
            expires_in,
            user: UserSummary {
                id:        user.id,
                email:     user.email,
                full_name: user.full_name,
            },
            memberships,
        }),
    ))
}

// ── Google token verification ────────────────────────────────────────────────

async fn verify_google_token(
    state: &AppState,
    id_token: &str,
) -> Result<(String, Option<String>), ApiError> {
    // ── Local Development / Offline Mock ──────────────────────────────────
    if state.config.env == "development" || state.config.env == "test" {
        // If token starts with mock_, bypass Google servers (enables offline dev)
        if id_token.starts_with("mock_") {
            let email = id_token.strip_prefix("mock_").unwrap_or("dev@visitorpass.app").to_string();
            let name = Some("Developer User".to_string());
            return Ok((email, name));
        }
    }

    // ── Production Verification ───────────────────────────────────────────
    // Fetch google keys and verify JWT signature
    let header = jsonwebtoken::decode_header(id_token)
        .map_err(|_| ApiError::unauthorized("TOKEN_INVALID", "Invalid JWT header format"))?;

    let kid = header.kid.ok_or_else(|| {
        ApiError::unauthorized("TOKEN_INVALID", "Google ID token must contain kid header")
    })?;

    // Fetch JWKS certificates from Google, through the process-wide cache.
    let jwks = state.jwks_cache.get(&kid, fetch_google_jwks).await?;
    let key = jwks
        .keys
        .iter()
        .find(|k| k.kid == kid)
        .ok_or_else(|| ApiError::unauthorized("TOKEN_INVALID", "Google signing key not found in JWKS"))?;

    let decoding_key = jsonwebtoken::DecodingKey::from_rsa_components(&key.n, &key.e)
        .map_err(|_| ApiError::internal())?;

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_issuer(&["https://accounts.google.com", "accounts.google.com"]);
    // Audience validation: check that token is issued for our app (prevents account takeover)
    validation.set_audience(&[state.config.google_client_id.as_str()]);
    validation.validate_aud = true;

    let claims = jsonwebtoken::decode::<GoogleClaims>(id_token, &decoding_key, &validation)
        .map_err(|e| {
            tracing::error!(error = %e, "Google signature validation failed");
            ApiError::unauthorized("TOKEN_INVALID", "Google signature verification failed")
        })?;

    Ok((claims.claims.email, claims.claims.name))
}

// JWKS fetching structures
#[derive(Debug, Clone, Deserialize)]
pub struct JwksResponse {
    keys: Vec<JwksKey>,
}

#[derive(Debug, Clone, Deserialize)]
struct JwksKey {
    kid: String,
    n:   String,
    e:   String,
}

/// In-memory cache for Google's JWKS (signing key set), with a TTL and
/// kid-aware refetch so key rotation doesn't require waiting out the TTL.
///
/// The fetch mechanism is injected as a closure (rather than calling
/// `fetch_google_jwks` directly) so the caching POLICY -- when to reuse the
/// cache vs. hit the network -- can be unit tested with a fake, counting
/// fetcher, independent of any real network call to Google.
pub struct JwksCache {
    state: tokio::sync::RwLock<Option<CachedJwks>>,
    ttl: std::time::Duration,
}

struct CachedJwks {
    jwks: JwksResponse,
    fetched_at: std::time::Instant,
}

/// Refetch at most this often when the cache is otherwise fresh and already
/// contains the requested kid. Google recommends caching for hours, not
/// fetching on every verification; 6h keeps us well within their guidance
/// while still picking up a rotation within the same business day via the
/// kid-miss path below.
const JWKS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(6 * 60 * 60);

impl JwksCache {
    pub fn new() -> Self {
        Self::with_ttl(JWKS_CACHE_TTL)
    }

    /// Same as `new()`, but with an explicit TTL -- used by tests to avoid
    /// waiting out a real 6-hour window to exercise expiry.
    pub fn with_ttl(ttl: std::time::Duration) -> Self {
        Self { state: tokio::sync::RwLock::new(None), ttl }
    }

    /// Returns a JWKS response known to contain `kid` when possible.
    /// Refetches via `fetcher` on cache miss, TTL expiry, or when `kid`
    /// isn't present in the currently cached set (handles Google rotating
    /// keys without forcing every caller to wait out the TTL).
    pub async fn get<F, Fut>(&self, kid: &str, fetcher: F) -> Result<JwksResponse, ApiError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<JwksResponse, ApiError>>,
    {
        {
            let guard = self.state.read().await;
            if let Some(cached) = guard.as_ref() {
                let fresh = cached.fetched_at.elapsed() < self.ttl;
                let has_kid = cached.jwks.keys.iter().any(|k| k.kid == kid);
                if fresh && has_kid {
                    return Ok(cached.jwks.clone());
                }
            }
        }

        let jwks = fetcher().await?;
        let mut guard = self.state.write().await;
        *guard = Some(CachedJwks { jwks: jwks.clone(), fetched_at: std::time::Instant::now() });
        Ok(jwks)
    }
}

impl Default for JwksCache {
    fn default() -> Self {
        Self::new()
    }
}

async fn fetch_google_jwks() -> Result<JwksResponse, ApiError> {
    let resp = reqwest::get("https://www.googleapis.com/oauth2/v3/certs")
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to connect to Google certificate servers");
            ApiError::internal()
        })?;

    let jwks = resp.json::<JwksResponse>().await.map_err(|e| {
        tracing::error!(error = %e, "Failed to parse Google JWKS response");
        ApiError::internal()
    })?;

    Ok(jwks)
}

// ── Memberships loading helper ───────────────────────────────────────────────

async fn load_user_memberships(
    state: &AppState,
    user_id: Uuid,
) -> Result<Vec<MembershipSummary>, ApiError> {
    let list = state.users.list_memberships(user_id).await?;
    let summaries = list.into_iter().map(|(org_id, org_name, role, unit_id)| MembershipSummary {
        org_id,
        org_name,
        role: role.as_str().to_string(),
        unit_identifier: unit_id,
    }).collect();

    Ok(summaries)
}

// ── PASETO Token Builder ─────────────────────────────────────────────────────

fn generate_paseto_token(
    state: &AppState,
    org_id: Option<Uuid>,
    user_id: Uuid,
    role: Role,
    device_id: Option<Uuid>,
    location_id: Option<Uuid>,
) -> Result<String, DomainError> {
    let key_bytes = state.key_provider.derive_paseto_key()?;
    // AsymmetricSecretKey<V4> requires the full 64-byte seed||pubkey expansion;
    // see EnvKeyProvider::derive_paseto_key for why both halves matter.
    let secret_key = AsymmetricSecretKey::<V4>::from(&key_bytes[..])
        .map_err(|_| DomainError::CryptoError)?;

    let now = chrono::Utc::now();
    let expiry = now + chrono::Duration::minutes(15);

    let mut claims = PasetoClaims::new().map_err(|_| DomainError::CryptoError)?;
    claims.subject(&user_id.to_string()).map_err(|_| DomainError::CryptoError)?;
    claims.expiration(&expiry.to_rfc3339()).map_err(|_| DomainError::CryptoError)?;
    if let Some(org_id) = org_id {
        claims.add_additional("org", org_id.to_string()).map_err(|_| DomainError::CryptoError)?;
    }
    claims.add_additional("role", role.as_str()).map_err(|_| DomainError::CryptoError)?;

    if let Some(dev_id) = device_id {
        claims.add_additional("dev", dev_id.to_string()).map_err(|_| DomainError::CryptoError)?;
    }
    if let Some(loc_id) = location_id {
        claims.add_additional("loc", loc_id.to_string()).map_err(|_| DomainError::CryptoError)?;
    }

    let token = pasetors::public::sign(&secret_key, &claims, None, None)
        .map_err(|_| DomainError::CryptoError)?;

    Ok(token)
}

/// GET /api/v1/users/memberships
/// Returns all active memberships of the authenticated user.
pub async fn list_user_memberships(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<visitorpass_domain::value_objects::OrgContext>,
) -> Result<impl IntoResponse, ApiError> {
    let list = state.users.list_memberships(ctx.user_id).await?;
    let summaries: Vec<MembershipSummary> = list.into_iter().map(|(id, name, role, unit_id)| {
        MembershipSummary {
            org_id: id,
            org_name: name,
            role: role.as_str().to_string(),
            unit_identifier: unit_id,
        }
    }).collect();

    Ok(Json(serde_json::json!({
        "memberships": summaries
    })))
}

#[cfg(test)]
mod jwks_cache_tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    fn fake_jwks(kid: &str) -> JwksResponse {
        JwksResponse {
            keys: vec![JwksKey { kid: kid.to_string(), n: "fake-n".to_string(), e: "AQAB".to_string() }],
        }
    }

    // Two "logins" (calls to `.get()`) for the SAME kid, well within the TTL,
    // must trigger exactly ONE real fetch -- the second is served from cache.
    // This is the exact scenario the B3 fix addresses: fetch_google_jwks was
    // previously called unconditionally on every single login.
    #[tokio::test]
    async fn test_two_logins_within_ttl_trigger_one_fetch() {
        let cache = JwksCache::with_ttl(std::time::Duration::from_secs(3600));
        let fetch_count = Arc::new(AtomicU32::new(0));

        let fetch = |count: Arc<AtomicU32>, kid: &'static str| {
            let count = Arc::clone(&count);
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                Ok(fake_jwks(kid))
            }
        };

        let r1 = cache.get("kid-a", || fetch(Arc::clone(&fetch_count), "kid-a")).await.unwrap();
        assert_eq!(r1.keys[0].kid, "kid-a");
        assert_eq!(fetch_count.load(Ordering::SeqCst), 1, "first call must fetch");

        let r2 = cache.get("kid-a", || fetch(Arc::clone(&fetch_count), "kid-a")).await.unwrap();
        assert_eq!(r2.keys[0].kid, "kid-a");
        assert_eq!(fetch_count.load(Ordering::SeqCst), 1, "second call within TTL for a known kid must be served from cache, not refetch");
    }

    // A kid that isn't in the cached set must trigger an IMMEDIATE refetch,
    // even though the cache is still well within its TTL -- this is how key
    // rotation is picked up without waiting out the TTL.
    #[tokio::test]
    async fn test_unknown_kid_triggers_immediate_refetch_within_ttl() {
        let cache = JwksCache::with_ttl(std::time::Duration::from_secs(3600));
        let fetch_count = Arc::new(AtomicU32::new(0));
        // The fetcher simulates Google rotating in a new key: after the
        // first call it starts returning a JWKS containing "kid-new" too.
        let served_new_key = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let fetch = |count: Arc<AtomicU32>, served_new_key: Arc<std::sync::atomic::AtomicBool>| async move {
            count.fetch_add(1, Ordering::SeqCst);
            if served_new_key.load(Ordering::SeqCst) {
                Ok(fake_jwks("kid-new"))
            } else {
                Ok(fake_jwks("kid-old"))
            }
        };

        // Warm the cache with "kid-old".
        let r1 = cache.get("kid-old", || fetch(Arc::clone(&fetch_count), Arc::clone(&served_new_key))).await.unwrap();
        assert_eq!(r1.keys[0].kid, "kid-old");
        assert_eq!(fetch_count.load(Ordering::SeqCst), 1);

        // A second call for the SAME, already-cached kid must NOT refetch.
        cache.get("kid-old", || fetch(Arc::clone(&fetch_count), Arc::clone(&served_new_key))).await.unwrap();
        assert_eq!(fetch_count.load(Ordering::SeqCst), 1, "known kid within TTL must not refetch");

        // Now simulate rotation: the next real fetch would return "kid-new".
        served_new_key.store(true, Ordering::SeqCst);

        // Requesting "kid-new" -- NOT in the currently cached set -- must
        // trigger an immediate refetch despite the cache being fresh.
        let r3 = cache.get("kid-new", || fetch(Arc::clone(&fetch_count), Arc::clone(&served_new_key))).await.unwrap();
        assert_eq!(r3.keys[0].kid, "kid-new");
        assert_eq!(fetch_count.load(Ordering::SeqCst), 2, "an unknown kid must trigger an immediate refetch even within the TTL");
    }

    // Once the TTL has genuinely elapsed, even a previously-known kid must
    // trigger a refetch (belt-and-suspenders freshness, independent of the
    // kid-miss path).
    #[tokio::test]
    async fn test_expired_ttl_triggers_refetch_for_known_kid() {
        let cache = JwksCache::with_ttl(std::time::Duration::from_millis(20));
        let fetch_count = Arc::new(AtomicU32::new(0));

        let fetch = |count: Arc<AtomicU32>| async move {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(fake_jwks("kid-a"))
        };

        cache.get("kid-a", || fetch(Arc::clone(&fetch_count))).await.unwrap();
        assert_eq!(fetch_count.load(Ordering::SeqCst), 1);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        cache.get("kid-a", || fetch(Arc::clone(&fetch_count))).await.unwrap();
        assert_eq!(fetch_count.load(Ordering::SeqCst), 2, "an expired TTL must trigger a refetch even for a previously-known kid");
    }
}

#[cfg(test)]
mod jwks_wiring_test {
    use super::*;
    use std::sync::Arc;

    // Test-only RSA keypair (2048-bit, generated with `openssl genrsa`),
    // used ONLY to prove that `verify_google_token` genuinely consults
    // `state.jwks_cache` rather than always hitting the network. Never used
    // for anything security-relevant.
    const TEST_RSA_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCHUPQ7SnnG0r8x\n\
ontIW4BvZTs/AFLXkSlu7pFaxp2Z6+Vl7aXz3p3KEY0hd9ZFqQSy3eN2rpdrM6qp\n\
XhGOSPX2bM+yn9z3QkovUlF8p1OkTaen8XVkG6g7Yq0FJQz7OPPnyYFE59awtD7L\n\
m4b/evQtOXYHaeB2+s17TV7xJ46XiIhLzzUIqmUV56YYvvTdynM5Bjs3u38RfRDp\n\
ZFJW+Onl4WTiomLUN43gt4K3gIfiAl4KsvpbQXpJq1iW5Vz20QQn7QZPXZ9SbGJk\n\
sLAYKexZUoR3Q0rpnaQvM6zV75IrvWZR+FJCqo6zT470IPLyUb49/KqWkTn2+/C1\n\
3fRdEI+ZAgMBAAECggEABiXR6s2v6a4SfK1On5N0qtr1DaA0o1GXidAx72ddqqwS\n\
gIaDByjij1cry8z3gbOzoHK/TlmRTJAM3WQGNSowbpE0AIAN2Hf9CdhaFmk9vhW/\n\
G7y3IiS1iHkrtjOgOtu0DSBVDK3hzaZqwfJfeET8Sf+10pFnXtB3PHZf7WHoMw8y\n\
g2gzQJ6ovyiQEZGbqNWwmwGAp9bZKlVrtXKdD3mdcTljWOGEhfP5htivg+mdX0gN\n\
FUrpbhL5DAgCToXiNidQc5sSi0YJb36WnzjLsEyFmw4NoyhZ9RkZ+dDRc+omj6uB\n\
SOA/nOwe1TaM1FyKmdkVNi5x93ORrhD+1DtDGmGzGQKBgQC+dF2s/roKVWE7KBxR\n\
IBcAyLbHIqI9C4dae24T7Y+oNbuwt1828aoZbomoyCJaksK1Pd0STh/Tf1XA98/F\n\
gaNZE/KPbpNeg/ORcUSrjzha/5j6e+Nnoti/XuoeccTIjwcOAd+X+ghX+bqRQh94\n\
IgiYUWYXARkvRpDe0CucDUV1BQKBgQC14rszc6gZ8LBxCHqj3/npSWVdLs5I18g5\n\
/Mlyzs6syaeGUcrPawAFw7YNeHLqjnL//tUSDYbWYQGbA8qZN5Kj/eFCh9aztrJp\n\
XQ2fEpOaEhdeHWxCPmGVKXbi+UmR3ujnbwu+9HDiIwBUwX4xvd7fvkaEoe7ELOZJ\n\
HmQ0fUr0hQKBgQCifJMDKdu9PzSSDNmD2RXnBFb0NDcoT7Kt3op+k/oxL46u6PNh\n\
4/IUensVtZGhpn5ZtKrsmByNC6E03fe0cLLVJ7CU8GjohTkDiBhnKeyRrmlsos/T\n\
tlqngqnJSZTy6xvAtpZ1icsei5/BmCFTE+4zTZcE31oGPHUSs5XRMH1mpQKBgAQO\n\
AuhZurShVf2fF8TReGvH9BeItJaRIOiSBxelHpxhfneTGTdYhk6al1NjjQRHmq60\n\
SqG1ZX0f+n4vLnQN9hnrzfrCtnmZKA8LQQN70YiMwLKba09qvpgprXnP3uD+nCiU\n\
pClkn6Oa7iX1jk+jkPVh84Z/aag77AJTSB6XcHVVAoGAaoIoMwyA2kysUJom+lAm\n\
iYXIZdsEX2zzzPPEZgQ6eqnmWy1Roz/gtu9cbNVMQNmId9b1GBVfsXVNgRpvgq2q\n\
0eMCWUQS22Ar5NCRZNrTC0Utwl87oV66E2zrSiK53CHJPTcuS3oBGlO6DzvS9HSX\n\
dcc5y7nUCPrbx+0yu5Eieh8=\n\
-----END PRIVATE KEY-----";

    // Modulus (n) / exponent (e) of the SAME test keypair's public half,
    // base64url-encoded, for the fake JWKS entry.
    const TEST_RSA_N: &str = "h1D0O0p5xtK_MaJ7SFuAb2U7PwBS15Epbu6RWsadmevlZe2l896dyhGNIXfWRakEst3jdq6XazOqqV4Rjkj19mzPsp_c90JKL1JRfKdTpE2np_F1ZBuoO2KtBSUM-zjz58mBROfWsLQ-y5uG_3r0LTl2B2ngdvrNe01e8SeOl4iIS881CKplFeemGL703cpzOQY7N7t_EX0Q6WRSVvjp5eFk4qJi1DeN4LeCt4CH4gJeCrL6W0F6SatYluVc9tEEJ-0GT12fUmxiZLCwGCnsWVKEd0NK6Z2kLzOs1e-SK71mUfhSQqqOs0-O9CDy8lG-PfyqlpE59vvwtd30XRCPmQ";
    const TEST_RSA_E: &str = "AQAB";

    fn build_signed_jwt(kid: &str, aud: &str, email: &str) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(kid.to_string());

        let claims = serde_json::json!({
            "iss": "https://accounts.google.com",
            "aud": aud,
            "email": email,
            "name": "Wiring Test User",
            "exp": (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
            "iat": chrono::Utc::now().timestamp(),
        });

        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes())
            .expect("test RSA private key must parse");
        jsonwebtoken::encode(&header, &claims, &encoding_key).expect("signing must succeed")
    }

    async fn test_state() -> Option<AppState> {
        let app_database_url = std::env::var("APP_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://visitorpass_app:CHANGEME_APP_ROLE_PASSWORD@localhost:5432/visitorpass".to_string());
        let db_pool = sqlx::PgPool::connect(&app_database_url).await.ok()?;

        let master_key_hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_string();
        std::env::set_var("MASTER_KEY_HEX", &master_key_hex);
        let key_provider: Arc<dyn visitorpass_application::ports::KeyProvider> = Arc::new(
            visitorpass_infrastructure::key_provider::env_key_provider::EnvKeyProvider::from_env()
        );
        let crypto: Arc<dyn visitorpass_application::ports::CryptoService> = Arc::new(
            visitorpass_infrastructure::crypto::service::DefaultCryptoService::new(Arc::clone(&key_provider))
        );

        let config = crate::config::AppConfig {
            host: "0.0.0.0".to_string(),
            port: 8080,
            database_url: app_database_url.clone(),
            migration_database_url: None,
            database_max_connections: 5,
            database_min_connections: 1,
            master_key_hex,
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
        let platform_admins: Arc<dyn visitorpass_application::ports::PlatformAdminRepository> =
            Arc::new(visitorpass_infrastructure::db::postgres::PgPlatformAdminRepository::new(db_pool.clone()));

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

        Some(AppState {
            config,
            db_pool,
            key_provider,
            crypto,
            notifier,
            whatsapp_channel: Arc::new(visitorpass_infrastructure::share::whatsapp::WhatsAppShareChannel::default()),
            sms_channel: Arc::new(visitorpass_infrastructure::share::sms::SmsShareChannel::new(true, Arc::new(visitorpass_infrastructure::share::sms::NoopSmsHttpClient))),
            create_pass, verify_pass, revoke_pass, register_org, register_device, revoke_device, sync_events,
            orgs, users, passes, entries, devices, locations, audit, platform_admins,
            broadcast_tx,
            rate_limiter: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            jwks_cache: Arc::new(JwksCache::with_ttl(std::time::Duration::from_secs(3600))),
        })
    }

    // Proves `verify_google_token` -- the real, unmodified production
    // function -- genuinely reads through `state.jwks_cache` rather than
    // always hitting the network directly. Uses a `kid` that could never
    // coincidentally appear in Google's real JWKS, pre-warms the cache with
    // a locally-signed JWT/JWKS pair, and asserts verification succeeds
    // using ONLY that pre-warmed (fake) data -- which is only possible if
    // the cache was actually consulted.
    #[tokio::test]
    async fn test_verify_google_token_reads_through_jwks_cache() {
        let Some(state) = test_state().await else { return };

        let kid = format!("wiring-test-kid-{}", uuid::Uuid::new_v4());
        let email = "wiring-test@visitorpass.app";
        let jwt = build_signed_jwt(&kid, &state.config.google_client_id, email);

        // Pre-warm the cache directly, exactly as the FIRST real login would
        // (via fetch_google_jwks() over the network) -- except our fetcher
        // returns our own fake JWKS instead of calling Google.
        let fake_jwks = JwksResponse {
            keys: vec![JwksKey { kid: kid.clone(), n: TEST_RSA_N.to_string(), e: TEST_RSA_E.to_string() }],
        };
        let warm = fake_jwks.clone();
        state.jwks_cache.get(&kid, || async move { Ok(warm) }).await.unwrap();

        // The REAL verify_google_token must now find this kid in the
        // already-warmed cache and successfully verify -- proving the cache
        // is genuinely consulted by production code, not bypassed.
        let (verified_email, _name) = verify_google_token(&state, &jwt).await
            .expect("verify_google_token must succeed using the pre-warmed cache entry");
        assert_eq!(verified_email, email);
    }
}
