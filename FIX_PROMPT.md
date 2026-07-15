# Task: Fix and test all launch-blocking issues in VisitorPass

You are working in the repository at the current working directory (Rust workspace: `crates/domain`, `crates/application`, `crates/infrastructure`, `crates/api`; web frontend in `web/`; Kotlin Multiplatform mobile app in `mobile/`; SQL migrations in `migrations/`). This is a visitor-management SaaS ("VisitorPass"). A prior security/correctness audit found the issues listed below, each already verified against the actual code (file:line references are accurate as of this writing — re-read each file before editing since line numbers may have drifted).

Work through the items in order (CRITICAL first). For **every** item: (1) make the fix, (2) add or update an automated test that fails before the fix and passes after it, (3) run the relevant test suite (`cargo test` for Rust, `npm test` in `web/` for the frontend, the Kotlin test target for mobile) and confirm it's green, (4) do not introduce new abstractions beyond what's needed to fix the specific bug — match existing code style and patterns in the surrounding file.

After finishing all items, run the full workspace build (`cargo build --workspace`) and full test suite one more time, and report a summary table: item → file(s) changed → test added → pass/fail.

---

## CRITICAL (fix and test all of these — each is independently exploitable or breaks core functionality)

### 1. QR pass signing uses the wrong key
- **File**: `crates/infrastructure/src/crypto/service.rs`, function `sign_cbor_payload` (~line 356-369).
- **Bug**: The function takes `_encrypted_private_key: &[u8]` as a parameter but never uses it — it signs every pass with `self.key_provider.derive_paseto_key()` (the server's global PASETO key) instead of decrypting and using the org-specific Ed25519 private key from `org_keys`. Comment in the code admits this is a placeholder.
- **Fix**: Decrypt `_encrypted_private_key` using the org's key-derivation path (see `decrypt_org_private_key` elsewhere in the same file for the existing pattern — it derives via `key_provider.derive_org_enc_key(org_id, key_version)` + ChaCha20-Poly1305), then sign with the resulting `SigningKey`. Ensure the plaintext key is zeroized after use (the codebase already uses `Zeroize` elsewhere — follow that pattern).
- **Test**: Add a test that creates a pass for org A, signs it, then verifies it against org A's real public key (must pass) and against org B's public key or the global PASETO key (must fail). Also add a test confirming two different orgs' passes are signed with cryptographically distinct keys (i.e., a signature valid for org A's pass must not verify under org B's key, and vice versa).

### 2. Google Sign-In doesn't validate token audience (account takeover)
- **File**: `crates/api/src/handlers/google_auth.rs`, function `verify_google_token` (~line 128-174), specifically `validation.validate_aud = false` (~line 165).
- **Bug**: The `aud` claim of the Google ID token is never checked against this app's own Google OAuth client ID. Any valid Google-signed ID token — including one issued to a completely unrelated third-party site — is accepted, allowing an attacker who obtains a victim's ID token from another site to authenticate as that victim here.
- **Fix**: Add a `GOOGLE_OAUTH_CLIENT_ID` config value (env var, add to `.env.example` and the config loader), set `validation.validate_aud = true`, and `validation.set_audience(&[client_id])`. Reject tokens that don't match.
- **Test**: Unit test that constructs/mocks a JWT with a mismatched `aud` claim and asserts `verify_google_token` returns an error; a second test with a matching `aud` returns success. If full JWKS mocking is impractical, at minimum refactor so the audience-check logic is a pure function you can unit test in isolation (extract `fn check_audience(claims: &GoogleClaims, expected: &str) -> Result<(), ApiError>` and test that directly), then wire it into the handler.

### 3. `GET /organizations/:org_id/passes` is routed to the wrong handler
- **File**: `crates/api/src/router.rs` (~line 54): `.route("/api/v1/organizations/:org_id/passes", post(create_pass).get(list_locations))`.
- **Bug**: Listing passes returns location data. There is no working `list_passes` handler wired up.
- **Fix**: Implement (or wire up, if it exists elsewhere unused) a proper `list_passes` handler in `crates/api/src/handlers/passes.rs` that queries `visitor_passes` scoped to `org_id` (and ideally supports pagination/status filter, matching the existing style of `list_locations`), and change the route to `.get(list_passes)`.
- **Test**: Integration test (following the pattern in `crates/api/src/tests.rs`) that creates 2+ passes for an org, calls `GET /organizations/:org_id/passes`, and asserts the response contains pass objects (with `pass_number`, `status`, etc.) — not location fields — and does not leak passes from a different org.

### 4. Org join tokens have ~12 bits of entropy and aren't actually hashed
- **File**: `crates/infrastructure/src/db/postgres/org.rs`, function `generate_join_token` (~line 351-379) and `verify_join_token` (~line 397+).
- **Bug**: `let raw_token = format!("INV-{}", Uuid::now_v7().to_string().replace("-", "")[..16].to_uppercase());` — the leading bytes of a UUIDv7 are a millisecond timestamp, not randomness, leaving only ~12-16 bits of real entropy. The token is also stored and compared as plaintext in a column named `token_hash`, not actually hashed.
- **Fix**: Generate the raw token from a CSPRNG (e.g. `rand::rngs::OsRng` / the `rand` crate already in workspace deps) with at least 128 bits of entropy, base32/base62-encoded for shareability. Store `SHA-256(raw_token)` in `token_hash` (there's a `sha2` crate already in workspace deps) and compare hashes in `verify_join_token`, never the raw token. Return the raw token to the caller once (for the invite link/QR) — never store it.
- **Test**: Test that `generate_join_token` returns tokens with high entropy (e.g. assert two calls never collide across many iterations, and that the stored `token_hash` in the DB never equals the raw token returned to the caller). Test that `verify_join_token` correctly matches a valid raw token and rejects a tampered one.

### 5. Pass numbers use a non-cryptographic PRNG and are enumerable with no rate limit
- **File**: `crates/domain/src/value_objects/pass_number.rs`, function `generate()`; lookup in `crates/infrastructure/src/db/postgres/pass.rs`, function `find_by_pass_number_public` (~line 113); public route in `crates/api/src/handlers/share_page.rs` (`GET /v/:pass_number`).
- **Bug**: `generate()` seeds a plain xorshift PRNG from `subsec_nanos()` only — predictable and low-entropy. The public share-page lookup has no org scoping and no rate limiting, so pass numbers (which grant physical entry visibility) can be brute-forced/enumerated.
- **Fix**: Replace the PRNG with `rand::rngs::OsRng` (or equivalent CSPRNG already available) for pass number generation, keeping the same human-readable format (Base36, 8 chars) if that's a product requirement. Add a per-IP rate limiter to the `/v/:pass_number` route (use `tower-http`'s rate-limiting/governor, or a lightweight in-memory token-bucket keyed by IP in `AppState` if no rate-limit dependency is wired up yet — check `crates/api/src/middleware/` for any existing partial implementation first before adding a new one).
- **Test**: Test that repeated calls to `generate()` produce non-sequential, non-predictable output (e.g., statistical test or just assert successive outputs aren't derivable from timestamp alone — check the actual RNG source is used, not the clock). Integration test that hammering `/v/:pass_number` beyond the configured limit returns 429.

### 6. Stored XSS on the public visitor share page
- **File**: `crates/api/src/handlers/share_page.rs`, lines ~34, ~236-237.
- **Bug**: `visitor_name` and `purpose` (free text supplied by whoever creates a pass) are interpolated into raw HTML via `format!` with no escaping, then served to unauthenticated viewers of the share link.
- **Fix**: HTML-escape all user-supplied fields before interpolation (there may already be an HTML-escaping helper/crate available — check `Cargo.toml`/existing utils first; if none, add a minimal escape function or a small well-known crate like `askama`/`html-escape` consistent with the rest of the stack, or switch this handler to a templating engine that auto-escapes).
- **Test**: Integration test that creates a pass with `visitor_name = "<script>alert(1)</script>"`, fetches the share page, and asserts the raw `<script>` tag does NOT appear unescaped in the response body (assert it appears as `&lt;script&gt;` or is stripped).

### 7. Idempotency cache replays cross-tenant, pre-authentication
- **File**: `crates/api/src/middleware/idempotency.rs`; ordering in `crates/api/src/router.rs` (~line 74, idempotency layered before auth).
- **Bug**: Cached responses are keyed only by the client-supplied `Idempotency-Key` header — no binding to the authenticated user/org/path. Anyone who reuses another request's key gets that cached response replayed, including other tenants' data. It also runs before auth middleware, so it's reachable pre-authentication.
- **Fix**: Move the idempotency middleware layer to run *after* authentication in the router stack. Change the cache key to a composite of `(org_id or user_id, request path, Idempotency-Key)` rather than the raw header value alone.
- **Test**: Integration test: make an authenticated request as user/org A with `Idempotency-Key: X`, then make a request as user/org B with the same `Idempotency-Key: X` — assert org B does NOT receive org A's cached response (should execute independently). Also assert the idempotency route requires authentication (401 without a valid token, key alone doesn't bypass auth).

### 8. Revoked/expired passes can be reactivated via offline sync replay
- **File**: `crates/infrastructure/src/db/postgres/pass.rs`, function `increment_use_count` (~line 258-300); `crates/application/src/use_cases/sync_events.rs`, function `process_push_event` (~line 189-233).
- **Bug**: `increment_use_count` updates `status` based on use-count logic with no `AND status = 'ACTIVE'` guard in the SQL. `process_push_event` never re-validates `pass.check_valid()` (the domain method already exists — see `crates/domain/src/entities/visitor_pass.rs`) before accepting a device's queued "ENTRY" sync event. A previously revoked or expired pass can be flipped back to ACTIVE/USED by replaying/syncing a stale offline entry event.
- **Fix**: Add `AND status = 'ACTIVE'` to the `increment_use_count` SQL `WHERE` clause (mirroring the pattern already used correctly in `approve_entry` in `sync.rs`, which does `WHERE ... AND status = 'PENDING'`). In `process_push_event`, call `pass.check_valid()` (or re-fetch and check `status`/`valid_until` server-side) before accepting the event as a legitimate ENTRY; if invalid, record it as a `DENIED` entry_log instead of an accepted ENTRY, and do not touch pass status/use_count.
- **Test**: Test that syncing an ENTRY event for a REVOKED pass results in a `DENIED` entry_log and the pass status remains REVOKED (not flipped back to ACTIVE/USED). Test the same for an EXPIRED pass.

### 9. Device challenge-response has no replay protection
- **File**: `crates/api/src/handlers/auth.rs`, functions `device_challenge` (~line 92) and `device_login` (~line 109); table `app.device_challenges` (migration `20240101000006_sessions.sql`).
- **Bug**: `device_challenge` generates a nonce but never persists it to `device_challenges`; `device_login` never checks a nonce against that table, never marks one as used, and never checks expiry. A captured `(challenge, signature)` pair can be replayed indefinitely to mint new device tokens.
- **Fix**: In `device_challenge`, insert the generated nonce into `app.device_challenges` with a 60s expiry (table already supports this). In `device_login`, look up the challenge by nonce, reject if not found / already used (`used_at IS NOT NULL`) / expired (`expires_at < NOW()`), and mark it `used_at = NOW()` atomically (single `UPDATE ... WHERE nonce = $1 AND used_at IS NULL AND expires_at > NOW()` with a rows-affected check, to avoid a race between two concurrent replays).
- **Test**: Test that a valid (challenge, signature) pair succeeds once, and replaying the exact same pair a second time fails. Test that a challenge older than 60s is rejected.

### 10. A "pending org-selection" token leaks every organization's realtime events
- **File**: `crates/api/src/handlers/sync.rs`, `ws_handler` (~line 108): `if event.org_id == ctx.org_id || ctx.org_id.is_nil() { ... }`; token issuance in `crates/api/src/handlers/google_auth.rs` (~line 108, `Uuid::nil()` fallback token).
- **Bug**: Any user with 2+ or 0 org memberships gets a token scoped to `org_id = Uuid::nil()` before calling `select-org`. The WebSocket handler treats a nil org_id as "match everything," forwarding every organization's realtime broadcasts (including ad-hoc visitor names/phone numbers) to that connection.
- **Fix**: Remove the `|| ctx.org_id.is_nil()` clause. A nil-org token should not be allowed to open the realtime WebSocket at all — reject the WS upgrade with 403 if `ctx.org_id.is_nil()`, requiring the client to call `select-org` first to get a properly scoped token.
- **Test**: Test that a nil-org token attempting to open the WebSocket is rejected. Test that a properly org-scoped token only receives events for its own org, never another org's.

### 11. Ad-hoc visitor approval has no unit-ownership check
- **File**: `crates/api/src/handlers/sync.rs`, `approve_entry` (~line 210+) — the query only checks `WHERE id = $2 AND org_id = $3 AND status = 'PENDING'`, with no check that the approving user's membership `unit_identifier` matches the `unit_identifier` on the `ad_hoc_approvals` row.
- **Fix**: Before executing the approve/deny update, look up the requesting user's membership for this org and confirm their `unit_identifier` matches the approval row's `unit_identifier` (or that they hold an ADMIN/OWNER/GUARD role authorized to approve on behalf of others — check `crates/domain` for the existing `Role` semantics and apply whatever the intended authorization model is; if unclear, restrict to exact unit match plus ADMIN/OWNER override). Also add an `audit.append`-style audit event on approve/deny (follow the pattern used in `create_pass.rs`/`revoke_pass.rs`), and encrypt/HMAC `ad_hoc_approvals.visitor_phone` the same way `visitor_passes.visitor_phone_enc`/`visitor_phone_hmac` are handled, rather than storing it in plaintext.
- **Test**: Test that a resident of unit 101 cannot approve/deny an ad-hoc request targeted at unit 402 (expect 403), and that the correct resident (or an ADMIN) can. Test that an audit event is recorded on approve and on deny.

---

## HIGH (fix and test after all CRITICAL items are done)

### 12. No application-layer rate limiting anywhere
- Add rate limiting (per-IP and/or per-account) to at minimum: login/auth endpoints, `verify_pass`, `join-by-token`, and the public share page (`/v/:pass_number`, already covered in item 5 above). Use whatever's simplest given current deps — check if `tower-http`'s `limit` feature (already in `Cargo.toml`) can be used directly, or add a small governor-based layer.
- **Test**: For each protected endpoint, a test that exceeds the configured threshold and asserts a 429 response.

### 13. No session revocation or token refresh
- **File**: `app.sessions` table exists (migration `20240101000006_sessions.sql`) but is never read/written in Rust; no `/refresh` route exists in `router.rs`.
- **Fix**: Implement session persistence on login (store the refresh token hash in `app.sessions`), a `POST /api/v1/auth/refresh` endpoint that validates against the stored session/family and rotates it (the table already has `previous_token_hash`/`family_id` columns designed for refresh-token rotation with theft detection — implement per that existing schema design), and a `POST /api/v1/auth/logout` that revokes the session (`revoked_at = NOW()`).
- **Test**: Test refresh-token rotation succeeds once and the old token then fails; test that using a `previous_token_hash` within the grace window re-issues correctly; test logout revokes the session so a subsequent refresh fails.

### 14. Retention/cleanup/partition-maintenance SQL functions are dead code
- **Files**: `migrations/20240101000014_pass_expiry_cron.sql` (`expire_passes()`), `migrations/20240101000015_retention_cleanup.sql` (`cleanup_expired_sessions()`, `cleanup_expired_challenges()`, `cleanup_entry_logs_partition()`).
- **Bug**: None of these are ever invoked from the Rust codebase. `entry_logs`/`audit_events` partitions only exist through end of 2026-12 (check current partition ranges in `migrations/20240101000010_entry_logs.sql` and `migrations/20240101000011_audit_events.sql`) — inserts will start failing once partitions run out. Retention (`organizations.retention_days`) is never enforced.
- **Fix**: Add a background scheduled task in the API process (a `tokio::spawn` loop with `tokio::time::interval`, following the existing pattern already used in `crates/api/src/handlers/sync.rs` for its 30s interval) that runs on startup and periodically: (a) calls `expire_passes()` every ~15 minutes, (b) calls the session/challenge cleanup functions daily, (c) creates new monthly `entry_logs`/quarterly `audit_events` partitions ahead of time (e.g., ensure partitions exist 60 days into the future, creating them if missing), and (d) enforces each org's `retention_days` by dropping/cleaning entry_log partitions older than the applicable retention window (respecting that retention is per-org, so this needs care — a partition can only be dropped once it's past retention for the strictest org still referencing it, or switch to a per-org soft-delete/purge query for entries rather than dropping shared partitions wholesale — think through this rather than blindly calling `cleanup_entry_logs_partition`, since partitions currently aren't per-org).
- **Test**: Test that starting the app schedules the expiry job and that after advancing time (or directly invoking the job function), an overdue ACTIVE pass flips to EXPIRED. Test that a partition-ensure function creates the next N months/quarters of partitions when run against a test DB missing them. Document (in a code comment, not a separate doc file) the retention enforcement approach you chose given the shared-partition constraint.

### 15. `validator` crate is a dependency but unused; validation is inconsistent
- Add `#[derive(Validate)]` (the crate is already in `Cargo.toml`) to at least the most sensitive incoming DTOs: pass creation (visitor name/phone format), ad-hoc approval request (phone format), org join request. Use it consistently rather than ad hoc `if x.trim().is_empty()` checks scattered per-handler.
- **Test**: Test that malformed input (e.g., invalid phone format, empty required fields) is rejected with a 400 before reaching business logic, for each DTO you add validation to.

---

## Constraints for whoever executes this

- Do not restructure crate boundaries, add new dependencies beyond what's already in `Cargo.toml`/`package.json` unless a fix is genuinely impossible without one (rate limiting and HTML escaping may need one — pick the smallest well-maintained option and justify it in a one-line comment).
- Match existing patterns already present in the codebase (e.g., the `WHERE status = 'PENDING'` conditional-update pattern in `approve_entry`, the `audit.append` calls in `create_pass.rs`, the Zeroize usage in `decrypt_org_private_key`) rather than inventing new idioms.
- Every fix must ship with a test that would have failed before the fix — do not mark an item done without one.
- Do not touch the mobile app (`mobile/`) or web frontend (`web/`) as part of this pass except where explicitly noted (none of the items above require it) — this pass is backend-only.
- At the end, run `cargo build --workspace` and the full `cargo test --workspace`, and report which items are fully green vs. blocked, with reasons for any blockers.
