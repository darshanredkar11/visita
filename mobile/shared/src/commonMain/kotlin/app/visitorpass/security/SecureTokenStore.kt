package app.visitorpass.security

/**
 * Persists the refresh token (opaque, long-lived -- 30 days -- and
 * sufficient on its own to mint new access tokens; see
 * `crates/api/src/handlers/auth.rs::create_session`) outside of SQLDelight.
 *
 * The rest of the app's local session state (`session.token`, `role`,
 * `org_id`, `unit_identifier`, `user_name` in `VisitorPassDatabase.sq`)
 * stays in the plain SQLite database -- those aren't secrets. The refresh
 * token is: it's a bearer credential that alone lets a holder mint fresh
 * access tokens for 30 days, so it must not sit in a plaintext SQLite
 * column readable by anyone with root access or an unencrypted device
 * backup.
 *
 * `actual`-per-platform implementations live under `androidMain` (Keystore-
 * backed AES/GCM) etc., matching this project's existing
 * [app.visitorpass.crypto.PlatformCrypto] delegate pattern rather than KMP
 * `expect`/`actual`.
 */
interface SecureTokenStore {
    /** Encrypts and persists [token], replacing any previously stored value. */
    fun saveRefreshToken(token: String)

    /**
     * Decrypts and returns the stored token, or `null` if none is stored --
     * including when the stored blob is corrupt/undecryptable, which is
     * treated as "no valid session" rather than surfaced as a crash.
     */
    fun getRefreshToken(): String?

    /** Removes the stored token, e.g. on logout. */
    fun clearRefreshToken()
}
