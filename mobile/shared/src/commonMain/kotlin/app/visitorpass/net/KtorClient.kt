package app.visitorpass.net

import app.visitorpass.db.DatabaseHelper
import app.visitorpass.security.SecureTokenStore
import io.ktor.client.HttpClient
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.header
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class GoogleAuthRequest(val id_token: String)

@Serializable
data class SelectOrgRequest(val org_id: String)

@Serializable
data class CreatePassRequest(
    val visitor_name: String,
    val visitor_phone: String,
    val valid_from: String,
    val valid_until: String
)

@Serializable
data class AdHocApprovalRequest(
    val visitor_name: String,
    val visitor_phone: String,
    val location_id: String,
    val unit_identifier: String
)

class KtorClient(
    private val databaseHelper: DatabaseHelper,
    private val secureTokenStore: SecureTokenStore,
    private val baseUrl: String = "http://10.0.2.2:8080", // Default Android loopback emulator address
    // Injectable HTTP engine so tests can substitute a MockEngine instead of
    // making a real network call. Defaults to Ktor's platform-default engine.
    engine: HttpClientEngine? = null
) {
    val client = if (engine != null) {
        HttpClient(engine) {
            install(ContentNegotiation) {
                json(Json {
                    ignoreUnknownKeys = true
                    prettyPrint = true
                })
            }
        }
    } else {
        HttpClient {
            install(ContentNegotiation) {
                json(Json {
                    ignoreUnknownKeys = true
                    prettyPrint = true
                })
            }
        }
    }

    private fun getAuthToken(): String? {
        return databaseHelper.queries.getSession().executeAsOneOrNull()?.token
    }

    /**
     * The backend hands the refresh token to browsers as a `Set-Cookie`
     * header (never in the JSON body -- see `auth.rs`'s cookie helpers);
     * mobile has no browser cookie jar, so it reads that header manually
     * and re-sends the value as a plain `Cookie` header on the next call,
     * exactly like a browser would. `name` is matched against the
     * `name=value` pair BEFORE the first `;` (the attributes -- `HttpOnly`,
     * `Path`, etc. -- are meaningless off-browser and ignored).
     */
    private fun extractCookieValue(response: HttpResponse, name: String): String? {
        val setCookieHeaders = response.headers.getAll(HttpHeaders.SetCookie) ?: return null
        for (rawHeader in setCookieHeaders) {
            val pair = rawHeader.substringBefore(';').trim()
            val eq = pair.indexOf('=')
            if (eq <= 0) continue
            if (pair.substring(0, eq) == name) return pair.substring(eq + 1)
        }
        return null
    }

    /** `Cookie` request header built from the persisted refresh token, if any. */
    private fun refreshCookieHeaderOrNull(): String? =
        secureTokenStore.getRefreshToken()?.let { "refresh_token=$it" }

    suspend fun loginWithGoogle(idToken: String): String {
        val response = client.post("$baseUrl/api/v1/auth/google") {
            contentType(ContentType.Application.Json)
            setBody(GoogleAuthRequest(idToken))
        }
        extractCookieValue(response, "refresh_token")?.let { secureTokenStore.saveRefreshToken(it) }
        return response.bodyAsText()
    }

    suspend fun selectOrg(orgId: String): String {
        val token = getAuthToken()
        val response = client.post("$baseUrl/api/v1/auth/select-org") {
            contentType(ContentType.Application.Json)
            token?.let { header("Authorization", "Bearer $it") }
            setBody(SelectOrgRequest(orgId))
        }
        extractCookieValue(response, "refresh_token")?.let { secureTokenStore.saveRefreshToken(it) }
        return response.bodyAsText()
    }

    /**
     * Exchanges the persisted refresh token (Keystore-encrypted, see
     * [SecureTokenStore]) for a fresh access token, and persists the
     * rotated refresh token the backend returns alongside it. Mirrors the
     * `/auth/refresh` contract's rotate-on-use semantics -- the OLD stored
     * token is no longer valid after this call succeeds.
     */
    suspend fun refreshAccessToken(): String {
        val response = client.post("$baseUrl/api/v1/auth/refresh") {
            contentType(ContentType.Application.Json)
            refreshCookieHeaderOrNull()?.let { header(HttpHeaders.Cookie, it) }
            setBody("{}")
        }
        extractCookieValue(response, "refresh_token")?.let { secureTokenStore.saveRefreshToken(it) }
        return response.bodyAsText()
    }

    /** Revokes the session server-side and clears the locally persisted refresh token. */
    suspend fun logout(): String {
        val response = client.post("$baseUrl/api/v1/auth/logout") {
            contentType(ContentType.Application.Json)
            refreshCookieHeaderOrNull()?.let { header(HttpHeaders.Cookie, it) }
            setBody("{}")
        }
        secureTokenStore.clearRefreshToken()
        return response.bodyAsText()
    }

    /**
     * Synchronous, local-only counterpart to [logout] for UI call sites
     * that clear session state outside a coroutine (see
     * `RootNavigation.kt`'s `onLogout`) -- clears the persisted refresh
     * token without calling the backend. Prefer [logout] when a suspend
     * context is available, since it also revokes the session server-side.
     */
    fun clearLocalSession() {
        secureTokenStore.clearRefreshToken()
    }

    suspend fun createPass(visitorName: String, visitorPhone: String, validFrom: String, validUntil: String): String {
        val token = getAuthToken()
        val orgId = databaseHelper.queries.getSession().executeAsOneOrNull()?.org_id ?: ""
        val response = client.post("$baseUrl/api/v1/organizations/$orgId/passes") {
            contentType(ContentType.Application.Json)
            token?.let { header("Authorization", "Bearer $it") }
            setBody(CreatePassRequest(visitorName, visitorPhone, validFrom, validUntil))
        }
        return response.bodyAsText()
    }

    suspend fun requestAdHocApproval(visitorName: String, visitorPhone: String, locationId: String, unitIdentifier: String): String {
        val token = getAuthToken()
        val orgId = databaseHelper.queries.getSession().executeAsOneOrNull()?.org_id ?: ""
        val response = client.post("$baseUrl/api/v1/organizations/$orgId/entries/request-approval") {
            contentType(ContentType.Application.Json)
            token?.let { header("Authorization", "Bearer $it") }
            setBody(AdHocApprovalRequest(visitorName, visitorPhone, locationId, unitIdentifier))
        }
        return response.bodyAsText()
    }

    suspend fun getPasses(): String {
        val token = getAuthToken()
        val orgId = databaseHelper.queries.getSession().executeAsOneOrNull()?.org_id ?: ""
        val response = client.get("$baseUrl/api/v1/organizations/$orgId/passes") {
            token?.let { header("Authorization", "Bearer $it") }
        }
        return response.bodyAsText()
    }

    suspend fun syncEvents(deviceId: String, lastSyncSeq: Long, events: List<SyncPushEventBody>): String {
        val token = getAuthToken()
        val response = client.post("$baseUrl/api/v1/sync") {
            contentType(ContentType.Application.Json)
            token?.let { header("Authorization", "Bearer $it") }
            setBody(SyncRequest(deviceId, lastSyncSeq, events))
        }
        return response.bodyAsText()
    }
}

@Serializable
data class SyncRequest(
    val device_id: String,
    val last_sync_seq: Long,
    val events: List<SyncPushEventBody>
)

@Serializable
data class SyncPushEventBody(
    val client_event_id: String,
    val event_type: String,
    val pass_id: String,
    val action: String,
    val occurred_at: String,
    val location_id: String,
    val denial_reason: String?,
    val guard_note: String?
)

