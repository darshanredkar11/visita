package app.visitorpass.net

import app.visitorpass.db.DatabaseHelper
import io.ktor.client.HttpClient
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.header
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
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
    private val baseUrl: String = "http://10.0.2.2:8080" // Default Android loopback emulator address
) {
    val client = HttpClient {
        install(ContentNegotiation) {
            json(Json {
                ignoreUnknownKeys = true
                prettyPrint = true
            })
        }
    }

    private fun getAuthToken(): String? {
        return databaseHelper.queries.getSession().executeAsOneOrNull()?.token
    }

    suspend fun loginWithGoogle(idToken: String): String {
        val response = client.post("$baseUrl/api/v1/auth/google") {
            contentType(ContentType.Application.Json)
            setBody(GoogleAuthRequest(idToken))
        }
        return response.bodyAsText()
    }

    suspend fun selectOrg(orgId: String): String {
        val token = getAuthToken()
        val response = client.post("$baseUrl/api/v1/auth/select-org") {
            contentType(ContentType.Application.Json)
            token?.let { header("Authorization", "Bearer $it") }
            setBody(SelectOrgRequest(orgId))
        }
        return response.bodyAsText()
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

