package app.visitorpass.sync

import app.visitorpass.db.DatabaseHelper
import app.visitorpass.net.KtorClient
import app.visitorpass.net.SyncPushEventBody
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

@Serializable
data class SyncResponse(
    val new_sync_seq: Long,
    val accepted: List<String> = emptyList(),
    val rejected: List<String> = emptyList()
)

@Serializable
data class SyncPassItem(
    val id: String,
    val pass_number: String,
    val visitor_name: String,
    val valid_from: String,
    val valid_until: String,
    val status: String,
    val qr_payload: String
)

class SyncEngine(
    private val databaseHelper: DatabaseHelper,
    private val ktorClient: KtorClient
) {
    private val json = Json { ignoreUnknownKeys = true }

    suspend fun performSync(deviceId: String, locationId: String): Boolean {
        try {
            // 1. Get unsynced local logs
            val unsyncedLogs = databaseHelper.queries.getUnsyncedEntryLogs().executeAsList()
            
            if (unsyncedLogs.isNotEmpty()) {
                val syncEvents = unsyncedLogs.map { log ->
                    SyncPushEventBody(
                        client_event_id = log.id,
                        event_type = "PASS_VERIFICATION",
                        pass_id = log.pass_id,
                        action = log.action,
                        occurred_at = log.occurred_at,
                        location_id = locationId,
                        denial_reason = log.denial_reason,
                        guard_note = log.guard_note
                    )
                }

                // 2. Transmit batch to backend
                val syncResText = ktorClient.syncEvents(deviceId, 0L, syncEvents)
                val syncResponse = json.decodeFromString<SyncResponse>(syncResText)

                // 3. Mark successfully accepted logs as synced
                for (acceptedId in syncResponse.accepted) {
                    databaseHelper.queries.markEntryLogSynced(acceptedId)
                }
            }

            // 4. Pull updated passes list
            val passesResText = ktorClient.getPasses()
            val passesList = json.decodeFromString<List<SyncPassItem>>(passesResText)

            // 5. Update local visitor passes SQLite cache
            for (pass in passesList) {
                databaseHelper.queries.insertPass(
                    id = pass.id,
                    pass_number = pass.pass_number,
                    visitor_name = pass.visitor_name,
                    visitor_phone_enc = null, // In production, we'd cache decrypt keys if secretary, otherwise null
                    valid_from = pass.valid_from,
                    valid_until = pass.valid_until,
                    status = pass.status,
                    qr_payload = pass.qr_payload
                )
            }

            return true
        } catch (e: Exception) {
            println("SyncEngine error: ${e.message}")
            return false
        }
    }
}
