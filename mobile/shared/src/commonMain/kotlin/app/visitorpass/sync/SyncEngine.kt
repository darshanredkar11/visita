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
    val rejected: List<String> = emptyList(),
    val org_public_key: String? = null,
    val org_key_version: Int? = null
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

/** Decodes a hex string (as sent by the backend's `hex::encode`) to raw bytes. */
private fun hexToBytes(hex: String): ByteArray =
    ByteArray(hex.length / 2) { i ->
        hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
    }

class SyncEngine(
    private val databaseHelper: DatabaseHelper,
    private val ktorClient: KtorClient
) {
    private val json = Json { ignoreUnknownKeys = true }

    suspend fun performSync(deviceId: String, locationId: String, orgId: String): Boolean {
        try {
            // 1. Get unsynced local logs
            val unsyncedLogs = databaseHelper.queries.getUnsyncedEntryLogs().executeAsList()
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

            // 2. Read this device's own last-synced checkpoint and resume
            //    from there -- NOT from 0, which would re-pull the device's
            //    entire event history on every single sync. Always call
            //    syncEvents(), even with an empty push list, so the
            //    checkpoint and the org's signing public key (delivered in
            //    every sync response) keep refreshing on read-only syncs,
            //    which are the common case for an idle guard kiosk.
            val lastSeq = databaseHelper.queries.getSyncCheckpoint().executeAsOneOrNull()?.last_seq ?: 0L
            val syncResText = ktorClient.syncEvents(deviceId, lastSeq, syncEvents)
            val syncResponse = json.decodeFromString<SyncResponse>(syncResText)

            // 3. Mark successfully accepted logs as synced
            for (acceptedId in syncResponse.accepted) {
                databaseHelper.queries.markEntryLogSynced(acceptedId)
            }

            // 4. Persist the new checkpoint so the NEXT sync resumes from
            //    here instead of replaying from the start.
            databaseHelper.queries.upsertSyncCheckpoint(syncResponse.new_sync_seq)

            // 5. Cache the org's current signing public key for fully
            //    offline pass verification (see GuardKioskDashboard).
            val orgPublicKeyHex = syncResponse.org_public_key
            val orgKeyVersion = syncResponse.org_key_version
            if (orgPublicKeyHex != null && orgKeyVersion != null) {
                databaseHelper.queries.upsertOrgKey(orgId, hexToBytes(orgPublicKeyHex), orgKeyVersion.toLong())
            }

            // 6. Pull updated passes list
            val passesResText = ktorClient.getPasses()
            val passesList = json.decodeFromString<List<SyncPassItem>>(passesResText)

            // 7. Update local visitor passes SQLite cache
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
