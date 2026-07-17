package app.visitorpass.sync

import app.cash.sqldelight.driver.jdbc.sqlite.JdbcSqliteDriver
import app.visitorpass.db.DatabaseHelper
import app.visitorpass.db.VisitorPassDatabase
import app.visitorpass.net.KtorClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.content.TextContent
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.runBlocking
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Real behavioral tests for [SyncEngine.performSync] against a real
 * in-memory SQLite database (via SQLDelight's JDBC driver -- JVM-only,
 * hence this lives in `androidUnitTest` rather than `commonTest`, which is
 * also compiled for the iOS targets) and a real [KtorClient] backed by
 * Ktor's [MockEngine] (no actual network call).
 *
 * This replaces the previous "test" here, which only asserted that the
 * string `"SyncEngine"` was not null -- it never invoked `performSync` at
 * all, so it could never have caught the hardcoded `0L` checkpoint bug.
 */
class SyncEngineTest {

    private fun newDatabaseHelper(): DatabaseHelper {
        val driver = JdbcSqliteDriver(JdbcSqliteDriver.IN_MEMORY)
        VisitorPassDatabase.Schema.create(driver)
        return DatabaseHelper(driver)
    }

    private fun syncResponseJson(newSyncSeq: Long): String = """
        {"new_sync_seq": $newSyncSeq, "accepted": [], "rejected": [], "org_public_key": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "org_key_version": 1}
    """.trimIndent()

    /** Routes /api/v1/sync to [syncSeqResponder]; everything else (getPasses) gets an empty list. */
    private fun mockEngine(syncSeqResponder: (lastSyncSeqInRequest: Long) -> Long): MockEngine =
        MockEngine { request ->
            if (request.url.encodedPath.endsWith("/api/v1/sync")) {
                val bodyText = (request.body as TextContent).text
                val seqInRequest = Regex(""""last_sync_seq"\s*:\s*(\d+)""")
                    .find(bodyText)?.groupValues?.get(1)?.toLong() ?: -1L
                respond(
                    content = syncResponseJson(syncSeqResponder(seqInRequest)),
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "application/json")
                )
            } else {
                respond(
                    content = "[]",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "application/json")
                )
            }
        }

    @Test
    fun testSecondSyncUsesCheckpointFromFirstResponse_notZero() = runBlocking {
        val db = newDatabaseHelper()
        val capturedSeqs = mutableListOf<Long>()
        var callCount = 0

        val engine = mockEngine { seqInRequest ->
            capturedSeqs.add(seqInRequest)
            callCount += 1
            // First call returns new_sync_seq=42; the SECOND call's request
            // must carry THAT value as its own last_sync_seq, not 0.
            if (callCount == 1) 42L else 999L
        }
        val ktorClient = KtorClient(db, engine = engine)
        val syncEngine = SyncEngine(db, ktorClient)

        val firstOk = syncEngine.performSync(deviceId = "device-1", locationId = "loc-1", orgId = "org-1")
        assertTrue(firstOk, "first sync should succeed")

        val secondOk = syncEngine.performSync(deviceId = "device-1", locationId = "loc-1", orgId = "org-1")
        assertTrue(secondOk, "second sync should succeed")

        assertEquals(2, capturedSeqs.size, "syncEvents should have been called exactly twice")
        assertEquals(0L, capturedSeqs[0], "the FIRST sync (no prior checkpoint) starts from 0")
        assertEquals(
            42L, capturedSeqs[1],
            "the SECOND sync's since-seq must equal the first response's new_sync_seq (42), not be hardcoded to 0"
        )
    }

    @Test
    fun testCheckpointIsPersistedAcrossSyncEngineInstances() = runBlocking {
        val db = newDatabaseHelper()
        val ktorClient = KtorClient(db, engine = mockEngine { 77L })

        SyncEngine(db, ktorClient).performSync("device-1", "loc-1", "org-1")

        val stored = db.queries.getSyncCheckpoint().executeAsOneOrNull()
        assertEquals(77L, stored?.last_seq, "the checkpoint must be durably persisted, not just held in memory")
    }

    @Test
    fun testOrgPublicKeyIsCachedFromSyncResponse() = runBlocking {
        val db = newDatabaseHelper()
        val ktorClient = KtorClient(db, engine = mockEngine { 1L })

        SyncEngine(db, ktorClient).performSync("device-1", "loc-1", "org-42")

        val storedKey = db.queries.getOrgKey().executeAsOneOrNull()
        assertEquals("org-42", storedKey?.org_id)
        assertEquals(1L, storedKey?.key_version)
        assertEquals(
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            storedKey?.public_key?.joinToString("") { "%02x".format(it) }
        )
    }
}
