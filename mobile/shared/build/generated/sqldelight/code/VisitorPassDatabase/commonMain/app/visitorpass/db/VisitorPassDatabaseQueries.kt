package app.visitorpass.db

import app.cash.sqldelight.Query
import app.cash.sqldelight.TransacterImpl
import app.cash.sqldelight.db.SqlDriver
import kotlin.Any
import kotlin.ByteArray
import kotlin.Long
import kotlin.String

public class VisitorPassDatabaseQueries(
  driver: SqlDriver,
) : TransacterImpl(driver) {
  public fun <T : Any> getSession(mapper: (
    key: Long,
    token: String,
    role: String,
    org_id: String,
    unit_identifier: String,
    user_name: String,
  ) -> T): Query<T> = Query(286_711_144, arrayOf("session"), driver, "VisitorPassDatabase.sq",
      "getSession", "SELECT * FROM session WHERE key = 0 LIMIT 1") { cursor ->
    mapper(
      cursor.getLong(0)!!,
      cursor.getString(1)!!,
      cursor.getString(2)!!,
      cursor.getString(3)!!,
      cursor.getString(4)!!,
      cursor.getString(5)!!
    )
  }

  public fun getSession(): Query<Session> = getSession { key, token, role, org_id, unit_identifier,
      user_name ->
    Session(
      key,
      token,
      role,
      org_id,
      unit_identifier,
      user_name
    )
  }

  public fun <T : Any> listPasses(mapper: (
    id: String,
    pass_number: String,
    visitor_name: String,
    visitor_phone_enc: ByteArray?,
    valid_from: String,
    valid_until: String,
    status: String,
    qr_payload: String,
  ) -> T): Query<T> = Query(1_821_441_477, arrayOf("visitor_pass"), driver,
      "VisitorPassDatabase.sq", "listPasses",
      "SELECT * FROM visitor_pass ORDER BY valid_from DESC") { cursor ->
    mapper(
      cursor.getString(0)!!,
      cursor.getString(1)!!,
      cursor.getString(2)!!,
      cursor.getBytes(3),
      cursor.getString(4)!!,
      cursor.getString(5)!!,
      cursor.getString(6)!!,
      cursor.getString(7)!!
    )
  }

  public fun listPasses(): Query<Visitor_pass> = listPasses { id, pass_number, visitor_name,
      visitor_phone_enc, valid_from, valid_until, status, qr_payload ->
    Visitor_pass(
      id,
      pass_number,
      visitor_name,
      visitor_phone_enc,
      valid_from,
      valid_until,
      status,
      qr_payload
    )
  }

  public fun <T : Any> getUnsyncedEntryLogs(mapper: (
    id: String,
    pass_id: String,
    action: String,
    occurred_at: String,
    synced: Long,
    denial_reason: String?,
    guard_note: String?,
  ) -> T): Query<T> = Query(-885_809_536, arrayOf("entry_log"), driver, "VisitorPassDatabase.sq",
      "getUnsyncedEntryLogs", "SELECT * FROM entry_log WHERE synced = 0") { cursor ->
    mapper(
      cursor.getString(0)!!,
      cursor.getString(1)!!,
      cursor.getString(2)!!,
      cursor.getString(3)!!,
      cursor.getLong(4)!!,
      cursor.getString(5),
      cursor.getString(6)
    )
  }

  public fun getUnsyncedEntryLogs(): Query<Entry_log> = getUnsyncedEntryLogs { id, pass_id, action,
      occurred_at, synced, denial_reason, guard_note ->
    Entry_log(
      id,
      pass_id,
      action,
      occurred_at,
      synced,
      denial_reason,
      guard_note
    )
  }

  public fun <T : Any> getPendingAdHocApprovals(mapper: (
    id: String,
    visitor_name: String,
    visitor_phone: String,
    unit_identifier: String,
    status: String,
    created_at: String,
  ) -> T): Query<T> = Query(347_437_632, arrayOf("ad_hoc_approval"), driver,
      "VisitorPassDatabase.sq", "getPendingAdHocApprovals",
      "SELECT * FROM ad_hoc_approval WHERE status = 'PENDING' ORDER BY created_at DESC") { cursor ->
    mapper(
      cursor.getString(0)!!,
      cursor.getString(1)!!,
      cursor.getString(2)!!,
      cursor.getString(3)!!,
      cursor.getString(4)!!,
      cursor.getString(5)!!
    )
  }

  public fun getPendingAdHocApprovals(): Query<Ad_hoc_approval> = getPendingAdHocApprovals { id,
      visitor_name, visitor_phone, unit_identifier, status, created_at ->
    Ad_hoc_approval(
      id,
      visitor_name,
      visitor_phone,
      unit_identifier,
      status,
      created_at
    )
  }

  public fun insertSession(
    token: String,
    role: String,
    org_id: String,
    unit_identifier: String,
    user_name: String,
  ) {
    driver.execute(-1_168_791_147, """
        |INSERT OR REPLACE INTO session (key, token, role, org_id, unit_identifier, user_name)
        |VALUES (0, ?, ?, ?, ?, ?)
        """.trimMargin(), 5) {
          bindString(0, token)
          bindString(1, role)
          bindString(2, org_id)
          bindString(3, unit_identifier)
          bindString(4, user_name)
        }
    notifyQueries(-1_168_791_147) { emit ->
      emit("session")
    }
  }

  public fun clearSession() {
    driver.execute(2_014_486_673, """DELETE FROM session""", 0)
    notifyQueries(2_014_486_673) { emit ->
      emit("session")
    }
  }

  public fun insertPass(
    id: String,
    pass_number: String,
    visitor_name: String,
    visitor_phone_enc: ByteArray?,
    valid_from: String,
    valid_until: String,
    status: String,
    qr_payload: String,
  ) {
    driver.execute(-1_769_097_870, """
        |INSERT OR REPLACE INTO visitor_pass (id, pass_number, visitor_name, visitor_phone_enc, valid_from, valid_until, status, qr_payload)
        |VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """.trimMargin(), 8) {
          bindString(0, id)
          bindString(1, pass_number)
          bindString(2, visitor_name)
          bindBytes(3, visitor_phone_enc)
          bindString(4, valid_from)
          bindString(5, valid_until)
          bindString(6, status)
          bindString(7, qr_payload)
        }
    notifyQueries(-1_769_097_870) { emit ->
      emit("visitor_pass")
    }
  }

  public fun insertEntryLog(
    id: String,
    pass_id: String,
    action: String,
    occurred_at: String,
    synced: Long,
    denial_reason: String?,
    guard_note: String?,
  ) {
    driver.execute(-1_076_580_781, """
        |INSERT INTO entry_log (id, pass_id, action, occurred_at, synced, denial_reason, guard_note)
        |VALUES (?, ?, ?, ?, ?, ?, ?)
        """.trimMargin(), 7) {
          bindString(0, id)
          bindString(1, pass_id)
          bindString(2, action)
          bindString(3, occurred_at)
          bindLong(4, synced)
          bindString(5, denial_reason)
          bindString(6, guard_note)
        }
    notifyQueries(-1_076_580_781) { emit ->
      emit("entry_log")
    }
  }

  public fun markEntryLogSynced(id: String) {
    driver.execute(233_271_233, """UPDATE entry_log SET synced = 1 WHERE id = ?""", 1) {
          bindString(0, id)
        }
    notifyQueries(233_271_233) { emit ->
      emit("entry_log")
    }
  }

  public fun insertAdHocApproval(
    id: String,
    visitor_name: String,
    visitor_phone: String,
    unit_identifier: String,
    status: String,
    created_at: String,
  ) {
    driver.execute(412_141_115, """
        |INSERT OR REPLACE INTO ad_hoc_approval (id, visitor_name, visitor_phone, unit_identifier, status, created_at)
        |VALUES (?, ?, ?, ?, ?, ?)
        """.trimMargin(), 6) {
          bindString(0, id)
          bindString(1, visitor_name)
          bindString(2, visitor_phone)
          bindString(3, unit_identifier)
          bindString(4, status)
          bindString(5, created_at)
        }
    notifyQueries(412_141_115) { emit ->
      emit("ad_hoc_approval")
    }
  }

  public fun updateAdHocStatus(status: String, id: String) {
    driver.execute(-1_494_880_806, """UPDATE ad_hoc_approval SET status = ? WHERE id = ?""", 2) {
          bindString(0, status)
          bindString(1, id)
        }
    notifyQueries(-1_494_880_806) { emit ->
      emit("ad_hoc_approval")
    }
  }
}
