package app.visitorpass.db.shared

import app.cash.sqldelight.TransacterImpl
import app.cash.sqldelight.db.AfterVersion
import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.db.SqlSchema
import app.visitorpass.db.VisitorPassDatabase
import app.visitorpass.db.VisitorPassDatabaseQueries
import kotlin.Long
import kotlin.Unit
import kotlin.reflect.KClass

internal val KClass<VisitorPassDatabase>.schema: SqlSchema<QueryResult.Value<Unit>>
  get() = VisitorPassDatabaseImpl.Schema

internal fun KClass<VisitorPassDatabase>.newInstance(driver: SqlDriver): VisitorPassDatabase =
    VisitorPassDatabaseImpl(driver)

private class VisitorPassDatabaseImpl(
  driver: SqlDriver,
) : TransacterImpl(driver), VisitorPassDatabase {
  override val visitorPassDatabaseQueries: VisitorPassDatabaseQueries =
      VisitorPassDatabaseQueries(driver)

  public object Schema : SqlSchema<QueryResult.Value<Unit>> {
    override val version: Long
      get() = 1

    override fun create(driver: SqlDriver): QueryResult.Value<Unit> {
      driver.execute(null, """
          |CREATE TABLE session (
          |    key INTEGER PRIMARY KEY CHECK (key = 0), -- single-row constraint
          |    token TEXT NOT NULL,
          |    role TEXT NOT NULL,
          |    org_id TEXT NOT NULL,
          |    unit_identifier TEXT NOT NULL,
          |    user_name TEXT NOT NULL
          |)
          """.trimMargin(), 0)
      driver.execute(null, """
          |CREATE TABLE visitor_pass (
          |    id TEXT NOT NULL PRIMARY KEY,
          |    pass_number TEXT NOT NULL,
          |    visitor_name TEXT NOT NULL,
          |    visitor_phone_enc BLOB,
          |    valid_from TEXT NOT NULL,
          |    valid_until TEXT NOT NULL,
          |    status TEXT NOT NULL,
          |    qr_payload TEXT NOT NULL
          |)
          """.trimMargin(), 0)
      driver.execute(null, """
          |CREATE TABLE entry_log (
          |    id TEXT NOT NULL PRIMARY KEY,
          |    pass_id TEXT NOT NULL,
          |    action TEXT NOT NULL,
          |    occurred_at TEXT NOT NULL,
          |    synced INTEGER NOT NULL DEFAULT 0, -- 0 = false, 1 = true
          |    denial_reason TEXT,
          |    guard_note TEXT
          |)
          """.trimMargin(), 0)
      driver.execute(null, """
          |CREATE TABLE ad_hoc_approval (
          |    id TEXT NOT NULL PRIMARY KEY,
          |    visitor_name TEXT NOT NULL,
          |    visitor_phone TEXT NOT NULL,
          |    unit_identifier TEXT NOT NULL,
          |    status TEXT NOT NULL, -- 'PENDING', 'APPROVED', 'DENIED'
          |    created_at TEXT NOT NULL
          |)
          """.trimMargin(), 0)
      return QueryResult.Unit
    }

    override fun migrate(
      driver: SqlDriver,
      oldVersion: Long,
      newVersion: Long,
      vararg callbacks: AfterVersion,
    ): QueryResult.Value<Unit> = QueryResult.Unit
  }
}
