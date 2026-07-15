package app.visitorpass.db

import app.cash.sqldelight.Transacter
import app.cash.sqldelight.db.QueryResult
import app.cash.sqldelight.db.SqlDriver
import app.cash.sqldelight.db.SqlSchema
import app.visitorpass.db.shared.newInstance
import app.visitorpass.db.shared.schema
import kotlin.Unit

public interface VisitorPassDatabase : Transacter {
  public val visitorPassDatabaseQueries: VisitorPassDatabaseQueries

  public companion object {
    public val Schema: SqlSchema<QueryResult.Value<Unit>>
      get() = VisitorPassDatabase::class.schema

    public operator fun invoke(driver: SqlDriver): VisitorPassDatabase =
        VisitorPassDatabase::class.newInstance(driver)
  }
}
