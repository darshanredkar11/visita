package app.visitorpass.db

import app.cash.sqldelight.db.SqlDriver

class DatabaseHelper(val driver: SqlDriver) {
    val database = VisitorPassDatabase(driver)
    val queries = database.visitorPassDatabaseQueries

    // Helper to log out and purge all local offline caches
    fun clearAllData() {
        database.transaction {
            queries.clearSession()
            queries.upsertSyncCheckpoint(0)
        }
    }
}
