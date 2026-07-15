package app.visitorpass

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import app.cash.sqldelight.driver.android.AndroidSqliteDriver
import app.visitorpass.db.DatabaseHelper
import app.visitorpass.db.VisitorPassDatabase
import app.visitorpass.crypto.CryptoService
import app.visitorpass.crypto.JvmCrypto
import app.visitorpass.net.KtorClient
import app.visitorpass.ui.RootNavigation

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // 1. Set JVM Crypto Provider Delegate
        CryptoService.setDelegate(JvmCrypto())
        
        // 2. Initialize SQLDelight SQLite database
        val driver = AndroidSqliteDriver(
            schema = VisitorPassDatabase.Schema,
            context = applicationContext,
            name = "visitorpass.db"
        )
        val databaseHelper = DatabaseHelper(driver)
        
        // 3. Initialize Network Client
        val ktorClient = KtorClient(databaseHelper = databaseHelper)
        
        // 4. Render Compose Multiplatform Root Navigation
        setContent {
            RootNavigation(
                databaseHelper = databaseHelper,
                ktorClient = ktorClient
            )
        }
    }
}
