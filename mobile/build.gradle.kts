plugins {
    // Kotlin Multiplatform and Serialization Plugins
    kotlin("multiplatform") version "1.9.22" apply false
    kotlin("plugin.serialization") version "1.9.22" apply false

    // Android Plugins
    id("com.android.application") version "8.2.2" apply false
    id("com.android.library") version "8.2.2" apply false

    // SQLite Database Plugin (SQLDelight)
    id("app.cash.sqldelight") version "2.0.1" apply false

    // UI Framework (Compose Multiplatform)
    id("org.jetbrains.compose") version "1.5.12" apply false
}
