plugins {
    kotlin("multiplatform")
    kotlin("plugin.serialization")
    id("com.android.library")
    id("app.cash.sqldelight")
    id("org.jetbrains.compose")
}

kotlin {
    androidTarget {
        compilations.all {
            kotlinOptions {
                jvmTarget = "1.8"
            }
        }
    }
    
    // Support iOS targets
    iosX64()
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(compose.runtime)
                implementation(compose.foundation)
                implementation(compose.material3)
                @OptIn(org.jetbrains.compose.ExperimentalComposeLibrary::class)
                implementation(compose.components.resources)
                
                // SQLDelight Runtime
                implementation("app.cash.sqldelight:runtime:2.0.1")
                
                // Ktor Client
                implementation("io.ktor:ktor-client-core:2.3.8")
                implementation("io.ktor:ktor-client-content-negotiation:2.3.8")
                implementation("io.ktor:ktor-serialization-kotlinx-json:2.3.8")
                
                // Serialization & Date Utility
                implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.2")
                implementation("org.jetbrains.kotlinx:kotlinx-datetime:0.5.0")
            }
        }

        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
                implementation("io.ktor:ktor-client-mock:2.3.8")
            }
        }
        
        val androidMain by getting {
            dependencies {
                implementation("app.cash.sqldelight:android-driver:2.0.1")
                implementation("io.ktor:ktor-client-okhttp:2.3.8")
            }
        }

        val androidUnitTest by getting {
            dependencies {
                // JVM-only JDBC SQLite driver: NOT multiplatform, so it must
                // live here (compiled only for the Android/JVM unit test
                // variant, i.e. `testDebugUnitTest`) rather than commonTest,
                // which is also compiled for the iOS targets above.
                implementation("app.cash.sqldelight:sqlite-driver:2.0.1")
            }
        }
        
        val iosX64Main by getting
        val iosArm64Main by getting
        val iosSimulatorArm64Main by getting
        
        val iosMain by creating {
            dependsOn(commonMain)
            iosX64Main.dependsOn(this)
            iosArm64Main.dependsOn(this)
            iosSimulatorArm64Main.dependsOn(this)
            
            dependencies {
                implementation("app.cash.sqldelight:native-driver:2.0.1")
                implementation("io.ktor:ktor-client-darwin:2.3.8")
            }
        }
    }
}

android {
    namespace = "app.visitorpass.shared"
    compileSdk = 34
    defaultConfig {
        minSdk = 26
    }
    testOptions {
        unitTests.all {
            it.testLogging {
                events("passed", "failed", "skipped")
                showStandardStreams = false
                exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
            }
        }
    }
}

sqldelight {
    databases {
        create("VisitorPassDatabase") {
            packageName.set("app.visitorpass.db")
        }
    }
}
