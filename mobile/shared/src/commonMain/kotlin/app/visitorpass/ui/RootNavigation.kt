package app.visitorpass.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.visitorpass.db.DatabaseHelper
import app.visitorpass.net.KtorClient

// Colors that match our premium web portal
val DarkBg = Color(0xFF0A0B10)
val SurfaceBg = Color(0xFF12131A)
val PrimaryAccent = Color(0xFF6366F1)
val AccentAqua = Color(0xFF10B981)
val TextPrimary = Color(0xFFFFFFFF)
val TextSecondary = Color(0xFF9CA3AF)

@Composable
fun RootNavigation(databaseHelper: DatabaseHelper, ktorClient: KtorClient) {
    // Basic state routing based on DB Session
    var currentSession by remember {
        mutableStateOf(databaseHelper.queries.getSession().executeAsOneOrNull())
    }

    val onSessionChanged = {
        currentSession = databaseHelper.queries.getSession().executeAsOneOrNull()
    }

    MaterialTheme(
        colorScheme = darkColorScheme(
            background = DarkBg,
            surface = SurfaceBg,
            primary = PrimaryAccent,
            onBackground = TextPrimary,
            onSurface = TextPrimary
        )
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(DarkBg)
                .safeContentPadding()
        ) {
            val session = currentSession
            if (session == null) {
                LoginScreen(
                    databaseHelper = databaseHelper,
                    ktorClient = ktorClient,
                    onLoginSuccess = onSessionChanged
                )
            } else {
                when (session.role.uppercase()) {
                    "RESIDENT" -> ResidentDashboard(
                        session = session,
                        databaseHelper = databaseHelper,
                        ktorClient = ktorClient,
                        onLogout = {
                            databaseHelper.clearAllData()
                            onSessionChanged()
                        }
                    )
                    else -> GuardKioskDashboard(
                        session = session,
                        databaseHelper = databaseHelper,
                        ktorClient = ktorClient,
                        onLogout = {
                            databaseHelper.clearAllData()
                            onSessionChanged()
                        }
                    )
                }
            }
        }
    }
}

@Composable
fun LoginScreen(databaseHelper: DatabaseHelper, ktorClient: KtorClient, onLoginSuccess: () -> Unit) {
    var emailInput by remember { mutableStateOf("resident@visitorpass.app") }
    var roleInput by remember { mutableStateOf("RESIDENT") } // Toggle between RESIDENT and GUARD for local dev demo
    var loading by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "VisitorPass",
            fontSize = 32.sp,
            color = PrimaryAccent,
            modifier = Modifier.padding(bottom = 8.dp)
        )
        Text(
            text = "Offline-First Access Security",
            fontSize = 14.sp,
            color = TextSecondary,
            modifier = Modifier.padding(bottom = 40.dp)
        )

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = SurfaceBg)
        ) {
            Column(modifier = Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                Text("Select Mock Login (Dev Mode)", color = TextPrimary, fontSize = 16.sp)

                OutlinedTextField(
                    value = emailInput,
                    onValueChange = { emailInput = it },
                    label = { Text("Mock Email", color = TextSecondary) },
                    modifier = Modifier.fillMaxWidth(),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = TextPrimary,
                        unfocusedTextColor = TextPrimary,
                        focusedBorderColor = PrimaryAccent,
                        unfocusedBorderColor = Color.DarkGray
                    )
                )

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Button(
                        onClick = { roleInput = "RESIDENT" },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (roleInput == "RESIDENT") PrimaryAccent else Color.DarkGray
                        )
                    ) {
                        Text("Resident")
                    }
                    Button(
                        onClick = { roleInput = "GUARD" },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (roleInput == "GUARD") PrimaryAccent else Color.DarkGray
                        )
                    ) {
                        Text("Guard")
                    }
                }

                Button(
                    onClick = {
                        loading = true
                        // Simulate bypass authentication
                        databaseHelper.queries.insertSession(
                            token = "mock_session_token_123",
                            role = roleInput,
                            org_id = "00000000-0000-0000-0000-000000000000",
                            unit_identifier = if (roleInput == "RESIDENT") "Flat 402" else "Main Gate",
                            user_name = "Jane Doe"
                        )
                        onLoginSuccess()
                        loading = false
                    },
                    modifier = Modifier.fillMaxWidth().height(48.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = PrimaryAccent)
                ) {
                    if (loading) {
                        CircularProgressIndicator(color = Color.White, modifier = Modifier.size(24.dp))
                    } else {
                        Text("Bypass OAuth Login", color = Color.White)
                    }
                }
            }
        }
    }
}
