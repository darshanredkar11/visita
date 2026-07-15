package app.visitorpass.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.visitorpass.db.DatabaseHelper
import app.visitorpass.net.KtorClient
import app.visitorpass.db.Session
import app.visitorpass.db.Visitor_pass
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

@Composable
fun ResidentDashboard(
    session: Session,
    databaseHelper: DatabaseHelper,
    ktorClient: KtorClient,
    onLogout: () -> Unit
) {
    val coroutineScope = rememberCoroutineScope()
    var nameInput by remember { mutableStateOf("") }
    var phoneInput by remember { mutableStateOf("") }
    var activeTab by remember { mutableStateOf(0) } // 0 = Create, 1 = History
    var createdPassResult by remember { mutableStateOf<String?>(null) }
    var errorMsg by remember { mutableStateOf<String?>(null) }
    var loading by remember { mutableStateOf(false) }

    // Read list of passes cached in SQLite
    var cachedPasses by remember {
        mutableStateOf(databaseHelper.queries.listPasses().executeAsList())
    }

    val refreshPasses = {
        cachedPasses = databaseHelper.queries.listPasses().executeAsList()
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Top Header
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text("VisitorPass", color = PrimaryAccent, fontSize = 20.sp)
                Text("Flat: ${session.unit_identifier}", color = TextSecondary, fontSize = 14.sp)
            }
            Button(
                onClick = onLogout,
                colors = ButtonDefaults.buttonColors(containerColor = Color.DarkGray)
            ) {
                Text("Logout")
            }
        }

        // Tab Row
        TabRow(
            selectedTabIndex = activeTab,
            containerColor = SurfaceBg,
            contentColor = PrimaryAccent
        ) {
            Tab(selected = activeTab == 0, onClick = { activeTab = 0 }) {
                Text("Invite Guest", modifier = Modifier.padding(12.dp), color = if (activeTab == 0) Color.White else TextSecondary)
            }
            Tab(selected = activeTab == 1, onClick = { activeTab = 1 }) {
                Text("Pass History", modifier = Modifier.padding(12.dp), color = if (activeTab == 1) Color.White else TextSecondary)
            }
        }

        if (activeTab == 0) {
            // Invite Guest Panel
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = SurfaceBg)
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text("New Pre-Approved Invite", fontSize = 16.sp, color = TextPrimary)

                    errorMsg?.let {
                        Text(it, color = Color.Red, fontSize = 13.sp)
                    }

                    createdPassResult?.let {
                        Text("Pass Generated: $it", color = AccentAqua, fontSize = 14.sp)
                    }

                    OutlinedTextField(
                        value = nameInput,
                        onValueChange = { nameInput = it },
                        label = { Text("Guest Name", color = TextSecondary) },
                        modifier = Modifier.fillMaxWidth(),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary,
                            focusedBorderColor = PrimaryAccent,
                            unfocusedBorderColor = Color.DarkGray
                        )
                    )

                    OutlinedTextField(
                        value = phoneInput,
                        onValueChange = { phoneInput = it },
                        label = { Text("Guest Phone", color = TextSecondary) },
                        modifier = Modifier.fillMaxWidth(),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary,
                            focusedBorderColor = PrimaryAccent,
                            unfocusedBorderColor = Color.DarkGray
                        )
                    )

                    Button(
                        onClick = {
                            if (nameInput.trim().isEmpty() || phoneInput.trim().isEmpty()) {
                                errorMsg = "Please fill in all fields"
                                return@Button
                            }
                            coroutineScope.launch {
                                loading = true
                                errorMsg = null
                                createdPassResult = null
                                try {
                                    val validFrom = "2026-07-10T12:00:00Z"
                                    val validUntil = "2026-07-11T12:00:00Z"
                                    
                                    val resJson = ktorClient.createPass(
                                        visitorName = nameInput.trim(),
                                        visitorPhone = phoneInput.trim(),
                                        validFrom = validFrom,
                                        validUntil = validUntil
                                    )
                                    
                                    // Parse response json
                                    val obj = Json.parseToJsonElement(resJson).jsonObject
                                    val passNumber = obj["pass_number"]?.jsonPrimitive?.content ?: "VP-UNKNOWN"
                                    val passId = obj["id"]?.jsonPrimitive?.content ?: kotlinx.datetime.Clock.System.now().toEpochMilliseconds().toString()
                                    val qr = obj["qr_payload"]?.jsonPrimitive?.content ?: "vp1.mock"

                                    // Cache pass in SQLDelight SQLite
                                    databaseHelper.queries.insertPass(
                                        id = passId,
                                        pass_number = passNumber,
                                        visitor_name = nameInput.trim(),
                                        visitor_phone_enc = phoneInput.trim().encodeToByteArray(),
                                        valid_from = validFrom,
                                        valid_until = validUntil,
                                        status = "ACTIVE",
                                        qr_payload = qr
                                    )
                                    
                                    createdPassResult = passNumber
                                    nameInput = ""
                                    phoneInput = ""
                                    refreshPasses()
                                } catch (e: Exception) {
                                    errorMsg = "API Error: Network unreachable"
                                } finally {
                                    loading = false
                                }
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = PrimaryAccent),
                        enabled = !loading
                    ) {
                        if (loading) {
                            CircularProgressIndicator(color = Color.White, modifier = Modifier.size(24.dp))
                        } else {
                            Text("Create Pass", color = Color.White)
                        }
                    }
                }
            }
        } else {
            // Pass History Panel
            LazyColumn(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(cachedPasses) { pass ->
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = SurfaceBg)
                    ) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Text(pass.visitor_name, fontSize = 16.sp, color = TextPrimary)
                                Text(pass.pass_number, color = PrimaryAccent, fontSize = 14.sp)
                            }
                            Spacer(modifier = Modifier.height(4.dp))
                            Text("Valid until: ${pass.valid_until}", color = TextSecondary, fontSize = 12.sp)
                        }
                    }
                }
            }
        }
    }
}
