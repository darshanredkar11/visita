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
import app.visitorpass.crypto.PassVerificationResult
import app.visitorpass.crypto.verifyScannedPass
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

@Composable
fun GuardKioskDashboard(
    session: Session,
    databaseHelper: DatabaseHelper,
    ktorClient: KtorClient,
    onLogout: () -> Unit
) {
    val coroutineScope = rememberCoroutineScope()
    var qrInput by remember { mutableStateOf("") }
    
    // Ad-hoc entry forms
    var visitorName by remember { mutableStateOf("") }
    var visitorPhone by remember { mutableStateOf("") }
    var unitTarget by remember { mutableStateOf("") }
    var adHocStatus by remember { mutableStateOf<String?>(null) }
    
    var activeTab by remember { mutableStateOf(0) } // 0 = Scanner, 1 = Ad-Hoc
    var validationResult by remember { mutableStateOf<String?>(null) }
    var isValidState by remember { mutableStateOf(false) }
    var loadingAdHoc by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Kiosk Header
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text("VisitorPass Kiosk", color = PrimaryAccent, fontSize = 20.sp)
                Text("Gate: ${session.unit_identifier}", color = TextSecondary, fontSize = 14.sp)
            }
            Button(
                onClick = onLogout,
                colors = ButtonDefaults.buttonColors(containerColor = Color.DarkGray)
            ) {
                Text("Logout")
            }
        }

        // Tabs
        TabRow(
            selectedTabIndex = activeTab,
            containerColor = SurfaceBg,
            contentColor = PrimaryAccent
        ) {
            Tab(selected = activeTab == 0, onClick = { activeTab = 0 }) {
                Text("QR Scanner", modifier = Modifier.padding(12.dp), color = if (activeTab == 0) Color.White else TextSecondary)
            }
            Tab(selected = activeTab == 1, onClick = { activeTab = 1 }) {
                Text("Ad-Hoc Guest", modifier = Modifier.padding(12.dp), color = if (activeTab == 1) Color.White else TextSecondary)
            }
        }

        if (activeTab == 0) {
            // Scanner View
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = SurfaceBg)
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text("Offline Pass Verification", fontSize = 16.sp, color = TextPrimary)

                    // Simulator input override
                    OutlinedTextField(
                        value = qrInput,
                        onValueChange = { qrInput = it },
                        label = { Text("Paste Scanned QR Code", color = TextSecondary) },
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
                            val orgKey = databaseHelper.queries.getOrgKey().executeAsOneOrNull()
                            if (orgKey == null) {
                                validationResult = "DENIED: No org signing key cached yet -- sync while online first"
                                isValidState = false
                                return@Button
                            }

                            when (val result = verifyScannedPass(qrInput, orgKey.public_key)) {
                                is PassVerificationResult.Verified -> {
                                    validationResult = "VERIFIED: Pass Signature Authentic! (${result.visitorName})"
                                    isValidState = true

                                    // Save log entry locally in SQLite using the REAL decoded
                                    // pass_id and the REAL current device timestamp -- both
                                    // were previously hardcoded placeholders.
                                    databaseHelper.queries.insertEntryLog(
                                        id = kotlinx.datetime.Clock.System.now().toEpochMilliseconds().toString(),
                                        pass_id = result.passId,
                                        action = "ENTRY",
                                        occurred_at = kotlinx.datetime.Clock.System.now().toString(),
                                        synced = 0,
                                        denial_reason = null,
                                        guard_note = "Scanned at main gate"
                                    )
                                }
                                is PassVerificationResult.Denied -> {
                                    validationResult = "DENIED: ${result.reason}"
                                    isValidState = false
                                }
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = PrimaryAccent)
                    ) {
                        Text("Verify Offline")
                    }

                    // Result card
                    validationResult?.let {
                        Card(
                            modifier = Modifier.fillMaxWidth().padding(top = 10.dp),
                            colors = CardDefaults.cardColors(
                                containerColor = if (isValidState) Color(0xFF064E3B) else Color(0xFF7F1D1D)
                            )
                        ) {
                            Column(modifier = Modifier.padding(16.dp)) {
                                Text(
                                    text = if (isValidState) "ACCESS GRANTED" else "ACCESS DENIED",
                                    fontSize = 18.sp,
                                    color = Color.White
                                )
                                Spacer(modifier = Modifier.height(4.dp))
                                Text(it, fontSize = 13.sp, color = Color.White)
                            }
                        }
                    }
                }
            }
        } else {
            // Ad-Hoc unexpected guest panel
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = SurfaceBg)
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Text("Ad-Hoc Visitor Approval", fontSize = 16.sp, color = TextPrimary)

                    adHocStatus?.let {
                        Text("Status: $it", color = PrimaryAccent, fontSize = 14.sp)
                    }

                    OutlinedTextField(
                        value = visitorName,
                        onValueChange = { visitorName = it },
                        label = { Text("Visitor Name", color = TextSecondary) },
                        modifier = Modifier.fillMaxWidth(),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary,
                            focusedBorderColor = PrimaryAccent,
                            unfocusedBorderColor = Color.DarkGray
                        )
                    )

                    OutlinedTextField(
                        value = visitorPhone,
                        onValueChange = { visitorPhone = it },
                        label = { Text("Visitor Phone", color = TextSecondary) },
                        modifier = Modifier.fillMaxWidth(),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary,
                            focusedBorderColor = PrimaryAccent,
                            unfocusedBorderColor = Color.DarkGray
                        )
                    )

                    OutlinedTextField(
                        value = unitTarget,
                        onValueChange = { unitTarget = it },
                        label = { Text("Target Flat / Apartment", color = TextSecondary) },
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
                            if (visitorName.trim().isEmpty() || unitTarget.trim().isEmpty()) return@Button
                            coroutineScope.launch {
                                loadingAdHoc = true
                                adHocStatus = "SENDING REQUEST..."
                                try {
                                    val res = ktorClient.requestAdHocApproval(
                                        visitorName = visitorName.trim(),
                                        visitorPhone = visitorPhone.trim(),
                                        locationId = "00000000-0000-0000-0000-000000000000",
                                        unitIdentifier = unitTarget.trim()
                                    )
                                    val obj = Json.parseToJsonElement(res).jsonObject
                                    val status = obj["status"]?.jsonPrimitive?.content ?: "PENDING"
                                    adHocStatus = "PENDING RESIDENT DECISION..."
                                    
                                    // Cache locally
                                    databaseHelper.queries.insertAdHocApproval(
                                        id = obj["approval_id"]?.jsonPrimitive?.content ?: kotlinx.datetime.Clock.System.now().toEpochMilliseconds().toString(),
                                        visitor_name = visitorName.trim(),
                                        visitor_phone = visitorPhone.trim(),
                                        unit_identifier = unitTarget.trim(),
                                        status = status,
                                        created_at = "2026-07-10T12:00:00Z"
                                    )
                                } catch (e: Exception) {
                                    adHocStatus = "API OFFLINE: Offline validation mandatory"
                                } finally {
                                    loadingAdHoc = false
                                }
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = PrimaryAccent),
                        enabled = !loadingAdHoc
                    ) {
                        if (loadingAdHoc) {
                            CircularProgressIndicator(color = Color.White, modifier = Modifier.size(24.dp))
                        } else {
                            Text("Request Resident Approval", color = Color.White)
                        }
                    }
                }
            }
        }
    }
}
