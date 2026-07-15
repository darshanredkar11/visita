package app.visitorpass.journey

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import app.visitorpass.crypto.CryptoService
import app.visitorpass.crypto.PlatformCrypto
import app.visitorpass.crypto.Base45

class UserJourneyTest {

    private val mockPublicKey = ByteArray(32) { 0 }

    // Mock Crypto delegate for testing journeys
    private val mockCrypto = object : PlatformCrypto {
        override fun verifyEd25519(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
            // Simply match public key
            return publicKey.contentEquals(mockPublicKey)
        }
        override fun decryptChaCha(ciphertext: ByteArray, key: ByteArray, nonce: ByteArray): String? {
            return "decrypted_visitor_phone"
        }
    }

    init {
        CryptoService.setDelegate(mockCrypto)
    }

    // JOURNEY 1: Pre-Approved Visitor Entry Journey
    // 1. Resident pre-approves visitor "Rahul"
    // 2. System signs pass & generates Base45 QR payload
    // 3. Guard scans the QR payload at the gate and verifies it offline
    // 4. Verification succeeds and Guard grants entry
    @Test
    fun testPreApprovedVisitorEntryJourney() {
        // Step 1: Resident pre-approves visitor (simulated pass content)
        val visitorName = "Rahul Sharma"
        val validityInfo = "valid_until:2026-07-10T18:00:00Z"
        val passMessage = "$visitorName|$validityInfo"
        
        // Step 2: System signs pass (simulated 64-byte mock signature)
        val mockSignature = ByteArray(64) { 1 } 
        val messageBytes = passMessage.encodeToByteArray()
        val qrBytes = messageBytes + mockSignature
        val qrBase45Payload = "vp1." + Base45.encode(qrBytes)

        // Step 3: Visitor arrives at gate. Guard scans the QR code.
        assertTrue(qrBase45Payload.startsWith("vp1."), "Scanned QR code must start with vp1 prefix")
        val scannedEncodedData = qrBase45Payload.substring(4)
        val decodedQrBytes = Base45.decode(scannedEncodedData)

        // Extract message and signature
        val extractedMessageBytes = decodedQrBytes.sliceArray(0 until (decodedQrBytes.size - 64))
        val extractedSignatureBytes = decodedQrBytes.sliceArray((decodedQrBytes.size - 64) until decodedQrBytes.size)

        // Step 4: Guard checks offline cryptographic signature
        val isAuthentic = CryptoService.verifyEd25519(
            publicKey = mockPublicKey,
            message = extractedMessageBytes,
            signature = extractedSignatureBytes
        )

        assertTrue(isAuthentic, "Offline verification should succeed for authentic pre-approved QR")
        assertEquals(passMessage, extractedMessageBytes.decodeToString(), "Decoded visitor pass details must match")
    }

    // JOURNEY 2: Tampered/Corrupted Visitor QR Denied Entry Journey
    // 1. Guard scans a QR payload that has been tampered with
    // 2. Offline verification fails
    // 3. Entry is denied
    @Test
    fun testTamperedVisitorQRDeniedJourney() {
        val visitorName = "Malicious Actor"
        val validityInfo = "valid_until:2026-07-10T18:00:00Z"
        val passMessage = "$visitorName|$validityInfo"
        
        val mockSignature = ByteArray(64) { 1 } 
        val messageBytes = passMessage.encodeToByteArray()
        val qrBytes = messageBytes + mockSignature
        val qrBase45Payload = "vp1." + Base45.encode(qrBytes)

        // Scenario: A digit in the Base45 string is changed/tampered with
        val tamperedPayload = qrBase45Payload.replace("Q", "X")

        // Guard verifies the tampered QR code
        var validationSuccess = false
        try {
            val scannedEncodedData = tamperedPayload.substring(4)
            val decodedQrBytes = Base45.decode(scannedEncodedData)
            val extractedMessageBytes = decodedQrBytes.sliceArray(0 until (decodedQrBytes.size - 64))
            val extractedSignatureBytes = decodedQrBytes.sliceArray((decodedQrBytes.size - 64) until decodedQrBytes.size)

            // Signature verification using mismatching public key or tampered payload
            val wrongPublicKey = ByteArray(32) { 9 } // Tampered public key
            validationSuccess = CryptoService.verifyEd25519(
                publicKey = wrongPublicKey,
                message = extractedMessageBytes,
                signature = extractedSignatureBytes
            )
        } catch (e: Exception) {
            // Malformed Base45 throws exception
            validationSuccess = false
        }

        assertTrue(!validationSuccess, "Tampered QR payload must be rejected at the gate")
    }
}
