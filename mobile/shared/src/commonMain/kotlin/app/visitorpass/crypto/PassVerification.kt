package app.visitorpass.crypto

/**
 * Outcome of offline pass verification. Extracted out of
 * `GuardKioskDashboard`'s Compose `onClick` lambda so it's directly
 * testable without any UI framework in the loop.
 */
sealed class PassVerificationResult {
    data class Verified(val passId: String, val visitorName: String) : PassVerificationResult()
    data class Denied(val reason: String) : PassVerificationResult()
}

/**
 * Verifies a scanned QR string fully offline against the org's cached
 * Ed25519 public key. This is the exact logic that used to be inlined in
 * `GuardKioskDashboard`'s "Verify Offline" button handler, pulled out so it
 * can be unit tested directly.
 */
fun verifyScannedPass(qrString: String, orgPublicKey: ByteArray): PassVerificationResult {
    val decoded = try {
        QrPayloadCodec.decode(qrString)
    } catch (e: Exception) {
        return PassVerificationResult.Denied("Malformed QR payload: ${e.message}")
    }

    val isSignatureValid = CryptoService.verifyEd25519(
        publicKey = orgPublicKey,
        message = decoded.messageBytes,
        signature = decoded.signatureBytes
    )

    return if (isSignatureValid) {
        PassVerificationResult.Verified(passId = decoded.passId, visitorName = decoded.visitorName)
    } else {
        PassVerificationResult.Denied("Cryptographic signature mismatch")
    }
}
