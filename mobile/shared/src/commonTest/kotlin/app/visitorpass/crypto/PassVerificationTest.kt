package app.visitorpass.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Tests [verifyScannedPass] -- the function GuardKioskDashboard's
 * "Verify Offline" button now calls, extracted out of its Compose
 * `onClick` lambda specifically so it can be exercised here without any UI
 * framework.
 *
 * Real Ed25519 math is deliberately NOT used in these `commonTest` cases:
 * Kotlin Multiplatform's `commonTest` source set can only see `commonMain`
 * API (interfaces / expect-declarations), never `androidMain`-only concrete
 * classes like `JvmCrypto` (which uses `java.security.Signature`) -- using
 * it here would break compilation for the iOS targets this module also
 * builds for. So, exactly like the pre-existing `CryptoServiceTest`'s
 * `testCryptoDelegateWiring`, a fake [PlatformCrypto] delegate stands in for
 * the signature primitive. What IS real and exact here: the base64url
 * decoding (fixing the previous Base45-vs-base64url mismatch) and the CBOR
 * field layout (fixing the previous "slice off the last 64 bytes" message
 * reconstruction, which was wrong by exactly the 3 extra header/length-
 * prefix bytes CBOR field 13 adds) -- both copied field-for-field from
 * `crates/infrastructure/src/crypto/service.rs`.
 *
 * A companion test using REAL Ed25519 (`java.security.Signature`) lives in
 * `androidUnitTest`'s `RealCryptoPassVerificationTest`, for end-to-end
 * confidence beyond this wiring-level fake.
 */
class PassVerificationTest {

    /** Deterministic, NON-cryptographic stand-in "signature": see class doc. */
    private fun fakeSign(key: ByteArray, message: ByteArray): ByteArray {
        var h = 1125899906842597L // arbitrary odd seed
        for (b in key) h = h * 31 + b
        for (b in message) h = h * 31 + b
        return ByteArray(64) { i -> ((h shr ((i % 8) * 8)) and 0xFF).toByte() }
    }

    private val fakeCrypto = object : PlatformCrypto {
        override fun verifyEd25519(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
            return signature.contentEquals(fakeSign(publicKey, message))
        }
        override fun decryptChaCha(ciphertext: ByteArray, key: ByteArray, nonce: ByteArray): String? = null
    }

    init {
        CryptoService.setDelegate(fakeCrypto)
    }

    private val testPassId = "0195b1f0-1234-7abc-9def-0123456789ab"
    private val testOrgId = "0195b1f0-aaaa-7bbb-cccc-fedcba987654"
    private val testLocationId = "0195b1f0-1111-7222-3333-444455556666"
    private val correctKey = ByteArray(32) { (it + 1).toByte() }
    private val wrongKey = ByteArray(32) { (it + 99).toByte() }

    /** Builds a "vp1."-prefixed QR string matching the backend's exact CBOR field layout and signs it with [signingKey]. */
    private fun buildSignedQr(
        visitorName: String = "Rahul Sharma",
        signingKey: ByteArray = correctKey
    ): String {
        val fields = QrPayloadCodec.uintBytes(1) + QrPayloadCodec.uintValueBytes(1) +               // 1: version
            QrPayloadCodec.uintBytes(2) + QrPayloadCodec.byteStringBytes(QrPayloadCodec.uuidStringToBytes(testPassId)) + // 2: pass_id
            QrPayloadCodec.uintBytes(3) + QrPayloadCodec.uintValueBytes(1_800_000_000L) +            // 3: valid_until
            QrPayloadCodec.uintBytes(4) + QrPayloadCodec.uintValueBytes(1_799_000_000L) +            // 4: valid_from
            QrPayloadCodec.uintBytes(5) + QrPayloadCodec.uintValueBytes(1L) +                         // 5: key_version
            QrPayloadCodec.uintBytes(6) + QrPayloadCodec.byteStringBytes(QrPayloadCodec.uuidStringToBytes(testOrgId)) +  // 6: org_id
            QrPayloadCodec.uintBytes(7) + QrPayloadCodec.byteStringBytes(QrPayloadCodec.uuidStringToBytes(testLocationId)) + // 7: location_id
            QrPayloadCodec.uintBytes(8) + QrPayloadCodec.textStringBytes(visitorName) +               // 8: visitor_name
            QrPayloadCodec.uintBytes(9) + QrPayloadCodec.textStringBytes("Guest visit") +             // 9: purpose
            QrPayloadCodec.uintBytes(10) + QrPayloadCodec.arrayBytes(listOf(QrPayloadCodec.textStringBytes("ENTRY"), QrPayloadCodec.textStringBytes("EXIT"))) + // 10: permissions
            QrPayloadCodec.uintBytes(11) + QrPayloadCodec.NULL_BYTES +                                // 11: vehicle_number
            QrPayloadCodec.uintBytes(12) + QrPayloadCodec.NULL_BYTES                                  // 12: encrypted_phone

        val unsignedCbor = QrPayloadCodec.mapHeaderBytes(12) + fields
        val signature = fakeSign(signingKey, unsignedCbor)

        val signedCbor = QrPayloadCodec.mapHeaderBytes(13) + fields +
            QrPayloadCodec.uintBytes(13) + QrPayloadCodec.byteStringBytes(signature)

        return QrPayloadCodec.QR_PREFIX + QrPayloadCodec.base64UrlEncode(signedCbor)
    }

    @Test
    fun testVerifiedForCorrectlySignedPayloadAgainstMatchingKey() {
        val qr = buildSignedQr(visitorName = "Rahul Sharma", signingKey = correctKey)

        val result = verifyScannedPass(qr, correctKey)

        val verified = assertIs<PassVerificationResult.Verified>(result, "correctly-signed payload against the matching key must verify")
        assertEquals(testPassId, verified.passId, "the REAL pass_id must be decoded from the CBOR payload, not hardcoded")
        assertEquals("Rahul Sharma", verified.visitorName)
    }

    @Test
    fun testDeniedForSamePayloadAgainstDifferentKey() {
        val qr = buildSignedQr(signingKey = correctKey)

        val result = verifyScannedPass(qr, wrongKey)

        assertIs<PassVerificationResult.Denied>(result, "the same payload verified against the WRONG org key must be denied")
    }

    @Test
    fun testDeniedForTamperedPayload() {
        val qr = buildSignedQr(visitorName = "Rahul Sharma", signingKey = correctKey)

        // Tamper with the payload after signing: flip one byte inside the
        // encoded CBOR (well past the "vp1." prefix, inside the base64url
        // body), then re-encode. The signature no longer matches.
        val prefix = QrPayloadCodec.QR_PREFIX
        val cborBytes = QrPayloadCodec.base64UrlDecode(qr.removePrefix(prefix))
        val tampered = cborBytes.copyOf()
        val tamperIndex = tampered.size / 2
        tampered[tamperIndex] = (tampered[tamperIndex] + 1).toByte()
        val tamperedQr = prefix + QrPayloadCodec.base64UrlEncode(tampered)

        val result = verifyScannedPass(tamperedQr, correctKey)

        assertIs<PassVerificationResult.Denied>(result, "a tampered payload must be denied even against the correct key")
    }

    @Test
    fun testDeniedForMalformedQrPrefix() {
        val result = verifyScannedPass("not-a-real-qr-payload", correctKey)
        assertIs<PassVerificationResult.Denied>(result)
    }

    @Test
    fun testBase64UrlRoundTripMatchesKnownVector() {
        // Sanity check against a known base64url vector, independent of the
        // CBOR logic above -- this is the exact encoding the backend uses
        // (`base64::engine::general_purpose::URL_SAFE_NO_PAD`), NOT Base45.
        val decoded = "any carnal pleasure.".encodeToByteArray()
        val encoded = QrPayloadCodec.base64UrlEncode(decoded)
        assertEquals("YW55IGNhcm5hbCBwbGVhc3VyZS4", encoded)
        assertTrue(QrPayloadCodec.base64UrlDecode(encoded).contentEquals(decoded))
    }
}
