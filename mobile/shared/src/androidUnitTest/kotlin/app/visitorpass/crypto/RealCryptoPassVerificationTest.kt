package app.visitorpass.crypto

import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import kotlin.test.assertEquals
import kotlin.test.assertIs

/**
 * Supplementary to [PassVerificationTest] (which uses a fake, non-
 * cryptographic [PlatformCrypto] delegate for `commonTest`-visibility
 * reasons -- see its doc comment). This test lives in `androidUnitTest`
 * specifically so it CAN use the real, production [JvmCrypto] delegate and
 * genuine `java.security.Signature`-based Ed25519 signing/verification --
 * closing the gap the fake delegate leaves: does the actual cryptography,
 * not just the wiring around it, work end-to-end for a correctly-signed
 * payload, a wrong key, and a tampered payload?
 */
class RealCryptoPassVerificationTest {

    init {
        CryptoService.setDelegate(JvmCrypto())
    }

    private fun ed25519KeyPair() = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

    /** Strips the fixed 12-byte X.509 ASN.1 prefix `JvmCrypto` expects/produces to get the raw 32-byte key. */
    private fun rawPublicKeyBytes(publicKey: java.security.PublicKey): ByteArray =
        publicKey.encoded.copyOfRange(12, 44)

    private val testPassId = "0195b1f0-1234-7abc-9def-0123456789ab"
    private val testOrgId = "0195b1f0-aaaa-7bbb-cccc-fedcba987654"
    private val testLocationId = "0195b1f0-1111-7222-3333-444455556666"

    private fun buildUnsignedMessage(visitorName: String): ByteArray {
        val fields = QrPayloadCodec.uintBytes(1) + QrPayloadCodec.uintValueBytes(1) +
            QrPayloadCodec.uintBytes(2) + QrPayloadCodec.byteStringBytes(QrPayloadCodec.uuidStringToBytes(testPassId)) +
            QrPayloadCodec.uintBytes(3) + QrPayloadCodec.uintValueBytes(1_800_000_000L) +
            QrPayloadCodec.uintBytes(4) + QrPayloadCodec.uintValueBytes(1_799_000_000L) +
            QrPayloadCodec.uintBytes(5) + QrPayloadCodec.uintValueBytes(1L) +
            QrPayloadCodec.uintBytes(6) + QrPayloadCodec.byteStringBytes(QrPayloadCodec.uuidStringToBytes(testOrgId)) +
            QrPayloadCodec.uintBytes(7) + QrPayloadCodec.byteStringBytes(QrPayloadCodec.uuidStringToBytes(testLocationId)) +
            QrPayloadCodec.uintBytes(8) + QrPayloadCodec.textStringBytes(visitorName) +
            QrPayloadCodec.uintBytes(9) + QrPayloadCodec.textStringBytes("Guest visit") +
            QrPayloadCodec.uintBytes(10) + QrPayloadCodec.arrayBytes(listOf(QrPayloadCodec.textStringBytes("ENTRY"))) +
            QrPayloadCodec.uintBytes(11) + QrPayloadCodec.NULL_BYTES +
            QrPayloadCodec.uintBytes(12) + QrPayloadCodec.NULL_BYTES
        return QrPayloadCodec.mapHeaderBytes(12) + fields
    }

    private fun signAndBuildQr(privateKey: java.security.PrivateKey, visitorName: String = "Real Crypto Guest"): String {
        val unsigned = buildUnsignedMessage(visitorName)
        val signature = Signature.getInstance("Ed25519").run {
            initSign(privateKey)
            update(unsigned)
            sign()
        }
        val signed = QrPayloadCodec.mapHeaderBytes(13) + unsigned.copyOfRange(1, unsigned.size) +
            QrPayloadCodec.uintBytes(13) + QrPayloadCodec.byteStringBytes(signature)
        return QrPayloadCodec.QR_PREFIX + QrPayloadCodec.base64UrlEncode(signed)
    }

    @Test
    fun testRealEd25519VerifiedForCorrectlySignedPayload() {
        val keyPair = ed25519KeyPair()
        val qr = signAndBuildQr(keyPair.private)

        val result = verifyScannedPass(qr, rawPublicKeyBytes(keyPair.public))

        val verified = assertIs<PassVerificationResult.Verified>(result, "real Ed25519 signature must verify against the matching real public key")
        assertEquals(testPassId, verified.passId)
    }

    @Test
    fun testRealEd25519DeniedForDifferentKeyPair() {
        val signingKeyPair = ed25519KeyPair()
        val otherKeyPair = ed25519KeyPair()
        val qr = signAndBuildQr(signingKeyPair.private)

        val result = verifyScannedPass(qr, rawPublicKeyBytes(otherKeyPair.public))

        assertIs<PassVerificationResult.Denied>(result, "a genuinely different org's real public key must not verify this signature")
    }

    @Test
    fun testRealEd25519DeniedForTamperedPayload() {
        val keyPair = ed25519KeyPair()
        val qr = signAndBuildQr(keyPair.private)

        val cborBytes = QrPayloadCodec.base64UrlDecode(qr.removePrefix(QrPayloadCodec.QR_PREFIX))
        val tampered = cborBytes.copyOf()
        tampered[tampered.size / 2] = (tampered[tampered.size / 2] + 1).toByte()
        val tamperedQr = QrPayloadCodec.QR_PREFIX + QrPayloadCodec.base64UrlEncode(tampered)

        val result = verifyScannedPass(tamperedQr, rawPublicKeyBytes(keyPair.public))

        assertIs<PassVerificationResult.Denied>(result, "tampering must invalidate even a genuinely real Ed25519 signature")
    }
}
