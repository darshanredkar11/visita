package app.visitorpass.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith

class CryptoServiceTest {

    // SCENARIO 1: Base45 standard vectors & codec verification
    @Test
    fun testBase45StandardRFCVectors() {
        val testCases = listOf(
            "" to "",
            "AB" to "BB8",
            "Hello!!" to "%69 VD92EX0",
            "VisitorPass" to "Q-APQEHWEEKEHECP2"
        )

        for ((plain, expectedBase45) in testCases) {
            val plainBytes = plain.encodeToByteArray()
            val encoded = Base45.encode(plainBytes)
            assertEquals(expectedBase45, encoded, "Failed encoding for '$plain'")

            val decodedBytes = Base45.decode(encoded)
            val decodedString = decodedBytes.decodeToString()
            assertEquals(plain, decodedString, "Failed decoding for '$encoded'")
        }
    }

    // SCENARIO 2: Base45 Boundary and Odd-Length Combinations
    @Test
    fun testBase45OddAndBoundaryLengths() {
        // Single byte remaining (odd length)
        val singleByte = byteArrayOf(0x41) // "A"
        val expectedSingle = "A0" // 65 % 45 = 20 (A), 65 / 45 = 1 (1? No, ALPHABET[1] is '1', ALPHABET[0] is '0'. Wait, 65 = 20 + 1 * 45. ALPHABET[20] is 'K', ALPHABET[1] is '1'. So "K1")
        val encodedSingle = Base45.encode(singleByte)
        val decodedSingle = Base45.decode(encodedSingle)
        assertTrue(singleByte.contentEquals(decodedSingle), "Odd byte length failed roundtrip")

        // 3 bytes input
        val threeBytes = byteArrayOf(0x41, 0x42, 0x43) // "ABC"
        val encodedThree = Base45.encode(threeBytes)
        val decodedThree = Base45.decode(encodedThree)
        assertTrue(threeBytes.contentEquals(decodedThree), "3 bytes length failed roundtrip")

        // Zero-filled buffer
        val zeroBytes = ByteArray(10) { 0 }
        val encodedZero = Base45.encode(zeroBytes)
        val decodedZero = Base45.decode(encodedZero)
        assertTrue(zeroBytes.contentEquals(decodedZero), "Zero buffer failed roundtrip")
    }

    // SCENARIO 3: Base45 Error Validation Check on Invalid Inputs
    @Test
    fun testBase45DecodingErrorHandling() {
        // Lowercase characters are invalid in Base45 alphabet
        assertFailsWith<IllegalArgumentException> {
            Base45.decode("lowercase")
        }

        // Invalid length (Base45 string must not have length % 3 == 1)
        assertFailsWith<IllegalArgumentException> {
            Base45.decode("A") 
        }

        // Invalid punctuation characters
        assertFailsWith<IllegalArgumentException> {
            Base45.decode("BB#")
        }
    }

    // SCENARIO 4: Cryptographic Delegate Wiring Assertions
    @Test
    fun testCryptoDelegateWiring() {
        var verifyInvoked = false
        var decryptInvoked = false
        
        val mockCrypto = object : PlatformCrypto {
            override fun verifyEd25519(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
                verifyInvoked = true
                return true
            }

            override fun decryptChaCha(ciphertext: ByteArray, key: ByteArray, nonce: ByteArray): String? {
                decryptInvoked = true
                return "decrypted_phone_number"
            }
        }

        CryptoService.setDelegate(mockCrypto)
        
        val verifyRes = CryptoService.verifyEd25519(ByteArray(32), ByteArray(10), ByteArray(64))
        assertTrue(verifyRes, "Verify should pass")
        assertTrue(verifyInvoked, "Ed25519 verify delegate should be invoked")

        val decryptRes = CryptoService.decryptChaCha(ByteArray(16), ByteArray(32), ByteArray(12))
        assertEquals("decrypted_phone_number", decryptRes)
        assertTrue(decryptInvoked, "ChaCha decrypt delegate should be invoked")
    }
}
