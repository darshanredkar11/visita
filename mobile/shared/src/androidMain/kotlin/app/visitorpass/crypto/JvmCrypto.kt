package app.visitorpass.crypto

import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class JvmCrypto : PlatformCrypto {

    override fun verifyEd25519(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        return try {
            // Prepend ASN.1 header to wrap raw 32-byte public key to X.509 DER format
            val header = byteArrayOf(
                0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
            )
            val x509Key = header + publicKey
            
            val keyFactory = KeyFactory.getInstance("Ed25519")
            val pubKey = keyFactory.generatePublic(X509EncodedKeySpec(x509Key))
            
            val sig = Signature.getInstance("Ed25519")
            sig.initVerify(pubKey)
            sig.update(message)
            sig.verify(signature)
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }

    override fun decryptChaCha(ciphertext: ByteArray, key: ByteArray, nonce: ByteArray): String? {
        return try {
            val cipher = Cipher.getInstance("ChaCha20-Poly1305")
            val keySpec = SecretKeySpec(key, "ChaCha20")
            val ivSpec = IvParameterSpec(nonce)
            
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
            val plainText = cipher.doFinal(ciphertext)
            String(plainText, Charsets.UTF_8)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }
}
