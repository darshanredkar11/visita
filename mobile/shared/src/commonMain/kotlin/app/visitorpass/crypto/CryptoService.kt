package app.visitorpass.crypto

interface PlatformCrypto {
    fun verifyEd25519(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean
    fun decryptChaCha(ciphertext: ByteArray, key: ByteArray, nonce: ByteArray): String?
}

object CryptoService {
    private var delegate: PlatformCrypto? = null

    fun setDelegate(crypto: PlatformCrypto) {
        delegate = crypto
    }

    fun verifyEd25519(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        val active = delegate
        if (active == null) {
            println("CryptoService delegate not set!")
            return false
        }
        return active.verifyEd25519(publicKey, message, signature)
    }

    fun decryptChaCha(ciphertext: ByteArray, key: ByteArray, nonce: ByteArray): String? {
        val active = delegate
        if (active == null) {
            println("CryptoService delegate not set!")
            return null
        }
        return active.decryptChaCha(ciphertext, key, nonce)
    }
}
