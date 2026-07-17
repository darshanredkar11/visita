package app.visitorpass.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * [SecureTokenStore] backed directly by the Android Keystore: the AES-256
 * key never leaves hardware-backed storage (TEE/StrongBox where available)
 * and cannot be extracted even with root, unlike a plain SQLite column.
 *
 * `androidx.security:security-crypto`'s `EncryptedSharedPreferences` -- the
 * commonly cited "standard Android answer" for this -- was considered, but
 * the whole library was deprecated by Google in April 2025 in favor of
 * using Android Keystore directly
 * (https://developer.android.com/jetpack/androidx/releases/security), and
 * it pulls in Google Tink as a transitive dependency for what is
 * fundamentally "AES/GCM-encrypt a small blob with a Keystore key". This
 * class does exactly that with only platform APIs
 * (`javax.crypto`/`java.security`/`android.security.keystore`), already
 * available since API 23 -- no extra Gradle dependency needed given this
 * module's `minSdk 26`.
 *
 * The ciphertext + IV are stored in a regular (unencrypted) `SharedPreferences`
 * file -- that's fine, they're useless without the Keystore-resident key,
 * which is the actual secret and never touches disk in extractable form.
 */
class AndroidKeystoreTokenStore(context: Context) : SecureTokenStore {

    private val prefs = context.applicationContext
        .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }

        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        keyGenerator.init(
            KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return keyGenerator.generateKey()
    }

    override fun saveRefreshToken(token: String) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val ciphertext = cipher.doFinal(token.toByteArray(Charsets.UTF_8))
        prefs.edit()
            .putString(PREF_IV, Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
            .putString(PREF_CIPHERTEXT, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
            .apply()
    }

    override fun getRefreshToken(): String? {
        val ivB64 = prefs.getString(PREF_IV, null) ?: return null
        val ciphertextB64 = prefs.getString(PREF_CIPHERTEXT, null) ?: return null
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                getOrCreateKey(),
                GCMParameterSpec(GCM_TAG_LENGTH_BITS, Base64.decode(ivB64, Base64.NO_WRAP))
            )
            String(cipher.doFinal(Base64.decode(ciphertextB64, Base64.NO_WRAP)), Charsets.UTF_8)
        } catch (e: Exception) {
            // Key invalidated (e.g. Keystore wiped/reset) or corrupt data --
            // treat as "no valid session" rather than crash the caller.
            null
        }
    }

    override fun clearRefreshToken() {
        prefs.edit().remove(PREF_IV).remove(PREF_CIPHERTEXT).apply()
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "visitorpass_refresh_token_key"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_TAG_LENGTH_BITS = 128
        const val PREFS_NAME = "visitorpass_secure_prefs"
        const val PREF_IV = "refresh_token_iv"
        const val PREF_CIPHERTEXT = "refresh_token_ciphertext"
    }
}
