package app.visitorpass.crypto

/**
 * Decodes / encodes the visitor-pass QR payload format the backend produces
 * in `crates/infrastructure/src/crypto/service.rs` (`build_cbor_envelope` /
 * `sign_cbor_payload` / `parse_signed_cbor` / `rebuild_unsigned_cbor`):
 *
 *   "vp1." + base64url_no_pad(cbor_bytes)
 *
 * where `cbor_bytes` is a CBOR map with INTEGER keys 1-12 (the "unsigned"
 * fields) plus key 13 (the 64-byte Ed25519 signature over the CBOR encoding
 * of keys 1-12 alone), always in that fixed field order:
 *
 *   1  version           uint
 *   2  pass_id           bstr(16)  -- UUID bytes
 *   3  valid_until       uint
 *   4  valid_from        uint
 *   5  key_version       uint
 *   6  org_id            bstr(16)
 *   7  location_id       bstr(16)
 *   8  visitor_name      tstr
 *   9  purpose           tstr
 *   10 permissions       array<tstr>
 *   11 vehicle_number    tstr | null
 *   12 encrypted_phone   bstr | null
 *   13 signature         bstr(64)  -- present only once signed
 *
 * This is intentionally a MINIMAL, targeted reader/writer for exactly this
 * known, fixed schema -- not a general-purpose CBOR library. A general CBOR
 * library adds real risk here: two different CBOR implementations (this and
 * the backend's `ciborium`) agreeing byte-for-byte on canonical encoding for
 * every edge case is not guaranteed, whereas reading/writing this one fixed,
 * already-known layout directly is simple to get exactly right and to test.
 *
 * The mobile client previously used `Base45.decode` on this string, which
 * is a COMPLETELY DIFFERENT encoding from what the backend actually sends
 * (base64url); real QR codes issued by the backend could never have been
 * decoded correctly. That bug is fixed here alongside the mock-key issue.
 */
object QrPayloadCodec {

    const val QR_PREFIX = "vp1."
    private const val FIELD_SIGNATURE = 13
    private const val UNSIGNED_FIELD_COUNT = 12
    private val BASE64URL_ALPHABET =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    data class DecodedQrPayload(
        val passId: String,
        val orgId: String,
        val visitorName: String,
        /** The exact bytes that were Ed25519-signed (CBOR map of fields 1-12). */
        val messageBytes: ByteArray,
        val signatureBytes: ByteArray
    )

    class MalformedQrException(message: String) : Exception(message)

    // ── Public API ────────────────────────────────────────────────────────

    /** Decodes a full scanned QR string (including the `vp1.` prefix). */
    fun decode(qrString: String): DecodedQrPayload {
        val encoded = qrString.removePrefix(QR_PREFIX)
        if (encoded == qrString) {
            throw MalformedQrException("missing $QR_PREFIX prefix")
        }
        val cborBytes = base64UrlDecode(encoded)
        return decodeCbor(cborBytes)
    }

    fun decodeCbor(cborBytes: ByteArray): DecodedQrPayload {
        var offset = 0
        val (entryCount, headerLen) = readMapHeader(cborBytes, offset)
        offset += headerLen
        val bodyStart = offset

        var passId: String? = null
        var orgId: String? = null
        var visitorName: String? = null
        var signatureStart = -1
        var signatureBytes: ByteArray? = null

        repeat(entryCount) {
            val entryStart = offset
            val (key, keyLen) = readUint(cborBytes, offset)
            offset += keyLen

            when (key.toInt()) {
                FIELD_SIGNATURE -> {
                    signatureStart = entryStart
                    val (bytes, len) = readByteString(cborBytes, offset)
                    signatureBytes = bytes
                    offset += len
                }
                2 -> {
                    val (bytes, len) = readByteString(cborBytes, offset)
                    passId = bytesToUuidString(bytes)
                    offset += len
                }
                6 -> {
                    val (bytes, len) = readByteString(cborBytes, offset)
                    orgId = bytesToUuidString(bytes)
                    offset += len
                }
                8 -> {
                    val (text, len) = readTextString(cborBytes, offset)
                    visitorName = text
                    offset += len
                }
                else -> {
                    offset += skipItem(cborBytes, offset)
                }
            }
        }

        val sigBytes = signatureBytes
            ?: throw MalformedQrException("payload has no signature field (key $FIELD_SIGNATURE)")
        val pid = passId ?: throw MalformedQrException("payload has no pass_id field (key 2)")
        val oid = orgId ?: throw MalformedQrException("payload has no org_id field (key 6)")
        val vname = visitorName ?: throw MalformedQrException("payload has no visitor_name field (key 8)")

        // The signed message is the CBOR encoding of fields 1..12 ONLY: same
        // body bytes (unchanged, since entries are laid out sequentially
        // with no gaps) but with a map header declaring 12 entries instead
        // of 13, and without field 13's bytes at all.
        val unsignedHeader = mapHeaderBytes(UNSIGNED_FIELD_COUNT)
        val message = unsignedHeader + cborBytes.copyOfRange(bodyStart, signatureStart)

        return DecodedQrPayload(
            passId = pid,
            orgId = oid,
            visitorName = vname,
            messageBytes = message,
            signatureBytes = sigBytes
        )
    }

    // ── Base64 (URL-safe, no padding) ─────────────────────────────────────

    fun base64UrlEncode(bytes: ByteArray): String {
        val sb = StringBuilder((bytes.size * 4 + 2) / 3)
        var i = 0
        while (i < bytes.size) {
            val b0 = bytes[i].toInt() and 0xFF
            val b1 = if (i + 1 < bytes.size) bytes[i + 1].toInt() and 0xFF else 0
            val b2 = if (i + 2 < bytes.size) bytes[i + 2].toInt() and 0xFF else 0
            val triple = (b0 shl 16) or (b1 shl 8) or b2

            sb.append(BASE64URL_ALPHABET[(triple shr 18) and 0x3F])
            sb.append(BASE64URL_ALPHABET[(triple shr 12) and 0x3F])
            if (i + 1 < bytes.size) sb.append(BASE64URL_ALPHABET[(triple shr 6) and 0x3F])
            if (i + 2 < bytes.size) sb.append(BASE64URL_ALPHABET[triple and 0x3F])
            i += 3
        }
        return sb.toString()
    }

    fun base64UrlDecode(encoded: String): ByteArray {
        val cleaned = encoded.trimEnd('=')
        val out = ArrayList<Byte>((cleaned.length * 3) / 4 + 3)
        var buffer = 0
        var bitsCollected = 0
        for (c in cleaned) {
            val value = BASE64URL_ALPHABET.indexOf(c)
            if (value < 0) throw MalformedQrException("invalid base64url character: $c")
            buffer = (buffer shl 6) or value
            bitsCollected += 6
            if (bitsCollected >= 8) {
                bitsCollected -= 8
                out.add(((buffer shr bitsCollected) and 0xFF).toByte())
            }
        }
        return out.toByteArray()
    }

    // ── Minimal CBOR primitives (read) ────────────────────────────────────

    /** Returns (entryCount, headerByteLength) for a CBOR map at `offset`. */
    private fun readMapHeader(bytes: ByteArray, offset: Int): Pair<Int, Int> {
        val first = bytes[offset].toInt() and 0xFF
        val majorType = first ushr 5
        if (majorType != 5) throw MalformedQrException("expected a CBOR map (major type 5), got major type $majorType")
        val (count, len) = readAdditionalInfo(bytes, offset)
        return count.toInt() to len
    }

    /** Returns (value, byteLength) for a CBOR unsigned integer (major type 0) at `offset`. */
    private fun readUint(bytes: ByteArray, offset: Int): Pair<Long, Int> {
        val majorType = (bytes[offset].toInt() and 0xFF) ushr 5
        if (majorType != 0) throw MalformedQrException("expected a CBOR uint (major type 0), got major type $majorType")
        return readAdditionalInfo(bytes, offset)
    }

    /** Decodes the "additional info" trailing a major-type byte: direct value (0-23) or 1/2/4/8-byte follow-on. */
    private fun readAdditionalInfo(bytes: ByteArray, offset: Int): Pair<Long, Int> {
        val first = bytes[offset].toInt() and 0xFF
        val info = first and 0x1F
        return when {
            info < 24 -> info.toLong() to 1
            info == 24 -> (bytes[offset + 1].toInt() and 0xFF).toLong() to 2
            info == 25 -> beBytesToLong(bytes, offset + 1, 2) to 3
            info == 26 -> beBytesToLong(bytes, offset + 1, 4) to 5
            info == 27 -> beBytesToLong(bytes, offset + 1, 8) to 9
            else -> throw MalformedQrException("unsupported CBOR additional info: $info")
        }
    }

    private fun beBytesToLong(bytes: ByteArray, offset: Int, len: Int): Long {
        var result = 0L
        for (i in 0 until len) {
            result = (result shl 8) or (bytes[offset + i].toLong() and 0xFF)
        }
        return result
    }

    /** Returns (bytes, totalByteLength incl. header) for a CBOR byte string (major type 2) at `offset`. */
    private fun readByteString(bytes: ByteArray, offset: Int): Pair<ByteArray, Int> {
        val majorType = (bytes[offset].toInt() and 0xFF) ushr 5
        if (majorType != 2) throw MalformedQrException("expected a CBOR byte string (major type 2), got major type $majorType")
        val (len, headerLen) = readAdditionalInfo(bytes, offset)
        val dataStart = offset + headerLen
        return bytes.copyOfRange(dataStart, dataStart + len.toInt()) to (headerLen + len.toInt())
    }

    /** Returns (text, totalByteLength incl. header) for a CBOR text string (major type 3) at `offset`. */
    private fun readTextString(bytes: ByteArray, offset: Int): Pair<String, Int> {
        val majorType = (bytes[offset].toInt() and 0xFF) ushr 5
        if (majorType != 3) throw MalformedQrException("expected a CBOR text string (major type 3), got major type $majorType")
        val (len, headerLen) = readAdditionalInfo(bytes, offset)
        val dataStart = offset + headerLen
        val text = bytes.copyOfRange(dataStart, dataStart + len.toInt()).decodeToString()
        return text to (headerLen + len.toInt())
    }

    /** Skips one CBOR data item of any type used in this schema; returns its byte length. */
    private fun skipItem(bytes: ByteArray, offset: Int): Int {
        val first = bytes[offset].toInt() and 0xFF
        val majorType = first ushr 5
        val info = first and 0x1F
        return when (majorType) {
            0 -> readAdditionalInfo(bytes, offset).second // uint
            2 -> readByteString(bytes, offset).second     // bstr
            3 -> readTextString(bytes, offset).second      // tstr
            4 -> { // array: skip `count` sub-items
                val (count, headerLen) = readAdditionalInfo(bytes, offset)
                var consumed = headerLen
                repeat(count.toInt()) { consumed += skipItem(bytes, offset + consumed) }
                consumed
            }
            7 -> when (info) { // null/bool/simple -- single byte, no follow-on in this schema
                20, 21, 22, 23 -> 1
                else -> throw MalformedQrException("unsupported CBOR simple value: $info")
            }
            else -> throw MalformedQrException("unsupported CBOR major type: $majorType")
        }
    }

    // ── Minimal CBOR primitives (write) -- used by production for the
    // unsigned-message header, and by tests to build fixture payloads ──────

    fun mapHeaderBytes(entryCount: Int): ByteArray {
        require(entryCount in 0..23) { "this codec only supports small maps (<=23 entries)" }
        return byteArrayOf((0xA0 or entryCount).toByte())
    }

    fun uintBytes(key: Int): ByteArray {
        require(key in 0..23) { "this codec only supports small immediate uints (<=23)" }
        return byteArrayOf(key.toByte())
    }

    /** General-purpose CBOR unsigned integer VALUE encoder (unlike [uintBytes], not limited to small keys). */
    fun uintValueBytes(value: Long): ByteArray {
        require(value >= 0) { "CBOR uints must be non-negative" }
        return when {
            value < 24 -> byteArrayOf(value.toByte())
            value < 256 -> byteArrayOf(0x18.toByte(), value.toByte())
            value < 65536 -> byteArrayOf(0x19.toByte(), (value ushr 8).toByte(), value.toByte())
            value < 4294967296L -> byteArrayOf(
                0x1A.toByte(),
                (value ushr 24).toByte(), (value ushr 16).toByte(), (value ushr 8).toByte(), value.toByte()
            )
            else -> byteArrayOf(
                0x1B.toByte(),
                (value ushr 56).toByte(), (value ushr 48).toByte(), (value ushr 40).toByte(), (value ushr 32).toByte(),
                (value ushr 24).toByte(), (value ushr 16).toByte(), (value ushr 8).toByte(), value.toByte()
            )
        }
    }

    fun byteStringBytes(value: ByteArray): ByteArray {
        val header = when {
            value.size < 24 -> byteArrayOf((0x40 or value.size).toByte())
            value.size < 256 -> byteArrayOf(0x58.toByte(), value.size.toByte())
            else -> throw IllegalArgumentException("fixture byte strings over 255 bytes are not supported")
        }
        return header + value
    }

    fun textStringBytes(value: String): ByteArray {
        val utf8 = value.encodeToByteArray()
        val header = when {
            utf8.size < 24 -> byteArrayOf((0x60 or utf8.size).toByte())
            utf8.size < 256 -> byteArrayOf(0x78.toByte(), utf8.size.toByte())
            else -> throw IllegalArgumentException("fixture text strings over 255 bytes are not supported")
        }
        return header + utf8
    }

    val NULL_BYTES: ByteArray = byteArrayOf(0xF6.toByte())

    /** Encodes a CBOR array (major type 4) of already-encoded item byte strings. */
    fun arrayBytes(items: List<ByteArray>): ByteArray {
        require(items.size < 24) { "this codec only supports small arrays (<24 items)" }
        val header = byteArrayOf((0x80 or items.size).toByte())
        return items.fold(header) { acc, item -> acc + item }
    }

    fun uuidStringToBytes(uuid: String): ByteArray {
        val hex = uuid.replace("-", "")
        require(hex.length == 32) { "not a valid UUID string: $uuid" }
        return ByteArray(16) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    }

    private fun bytesToUuidString(bytes: ByteArray): String {
        require(bytes.size == 16) { "expected a 16-byte UUID, got ${bytes.size} bytes" }
        val hex = bytes.joinToString("") { b -> (b.toInt() and 0xFF).toString(16).padStart(2, '0') }
        return "${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20, 32)}"
    }
}
