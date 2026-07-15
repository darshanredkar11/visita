package app.visitorpass.crypto

object Base45 {
    private val ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:".toCharArray()
    private val DECODE_MAP = IntArray(256) { -1 }.apply {
        for (i in ALPHABET.indices) {
            this[ALPHABET[i].code] = i
        }
    }

    // Encodes binary data to Base45 string
    fun encode(data: ByteArray): String {
        val sb = StringBuilder()
        var i = 0
        while (i < data.size) {
            if (i + 1 < data.size) {
                // Encode 2 bytes into 3 base45 chars
                val val1 = (data[i].toInt() and 0xFF) shl 8
                val val2 = data[i + 1].toInt() and 0xFF
                val value = val1 + val2
                
                val c1 = value % 45
                val c2 = (value / 45) % 45
                val c3 = (value / 2025) % 45
                
                sb.append(ALPHABET[c1])
                sb.append(ALPHABET[c2])
                sb.append(ALPHABET[c3])
                i += 2
            } else {
                // Encode 1 remaining byte into 2 base45 chars
                val value = data[i].toInt() and 0xFF
                val c1 = value % 45
                val c2 = (value / 45) % 45
                sb.append(ALPHABET[c1])
                sb.append(ALPHABET[c2])
                i++
            }
        }
        return sb.toString()
    }

    // Decodes Base45 string to binary data
    fun decode(input: String): ByteArray {
        if (input.isEmpty()) return ByteArray(0)
        val out = ArrayList<Byte>()
        var i = 0
        while (i < input.length) {
            if (i + 2 < input.length) {
                val v1 = DECODE_MAP.getOrNull(input[i].code) ?: -1
                val v2 = DECODE_MAP.getOrNull(input[i + 1].code) ?: -1
                val v3 = DECODE_MAP.getOrNull(input[i + 2].code) ?: -1
                if (v1 == -1 || v2 == -1 || v3 == -1) throw IllegalArgumentException("Invalid Base45 character")
                
                val value = v1 + v2 * 45 + v3 * 2025
                out.add((value ushr 8).toByte())
                out.add((value and 0xFF).toByte())
                i += 3
            } else if (i + 1 < input.length) {
                val v1 = DECODE_MAP.getOrNull(input[i].code) ?: -1
                val v2 = DECODE_MAP.getOrNull(input[i + 1].code) ?: -1
                if (v1 == -1 || v2 == -1) throw IllegalArgumentException("Invalid Base45 character")
                
                val value = v1 + v2 * 45
                out.add(value.toByte())
                i += 2
            } else {
                throw IllegalArgumentException("Invalid Base45 string length")
            }
        }
        return out.toByteArray()
    }
}
