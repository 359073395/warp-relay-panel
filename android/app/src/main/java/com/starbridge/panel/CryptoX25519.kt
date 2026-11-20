package com.starbridge.panel

import android.util.Base64
import java.math.BigInteger
import java.security.SecureRandom

object CryptoX25519 {
    private val P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
    private val A24 = BigInteger.valueOf(121665)

    private fun decodeLittleEndian(bytes: ByteArray): BigInteger {
        val rev = ByteArray(bytes.size)
        for (i in bytes.indices) {
            rev[i] = bytes[bytes.size - 1 - i]
        }
        return BigInteger(1, rev)
    }

    private fun encodeLittleEndian(value: BigInteger): ByteArray {
        val mod = value.mod(P)
        val raw = mod.toByteArray()
        val out = ByteArray(32)
        // raw is big-endian, copy right-aligned into reversed little-endian 32 bytes
        var outIdx = 0
        for (i in raw.size - 1 downTo 0) {
            if (outIdx >= 32) break
            out[outIdx++] = raw[i]
        }
        return out
    }

    fun x25519(kBytes: ByteArray, uBytes: ByteArray): ByteArray {
        val kList = kBytes.copyOf(32)
        kList[0] = (kList[0].toInt() and 248).toByte()
        kList[31] = (kList[31].toInt() and 127).toByte()
        kList[31] = (kList[31].toInt() or 64).toByte()
        val k = decodeLittleEndian(kList)

        val uList = uBytes.copyOf(32)
        uList[31] = (uList[31].toInt() and 127).toByte()
        val u = decodeLittleEndian(uList).mod(P)

        val x1 = u
        var x2 = BigInteger.ONE
        var z2 = BigInteger.ZERO
        var x3 = u
        var z3 = BigInteger.ONE
        var swap = 0

        for (t in 254 downTo 0) {
            val kt = if (k.testBit(t)) 1 else 0
            swap = swap xor kt
            if (swap == 1) {
                val tx = x2; x2 = x3; x3 = tx
                val tz = z2; z2 = z3; z3 = tz
            }
            swap = kt

            val a = x2.add(z2).mod(P)
            val aa = a.multiply(a).mod(P)
            val b = x2.subtract(z2).mod(P)
            val bb = b.multiply(b).mod(P)
            val e = aa.subtract(bb).mod(P)
            val c = x3.add(z3).mod(P)
            val d = x3.subtract(z3).mod(P)
            val da = d.multiply(a).mod(P)
            val cb = c.multiply(b).mod(P)
            val sumDc = da.add(cb).mod(P)
            val diffDc = da.subtract(cb).mod(P)
            x3 = sumDc.multiply(sumDc).mod(P)
            z3 = x1.multiply(diffDc.multiply(diffDc).mod(P)).mod(P)
            x2 = aa.multiply(bb).mod(P)
            z2 = e.multiply(aa.add(A24.multiply(e)).mod(P)).mod(P)
        }

        val res = finishLadder(swap, x2, x3, z2, z3)
        return encodeLittleEndian(res)
    }

    private fun finishLadder(swap: Int, x2Init: BigInteger, x3Init: BigInteger, z2Init: BigInteger, z3Init: BigInteger): BigInteger {
        var x2 = x2Init
        var x3 = x3Init
        var z2 = z2Init
        var z3 = z3Init
        if (swap == 1) {
            val tx = x2; x2 = x3; x3 = tx
            val tz = z2; z2 = z3; z3 = tz
        }
        return x2.multiply(z2.modPow(P.subtract(BigInteger.valueOf(2)), P)).mod(P)
    }

    fun generateWgKeypair(): Pair<String, String> {
        val rng = SecureRandom()
        val priv = ByteArray(32)
        rng.nextBytes(priv)
        priv[0] = (priv[0].toInt() and 248).toByte()
        priv[31] = (priv[31].toInt() and 127).toByte()
        priv[31] = (priv[31].toInt() or 64).toByte()

        val base = ByteArray(32)
        base[0] = 9
        val pub = x25519(priv, base)
        return Pair(
            Base64.encodeToString(priv, Base64.NO_WRAP),
            Base64.encodeToString(pub, Base64.NO_WRAP)
        )
    }
}
