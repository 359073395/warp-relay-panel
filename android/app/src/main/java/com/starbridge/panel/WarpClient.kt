package com.starbridge.panel

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit
import kotlin.random.Random

object WarpClient {
    private const val DEFAULT_WARP_PUBKEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
    private const val AWG_I1_DEFAULT = "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>"

    private val WARP_PREFIXES = listOf(
        "162.159.192", "162.159.195",
        "188.114.96", "188.114.97", "188.114.98", "188.114.99",
        "8.6.112", "8.34.70", "8.34.146", "8.35.211",
        "8.39.125", "8.39.204", "8.39.214", "8.47.69"
    )
    private val WARP_PORTS = listOf(2408, 500, 1701, 4500, 894, 908, 942, 1018)

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(12, TimeUnit.SECONDS)
        .writeTimeout(12, TimeUnit.SECONDS)
        .callTimeout(15, TimeUnit.SECONDS)
        .build()

    fun registerAccount(proxyPort: Int? = null): JSONObject {
        val http = if (proxyPort != null && proxyPort > 0) {
            client.newBuilder()
                .proxy(java.net.Proxy(java.net.Proxy.Type.HTTP, java.net.InetSocketAddress("127.0.0.1", proxyPort)))
                .build()
        } else {
            client
        }
        val (priv, pub) = CryptoX25519.generateWgKeypair()
        val bases = listOf(
            "https://api.cloudflareclient.com/v0a4005/reg",
            "https://edge-client-api.vercel.app/v0a4005/reg"
        )
        val jsonType = "application/json; charset=UTF-8".toMediaType()
        var lastErr: Exception? = null
        for (base in bases) {
            try {
                val regBody = JSONObject().put("key", pub).toString().toRequestBody(jsonType)
                val req = Request.Builder()
                    .url(base)
                    .post(regBody)
                    .header("CF-Client-Version", "a-6.11-2223")
                    .header("User-Agent", "okhttp/3.12.1")
                    .build()
                val regText = http.newCall(req).execute().use { resp ->
                    if (!resp.isSuccessful) error("HTTP ${resp.code}")
                    resp.body?.string() ?: error("Empty response")
                }
                val reg = JSONObject(regText)
                val accId = reg.getString("id")
                val token = reg.getString("token")

                val patchBody = JSONObject().put("warp_enabled", true).toString().toRequestBody(jsonType)
                val patchReq = Request.Builder()
                    .url("$base/$accId")
                    .patch(patchBody)
                    .header("Authorization", "Bearer $token")
                    .header("CF-Client-Version", "a-6.11-2223")
                    .header("User-Agent", "okhttp/3.12.1")
                    .build()
                runCatching { http.newCall(patchReq).execute().close() }

                val cfg = reg.optJSONObject("config") ?: JSONObject()
                val peers = cfg.optJSONArray("peers")
                val peerPub = if (peers != null && peers.length() > 0) {
                    peers.getJSONObject(0).optString("public_key", DEFAULT_WARP_PUBKEY)
                } else DEFAULT_WARP_PUBKEY
                val addrs = cfg.optJSONObject("interface")?.optJSONObject("addresses") ?: JSONObject()
                return JSONObject()
                    .put("id", accId)
                    .put("token", token)
                    .put("private_key", priv)
                    .put("peer_public_key", peerPub)
                    .put("ipv4", addrs.optString("v4", "172.16.0.2"))
                    .put("ipv6", addrs.optString("v6", ""))
            } catch (e: Exception) {
                lastErr = e
            }
        }
        throw RuntimeException("WARP 账号注册失败: ${lastErr?.message}")
    }

    fun sampleEndpoints(count: Int = 12): List<JSONObject> {
        val out = ArrayList<JSONObject>()
        val seen = HashSet<String>()
        var guard = 0
        while (out.size < count && guard < count * 20) {
            guard++
            val prefix = WARP_PREFIXES[Random.nextInt(WARP_PREFIXES.size)]
            val host = "$prefix.${Random.nextInt(1, 255)}"
            val port = WARP_PORTS[Random.nextInt(WARP_PORTS.size)]
            val key = "$host:$port"
            if (seen.add(key)) {
                out.add(
                    JSONObject()
                        .put("ip", host)
                        .put("port", port)
                        .put("delay_ms", JSONObject.NULL)
                        .put("speed_mbps", JSONObject.NULL)
                )
            }
        }
        return out
    }

    fun buildWarpProxies(
        account: JSONObject,
        endpoints: List<JSONObject>,
        useAwg: Boolean
    ): List<Map<String, Any?>> {
        val priv = account.optString("private_key")
        if (priv.isBlank()) return emptyList()
        val peerPub = account.optString("peer_public_key", DEFAULT_WARP_PUBKEY)
        val ipv4 = account.optString("ipv4", "172.16.0.2")
        val jc = Random.nextInt(4, 7)
        val jmin = Random.nextInt(15, 36)
        val jmax = jmin + Random.nextInt(25, 61)

        val list = ArrayList<Map<String, Any?>>()
        endpoints.forEachIndexed { idx, ep ->
            val name = "WARP-${if (useAwg) "AWG" else "WG"}-${(idx + 1).toString().padStart(2, '0')}"
            val p = LinkedHashMap<String, Any?>()
            p["name"] = name
            p["type"] = "wireguard"
            p["private-key"] = priv
            p["ip"] = ipv4
            p["peers"] = listOf(
                mapOf(
                    "server" to ep.getString("ip"),
                    "port" to ep.getInt("port"),
                    "public-key" to peerPub,
                    "allowed-ips" to listOf("0.0.0.0/0"),
                    "persistent-keepalive" to 25
                )
            )
            p["mtu"] = 1280
            p["udp"] = true
            p["remote-dns-resolve"] = true
            p["dns"] = listOf("1.1.1.1", "1.0.0.1", "8.8.8.8")
            if (useAwg) {
                p["amnezia-wg-option"] = mapOf(
                    "jc" to jc,
                    "jmin" to jmin,
                    "jmax" to jmax,
                    "s1" to 0,
                    "s2" to 0,
                    "h1" to 1,
                    "h2" to 2,
                    "h3" to 3,
                    "h4" to 4,
                    "i1" to AWG_I1_DEFAULT
                )
            }
            list.add(p)
        }
        return list
    }
}
