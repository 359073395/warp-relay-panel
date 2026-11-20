package com.starbridge.panel

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.ServerSocket

object XrayBridge {
    private fun pickFreePort(): Int {
        ServerSocket(0).use { return it.localPort }
    }

    fun shouldBridgeViaXray(proxy: Map<String, Any?>, hasXray: Boolean): Boolean {
        if (!hasXray) return false
        if (NodeParser.isXrayOnlyNode(proxy)) return true
        val ptype = proxy["type"]?.toString()?.lowercase() ?: ""
        val net = proxy["network"]?.toString()?.lowercase() ?: ""
        if (ptype == "vless" && (proxy.containsKey("reality-opts") || net == "xhttp")) return true
        return false
    }

    fun stripInternalFields(proxy: Map<String, Any?>): LinkedHashMap<String, Any?> {
        val clean = LinkedHashMap<String, Any?>()
        for ((k, v) in proxy) {
            if (!k.startsWith("_")) clean[k] = v
        }
        return clean
    }

    private fun buildStreamSettings(proxy: Map<String, Any?>): JSONObject {
        val net = proxy["network"]?.toString()?.lowercase() ?: "tcp"
        val ss = JSONObject().put("network", if (net == "xhttp") "splithttp" else net)

        val realityOpts = proxy["reality-opts"] as? Map<*, *>
        val isTls = proxy["tls"] == true || proxy["type"] == "trojan" || realityOpts != null
        if (realityOpts != null) {
            ss.put("security", "reality")
            val r = JSONObject()
                .put("show", false)
                .put("fingerprint", proxy["client-fingerprint"]?.toString() ?: "chrome")
                .put("serverName", proxy["servername"]?.toString() ?: proxy["server"]?.toString() ?: "")
                .put("publicKey", realityOpts["public-key"]?.toString() ?: "")
                .put("shortId", realityOpts["short-id"]?.toString() ?: "")
                .put("spiderX", realityOpts["spider-x"]?.toString() ?: "/")
            ss.put("realitySettings", r)
        } else if (isTls) {
            ss.put("security", "tls")
            val tls = JSONObject()
                .put("allowInsecure", proxy["skip-cert-verify"] == true)
            val sni = proxy["servername"]?.toString() ?: proxy["sni"]?.toString()
            if (!sni.isNullOrEmpty()) tls.put("serverName", sni)
            proxy["client-fingerprint"]?.toString()?.takeIf { it.isNotEmpty() }?.let { tls.put("fingerprint", it) }
            (proxy["alpn"] as? List<*>)?.let { tls.put("alpn", JSONArray(it)) }
            ss.put("tlsSettings", tls)
        }

        when (net) {
            "ws" -> {
                val opts = proxy["ws-opts"] as? Map<*, *>
                val ws = JSONObject().put("path", opts?.get("path")?.toString() ?: "/")
                val headers = opts?.get("headers") as? Map<*, *>
                headers?.get("Host")?.toString()?.takeIf { it.isNotEmpty() }?.let {
                    ws.put("headers", JSONObject().put("Host", it))
                }
                if (opts?.get("v2ray-http-upgrade") == true) {
                    ss.put("network", "httpupgrade")
                    ss.put("httpupgradeSettings", ws)
                } else {
                    ss.put("wsSettings", ws)
                }
            }
            "grpc" -> {
                val opts = proxy["grpc-opts"] as? Map<*, *>
                ss.put("grpcSettings", JSONObject().put("serviceName", opts?.get("grpc-service-name")?.toString() ?: ""))
            }
            "xhttp" -> {
                val opts = proxy["xhttp-opts"] as? Map<*, *>
                val xo = JSONObject().put("path", opts?.get("path")?.toString() ?: "/")
                opts?.get("host")?.toString()?.takeIf { it.isNotEmpty() }?.let { xo.put("host", it) }
                opts?.get("mode")?.toString()?.takeIf { it.isNotEmpty() }?.let { xo.put("mode", it) }
                proxy["_xray_extra"]?.toString()?.takeIf { it.isNotEmpty() }?.let { extra ->
                    runCatching { xo.put("extra", JSONObject(extra)) }
                }
                ss.put("splithttpSettings", xo)
            }
            "kcp" -> {
                val kcp = JSONObject()
                proxy["_header_type"]?.toString()?.takeIf { it.isNotEmpty() }?.let {
                    kcp.put("header", JSONObject().put("type", it))
                }
                proxy["_kcp_seed_or_host"]?.toString()?.takeIf { it.isNotEmpty() }?.let { kcp.put("seed", it) }
                ss.put("kcpSettings", kcp)
            }
            "quic" -> {
                val q = JSONObject()
                    .put("security", proxy["_quic_security"]?.toString() ?: "none")
                    .put("key", proxy["_quic_key"]?.toString() ?: "")
                proxy["_header_type"]?.toString()?.takeIf { it.isNotEmpty() }?.let {
                    q.put("header", JSONObject().put("type", it))
                }
                ss.put("quicSettings", q)
            }
        }
        return ss
    }

    private fun buildOutbound(proxy: Map<String, Any?>, tag: String): JSONObject? {
        val ptype = proxy["type"]?.toString()?.lowercase() ?: return null
        val server = proxy["server"]?.toString() ?: return null
        val port = (proxy["port"] as? Number)?.toInt() ?: proxy["port"]?.toString()?.toIntOrNull() ?: return null
        val out = JSONObject().put("tag", tag)

        when (ptype) {
            "vless" -> {
                val user = JSONObject()
                    .put("id", proxy["uuid"]?.toString() ?: "")
                    .put("encryption", proxy["encryption"]?.toString() ?: "none")
                proxy["flow"]?.toString()?.takeIf { it.isNotEmpty() }?.let { user.put("flow", it) }
                val vnext = JSONArray().put(
                    JSONObject().put("address", server).put("port", port).put("users", JSONArray().put(user))
                )
                out.put("protocol", "vless")
                    .put("settings", JSONObject().put("vnext", vnext))
                    .put("streamSettings", buildStreamSettings(proxy))
            }
            "vmess" -> {
                val user = JSONObject()
                    .put("id", proxy["uuid"]?.toString() ?: "")
                    .put("alterId", (proxy["alterId"] as? Number)?.toInt() ?: 0)
                    .put("security", proxy["cipher"]?.toString() ?: "auto")
                val vnext = JSONArray().put(
                    JSONObject().put("address", server).put("port", port).put("users", JSONArray().put(user))
                )
                out.put("protocol", "vmess")
                    .put("settings", JSONObject().put("vnext", vnext))
                    .put("streamSettings", buildStreamSettings(proxy))
            }
            "trojan" -> {
                val srv = JSONObject()
                    .put("address", server).put("port", port)
                    .put("password", proxy["password"]?.toString() ?: "")
                out.put("protocol", "trojan")
                    .put("settings", JSONObject().put("servers", JSONArray().put(srv)))
                    .put("streamSettings", buildStreamSettings(proxy))
            }
            "ss" -> {
                val srv = JSONObject()
                    .put("address", server).put("port", port)
                    .put("method", proxy["cipher"]?.toString() ?: "aes-256-gcm")
                    .put("password", proxy["password"]?.toString() ?: "")
                out.put("protocol", "shadowsocks")
                    .put("settings", JSONObject().put("servers", JSONArray().put(srv)))
            }
            else -> return null
        }
        return out
    }

    data class BridgeResult(
        val mihomoProxies: List<Map<String, Any?>>,
        val xrayConfigJson: String?
    )

    fun prepare(proxies: List<Map<String, Any?>>, xrayExe: File): BridgeResult {
        val hasXray = xrayExe.isFile && xrayExe.canExecute()
        val outProxies = ArrayList<Map<String, Any?>>()
        val inbounds = JSONArray()
        val outbounds = JSONArray()
        val rules = JSONArray()

        proxies.forEachIndexed { idx, p ->
            if (shouldBridgeViaXray(p, hasXray)) {
                val tagIn = "in_$idx"
                val tagOut = "out_$idx"
                val outbound = buildOutbound(p, tagOut)
                if (outbound != null) {
                    val port = pickFreePort()
                    inbounds.put(
                        JSONObject()
                            .put("tag", tagIn)
                            .put("listen", "127.0.0.1")
                            .put("port", port)
                            .put("protocol", "socks")
                            .put("settings", JSONObject().put("udp", true))
                    )
                    outbounds.put(outbound)
                    rules.put(
                        JSONObject()
                            .put("type", "field")
                            .put("inboundTag", JSONArray().put(tagIn))
                            .put("outboundTag", tagOut)
                    )
                    val wrapper = LinkedHashMap<String, Any?>()
                    wrapper["name"] = p["name"]?.toString() ?: "xray-$idx"
                    wrapper["type"] = "socks5"
                    wrapper["server"] = "127.0.0.1"
                    wrapper["port"] = port
                    wrapper["udp"] = true
                    p["dialer-proxy"]?.let { wrapper["dialer-proxy"] = it }
                    outProxies.add(wrapper)
                    return@forEachIndexed
                }
            }
            outProxies.add(stripInternalFields(p))
        }

        if (outbounds.length() == 0) {
            return BridgeResult(outProxies, null)
        }

        val cfg = JSONObject()
            .put("log", JSONObject().put("loglevel", "warning"))
            .put("inbounds", inbounds)
            .put("outbounds", outbounds)
            .put("routing", JSONObject().put("domainStrategy", "AsIs").put("rules", rules))
        return BridgeResult(outProxies, cfg.toString(2))
    }
}
