package com.starbridge.panel

import android.util.Base64
import org.json.JSONObject
import org.yaml.snakeyaml.Yaml
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

object NodeParser {
    private val SKIP_TYPES = setOf("direct", "reject", "reject-drop", "pass", "dns", "compatible")

    private fun b64DecodeStr(raw: String): String {
        val clean = raw.trim().replace('-', '+').replace('_', '/')
        val pad = (4 - clean.length % 4) % 4
        val padded = clean + "=".repeat(pad)
        return String(Base64.decode(padded, Base64.DEFAULT), StandardCharsets.UTF_8)
    }

    private fun urlDecode(s: String?): String {
        if (s.isNullOrEmpty()) return ""
        return try {
            URLDecoder.decode(s, "UTF-8")
        } catch (_: Exception) {
            s
        }
    }

    private fun parseQuery(query: String?): Map<String, String> {
        val map = LinkedHashMap<String, String>()
        if (query.isNullOrEmpty()) return map
        for (pair in query.split('&')) {
            if (pair.isEmpty()) continue
            val idx = pair.indexOf('=')
            val k = if (idx >= 0) urlDecode(pair.substring(0, idx)).lowercase() else urlDecode(pair).lowercase()
            val v = if (idx >= 0) urlDecode(pair.substring(idx + 1)) else ""
            map[k] = v
        }
        return map
    }

    private fun isTruth(v: String?): Boolean {
        return v?.trim()?.lowercase() in setOf("1", "true", "yes", "on")
    }

    private fun safePort(port: Int, rawUrl: String): Int {
        if (port in 1..65535) return port
        val m = Regex(":(\\d+)(?:[/?#]|$)").find(rawUrl)
        return m?.groupValues?.getOrNull(1)?.toIntOrNull() ?: 443
    }

    fun isXrayOnlyNode(proxy: Map<String, Any?>): Boolean {
        val ptype = proxy["type"]?.toString()?.lowercase() ?: ""
        val net = proxy["network"]?.toString()?.lowercase() ?: ""
        if (net == "kcp" || net == "quic") return true
        if (net == "xhttp" && proxy.containsKey("_xray_extra")) return true
        val enc = proxy["encryption"]?.toString()?.lowercase() ?: ""
        if (ptype == "vless" && enc.isNotEmpty() && enc != "none") return true
        return false
    }

    fun parseResidentialLine(line: String, remark: String = "", defaultType: String = "socks5"): Map<String, Any?>? {
        val clean = line.trim()
        if (clean.isEmpty() || clean.startsWith("#")) return null
        if ("://" in clean) {
            return parseProxyUri(clean)
        }
        var label = remark.trim()
        var body = clean
        if ("#" in body) {
            val idx = body.indexOf('#')
            val tail = body.substring(idx + 1).trim()
            body = body.substring(0, idx).trim()
            if (label.isEmpty()) label = tail
        }
        val parts = body.split(':')
        val server: String
        val port: Int
        var user = ""
        var pass = ""
        when {
            "@" in body -> {
                val at = body.lastIndexOf('@')
                val creds = body.substring(0, at)
                val hp = body.substring(at + 1)
                val hpParts = hp.split(':')
                if (hpParts.size != 2) return null
                server = hpParts[0]
                port = hpParts[1].toIntOrNull() ?: return null
                if (":" in creds) {
                    val cIdx = creds.indexOf(':')
                    user = creds.substring(0, cIdx)
                    pass = creds.substring(cIdx + 1)
                } else {
                    user = creds
                }
            }
            parts.size == 4 -> {
                server = parts[0]
                port = parts[1].toIntOrNull() ?: return null
                user = parts[2]
                pass = parts[3]
            }
            parts.size == 2 -> {
                server = parts[0]
                port = parts[1].toIntOrNull() ?: return null
            }
            else -> return null
        }
        val out = LinkedHashMap<String, Any?>()
        out["name"] = if (label.isNotEmpty()) label else "住宅-$server:$port"
        out["type"] = if (defaultType.lowercase() == "http") "http" else "socks5"
        out["server"] = server
        out["port"] = port
        out["udp"] = true
        if (user.isNotEmpty()) {
            out["username"] = user
            out["password"] = pass
        }
        return out
    }

    fun parseProxyUri(rawUrl: String): Map<String, Any?>? {
        val url = rawUrl.trim()
        if (!url.contains("://")) return null
        val scheme = url.substringBefore("://").lowercase()
        return when (scheme) {
            "vmess" -> parseVmess(url)
            "vless" -> parseVless(url)
            "trojan" -> parseTrojan(url)
            "ss" -> parseSs(url)
            "hy2", "hysteria2" -> parseHy2(url)
            "tuic" -> parseTuic(url)
            "anytls" -> parseAnyTls(url)
            "wireguard", "wg" -> parseWireguard(url)
            "socks", "socks5", "socks4", "http", "https" -> parseSocksOrHttp(url, scheme)
            else -> null
        }
    }

    private fun parseVmess(url: String): Map<String, Any?>? {
        val payload = url.removePrefix("vmess://").trim()
        val decoded = try { b64DecodeStr(payload) } catch (_: Exception) { return null }
        val json = try { JSONObject(decoded) } catch (_: Exception) { return null }
        val server = json.optString("add")
        val port = json.optInt("port", json.optString("port").toIntOrNull() ?: 443)
        val uuid = json.optString("id")
        if (server.isEmpty() || uuid.isEmpty()) return null
        val proxy = LinkedHashMap<String, Any?>()
        proxy["name"] = json.optString("ps").ifBlank { "vmess-$server:$port" }
        proxy["type"] = "vmess"
        proxy["server"] = server
        proxy["port"] = port
        proxy["uuid"] = uuid
        proxy["alterId"] = json.optInt("aid", 0)
        proxy["cipher"] = json.optString("scy", "auto").ifBlank { "auto" }
        proxy["udp"] = true
        val tlsVal = json.optString("tls").lowercase()
        val host = json.optString("host")
        if (tlsVal in setOf("tls", "true", "1")) {
            proxy["tls"] = true
            val sni = json.optString("sni").ifBlank { host }
            if (sni.isNotEmpty()) proxy["servername"] = sni
            json.optString("fp").takeIf { it.isNotEmpty() }?.let { proxy["client-fingerprint"] = it }
            json.optString("alpn").takeIf { it.isNotEmpty() }?.let { alpn ->
                proxy["alpn"] = alpn.split(',').map { it.trim() }.filter { it.isNotEmpty() }
            }
            if (isTruth(json.optString("allowInsecure")) || isTruth(json.optString("insecure"))) {
                proxy["skip-cert-verify"] = true
            }
        }
        var net = json.optString("net", "tcp").lowercase().ifBlank { "tcp" }
        if (net == "splithttp") net = "xhttp"
        val path = json.optString("path").ifBlank { "/" }
        when (net) {
            "ws", "httpupgrade" -> {
                proxy["network"] = if (net == "ws") "ws" else "httpupgrade"
                val opts = LinkedHashMap<String, Any?>()
                opts["path"] = path
                if (host.isNotEmpty()) opts["headers"] = mapOf("Host" to host)
                proxy["ws-opts"] = opts
                if (net == "httpupgrade") {
                    proxy["network"] = "ws"
                    opts["v2ray-http-upgrade"] = true
                }
            }
            "grpc" -> {
                proxy["network"] = "grpc"
                proxy["grpc-opts"] = mapOf("grpc-service-name" to json.optString("path"))
            }
            "xhttp" -> {
                proxy["network"] = "xhttp"
                val opts = linkedMapOf<String, Any?>("path" to path)
                if (host.isNotEmpty()) opts["host"] = host
                proxy["xhttp-opts"] = opts
            }
            "kcp", "quic" -> {
                proxy["network"] = net
                if (json.optString("type").isNotEmpty()) proxy["_header_type"] = json.optString("type")
                if (host.isNotEmpty()) proxy["_kcp_seed_or_host"] = host
                if (path.isNotEmpty()) proxy["_quic_key"] = path
            }
        }
        return proxy
    }

    private fun parseVless(url: String): Map<String, Any?>? {
        val uri = try { URI(url) } catch (_: Exception) { return null }
        val server = uri.host ?: return null
        val uuid = uri.userInfo ?: return null
        val port = safePort(uri.port, url)
        val qs = parseQuery(uri.rawQuery)
        val name = urlDecode(uri.fragment).ifBlank { "vless-$server:$port" }

        val proxy = LinkedHashMap<String, Any?>()
        proxy["name"] = name
        proxy["type"] = "vless"
        proxy["server"] = server
        proxy["port"] = port
        proxy["uuid"] = uuid
        proxy["udp"] = true

        qs["encryption"]?.takeIf { it.isNotEmpty() && it != "none" }?.let { proxy["encryption"] = it }
        qs["flow"]?.takeIf { it.isNotEmpty() }?.let { proxy["flow"] = it }

        val security = (qs["security"] ?: "").lowercase()
        val sni = qs["sni"] ?: qs["peer"] ?: ""
        val fp = qs["fp"] ?: qs["fingerprint"] ?: ""
        if (security == "tls" || security == "reality") {
            proxy["tls"] = true
            if (sni.isNotEmpty()) proxy["servername"] = sni
            if (fp.isNotEmpty()) proxy["client-fingerprint"] = fp
            else if (security == "reality") proxy["client-fingerprint"] = "chrome"
        }
        if (isTruth(qs["allowinsecure"]) || isTruth(qs["insecure"])) {
            proxy["skip-cert-verify"] = true
        }
        qs["alpn"]?.takeIf { it.isNotEmpty() }?.let { alpn ->
            proxy["alpn"] = alpn.split(',').map { it.trim() }.filter { it.isNotEmpty() }
        }
        if (security == "reality") {
            val ro = LinkedHashMap<String, Any?>()
            qs["pbk"]?.takeIf { it.isNotEmpty() }?.let { ro["public-key"] = it }
            qs["sid"]?.takeIf { it.isNotEmpty() }?.let { ro["short-id"] = it }
            qs["spx"]?.takeIf { it.isNotEmpty() }?.let { ro["spider-x"] = it }
            if (ro.isNotEmpty()) proxy["reality-opts"] = ro
        }

        var net = (qs["type"] ?: "tcp").lowercase()
        if (net == "splithttp") net = "xhttp"
        val host = qs["host"] ?: ""
        val path = qs["path"] ?: "/"
        when (net) {
            "ws", "httpupgrade" -> {
                proxy["network"] = "ws"
                val opts = LinkedHashMap<String, Any?>()
                opts["path"] = path
                if (host.isNotEmpty()) opts["headers"] = mapOf("Host" to host)
                if (net == "httpupgrade") opts["v2ray-http-upgrade"] = true
                proxy["ws-opts"] = opts
            }
            "grpc" -> {
                proxy["network"] = "grpc"
                proxy["grpc-opts"] = mapOf("grpc-service-name" to (qs["servicename"] ?: ""))
            }
            "xhttp" -> {
                proxy["network"] = "xhttp"
                val opts = LinkedHashMap<String, Any?>()
                opts["path"] = path
                if (host.isNotEmpty()) opts["host"] = host
                qs["mode"]?.takeIf { it.isNotEmpty() }?.let { opts["mode"] = it }
                proxy["xhttp-opts"] = opts
                qs["extra"]?.takeIf { it.isNotEmpty() }?.let { proxy["_xray_extra"] = it }
            }
            "kcp", "quic" -> {
                proxy["network"] = net
                qs["headertype"]?.takeIf { it.isNotEmpty() }?.let { proxy["_header_type"] = it }
                qs["seed"]?.takeIf { it.isNotEmpty() }?.let { proxy["_kcp_seed_or_host"] = it }
                qs["key"]?.takeIf { it.isNotEmpty() }?.let { proxy["_quic_key"] = it }
                qs["quicsecurity"]?.takeIf { it.isNotEmpty() }?.let { proxy["_quic_security"] = it }
            }
        }
        return proxy
    }

    private fun parseTrojan(url: String): Map<String, Any?>? {
        val uri = try { URI(url) } catch (_: Exception) { return null }
        val server = uri.host ?: return null
        val pass = urlDecode(uri.userInfo)
        val port = safePort(uri.port, url)
        val qs = parseQuery(uri.rawQuery)
        val proxy = LinkedHashMap<String, Any?>()
        proxy["name"] = urlDecode(uri.fragment).ifBlank { "trojan-$server:$port" }
        proxy["type"] = "trojan"
        proxy["server"] = server
        proxy["port"] = port
        proxy["password"] = pass
        proxy["udp"] = true
        (qs["sni"] ?: qs["peer"])?.takeIf { it.isNotEmpty() }?.let { proxy["sni"] = it }
        (qs["fp"] ?: qs["fingerprint"])?.takeIf { it.isNotEmpty() }?.let { proxy["client-fingerprint"] = it }
        if (isTruth(qs["allowinsecure"]) || isTruth(qs["insecure"])) proxy["skip-cert-verify"] = true
        val net = (qs["type"] ?: "tcp").lowercase()
        if (net == "ws" || net == "httpupgrade") {
            proxy["network"] = "ws"
            val opts = linkedMapOf<String, Any?>("path" to (qs["path"] ?: "/"))
            qs["host"]?.takeIf { it.isNotEmpty() }?.let { opts["headers"] = mapOf("Host" to it) }
            if (net == "httpupgrade") opts["v2ray-http-upgrade"] = true
            proxy["ws-opts"] = opts
        } else if (net == "grpc") {
            proxy["network"] = "grpc"
            proxy["grpc-opts"] = mapOf("grpc-service-name" to (qs["servicename"] ?: ""))
        }
        return proxy
    }

    private fun parseSs(url: String): Map<String, Any?>? {
        val raw = url.removePrefix("ss://").trim()
        val namePart = if ("#" in raw) urlDecode(raw.substringAfter("#")) else ""
        val beforeHash = raw.substringBefore("#")
        val beforeQuery = beforeHash.substringBefore("?")
        val userInfoPart: String
        val serverPortPart: String
        if ("@" in beforeQuery) {
            val uRaw = beforeQuery.substringBefore("@")
            userInfoPart = if (":" in uRaw) urlDecode(uRaw) else try { b64DecodeStr(uRaw) } catch (_: Exception) { uRaw }
            serverPortPart = beforeQuery.substringAfter("@")
        } else {
            val dec = try { b64DecodeStr(beforeQuery) } catch (_: Exception) { return null }
            if ("@" !in dec) return null
            userInfoPart = dec.substringBefore("@")
            serverPortPart = dec.substringAfter("@")
        }
        if (":" !in userInfoPart || ":" !in serverPortPart) return null
        val cipher = userInfoPart.substringBefore(":")
        val password = userInfoPart.substringAfter(":")
        val server = serverPortPart.substringBeforeLast(":").trim('[', ']')
        val port = serverPortPart.substringAfterLast(":").toIntOrNull() ?: return null
        val proxy = LinkedHashMap<String, Any?>()
        proxy["name"] = namePart.ifBlank { "ss-$server:$port" }
        proxy["type"] = "ss"
        proxy["server"] = server
        proxy["port"] = port
        proxy["cipher"] = cipher
        proxy["password"] = password
        proxy["udp"] = true
        return proxy
    }

    private fun parseHy2(url: String): Map<String, Any?>? {
        val norm = if (url.startsWith("hy2://", true)) "hysteria2://" + url.substring(6) else url
        val uri = try { URI(norm) } catch (_: Exception) { return null }
        val server = uri.host ?: return null
        val port = safePort(uri.port, norm)
        val qs = parseQuery(uri.rawQuery)
        val proxy = LinkedHashMap<String, Any?>()
        proxy["name"] = urlDecode(uri.fragment).ifBlank { "hy2-$server:$port" }
        proxy["type"] = "hysteria2"
        proxy["server"] = server
        proxy["port"] = port
        proxy["password"] = urlDecode(uri.userInfo)
        qs["sni"]?.takeIf { it.isNotEmpty() }?.let { proxy["sni"] = it }
        if (isTruth(qs["insecure"]) || isTruth(qs["allowinsecure"])) proxy["skip-cert-verify"] = true
        qs["obfs"]?.takeIf { it.isNotEmpty() }?.let { proxy["obfs"] = it }
        qs["obfs-password"]?.takeIf { it.isNotEmpty() }?.let { proxy["obfs-password"] = it }
        return proxy
    }

    private fun parseTuic(url: String): Map<String, Any?>? {
        val uri = try { URI(url) } catch (_: Exception) { return null }
        val server = uri.host ?: return null
        val port = safePort(uri.port, url)
        val ui = urlDecode(uri.userInfo)
        val uuid = ui.substringBefore(":")
        val password = if (":" in ui) ui.substringAfter(":") else ""
        val qs = parseQuery(uri.rawQuery)
        val proxy = LinkedHashMap<String, Any?>()
        proxy["name"] = urlDecode(uri.fragment).ifBlank { "tuic-$server:$port" }
        proxy["type"] = "tuic"
        proxy["server"] = server
        proxy["port"] = port
        proxy["uuid"] = uuid
        if (password.isNotEmpty()) proxy["password"] = password
        proxy["congestion-controller"] = qs["congestion_control"] ?: "bbr"
        proxy["udp-relay-mode"] = qs["udp_relay_mode"] ?: "native"
        qs["sni"]?.takeIf { it.isNotEmpty() }?.let { proxy["sni"] = it }
        if (isTruth(qs["allow_insecure"]) || isTruth(qs["insecure"])) proxy["skip-cert-verify"] = true
        return proxy
    }

    private fun parseAnyTls(url: String): Map<String, Any?>? {
        val uri = try { URI(url) } catch (_: Exception) { return null }
        val server = uri.host ?: return null
        val port = safePort(uri.port, url)
        val qs = parseQuery(uri.rawQuery)
        val proxy = LinkedHashMap<String, Any?>()
        proxy["name"] = urlDecode(uri.fragment).ifBlank { "anytls-$server:$port" }
        proxy["type"] = "anytls"
        proxy["server"] = server
        proxy["port"] = port
        proxy["password"] = urlDecode(uri.userInfo)
        proxy["udp"] = true
        qs["sni"]?.takeIf { it.isNotEmpty() }?.let { proxy["sni"] = it }
        (qs["fp"] ?: qs["fingerprint"])?.takeIf { it.isNotEmpty() }?.let { proxy["client-fingerprint"] = it }
        if (isTruth(qs["insecure"]) || isTruth(qs["allowinsecure"])) proxy["skip-cert-verify"] = true
        return proxy
    }

    private fun parseWireguard(url: String): Map<String, Any?>? {
        val norm = "wireguard://" + url.substringAfter("://")
        val uri = try { URI(norm) } catch (_: Exception) { return null }
        val server = uri.host ?: return null
        val priv = urlDecode(uri.userInfo)
        if (priv.isBlank()) return null
        val port = safePort(uri.port, norm)
        val qs = parseQuery(uri.rawQuery)
        val addrRaw = qs["address"] ?: "172.16.0.2/32"
        val ipv4 = addrRaw.split(',')[0].substringBefore('/').trim().ifBlank { "172.16.0.2" }

        val peer = LinkedHashMap<String, Any?>()
        peer["server"] = server
        peer["port"] = port
        peer["public-key"] = urlDecode(qs["publickey"] ?: qs["pbk"])
        peer["allowed-ips"] = listOf("0.0.0.0/0")
        (qs["presharedkey"] ?: qs["psk"])?.takeIf { it.isNotEmpty() }?.let { peer["pre-shared-key"] = urlDecode(it) }
        qs["reserved"]?.takeIf { it.isNotEmpty() }?.let { resRaw ->
            val parts = resRaw.split(',').mapNotNull { it.trim().toIntOrNull() }
            if (parts.isNotEmpty()) peer["reserved"] = parts
        }

        val proxy = LinkedHashMap<String, Any?>()
        proxy["name"] = urlDecode(uri.fragment).ifBlank { "wg-$server" }
        proxy["type"] = "wireguard"
        proxy["private-key"] = priv
        proxy["ip"] = ipv4
        proxy["peers"] = listOf(peer)
        proxy["mtu"] = qs["mtu"]?.toIntOrNull() ?: 1280
        proxy["udp"] = true
        return proxy
    }

    private fun parseSocksOrHttp(url: String, scheme: String): Map<String, Any?>? {
        val uri = try { URI(url) } catch (_: Exception) { return null }
        val server = uri.host ?: return null
        val port = safePort(uri.port, url)
        val proxy = LinkedHashMap<String, Any?>()
        proxy["name"] = urlDecode(uri.fragment).ifBlank { "$scheme-$server:$port" }
        proxy["type"] = when {
            scheme.startsWith("socks") -> "socks5"
            scheme == "https" -> "http"
            else -> "http"
        }
        proxy["server"] = server
        proxy["port"] = port
        proxy["udp"] = true
        if (scheme == "https") proxy["tls"] = true
        val ui = uri.userInfo
        if (!ui.isNullOrEmpty()) {
            if (":" in ui) {
                proxy["username"] = urlDecode(ui.substringBefore(":"))
                proxy["password"] = urlDecode(ui.substringAfter(":"))
            } else {
                proxy["username"] = urlDecode(ui)
            }
        }
        return proxy
    }

    @Suppress("UNCHECKED_CAST")
    fun parseSubscriptionContent(rawText: String): List<Map<String, Any?>> {
        val text = rawText.trim()
        if (text.isEmpty()) return emptyList()

        // Try Clash YAML first
        if ("proxies:" in text) {
            try {
                val parsed = Yaml().load<Any>(text)
                if (parsed is Map<*, *>) {
                    val proxies = parsed["proxies"] as? List<*>
                    if (proxies != null) {
                        val out = ArrayList<Map<String, Any?>>()
                        for (item in proxies) {
                            if (item is Map<*, *>) {
                                val ptype = item["type"]?.toString()?.lowercase() ?: ""
                                if (ptype.isNotEmpty() && ptype !in SKIP_TYPES && item["server"] != null) {
                                    val copy = LinkedHashMap<String, Any?>()
                                    for ((k, v) in item) {
                                        if (k != null) copy[k.toString()] = v
                                    }
                                    out.add(copy)
                                }
                            }
                        }
                        if (out.isNotEmpty()) return out
                    }
                }
            } catch (_: Exception) {
            }
        }

        // Plain URI lines or Base64 encoded lines
        val expanded = if ("://" !in text) {
            try { b64DecodeStr(text) } catch (_: Exception) { text }
        } else text

        val result = ArrayList<Map<String, Any?>>()
        for (line in expanded.lines()) {
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#")) continue
            parseProxyUri(trimmed)?.let { result.add(it) }
        }
        return result
    }
}
