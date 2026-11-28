package com.starbridge.panel

import android.util.Base64
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.util.Locale
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

object VpnGate {
    private val VPNGATE_API_URLS = listOf(
        "https://www.vpngate.net/api/iphone/",
        "http://www.vpngate.net/api/iphone/"
    )
    private const val IP_API_BATCH_URL =
        "http://ip-api.com/batch?fields=status,countryCode,isp,org,as,mobile,proxy,hosting,query"
    private const val IPWHO_ENDPOINT = "https://ipwho.is/"

    private val PRIORITY_WESTERN_COUNTRIES = setOf(
        "US", "CA", "GB", "UK", "DE", "FR", "NL", "CH", "SE", "IT",
        "ES", "AU", "NZ", "IE", "AT", "BE", "NO", "FI", "PL", "RO", "CZ"
    )

    private val HARD_DC_ASNS = setOf(
        16509, 14618, 15169, 396982, 8075, 13335, 14061, 20473, 63949, 16276,
        24940, 51167, 9009, 36352, 53667, 29802, 40676, 46844, 62240
    )

    private val RESIDENTIAL_BRANDS = listOf(
        "korea telecom", "kt corporation", "sk broadband", "skb-as-kr", "lg u+", "lgu+", "lg uplus",
        "softbank", "kddi", "comcast", "charter", "spectrum", "frontier", "fidium",
        "consolidated communications", "so-net", "sony network communications", "jcom",
        "chubu telecommunications", "commufa", "ctcx", "asahi net", "asahi-net", "ocn",
        "ntt-me", "wakwak", "xephion", "rostelecom", "er-telecom", "wave broadband",
        "lg powercomm", "powervis", "lg hellovision", "hellovision", "cjckn",
        "biglobe", "plala", "nifty", "@nifty", "orange", "etisalat", "arteria",
        "hawaiian telcom", "tt dotcom", "ttnet"
    )

    private val DC_KEYWORDS = listOf(
        "hosting", "cloud", "server", "datacenter", "data center", "data-centre", "colocation",
        " vps", "vps ", "dedicated", " idc", "amazon", "google llc", "microsoft", "oracle",
        "digitalocean", "linode", "vultr", "hetzner", "ovh", "contabo", "alibaba", "tencent",
        "cloudflare", "choopa", "leaseweb", "m247", "psychz", "quadranet", "colocrossing"
    )

    private val COUNTRY_FLAGS = mapOf(
        "JP" to "\uD83C\uDDEF\uD83C\uDDF5",
        "KR" to "\uD83C\uDDF0\uD83C\uDDF7",
        "US" to "\uD83C\uDDFA\uD83C\uDDF8",
        "TW" to "\uD83C\uDDF9\uD83C\uDDFC",
        "HK" to "\uD83C\uDDED\uD83C\uDDF0",
        "SG" to "\uD83C\uDDF8\uD83C\uDDEC",
        "GB" to "\uD83C\uDDEC\uD83C\uDDE7",
        "UK" to "\uD83C\uDDEC\uD83C\uDDE7",
        "DE" to "\uD83C\uDDE9\uD83C\uDDEA",
        "FR" to "\uD83C\uDDEB\uD83C\uDDF7",
        "CA" to "\uD83C\uDDE8\uD83C\uDDE6",
        "AU" to "\uD83C\uDDE6\uD83C\uDDFA",
        "NL" to "\uD83C\uDDF3\uD83C\uDDF1",
        "TH" to "\uD83C\uDDF9\uD83C\uDDED",
        "VN" to "\uD83C\uDDFB\uD83C\uDDF3",
        "ID" to "\uD83C\uDDEE\uD83C\uDDE9",
        "IN" to "\uD83C\uDDEE\uD83C\uDDF3",
        "BR" to "\uD83C\uDDE7\uD83C\uDDF7",
        "RU" to "\uD83C\uDDF7\uD83C\uDDFA",
        "RO" to "\uD83C\uDDF7\uD83C\uDDF4",
        "CH" to "\uD83C\uDDE8\uD83C\uDDED",
        "SE" to "\uD83C\uDDF8\uD83C\uDDEA",
        "IT" to "\uD83C\uDDEE\uD83C\uDDF9",
        "ES" to "\uD83C\uDDEA\uD83C\uDDF8",
        "PL" to "\uD83C\uDDF5\uD83C\uDDF1",
        "NO" to "\uD83C\uDDF3\uD83C\uDDF4",
        "FI" to "\uD83C\uDDEB\uD83C\uDDEE",
        "UA" to "\uD83C\uDDFA\uD83C\uDDE6",
        "NZ" to "\uD83C\uDDF3\uD83C\uDDFF",
        "IE" to "\uD83C\uDDEE\uD83C\uDDEA",
        "AT" to "\uD83C\uDDE6\uD83C\uDDF9",
        "BE" to "\uD83C\uDDE7\uD83C\uDDEA",
        "CZ" to "\uD83C\uDDE8\uD83C\uDDFF"
    )

    private fun parseAsn(asStr: String): Int {
        val s = asStr.trim().uppercase(Locale.US)
        if (!s.startsWith("AS")) return 0
        val sb = StringBuilder()
        for (i in 2 until s.length) {
            val ch = s[i]
            if (ch.isDigit()) sb.append(ch) else break
        }
        return sb.toString().toIntOrNull() ?: 0
    }

    fun parseOvpnProfile(rawText: String): JSONObject? {
        val blocks = HashMap<String, String>()
        var curTag = ""
        val buf = StringBuilder()
        val prof = JSONObject()
            .put("proto", "tcp")
            .put("dev", "tun")

        for (rawLine in rawText.lines()) {
            val line = rawLine.trim()
            if (line.isEmpty() || line.startsWith("#") || line.startsWith(";")) continue
            if (line.startsWith("<") && line.endsWith(">") && !line.startsWith("</")) {
                curTag = line.substring(1, line.length - 1).trim().lowercase(Locale.US)
                buf.setLength(0)
                continue
            }
            if (line.startsWith("</")) {
                if (curTag.isNotEmpty()) {
                    blocks[curTag] = buf.toString()
                }
                curTag = ""
                continue
            }
            if (curTag.isNotEmpty()) {
                buf.append(line).append('\n')
                continue
            }

            val parts = line.split(Regex("\\s+")).filter { it.isNotEmpty() }
            if (parts.isEmpty()) continue
            when (parts[0].lowercase(Locale.US)) {
                "remote" -> if (parts.size >= 3 && !prof.has("server")) {
                    val port = parts[2].toIntOrNull()
                    if (port != null) {
                        prof.put("server", parts[1])
                        prof.put("port", port)
                    }
                }
                "proto" -> if (parts.size >= 2) {
                    prof.put("proto", if (parts[1].lowercase(Locale.US).contains("udp")) "udp" else "tcp")
                }
                "dev" -> if (parts.size >= 2) prof.put("dev", parts[1])
                "cipher" -> if (parts.size >= 2) prof.put("cipher", parts[1])
                "data-ciphers" -> if (parts.size >= 2) {
                    val arr = JSONArray()
                    parts[1].split(":").filter { it.isNotEmpty() }.forEach { arr.put(it) }
                    prof.put("data-ciphers", arr)
                }
                "auth" -> if (parts.size >= 2) prof.put("auth", parts[1])
                "key-direction" -> if (parts.size >= 2) prof.put("key-direction", parts[1])
                "comp-lzo" -> {
                    val v = if (parts.size >= 2) parts[1].lowercase(Locale.US) else "yes"
                    if (v != "no") prof.put("comp-lzo", v)
                }
                "tun-mtu", "mtu" -> if (parts.size >= 2) {
                    val mtu = parts[1].toIntOrNull()
                    if (mtu != null) prof.put("mtu", mtu)
                }
            }
        }

        if (!prof.has("server") || !prof.has("port")) return null
        for (k in listOf("ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2")) {
            blocks[k]?.let { prof.put(k, it) }
        }
        return prof
    }

    private fun parseCsvRow(line: String): List<String> {
        val out = ArrayList<String>()
        val cur = StringBuilder()
        var inQuotes = false
        var i = 0
        while (i < line.length) {
            val ch = line[i]
            if (ch == '"') {
                if (inQuotes && i + 1 < line.length && line[i + 1] == '"') {
                    cur.append('"')
                    i++
                } else {
                    inQuotes = !inQuotes
                }
            } else if (ch == ',' && !inQuotes) {
                out.add(cur.toString())
                cur.setLength(0)
            } else {
                cur.append(ch)
            }
            i++
        }
        out.add(cur.toString())
        return out
    }

    private fun classifyNode(hostName: String, info: JSONObject?): Pair<String, String> {
        if (hostName.lowercase(Locale.US).startsWith("public-vpn")) {
            return "datacenter" to "PublicVPN"
        }
        if (info == null || info.optString("status") != "success") {
            return "residential" to ""
        }
        val isp = info.optString("isp").ifBlank { info.optString("org") }.trim()
        val blob = "${info.optString("isp")} ${info.optString("org")} ${info.optString("as")}".lowercase(Locale.US)
        val asn = parseAsn(info.optString("as"))
        if (asn in HARD_DC_ASNS) {
            return "datacenter" to isp
        }

        var dcGroups = 0
        if (info.optBoolean("hosting", false)) dcGroups++
        if (DC_KEYWORDS.any { blob.contains(it) }) dcGroups++
        val isResBrand = RESIDENTIAL_BRANDS.any { blob.contains(it) } || info.optBoolean("mobile", false)
        if (dcGroups >= 2 || info.optBoolean("hosting", false) || (dcGroups >= 1 && !isResBrand)) {
            return "datacenter" to isp
        }
        return "residential" to isp
    }

    private fun selectCandidates(parsed: List<JSONObject>, maxNodes: Int): List<JSONObject> {
        val cap = maxNodes.coerceAtLeast(1)
        val cmp = Comparator<JSONObject> { a, b ->
            val ta = if (a.optString("proto") == "tcp") 0 else 1
            val tb = if (b.optString("proto") == "tcp") 0 else 1
            if (ta != tb) return@Comparator ta - tb
            val sc = b.optInt("score", 0) - a.optInt("score", 0)
            if (sc != 0) return@Comparator sc
            b.optDouble("speed_mbps", 0.0).compareTo(a.optDouble("speed_mbps", 0.0))
        }
        if (parsed.size <= cap) {
            return parsed.sortedWith(cmp)
        }
        val western = parsed.filter { it.optString("country_short").uppercase(Locale.US) in PRIORITY_WESTERN_COUNTRIES }.sortedWith(cmp)
        val others = parsed.filter { it.optString("country_short").uppercase(Locale.US) !in PRIORITY_WESTERN_COUNTRIES }.sortedWith(cmp)
        val westernQuota = (cap / 2).coerceAtLeast(1)
        val pickedWestern = western.take(westernQuota)
        val remain = cap - pickedWestern.size
        val pickedOthers = others.take(remain)
        val leftoverWestern = western.drop(pickedWestern.size).take((remain - pickedOthers.size).coerceAtLeast(0))
        return (pickedWestern + pickedOthers + leftoverWestern).sortedWith(cmp)
    }

    private fun crossCheckIpWho(client: OkHttpClient, ips: List<String>): Set<String> {
        val dcIps = HashSet<String>()
        val uniq = ips.filter { it.isNotBlank() }.distinct().take(30)
        if (uniq.isEmpty()) return dcIps
        val whoClient = client.newBuilder()
            .connectTimeout(4, TimeUnit.SECONDS)
            .readTimeout(4, TimeUnit.SECONDS)
            .callTimeout(5, TimeUnit.SECONDS)
            .build()
        val deadline = System.currentTimeMillis() + 6000L
        val exec = Executors.newFixedThreadPool(6)
        try {
            val futures = uniq.map { ip ->
                exec.submit(Callable<String?> {
                    if (System.currentTimeMillis() >= deadline) return@Callable null
                    try {
                        val req = Request.Builder().url("$IPWHO_ENDPOINT$ip").header("User-Agent", "curl/8.0").build()
                        whoClient.newCall(req).execute().use { r ->
                            if (!r.isSuccessful) return@Callable null
                            val body = r.body?.string() ?: return@Callable null
                            val data = JSONObject(body)
                            if (!data.optBoolean("success", false)) return@Callable null
                            val conn = data.optJSONObject("connection") ?: return@Callable null
                            val asn = conn.optInt("asn", 0)
                            val blob = "${conn.optString("isp")} ${conn.optString("org")}".lowercase(Locale.US)
                            val isResBrand = RESIDENTIAL_BRANDS.any { blob.contains(it) }
                            if (asn in HARD_DC_ASNS || (DC_KEYWORDS.any { blob.contains(it) } && !isResBrand)) {
                                return@Callable ip
                            }
                        }
                    } catch (_: Exception) {
                    }
                    null
                })
            }
            for (f in futures) {
                val leftMs = deadline - System.currentTimeMillis()
                if (leftMs <= 0L) break
                runCatching { f.get(leftMs.coerceAtLeast(50L), TimeUnit.MILLISECONDS) }.getOrNull()?.let { dcIps.add(it) }
            }
        } finally {
            exec.shutdownNow()
        }
        return dcIps
    }

    fun buildMihomoOpenvpnOutbound(node: JSONObject): LinkedHashMap<String, Any?> {
        val prof = node.getJSONObject("profile")
        val proto = prof.optString("proto", "tcp")
        var mtu = prof.optInt("mtu", 0)
        if (proto == "udp" && (mtu <= 0 || mtu > 1200)) {
            mtu = 1200
        }
        val out = LinkedHashMap<String, Any?>()
        out["name"] = node.optString("name", "vpngate")
        out["type"] = "openvpn"
        out["server"] = prof.getString("server")
        out["port"] = prof.getInt("port")
        out["proto"] = proto
        out["dev"] = prof.optString("dev", "tun")
        out["udp"] = true
        out["handshake-timeout"] = 20
        for (k in listOf("cipher", "auth", "ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "key-direction", "comp-lzo")) {
            val v = prof.optString(k, "")
            if (v.isNotEmpty()) out[k] = v
        }
        if (prof.has("data-ciphers")) {
            val dcArr = prof.optJSONArray("data-ciphers")
            if (dcArr != null && dcArr.length() > 0) {
                val list = ArrayList<String>(dcArr.length())
                for (i in 0 until dcArr.length()) list.add(dcArr.getString(i))
                out["data-ciphers"] = list
            }
        }
        if (mtu > 0) {
            out["mtu"] = mtu
        }
        return out
    }

    fun fetchVpnGateNodes(
        client: OkHttpClient,
        maxNodes: Int = 200,
        apiUrls: List<String> = VPNGATE_API_URLS,
        onStage: ((String) -> Unit)? = null
    ): JSONArray {
        val fetchClient = if (client.callTimeoutMillis > 0) {
            client
        } else {
            client.newBuilder().callTimeout(20, TimeUnit.SECONDS).build()
        }
        var rawCsv = ""
        var lastErr: Exception? = null
        onStage?.invoke("正在下载 VPN Gate 节点列表...")
        for (apiUrl in apiUrls) {
            try {
                val req = Request.Builder().url(apiUrl).header("User-Agent", "curl/8.0").build()
                fetchClient.newCall(req).execute().use { r ->
                    if (!r.isSuccessful) error("HTTP ${r.code}")
                    rawCsv = r.body?.string() ?: ""
                }
                if (rawCsv.trim().isNotEmpty()) break
            } catch (e: Exception) {
                lastErr = e
            }
        }
        if (rawCsv.trim().isEmpty()) {
            throw RuntimeException("拉取免费家宽列表失败: ${lastErr?.message ?: "无响应"}")
        }

        val lines = rawCsv.lines().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("*") }.toMutableList()
        if (lines.isEmpty()) throw RuntimeException("VPN Gate 返回内容为空")
        if (lines[0].startsWith("#")) lines[0] = lines[0].substring(1)

        val headers = parseCsvRow(lines[0])
        val colIdx = HashMap<String, Int>()
        headers.forEachIndexed { idx, h -> colIdx[h.trim()] = idx }

        val parsedNodes = ArrayList<JSONObject>()
        for (i in 1 until lines.size) {
            val cols = parseCsvRow(lines[i])
            fun col(name: String): String {
                val idx = colIdx[name] ?: return ""
                return if (idx in cols.indices) cols[idx].trim() else ""
            }
            val b64 = col("OpenVPN_ConfigData_Base64")
            if (b64.isEmpty()) continue
            val ovpnText = try {
                String(Base64.decode(b64, Base64.DEFAULT), Charsets.UTF_8)
            } catch (_: Exception) {
                continue
            }
            val prof = parseOvpnProfile(ovpnText) ?: continue
            val cc = col("CountryShort").ifBlank { "GL" }.uppercase(Locale.US)
            val ip = col("IP").ifBlank { prof.optString("server") }
            val port = prof.optInt("port", 0)
            val score = col("Score").toIntOrNull() ?: 0
            val speed = col("Speed").toLongOrNull() ?: 0L
            val ping = col("Ping").toIntOrNull() ?: 999

            parsedNodes.add(
                JSONObject()
                    .put("id", "vg-${cc.lowercase(Locale.US)}-$ip-$port")
                    .put("host_name", col("HostName"))
                    .put("ip", ip)
                    .put("port", port)
                    .put("proto", prof.optString("proto", "tcp"))
                    .put("country_short", cc)
                    .put("country_long", col("CountryLong").ifBlank { cc })
                    .put("score", score)
                    .put("speed_mbps", Math.round((speed / 1_000_000.0) * 10.0) / 10.0)
                    .put("ping", ping)
                    .put("operator", col("Operator"))
                    .put("profile", prof)
                    .put("delay_ms", JSONObject.NULL)
            )
        }

        val candidates = selectCandidates(parsedNodes, maxNodes).toMutableList()
        val uniqIps = candidates.map { it.optString("ip") }.filter { it.isNotEmpty() }.distinct()
        val ipInfo = HashMap<String, JSONObject>()
        val enrichClient = client.newBuilder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(6, TimeUnit.SECONDS)
            .callTimeout(7, TimeUnit.SECONDS)
            .build()
        onStage?.invoke("已解析 ${candidates.size} 个候选，正在识别家宽/机房...")
        for (start in uniqIps.indices step 100) {
            val batch = uniqIps.subList(start, minOf(start + 100, uniqIps.size))
            try {
                val body = JSONArray(batch).toString().toRequestBody("application/json".toMediaType())
                val req = Request.Builder().url(IP_API_BATCH_URL).post(body).build()
                enrichClient.newCall(req).execute().use { r ->
                    if (r.isSuccessful) {
                        val arr = JSONArray(r.body?.string() ?: "[]")
                        for (j in 0 until arr.length()) {
                            val row = arr.optJSONObject(j) ?: continue
                            val q = row.optString("query")
                            if (q.isNotEmpty()) ipInfo[q] = row
                        }
                    }
                }
            } catch (_: Exception) {
            }
        }

        for (n in candidates) {
            val (cls, isp) = classifyNode(n.optString("host_name"), ipInfo[n.optString("ip")])
            n.put("line_class", cls)
            n.put("isp", isp.ifBlank { n.optString("operator").ifBlank { "志愿节点" } })
        }

        val resIpsToCheck = candidates
            .filter { n ->
                n.optString("line_class") == "residential" &&
                    n.optString("ip").isNotEmpty() &&
                    RESIDENTIAL_BRANDS.none { n.optString("isp").lowercase(Locale.US).contains(it) }
            }
            .map { it.optString("ip") }
        if (resIpsToCheck.isNotEmpty()) {
            onStage?.invoke("正在二次核验家宽 IP 归属...")
            val dcHits = crossCheckIpWho(enrichClient, resIpsToCheck)
            if (dcHits.isNotEmpty()) {
                for (n in candidates) {
                    if (n.optString("ip") in dcHits) {
                        n.put("line_class", "datacenter")
                    }
                }
            }
        }

        candidates.sortWith { a, b ->
            val ra = if (a.optString("line_class") == "residential") 0 else 1
            val rb = if (b.optString("line_class") == "residential") 0 else 1
            if (ra != rb) return@sortWith ra - rb
            val ta = if (a.optString("proto") == "tcp") 0 else 1
            val tb = if (b.optString("proto") == "tcp") 0 else 1
            if (ta != tb) return@sortWith ta - tb
            val sc = b.optInt("score", 0) - a.optInt("score", 0)
            if (sc != 0) return@sortWith sc
            b.optDouble("speed_mbps", 0.0).compareTo(a.optDouble("speed_mbps", 0.0))
        }

        val counter = HashMap<Pair<String, String>, Int>()
        val outArr = JSONArray()
        for (n in candidates) {
            val clsCn = if (n.optString("line_class") == "residential") "家宽" else "机房"
            val cc = n.optString("country_short")
            val key = cc to clsCn
            val num = (counter[key] ?: 0) + 1
            counter[key] = num
            val flag = COUNTRY_FLAGS[cc] ?: "\uD83C\uDF10"
            n.put("name", "$flag $cc $clsCn ${num.toString().padStart(2, '0')}")
            outArr.put(n)
        }
        return outArr
    }
}
