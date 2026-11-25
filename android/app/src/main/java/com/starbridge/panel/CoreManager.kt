package com.starbridge.panel

import android.content.Context
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import org.yaml.snakeyaml.DumperOptions
import org.yaml.snakeyaml.Yaml
import java.io.File
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.net.URLEncoder
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class CoreManager(private val context: Context) {
    companion object {
        const val MIXED_PORT = 17890
        const val CTRL_PORT = 19091
        private const val PUBLIC_REMOTE_URL =
            "https://raw.githubusercontent.com/359073395/subs-check-auto/main/subs/all.yaml"
        private const val GITHUB_LATEST_API =
            "https://api.github.com/repos/359073395/warp-relay-panel/releases/latest"
        private const val GITHUB_RELEASES_ATOM =
            "https://github.com/359073395/warp-relay-panel/releases.atom"
        private val GH_MIRRORS = listOf("", "https://gh-proxy.com/")
        private val GEO_FILES = listOf("geosite.dat", "geoip.dat", "geoip.metadb")
    }

    private val nativeDir = File(context.applicationInfo.nativeLibraryDir)
    val mihomoExe = File(nativeDir, "libmihomo.so")
    val xrayExe = File(nativeDir, "libxray.so")
    val coreDir = File(context.filesDir, "core").apply { mkdirs() }
    private val dataDir = File(context.filesDir, "data").apply { mkdirs() }
    private val stateFile = File(dataDir, "state.json")

    private val lock = Any()
    private val saveExec = Executors.newSingleThreadExecutor()
    private val reloadExec = Executors.newSingleThreadExecutor()
    @Volatile private var cachedState: JSONObject? = null
    @Volatile var running = false
    @Volatile var connecting = false
    @Volatile var updateDownloading = false
    @Volatile var updateProgress = 0
    @Volatile var updateMessage = ""
    private var mihomoProc: Process? = null
    private var xrayProc: Process? = null
    private var lastSmartSummary = ""
    private var lastSmartTime = ""
    private val devNull = File("/dev/null")
    @Volatile private var lastTrafficTs = 0L
    @Volatile private var lastUpBytes = 0L
    @Volatile private var lastDownBytes = 0L

    private val directHttp = OkHttpClient.Builder()
        .connectTimeout(12, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()

    init {
        ensureGeoAssets()
        cleanupTempArtifacts()
        if (!stateFile.exists()) {
            saveState(defaultState())
        }
    }

    private fun cleanupTempArtifacts() {
        coreDir.listFiles()?.forEach { f ->
            val n = f.name
            if (f.isDirectory && (n.startsWith("boot_tmp_") || n.startsWith("probe_tmp_"))) {
                runCatching { f.deleteRecursively() }
            }
        }
    }

    private fun truncateLogIfNeeded(file: File, maxBytes: Long = 1048576L) {
        if (file.isFile && file.length() > maxBytes) {
            runCatching { file.writeText("") }
        }
    }

    private fun ensureGeoAssets() {
        for (name in GEO_FILES) {
            val out = File(coreDir, name)
            if (out.exists() && out.length() > 0) continue
            runCatching {
                context.assets.open("core/$name").use { input ->
                    out.outputStream().use { output -> input.copyTo(output) }
                }
            }
        }
    }

    private fun defaultState(): JSONObject {
        val settings = JSONObject()
            .put("underlay_strategy", "auto_free")
            .put("selected_underlay", "")
            .put("use_awg", true)
            .put("use_exit_hop", false)
            .put("selected_exit_id", "")
            .put("route_mode", "bypass_cn")
            .put("smart_auto_select", false)
        return JSONObject()
            .put("settings", settings)
            .put("custom_underlays", JSONArray())
            .put("underlay_subs", JSONArray())
            .put("public_backups", JSONArray())
            .put("warp_account", JSONObject())
            .put("warp_endpoints", JSONArray())
            .put("exits", JSONArray())
    }

    private fun loadState(): JSONObject = synchronized(lock) {
        cachedState?.let { return JSONObject(it.toString()) }
        val loaded = try {
            val s = JSONObject(stateFile.readText())
            if (!s.has("settings")) s.put("settings", defaultState().getJSONObject("settings"))
            if (!s.has("custom_underlays")) s.put("custom_underlays", JSONArray())
            if (!s.has("underlay_subs")) s.put("underlay_subs", JSONArray())
            if (!s.has("public_backups")) s.put("public_backups", JSONArray())
            if (!s.has("warp_account")) s.put("warp_account", JSONObject())
            if (!s.has("warp_endpoints")) s.put("warp_endpoints", JSONArray())
            if (!s.has("exits")) s.put("exits", JSONArray())
            s
        } catch (_: Exception) {
            defaultState()
        }
        cachedState = loaded
        return JSONObject(loaded.toString())
    }

    private fun saveState(st: JSONObject) {
        val snapshot = synchronized(lock) {
            cachedState = JSONObject(st.toString())
            cachedState!!.toString(2)
        }
        saveExec.execute {
            runCatching { stateFile.writeText(snapshot) }
        }
    }

    private fun jsonToMap(obj: JSONObject): LinkedHashMap<String, Any?> {
        val map = LinkedHashMap<String, Any?>()
        val keys = obj.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            map[k] = unwrapJson(obj.get(k))
        }
        return map
    }

    private fun jsonToList(arr: JSONArray): ArrayList<Any?> {
        val list = ArrayList<Any?>(arr.length())
        for (i in 0 until arr.length()) {
            list.add(unwrapJson(arr.get(i)))
        }
        return list
    }

    private fun unwrapJson(v: Any?): Any? = when (v) {
        JSONObject.NULL, null -> null
        is JSONObject -> jsonToMap(v)
        is JSONArray -> jsonToList(v)
        else -> v
    }

    private fun mapToJson(map: Map<String, Any?>): JSONObject {
        val obj = JSONObject()
        for ((k, v) in map) {
            obj.put(k, wrapJson(v))
        }
        return obj
    }

    private fun wrapJson(v: Any?): Any = when (v) {
        null -> JSONObject.NULL
        is Map<*, *> -> {
            val obj = JSONObject()
            for ((k, vv) in v) {
                if (k != null) obj.put(k.toString(), wrapJson(vv))
            }
            obj
        }
        is List<*> -> {
            val arr = JSONArray()
            for (item in v) arr.put(wrapJson(item))
            arr
        }
        else -> v
    }

    private fun nowStr(): String = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())

    fun getStateSnapshot(): JSONObject {
        val st = loadState()
        val settings = st.getJSONObject("settings")
        val warpEps = st.getJSONArray("warp_endpoints")
        val warpAcc = st.getJSONObject("warp_account")
        val pub = st.getJSONArray("public_backups")
        val custom = st.getJSONArray("custom_underlays")
        val subs = st.getJSONArray("underlay_subs")
        val exits = st.getJSONArray("exits")

        val customSummary = JSONArray()
        for (i in 0 until custom.length()) {
            val it = custom.getJSONObject(i)
            val px = it.optJSONObject("proxy") ?: JSONObject()
            customSummary.put(
                JSONObject()
                    .put("id", it.optString("id"))
                    .put("name", it.optString("name"))
                    .put("type", px.optString("type"))
                    .put("server", px.optString("server"))
                    .put("port", px.opt("port"))
                    .put("delay_ms", it.opt("delay_ms"))
                    .put("speed_mbps", it.opt("speed_mbps"))
            )
        }

        val subSummary = JSONArray()
        val subUnderlays = JSONArray()
        for (i in 0 until subs.length()) {
            val sub = subs.getJSONObject(i)
            val nodes = sub.optJSONArray("nodes") ?: JSONArray()
            subSummary.put(
                JSONObject()
                    .put("id", sub.optString("id"))
                    .put("name", sub.optString("name"))
                    .put("url", sub.optString("url"))
                    .put("count", nodes.length())
                    .put("updated_at", sub.optString("updated_at"))
            )
            for (j in 0 until nodes.length()) {
                val n = nodes.getJSONObject(j)
                subUnderlays.put(
                    JSONObject()
                        .put("name", n.optString("name"))
                        .put("type", n.optString("type"))
                        .put("server", n.optString("server"))
                        .put("port", n.opt("port"))
                        .put("delay_ms", n.opt("delay_ms"))
                        .put("speed_mbps", n.opt("speed_mbps"))
                )
            }
        }

        val pubSummary = JSONArray()
        for (i in 0 until pub.length()) {
            val it = pub.getJSONObject(i)
            val px = it.optJSONObject("proxy") ?: JSONObject()
            pubSummary.put(
                JSONObject()
                    .put("id", it.optString("id"))
                    .put("name", it.optString("name"))
                    .put("type", px.optString("type"))
                    .put("delay_ms", it.opt("delay_ms"))
                    .put("speed_mbps", it.opt("speed_mbps"))
            )
        }

        val exitSummary = JSONArray()
        for (i in 0 until exits.length()) {
            val it = exits.getJSONObject(i)
            val px = it.optJSONObject("proxy") ?: JSONObject()
            exitSummary.put(
                JSONObject()
                    .put("id", it.optString("id"))
                    .put("name", it.optString("name"))
                    .put("type", px.optString("type"))
                    .put("server", px.optString("server"))
                    .put("port", px.opt("port"))
                    .put("delay_ms", it.opt("delay_ms"))
            )
        }

        val live = if (running) getLiveStatus() else JSONObject()
        return JSONObject()
            .put("app_version", getAppVersion())
            .put("settings", settings)
            .put(
                "core_status",
                JSONObject()
                    .put("ready", mihomoExe.isFile)
                    .put("has_exe", mihomoExe.isFile)
                    .put("has_xray", xrayExe.isFile)
                    .put("has_geo", GEO_FILES.all { File(coreDir, it).exists() })
            )
            .put(
                "runtime",
                JSONObject()
                    .put("running", running)
                    .put("connecting", connecting)
                    .put("mixed_port", MIXED_PORT)
                    .put("active_hop1", live.optString("active_hop1", ""))
                    .put("active_exit", live.optString("active_exit", ""))
                    .put("up_bps", live.optLong("up_bps", 0))
                    .put("down_bps", live.optLong("down_bps", 0))
                    .put("upload_total", live.optLong("upload_total", 0))
                    .put("download_total", live.optLong("download_total", 0))
            )
            .put(
                "warp",
                JSONObject()
                    .put("registered", warpAcc.optString("private_key").isNotEmpty())
                    .put("endpoint_count", warpEps.length())
                    .put("endpoints", warpEps)
            )
            .put("public_backups", pubSummary)
            .put("public_backups_count", pub.length())
            .put("custom_underlays", customSummary)
            .put("sub_underlays", subUnderlays)
            .put("underlay_subs", subSummary)
            .put("exits", exitSummary)
            .put(
                "smart_status",
                JSONObject()
                    .put("enabled", settings.optBoolean("smart_auto_select", false))
                    .put("last_summary", lastSmartSummary)
                    .put("last_time", lastSmartTime)
            )
            .put(
                "update_state",
                JSONObject()
                    .put("downloading", updateDownloading)
                    .put("progress", updateProgress)
                    .put("message", updateMessage)
            )
    }

    fun getAppVersion(): String {
        return runCatching {
            @Suppress("DEPRECATION")
            context.packageManager.getPackageInfo(context.packageName, 0).versionName ?: "2.2.0"
        }.getOrDefault("2.2.0")
    }

    private fun isNewerVersion(remote: String, current: String): Boolean {
        val r = Regex("\\d+").findAll(remote).map { it.value.toIntOrNull() ?: 0 }.toList()
        val c = Regex("\\d+").findAll(current).map { it.value.toIntOrNull() ?: 0 }.toList()
        val maxLen = maxOf(r.size, c.size)
        for (i in 0 until maxLen) {
            val rv = r.getOrElse(i) { 0 }
            val cv = c.getOrElse(i) { 0 }
            if (rv != cv) return rv > cv
        }
        return false
    }

    private fun checkUpdateViaAtom(clients: List<OkHttpClient>): JSONObject? {
        for (cli in clients) {
            for (prefix in GH_MIRRORS) {
                val u = if (prefix.isEmpty()) GITHUB_RELEASES_ATOM else "$prefix$GITHUB_RELEASES_ATOM"
                try {
                    val req = Request.Builder().url(u).header("User-Agent", "StarBridge/${getAppVersion()}").build()
                    cli.newCall(req).execute().use { r ->
                        if (!r.isSuccessful) return@use
                        val body = r.body?.string() ?: ""
                        val m = Regex("releases/tag/(v?\\d+(?:\\.\\d+)+)").find(body)
                        if (m != null) {
                            val tag = m.groupValues[1]
                            val dl = "https://github.com/359073395/warp-relay-panel/releases/download/$tag/StarBridge-android-arm64.apk"
                            val assets = JSONArray().put(
                                JSONObject().put("name", "StarBridge-android-arm64.apk").put("browser_download_url", dl)
                            )
                            return JSONObject()
                                .put("tag_name", tag)
                                .put("html_url", "https://github.com/359073395/warp-relay-panel/releases/tag/$tag")
                                .put("assets", assets)
                        }
                    }
                } catch (_: Exception) {
                }
            }
        }
        return null
    }

    fun checkUpdate(): JSONObject {
        val clients = ArrayList<OkHttpClient>()
        if (running) {
            clients.add(
                directHttp.newBuilder()
                    .proxy(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", MIXED_PORT)))
                    .build()
            )
        }
        clients.add(directHttp)
        var data: JSONObject? = null
        var lastErr: Exception? = null
        for (cli in clients) {
            try {
                val req = Request.Builder()
                    .url(GITHUB_LATEST_API)
                    .header("User-Agent", "StarBridge/${getAppVersion()}")
                    .header("Accept", "application/vnd.github+json")
                    .build()
                cli.newCall(req).execute().use { r ->
                    if (!r.isSuccessful) error("HTTP ${r.code}")
                    data = JSONObject(r.body?.string() ?: "{}")
                }
                break
            } catch (e: Exception) {
                lastErr = e
            }
        }
        if (data == null) {
            data = checkUpdateViaAtom(clients)
        }
        val rel = data ?: throw RuntimeException("检查更新失败: ${lastErr?.message}")
        val tag = rel.optString("tag_name", "").trim()
        val latest = tag.removePrefix("v").removePrefix("V")
        val current = getAppVersion()
        var apkUrl = ""
        val assets = rel.optJSONArray("assets") ?: JSONArray()
        for (i in 0 until assets.length()) {
            val a = assets.getJSONObject(i)
            if (a.optString("name") == "StarBridge-android-arm64.apk") {
                apkUrl = a.optString("browser_download_url")
                break
            }
        }
        return JSONObject()
            .put("ok", true)
            .put("current_version", current)
            .put("latest_version", latest)
            .put("has_update", isNewerVersion(latest, current))
            .put("apk_url", apkUrl)
            .put("html_url", rel.optString("html_url", ""))
    }

    fun downloadUpdateApk(rawUrl: String): File {
        val url = rawUrl.ifBlank { checkUpdate().optString("apk_url") }
        if (url.isBlank()) error("未找到 Android APK 下载地址")
        val updDir = File(context.filesDir, "updates").apply { mkdirs() }
        val dest = File(updDir, "StarBridge-update.apk")
        val tmp = File(updDir, "StarBridge-update.tmp")

        updateDownloading = true
        updateProgress = 1
        updateMessage = "正在连接下载服务器..."
        try {
            val attempts = ArrayList<Pair<String, OkHttpClient>>()
            if (running) {
                attempts.add(
                    url to directHttp.newBuilder()
                        .proxy(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", MIXED_PORT)))
                        .connectTimeout(15, TimeUnit.SECONDS)
                        .readTimeout(60, TimeUnit.SECONDS)
                        .build()
                )
            }
            val dlDirect = directHttp.newBuilder()
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(60, TimeUnit.SECONDS)
                .build()
            for (prefix in GH_MIRRORS) {
                val u = if (prefix.isEmpty()) url else "$prefix$url"
                attempts.add(u to dlDirect)
            }

            var lastErr: Exception? = null
            for ((targetUrl, cli) in attempts) {
                try {
                    val req = Request.Builder().url(targetUrl).header("User-Agent", "StarBridge/${getAppVersion()}").build()
                    cli.newCall(req).execute().use { r ->
                        if (!r.isSuccessful) error("HTTP ${r.code}")
                        val body = r.body ?: error("空响应")
                        val total = body.contentLength()
                        var downloaded = 0L
                        body.byteStream().use { inp ->
                            tmp.outputStream().use { out ->
                                val buf = ByteArray(65536)
                                while (true) {
                                    val n = inp.read(buf)
                                    if (n <= 0) break
                                    out.write(buf, 0, n)
                                    downloaded += n
                                    if (total > 0) {
                                        updateProgress = ((downloaded * 100) / total).toInt().coerceIn(1, 99)
                                        updateMessage = String.format(
                                            Locale.US,
                                            "已下载 %.1f / %.1f MB",
                                            downloaded / 1048576.0,
                                            total / 1048576.0
                                        )
                                    }
                                }
                            }
                        }
                    }
                    val magic = ByteArray(2)
                    val readLen = tmp.inputStream().use { it.read(magic) }
                    if (readLen < 2 || magic[0] != 'P'.code.toByte() || magic[1] != 'K'.code.toByte()) {
                        error("下载的安装包无效")
                    }
                    if (dest.exists()) dest.delete()
                    tmp.renameTo(dest)
                    updateProgress = 100
                    updateMessage = "下载完成，正在拉起系统安装..."
                    return dest
                } catch (e: Exception) {
                    lastErr = e
                    runCatching { tmp.delete() }
                }
            }
            throw RuntimeException("APK 下载失败: ${lastErr?.message}")
        } finally {
            updateDownloading = false
        }
    }

    fun getRuntimeSnapshot(): JSONObject {
        val st = loadState()
        val settings = st.getJSONObject("settings")
        val live = if (running) getLiveStatus() else JSONObject()
        return JSONObject()
            .put(
                "runtime",
                JSONObject()
                    .put("running", running)
                    .put("connecting", connecting)
                    .put("mixed_port", MIXED_PORT)
                    .put("active_hop1", live.optString("active_hop1", ""))
                    .put("active_exit", live.optString("active_exit", ""))
                    .put("up_bps", live.optLong("up_bps", 0))
                    .put("down_bps", live.optLong("down_bps", 0))
                    .put("upload_total", live.optLong("upload_total", 0))
                    .put("download_total", live.optLong("download_total", 0))
            )
            .put(
                "smart_status",
                JSONObject()
                    .put("enabled", settings.optBoolean("smart_auto_select", false))
                    .put("last_summary", lastSmartSummary)
                    .put("last_time", lastSmartTime)
            )
            .put(
                "update_state",
                JSONObject()
                    .put("downloading", updateDownloading)
                    .put("progress", updateProgress)
                    .put("message", updateMessage)
            )
    }

    fun readLogs(maxLines: Int = 100): String {
        val logFile = File(coreDir, "core.log")
        if (!logFile.exists()) return "暂无内核日志"
        return runCatching {
            logFile.readLines().takeLast(maxLines.coerceIn(10, 500)).joinToString("\n")
        }.getOrDefault("读取日志失败")
    }

    fun updateSettings(patch: JSONObject): JSONObject {
        val st = loadState()
        val settings = st.getJSONObject("settings")
        val changedKeys = HashSet<String>()
        val keys = patch.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            settings.put(k, patch.get(k))
            changedKeys.add(k)
        }
        saveState(st)
        val routingKeys = setOf("underlay_strategy", "selected_underlay", "use_awg", "use_exit_hop", "selected_exit_id", "route_mode")
        if (running && changedKeys.any { it in routingKeys }) {
            reloadExec.execute {
                runCatching { hotReloadConfig() }
            }
        }
        return getStateSnapshot()
    }

    private fun buildHttpClients(proxyFirst: Boolean = true): List<OkHttpClient> {
        val list = ArrayList<OkHttpClient>()
        if (proxyFirst && running) {
            list.add(
                directHttp.newBuilder()
                    .proxy(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", MIXED_PORT)))
                    .build()
            )
        }
        list.add(directHttp)
        return list
    }

    private fun fetchTextWithFallback(url: String, userAgent: String = "ClashMeta/1.18"): String {
        var lastErr: Exception? = null
        for (cli in buildHttpClients(proxyFirst = true)) {
            try {
                val req = Request.Builder().url(url).header("User-Agent", userAgent).build()
                cli.newCall(req).execute().use { r ->
                    if (!r.isSuccessful) error("HTTP ${r.code}")
                    val body = r.body?.string() ?: ""
                    if (body.isNotEmpty()) return body
                }
            } catch (e: Exception) {
                lastErr = e
            }
        }
        throw RuntimeException("订阅拉取失败: ${lastErr?.message ?: "无响应"}")
    }

    private fun fetchPublicNodes(proxyPort: Int? = null): List<Map<String, Any?>> {
        val http = if (proxyPort != null && proxyPort > 0) {
            directHttp.newBuilder()
                .proxy(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", proxyPort)))
                .build()
        } else {
            directHttp
        }
        val mirrors = if (proxyPort != null && proxyPort > 0) listOf("") else GH_MIRRORS
        for (prefix in mirrors) {
            try {
                val url = if (prefix.isEmpty()) PUBLIC_REMOTE_URL else "$prefix$PUBLIC_REMOTE_URL"
                val req = Request.Builder().url(url).header("User-Agent", "StarBridge/1.0").build()
                val body = http.newCall(req).execute().use { r ->
                    if (!r.isSuccessful) error("HTTP ${r.code}")
                    r.body?.string() ?: ""
                }
                val parsed = NodeParser.parseSubscriptionContent(body).shuffled().take(40)
                if (parsed.isNotEmpty()) return parsed
            } catch (_: Exception) {
            }
        }
        return emptyList()
    }

    private fun <T> withTempBootstrapProxy(proxies: List<Map<String, Any?>>, block: (Int) -> T): T? {
        if (!mihomoExe.isFile || proxies.isEmpty()) return null
        val tempMixed = ServerSocket(0).use { it.localPort }
        val bridged = XrayBridge.prepare(dedupeAndStrip(proxies), xrayExe)
        val names = bridged.mihomoProxies.map { it["name"].toString() }
        val tmpDir = File(coreDir, "boot_tmp_${System.currentTimeMillis()}").apply { mkdirs() }
        var xProc: Process? = null
        var mProc: Process? = null
        return try {
            if (bridged.xrayConfigJson != null && xrayExe.isFile) {
                val xf = File(tmpDir, "xray.json").apply { writeText(bridged.xrayConfigJson) }
                xProc = ProcessBuilder(xrayExe.absolutePath, "run", "-c", xf.absolutePath)
                    .directory(coreDir)
                    .redirectErrorStream(true)
                    .redirectOutput(devNull)
                    .start()
                Thread.sleep(200)
            }
            val cfg = linkedMapOf<String, Any?>(
                "mixed-port" to tempMixed,
                "allow-lan" to false,
                "mode" to "rule",
                "log-level" to "silent",
                "dns" to mapOf("enable" to false),
                "proxies" to bridged.mihomoProxies,
                "proxy-groups" to listOf(
                    mapOf("name" to "BOOT", "type" to "url-test", "proxies" to names, "url" to "http://cp.cloudflare.com/generate_204", "interval" to 120)
                ),
                "rules" to listOf("MATCH,BOOT")
            )
            val cf = File(tmpDir, "config.yaml").apply { writeText(buildYamlStr(cfg)) }
            mProc = ProcessBuilder(mihomoExe.absolutePath, "-d", coreDir.absolutePath, "-f", cf.absolutePath)
                .directory(coreDir)
                .redirectErrorStream(true)
                .redirectOutput(devNull)
                .start()
            if (!waitForPort(tempMixed, 4500)) return null
            block(tempMixed)
        } catch (_: Exception) {
            null
        } finally {
            runCatching { mProc?.destroy() }
            runCatching { xProc?.destroy() }
            runCatching { tmpDir.deleteRecursively() }
        }
    }

    fun pullFreeUnderlays(): JSONObject {
        val st = loadState()
        var acct = st.getJSONObject("warp_account")
        var warpErr: Exception? = null
        if (acct.optString("private_key").isBlank()) {
            var regOk = false
            if (running) {
                runCatching {
                    acct = WarpClient.registerAccount(proxyPort = MIXED_PORT)
                    st.put("warp_account", acct)
                    regOk = true
                }
            }
            if (!regOk) {
                try {
                    acct = WarpClient.registerAccount()
                    st.put("warp_account", acct)
                } catch (e: Exception) {
                    warpErr = e
                }
            }
        }
        // 保留最多 4 个已验证可用的低延迟 WARP 节点，其余重新随机抽样换新 IP
        val oldEps = st.getJSONArray("warp_endpoints")
        val keptEps = (0 until oldEps.length())
            .map { oldEps.getJSONObject(it) }
            .filter { it.optInt("delay_ms", 0) > 0 }
            .sortedBy { -(it.optDouble("speed_mbps", 0.0)) * 1000.0 + it.optInt("delay_ms", 99999) }
            .take(4)
        val eps = JSONArray()
        val seenKeys = HashSet<String>()
        for (k in keptEps) {
            val key = "${k.optString("ip")}:${k.optInt("port")}"
            if (seenKeys.add(key)) eps.put(k)
        }
        val freshSampled = WarpClient.sampleEndpoints(16)
        for (item in freshSampled) {
            if (eps.length() >= 12) break
            val key = "${item.optString("ip")}:${item.optInt("port")}"
            if (seenKeys.add(key)) eps.put(item)
        }
        st.put("warp_endpoints", eps)

        // 先按运行状态优先走本地代理，再直连/镜像源拉取公益节点
        var parsedPub = if (running) fetchPublicNodes(MIXED_PORT) else emptyList()
        if (parsedPub.isEmpty()) parsedPub = fetchPublicNodes()
        // 若公益节点未拉到但 WARP 已可用，用临时 WARP 通道拉取公益节点
        if (parsedPub.isEmpty() && acct.optString("private_key").isNotBlank()) {
            val epList = (0 until eps.length()).map { eps.getJSONObject(it) }
            val warpProxies = WarpClient.buildWarpProxies(acct, epList, true)
            parsedPub = withTempBootstrapProxy(warpProxies) { port -> fetchPublicNodes(port) } ?: emptyList()
        }
        // 若 WARP 直连注册失败但公益节点拉到了，借助临时公益节点完成 WARP 注册
        if (acct.optString("private_key").isBlank() && parsedPub.isNotEmpty()) {
            withTempBootstrapProxy(parsedPub.take(15)) { port ->
                runCatching {
                    acct = WarpClient.registerAccount(proxyPort = port)
                    st.put("warp_account", acct)
                    warpErr = null
                }
            }
        }

        if (parsedPub.isNotEmpty()) {
            val arr = JSONArray()
            parsedPub.forEachIndexed { i, p ->
                val pname = "公益-${(i + 1).toString().padStart(2, '0')}-${p["name"] ?: "node"}"
                val mut = LinkedHashMap(p)
                mut["name"] = pname
                arr.put(
                    JSONObject()
                        .put("id", "pub-${i + 1}")
                        .put("name", pname)
                        .put("proxy", mapToJson(mut))
                        .put("delay_ms", JSONObject.NULL)
                        .put("speed_mbps", JSONObject.NULL)
                )
            }
            st.put("public_backups", arr)
        }
        val pubCount = st.getJSONArray("public_backups").length()
        if (acct.optString("private_key").isBlank() && pubCount == 0 && warpErr != null) {
            throw warpErr!!
        }
        saveState(st)
        return JSONObject()
            .put("ok", true)
            .put("warp_count", eps.length())
            .put("public_count", pubCount)
    }

    fun addCustomUnderlays(text: String): JSONObject {
        val parsed = NodeParser.parseSubscriptionContent(text)
        val st = loadState()
        val arr = st.getJSONArray("custom_underlays")
        var added = 0
        for (p in parsed) {
            val name = p["name"]?.toString()?.ifBlank { "自建-${arr.length() + 1}" } ?: "自建-${arr.length() + 1}"
            val mut = LinkedHashMap(p)
            mut["name"] = name
            arr.put(
                JSONObject()
                    .put("id", UUID.randomUUID().toString().take(8))
                    .put("name", name)
                    .put("proxy", mapToJson(mut))
                    .put("delay_ms", JSONObject.NULL)
                    .put("speed_mbps", JSONObject.NULL)
            )
            added++
        }
        saveState(st)
        return JSONObject().put("ok", true).put("added", added)
    }

    fun deleteCustomUnderlay(id: String) {
        val st = loadState()
        val arr = st.getJSONArray("custom_underlays")
        val next = JSONArray()
        for (i in 0 until arr.length()) {
            if (arr.getJSONObject(i).optString("id") != id) next.put(arr.get(i))
        }
        st.put("custom_underlays", next)
        saveState(st)
    }

    fun addUnderlaySub(url: String, name: String = ""): JSONObject {
        val body = fetchTextWithFallback(url.trim())
        val nodes = NodeParser.parseSubscriptionContent(body)
        if (nodes.isEmpty()) error("未从订阅中解析到有效节点")
        val label = name.ifBlank { "订阅-${UUID.randomUUID().toString().take(4)}" }
        val nodeArr = JSONArray()
        nodes.forEachIndexed { idx, p ->
            val mut = LinkedHashMap(p)
            val rawName = p["name"]?.toString()?.ifBlank { "节点${idx + 1}" } ?: "节点${idx + 1}"
            mut["name"] = "[$label] $rawName"
            mut["delay_ms"] = null
            mut["speed_mbps"] = null
            nodeArr.put(mapToJson(mut))
        }
        val st = loadState()
        st.getJSONArray("underlay_subs").put(
            JSONObject()
                .put("id", UUID.randomUUID().toString().take(8))
                .put("name", label)
                .put("url", url.trim())
                .put("updated_at", nowStr())
                .put("nodes", nodeArr)
        )
        saveState(st)
        return JSONObject().put("ok", true).put("count", nodeArr.length())
    }

    fun deleteUnderlaySub(id: String) {
        val st = loadState()
        val subs = st.getJSONArray("underlay_subs")
        val next = JSONArray()
        for (i in 0 until subs.length()) {
            if (subs.getJSONObject(i).optString("id") != id) next.put(subs.get(i))
        }
        st.put("underlay_subs", next)
        saveState(st)
    }

    fun refreshUnderlaySubs(targetId: String = ""): JSONObject {
        val st = loadState()
        val subs = st.getJSONArray("underlay_subs")
        var totalNodes = 0
        for (i in 0 until subs.length()) {
            val sub = subs.getJSONObject(i)
            if (targetId.isNotEmpty() && sub.optString("id") != targetId) continue
            val url = sub.optString("url")
            val label = sub.optString("name", "订阅")
            if (url.isBlank()) continue
            val body = fetchTextWithFallback(url)
            val nodes = NodeParser.parseSubscriptionContent(body)
            if (nodes.isNotEmpty()) {
                val nodeArr = JSONArray()
                nodes.forEachIndexed { idx, p ->
                    val mut = LinkedHashMap(p)
                    val rawName = p["name"]?.toString()?.ifBlank { "节点${idx + 1}" } ?: "节点${idx + 1}"
                    mut["name"] = "[$label] $rawName"
                    mut["delay_ms"] = null
                    mut["speed_mbps"] = null
                    nodeArr.put(mapToJson(mut))
                }
                sub.put("nodes", nodeArr)
                sub.put("updated_at", nowStr())
                totalNodes += nodeArr.length()
            }
        }
        saveState(st)
        return JSONObject().put("ok", true).put("count", totalNodes)
    }

    fun addExitNode(raw: String, remark: String = "", defaultType: String = "socks5"): JSONObject {
        val lines = raw.lines().map { it.trim() }.filter { it.isNotEmpty() }
        val st = loadState()
        val exits = st.getJSONArray("exits")
        var added = 0
        var lastId = ""
        for (line in lines) {
            val p = NodeParser.parseResidentialLine(line, remark, defaultType) ?: continue
            val id = UUID.randomUUID().toString().take(8)
            exits.put(
                JSONObject()
                    .put("id", id)
                    .put("name", p["name"]?.toString() ?: "住宅-$id")
                    .put("proxy", mapToJson(p))
                    .put("delay_ms", JSONObject.NULL)
            )
            lastId = id
            added++
        }
        if (added > 0) {
            val s = st.getJSONObject("settings")
            s.put("use_exit_hop", true)
            s.put("selected_exit_id", lastId)
        }
        saveState(st)
        return JSONObject().put("ok", true).put("added", added).put("selected_exit_id", lastId)
    }

    fun deleteExitNode(id: String) {
        val st = loadState()
        val exits = st.getJSONArray("exits")
        val next = JSONArray()
        for (i in 0 until exits.length()) {
            if (exits.getJSONObject(i).optString("id") != id) next.put(exits.get(i))
        }
        st.put("exits", next)
        saveState(st)
    }

    fun selectUnderlay(name: String) {
        val st = loadState()
        val s = st.getJSONObject("settings")
        s.put("selected_underlay", name)
        s.put("underlay_strategy", "manual")
        saveState(st)
        if (running) {
            reloadExec.execute {
                val switched = runCatching { switchGroup("HOP1", name) }.getOrDefault(false)
                if (!switched) {
                    runCatching { hotReloadConfig() }
                }
            }
        }
    }

    private fun switchGroup(group: String, nodeName: String): Boolean {
        val body = JSONObject().put("name", nodeName).toString().toRequestBody("application/json".toMediaType())
        val enc = URLEncoder.encode(group, "UTF-8").replace("+", "%20")
        val req = Request.Builder().url("http://127.0.0.1:$CTRL_PORT/proxies/$enc").put(body).build()
        return directHttp.newCall(req).execute().use { it.isSuccessful }
    }

    private fun collectHop1Pool(st: JSONObject, kind: String): List<Triple<String, Map<String, Any?>, Any>> {
        // Triple(key, proxyMap, refObj)
        val result = ArrayList<Triple<String, Map<String, Any?>, Any>>()
        val settings = st.getJSONObject("settings")
        val useAwg = settings.optBoolean("use_awg", true)

        if (kind in setOf("all", "user", "custom")) {
            val arr = st.getJSONArray("custom_underlays")
            for (i in 0 until arr.length()) {
                val item = arr.getJSONObject(i)
                val px = jsonToMap(item.getJSONObject("proxy"))
                px["name"] = item.getString("name")
                result.add(Triple("custom:${item.getString("id")}", px, item))
            }
        }
        if (kind in setOf("all", "user", "sub")) {
            val subs = st.getJSONArray("underlay_subs")
            for (i in 0 until subs.length()) {
                val nodes = subs.getJSONObject(i).optJSONArray("nodes") ?: continue
                for (j in 0 until nodes.length()) {
                    val item = nodes.getJSONObject(j)
                    val px = jsonToMap(item)
                    px.remove("delay_ms")
                    px.remove("speed_mbps")
                    result.add(Triple("sub:${item.optString("name")}", px, item))
                }
            }
        }
        if (kind in setOf("all", "free", "public")) {
            val arr = st.getJSONArray("public_backups")
            for (i in 0 until arr.length()) {
                val item = arr.getJSONObject(i)
                val px = jsonToMap(item.getJSONObject("proxy"))
                px["name"] = item.getString("name")
                result.add(Triple("public:${item.getString("id")}", px, item))
            }
        }
        if (kind in setOf("all", "free", "warp")) {
            val acc = st.getJSONObject("warp_account")
            val eps = st.getJSONArray("warp_endpoints")
            if (acc.optString("private_key").isNotEmpty() && eps.length() > 0) {
                val epList = (0 until eps.length()).map { eps.getJSONObject(it) }
                val built = WarpClient.buildWarpProxies(acc, epList, useAwg)
                built.forEachIndexed { idx, px ->
                    result.add(Triple("warp:$idx", px, eps.getJSONObject(idx)))
                }
            }
        }
        return result
    }

    private fun dedupeAndStrip(proxies: List<Map<String, Any?>>): List<Map<String, Any?>> {
        val seen = HashSet<String>()
        val out = ArrayList<Map<String, Any?>>()
        for (p in proxies) {
            var name = p["name"]?.toString()?.ifBlank { "node" } ?: "node"
            var idx = 2
            while (!seen.add(name)) {
                name = "${p["name"]}_$idx"
                idx++
            }
            val mut = LinkedHashMap(p)
            mut["name"] = name
            out.add(mut)
        }
        return out
    }

    private fun buildYamlStr(config: Map<String, Any?>): String {
        val opts = DumperOptions().apply {
            defaultFlowStyle = DumperOptions.FlowStyle.BLOCK
            isPrettyFlow = true
        }
        return Yaml(opts).dump(config)
    }

    private fun waitForPort(port: Int, timeoutMs: Long = 5000): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            try {
                Socket().use { s ->
                    s.connect(InetSocketAddress("127.0.0.1", port), 200)
                    return true
                }
            } catch (_: Exception) {
                Thread.sleep(100)
            }
        }
        return false
    }

    fun testPool(kind: String, targetId: String = "", nodeName: String = "", testSpeed: Boolean = true): JSONObject {
        if (!mihomoExe.isFile) error("未找到 libmihomo.so 内核文件")
        val st = loadState()
        val items = collectHop1Pool(st, kind).filter { (key, px, _) ->
            when {
                targetId.isNotEmpty() -> key.endsWith(":$targetId")
                nodeName.isNotEmpty() -> px["name"]?.toString() == nodeName
                else -> true
            }
        }
        if (items.isEmpty()) {
            return JSONObject().put("tested", 0).put("alive", 0)
        }

        val tempMixed = ServerSocket(0).use { it.localPort }
        val tempCtrl = ServerSocket(0).use { it.localPort }
        val rawProxies = dedupeAndStrip(items.map { it.second })
        val bridged = XrayBridge.prepare(rawProxies, xrayExe)
        val aliases = bridged.mihomoProxies.map { it["name"].toString() }

        val tempDir = File(coreDir, "probe_tmp_${System.currentTimeMillis()}").apply { mkdirs() }
        var tmpXray: Process? = null
        var tmpMihomo: Process? = null

        try {
            if (bridged.xrayConfigJson != null && xrayExe.isFile) {
                val xf = File(tempDir, "xray.json").apply { writeText(bridged.xrayConfigJson) }
                tmpXray = ProcessBuilder(xrayExe.absolutePath, "run", "-c", xf.absolutePath)
                    .directory(coreDir)
                    .redirectErrorStream(true)
                    .redirectOutput(devNull)
                    .start()
                Thread.sleep(250)
            }

            val cfg = linkedMapOf<String, Any?>(
                "mixed-port" to tempMixed,
                "allow-lan" to false,
                "mode" to "rule",
                "log-level" to "silent",
                "external-controller" to "127.0.0.1:$tempCtrl",
                "dns" to mapOf("enable" to false),
                "proxies" to bridged.mihomoProxies,
                "proxy-groups" to listOf(
                    mapOf("name" to "PROBE", "type" to "select", "proxies" to aliases)
                ),
                "rules" to listOf("MATCH,PROBE")
            )
            val cf = File(tempDir, "config.yaml").apply { writeText(buildYamlStr(cfg)) }
            tmpMihomo = ProcessBuilder(mihomoExe.absolutePath, "-d", coreDir.absolutePath, "-f", cf.absolutePath)
                .directory(coreDir)
                .redirectErrorStream(true)
                .redirectOutput(devNull)
                .start()

            if (!waitForPort(tempCtrl, 5000)) error("临时测速内核启动超时")

            val exec = Executors.newFixedThreadPool(10)
            val delayMap = HashMap<String, Int?>()
            val futures = aliases.map { alias ->
                exec.submit(Callable {
                    val d = runCatching { probeSingleDelay(tempCtrl, alias) }.getOrNull()
                    alias to d
                })
            }
            for (f in futures) {
                runCatching {
                    val (alias, d) = f.get(4, TimeUnit.SECONDS)
                    delayMap[alias] = d
                }
            }
            exec.shutdownNow()

            val speedMap = HashMap<String, Double?>()
            if (testSpeed) {
                val aliveAliases = aliases
                    .filter { (delayMap[it] ?: -1) > 0 }
                    .sortedBy { delayMap[it] ?: 99999 }
                    .take(5)
                val proxyHttp = directHttp.newBuilder()
                    .proxy(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", tempMixed)))
                    .connectTimeout(3, TimeUnit.SECONDS)
                    .readTimeout(3, TimeUnit.SECONDS)
                    .build()
                for (alias in aliveAliases) {
                    runCatching {
                        val enc = URLEncoder.encode("PROBE", "UTF-8")
                        val putReq = Request.Builder()
                            .url("http://127.0.0.1:$tempCtrl/proxies/$enc")
                            .put(JSONObject().put("name", alias).toString().toRequestBody("application/json".toMediaType()))
                            .build()
                        directHttp.newCall(putReq).execute().close()

                        val start = System.nanoTime()
                        val dlReq = Request.Builder()
                            .url("https://speed.cloudflare.com/__down?bytes=524288")
                            .build()
                        var bytes = 0L
                        proxyHttp.newCall(dlReq).execute().use { r ->
                            val buf = ByteArray(16384)
                            val stream = r.body?.byteStream()
                            if (stream != null) {
                                while (true) {
                                    val n = stream.read(buf)
                                    if (n <= 0) break
                                    bytes += n
                                    if (System.nanoTime() - start > 1_800_000_000L) break
                                }
                            }
                        }
                        val sec = (System.nanoTime() - start) / 1e9
                        if (bytes > 4096 && sec > 0.04) {
                            val mbps = ((bytes * 8.0) / sec) / 1_000_000.0
                            speedMap[alias] = Math.round(mbps * 100.0) / 100.0
                        }
                    }
                }
            }

            var alive = 0
            var bestName = ""
            var bestMs = 0
            var bestMbps = 0.0
            var bestScore = -1.0

            items.forEachIndexed { idx, (_, px, refObj) ->
                val alias = aliases[idx]
                val d = delayMap[alias]
                val spd = speedMap[alias]
                val obj = refObj as JSONObject
                if (d != null && d > 0) {
                    alive++
                    obj.put("delay_ms", d)
                    if (spd != null) obj.put("speed_mbps", spd) else obj.put("speed_mbps", JSONObject.NULL)
                    val score = (spd ?: 0.0) * 1000.0 - d
                    if (score > bestScore) {
                        bestScore = score
                        bestName = px["name"].toString()
                        bestMs = d
                        bestMbps = spd ?: 0.0
                    }
                } else {
                    obj.put("delay_ms", -1)
                    obj.put("speed_mbps", JSONObject.NULL)
                }
            }
            if (targetId.isEmpty() && nodeName.isEmpty()) {
                sortRankedArrays(st)
            }
            saveState(st)
            return JSONObject()
                .put("tested", items.size)
                .put("alive", alive)
                .put("best_name", bestName)
                .put("best_ms", bestMs)
                .put("best_mbps", bestMbps)
        } finally {
            runCatching { tmpMihomo?.destroy() }
            runCatching { tmpXray?.destroy() }
            runCatching { tempDir.deleteRecursively() }
        }
    }

    private fun sortRankedArrays(st: JSONObject) {
        fun rank(obj: JSONObject): Double {
            val d = obj.optInt("delay_ms", 0)
            if (d > 0) return -1_000_000.0 - obj.optDouble("speed_mbps", 0.0) * 1000.0 + d
            if (d == -1) return 1_000_000.0
            return 0.0
        }
        for (key in listOf("custom_underlays", "public_backups", "warp_endpoints")) {
            val arr = st.getJSONArray(key)
            val list = (0 until arr.length()).map { arr.getJSONObject(it) }.sortedBy { rank(it) }
            val next = JSONArray()
            list.forEach { next.put(it) }
            st.put(key, next)
        }
        val subs = st.getJSONArray("underlay_subs")
        for (i in 0 until subs.length()) {
            val sub = subs.getJSONObject(i)
            val nodes = sub.optJSONArray("nodes") ?: continue
            val sorted = (0 until nodes.length()).map { nodes.getJSONObject(it) }.sortedBy { rank(it) }
            val nextNodes = JSONArray()
            sorted.forEach { nextNodes.put(it) }
            sub.put("nodes", nextNodes)
        }
    }

    private fun probeSingleDelay(ctrlPort: Int, alias: String): Int? {
        val enc = URLEncoder.encode(alias, "UTF-8").replace("+", "%20")
        for (testUrl in listOf("https://www.gstatic.com/generate_204", "http://cp.cloudflare.com/generate_204")) {
            try {
                val u = "http://127.0.0.1:$ctrlPort/proxies/$enc/delay?timeout=2800&url=${URLEncoder.encode(testUrl, "UTF-8")}"
                val req = Request.Builder().url(u).build()
                directHttp.newCall(req).execute().use { r ->
                    if (r.isSuccessful) {
                        val d = JSONObject(r.body?.string() ?: "{}").optInt("delay", 0)
                        if (d > 0) return d
                    }
                }
            } catch (_: Exception) {
            }
        }
        return null
    }

    fun smartSelectBest(): JSONObject {
        val st = loadState()
        val strat = st.getJSONObject("settings").optString("underlay_strategy", "auto_free")
        val kind = when (strat) {
            "warp_only" -> "warp"
            "public_only" -> "public"
            "custom_only" -> "user"
            else -> "free"
        }
        val res = testPool(kind, testSpeed = true)
        val best = res.optString("best_name", "")
        if (best.isNotEmpty()) {
            selectUnderlay(best)
            lastSmartSummary = "$best (${res.optInt("best_ms")}ms / ${res.optDouble("best_mbps")} Mbps)"
            lastSmartTime = nowStr()
        }
        return res.put("best_underlay", best)
    }

    private fun buildRuntimeConfigFiles(fresh: JSONObject): Pair<File, String?> {
        val fs = fresh.getJSONObject("settings")
        val strat = fs.optString("underlay_strategy", "auto_free")

        val hop1Candidates = when (strat) {
            "direct" -> emptyList()
            "warp_only" -> collectHop1Pool(fresh, "warp").map { it.second }
            "public_only" -> collectHop1Pool(fresh, "public").map { it.second }
            "custom_only" -> collectHop1Pool(fresh, "user").map { it.second }
            "auto_free", "auto" -> collectHop1Pool(fresh, "free").map { it.second }
            else -> collectHop1Pool(fresh, "all").map { it.second }
        }
        val hop1Unique = dedupeAndStrip(hop1Candidates)
        val selName = fs.optString("selected_underlay")
        val filteredHop1 = if (strat == "manual" && selName.isNotEmpty()) {
            // 仅对当前选中的节点保留 Xray 桥接资格，避免未用节点白白拉起额外进程
            hop1Unique.filter { it["name"].toString() == selName || !XrayBridge.shouldBridgeViaXray(it, xrayExe.isFile) }
        } else {
            hop1Unique
        }
        val allProxies = ArrayList<Map<String, Any?>>(filteredHop1)
        val hop1Names = filteredHop1.map { it["name"].toString() }.toMutableList()
        if (strat == "manual" && selName.isNotEmpty() && hop1Names.remove(selName)) {
            hop1Names.add(0, selName)
        }

        val groups = ArrayList<Map<String, Any?>>()
        if (strat == "direct" || hop1Names.isEmpty()) {
            groups.add(mapOf("name" to "HOP1", "type" to "select", "proxies" to listOf("DIRECT")))
        } else if (strat in setOf("auto_free", "auto", "warp_only", "public_only")) {
            groups.add(
                mapOf(
                    "name" to "HOP1",
                    "type" to "url-test",
                    "proxies" to hop1Names,
                    "url" to "http://www.gstatic.com/generate_204",
                    "interval" to 300
                )
            )
        } else {
            groups.add(mapOf("name" to "HOP1", "type" to "select", "proxies" to hop1Names))
        }

        var finalGroup = "HOP1"
        if (fs.optBoolean("use_exit_hop", false)) {
            val exits = fresh.getJSONArray("exits")
            val selExitId = fs.optString("selected_exit_id")
            var chosenExit: JSONObject? = null
            for (i in 0 until exits.length()) {
                val e = exits.getJSONObject(i)
                if (e.optString("id") == selExitId || chosenExit == null) chosenExit = e
                if (e.optString("id") == selExitId) break
            }
            if (chosenExit != null) {
                val exitPx = jsonToMap(chosenExit.getJSONObject("proxy"))
                exitPx["name"] = "EXIT-${chosenExit.optString("name", "node")}"
                if (strat != "direct" && hop1Names.isNotEmpty()) {
                    exitPx["dialer-proxy"] = "HOP1"
                }
                allProxies.add(exitPx)
                groups.add(mapOf("name" to "EXIT", "type" to "select", "proxies" to listOf(exitPx["name"].toString())))
                finalGroup = "EXIT"
            }
        }

        val bridged = XrayBridge.prepare(allProxies, xrayExe)
        val routeMode = fs.optString("route_mode", "bypass_cn")
        val rules = if (routeMode == "global") {
            listOf("MATCH,$finalGroup")
        } else {
            listOf(
                "GEOIP,PRIVATE,DIRECT,no-resolve",
                "GEOSITE,cn,DIRECT",
                "GEOIP,CN,DIRECT,no-resolve",
                "MATCH,$finalGroup"
            )
        }

        val cfg = linkedMapOf<String, Any?>(
            "mixed-port" to MIXED_PORT,
            "allow-lan" to false,
            "mode" to "rule",
            "log-level" to "warning",
            "find-process-mode" to "off",
            "tcp-concurrent" to true,
            "unified-delay" to true,
            "external-controller" to "127.0.0.1:$CTRL_PORT",
            "sniffer" to mapOf(
                "enable" to true,
                "sniff" to mapOf(
                    "HTTP" to mapOf("ports" to listOf(80, 8080)),
                    "TLS" to mapOf("ports" to listOf(443, 8443)),
                    "QUIC" to mapOf("ports" to listOf(443, 8443))
                )
            ),
            "dns" to mapOf(
                "enable" to true,
                "ipv6" to false,
                "enhanced-mode" to "fake-ip",
                "fake-ip-range" to "198.18.0.1/16",
                "proxy-server-nameserver" to listOf("223.5.5.5", "119.29.29.29"),
                "nameserver" to listOf("223.5.5.5", "119.29.29.29"),
                "fallback" to listOf("1.1.1.1", "8.8.8.8")
            ),
            "proxies" to bridged.mihomoProxies,
            "proxy-groups" to groups,
            "rules" to rules
        )
        val cf = File(coreDir, "config.yaml").apply { writeText(buildYamlStr(cfg)) }
        return cf to bridged.xrayConfigJson
    }

    private fun hotReloadConfig() {
        if (!running) return
        val fresh = loadState()
        val (cf, xrayJson) = buildRuntimeConfigFiles(fresh)
        if (xrayJson != null && xrayExe.isFile) {
            runCatching { xrayProc?.destroy() }
            val xf = File(coreDir, "xray.json").apply { writeText(xrayJson) }
            val xlog = File(coreDir, "xray.log").also { truncateLogIfNeeded(it) }
            xrayProc = ProcessBuilder(xrayExe.absolutePath, "run", "-c", xf.absolutePath)
                .directory(coreDir)
                .redirectErrorStream(true)
                .redirectOutput(xlog)
                .start()
            Thread.sleep(200)
        } else {
            runCatching { xrayProc?.destroy() }
            xrayProc = null
        }
        val body = JSONObject().put("path", cf.absolutePath).toString().toRequestBody("application/json".toMediaType())
        val req = Request.Builder().url("http://127.0.0.1:$CTRL_PORT/configs?force=true").put(body).build()
        val ok = runCatching {
            directHttp.newCall(req).execute().use { it.isSuccessful }
        }.getOrDefault(false)
        if (!ok) {
            startCore()
        }
    }

    fun startCore() {
        connecting = true
        try {
            stopCore()
            if (!mihomoExe.isFile) error("未找到 libmihomo.so 内核")
            val st = loadState()
            val s = st.getJSONObject("settings")
            if (s.optBoolean("smart_auto_select", false) && s.optString("underlay_strategy") != "direct") {
                runCatching { smartSelectBest() }
            }
            val fresh = loadState()
            val (cf, xrayJson) = buildRuntimeConfigFiles(fresh)

            if (xrayJson != null && xrayExe.isFile) {
                val xf = File(coreDir, "xray.json").apply { writeText(xrayJson) }
                val xlog = File(coreDir, "xray.log").also { truncateLogIfNeeded(it) }
                xrayProc = ProcessBuilder(xrayExe.absolutePath, "run", "-c", xf.absolutePath)
                    .directory(coreDir)
                    .redirectErrorStream(true)
                    .redirectOutput(xlog)
                    .start()
                Thread.sleep(200)
            }

            val logFile = File(coreDir, "core.log").also { truncateLogIfNeeded(it) }
            mihomoProc = ProcessBuilder(mihomoExe.absolutePath, "-d", coreDir.absolutePath, "-f", cf.absolutePath)
                .directory(coreDir)
                .redirectErrorStream(true)
                .redirectOutput(logFile)
                .start()

            if (!waitForPort(MIXED_PORT, 6000)) {
                stopCore()
                error("Mihomo 启动超时，请查看 core.log")
            }
            lastTrafficTs = System.currentTimeMillis()
            lastUpBytes = 0L
            lastDownBytes = 0L
            running = true
        } finally {
            connecting = false
        }
    }

    fun stopCore() {
        running = false
        connecting = false
        lastTrafficTs = 0L
        lastUpBytes = 0L
        lastDownBytes = 0L
        runCatching { mihomoProc?.destroy() }
        runCatching { xrayProc?.destroy() }
        mihomoProc = null
        xrayProc = null
    }

    fun getLiveStatus(): JSONObject {
        val out = JSONObject()
        runCatching {
            val req = Request.Builder().url("http://127.0.0.1:$CTRL_PORT/proxies").build()
            directHttp.newCall(req).execute().use { r ->
                val obj = JSONObject(r.body?.string() ?: "{}").optJSONObject("proxies") ?: JSONObject()
                out.put("active_hop1", obj.optJSONObject("HOP1")?.optString("now", "") ?: "")
                out.put("active_exit", obj.optJSONObject("EXIT")?.optString("now", "") ?: "")
            }
            val creq = Request.Builder().url("http://127.0.0.1:$CTRL_PORT/connections").build()
            directHttp.newCall(creq).execute().use { r ->
                val c = JSONObject(r.body?.string() ?: "{}")
                val upTotal = c.optLong("uploadTotal", 0)
                val downTotal = c.optLong("downloadTotal", 0)
                val now = System.currentTimeMillis()
                val dt = if (lastTrafficTs > 0L) (now - lastTrafficTs) / 1000.0 else 0.0
                var upBps = 0L
                var downBps = 0L
                if (dt >= 0.3 && upTotal >= lastUpBytes && downTotal >= lastDownBytes) {
                    upBps = ((upTotal - lastUpBytes) / dt).toLong()
                    downBps = ((downTotal - lastDownBytes) / dt).toLong()
                }
                lastTrafficTs = now
                lastUpBytes = upTotal
                lastDownBytes = downTotal
                out.put("up_bps", upBps)
                out.put("down_bps", downBps)
                out.put("upload_total", upTotal)
                out.put("download_total", downTotal)
            }
        }
        return out
    }

    fun diagnose(): JSONObject {
        val client = if (running) {
            directHttp.newBuilder()
                .proxy(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", MIXED_PORT)))
                .connectTimeout(8, TimeUnit.SECONDS)
                .readTimeout(8, TimeUnit.SECONDS)
                .build()
        } else directHttp

        val out = JSONObject()
        var gotIp = false
        runCatching {
            val r = client.newCall(Request.Builder().url("http://ip-api.com/json/?lang=zh-CN").build()).execute()
            r.use {
                if (it.isSuccessful) {
                    val j = JSONObject(it.body?.string() ?: "{}")
                    val ip = j.optString("query", "")
                    if (ip.isNotEmpty()) {
                        out.put("ip", ip)
                        out.put("country", j.optString("country", "-"))
                        out.put("city", j.optString("city", ""))
                        out.put("isp", j.optString("isp", ""))
                        gotIp = true
                    }
                }
            }
        }
        if (!gotIp) {
            runCatching {
                val r2 = client.newCall(Request.Builder().url("https://www.cloudflare.com/cdn-cgi/trace").build()).execute()
                r2.use {
                    if (it.isSuccessful) {
                        val txt = it.body?.string() ?: ""
                        val kv = HashMap<String, String>()
                        txt.lines().forEach { ln ->
                            val idx = ln.indexOf('=')
                            if (idx > 0) kv[ln.substring(0, idx)] = ln.substring(idx + 1)
                        }
                        val ip = kv["ip"] ?: ""
                        if (ip.isNotEmpty()) {
                            out.put("ip", ip)
                            out.put("country", kv["loc"] ?: "-")
                            out.put("city", kv["colo"] ?: "")
                            out.put("isp", "Cloudflare Trace")
                            gotIp = true
                        }
                    }
                }
            }.onFailure {
                out.put("error", it.message ?: "无法访问检测服务")
            }
            if (!gotIp && !out.has("error")) {
                out.put("error", "无法访问出口检测服务")
            }
        }
        val t0 = System.currentTimeMillis()
        val googleOk = runCatching {
            client.newCall(Request.Builder().url("https://www.gstatic.com/generate_204").build()).execute().use { it.code in 200..299 }
        }.getOrDefault(false)
        out.put("google_ok", googleOk)
        out.put("google_ms", if (googleOk) System.currentTimeMillis() - t0 else -1)
        return out
    }
}
