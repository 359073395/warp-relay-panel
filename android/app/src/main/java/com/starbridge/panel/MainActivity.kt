package com.starbridge.panel

import android.Manifest
import android.annotation.SuppressLint
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebSettings
import android.webkit.WebView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.File

class MainActivity : AppCompatActivity() {
    private lateinit var webView: WebView
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var pendingConnectReqId: String? = null
    private var pendingApkFile: File? = null

    private val installPermLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { _ ->
        val apk = pendingApkFile ?: File(File(filesDir, "updates"), "StarBridge-update.apk")
        pendingApkFile = null
        if (apk.exists() && packageManager.canRequestPackageInstalls()) {
            launchApkInstaller(apk)
        }
    }

    private val vpnPermLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { res ->
        val reqId = pendingConnectReqId
        pendingConnectReqId = null
        if (res.resultCode == RESULT_OK) {
            startVpnService()
            if (reqId != null) resolveJs(reqId, true, JSONObject().put("ok", true).toString())
        } else {
            if (reqId != null) resolveJs(reqId, false, JSONObject().put("error", "未授予 VPN 连接权限").toString())
        }
    }

    private val notifPermLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { _ -> }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                notifPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }

        webView = WebView(this)
        setContentView(webView)
        webView.setBackgroundColor(0xFF090E1A.toInt())
        webView.webChromeClient = WebChromeClient()
        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            allowFileAccess = true
            cacheMode = WebSettings.LOAD_NO_CACHE
        }
        webView.addJavascriptInterface(WebBridge(), "StarBridgeAndroid")
        webView.loadUrl("file:///android_asset/web/index.html")
    }

    private fun startVpnService() {
        val intent = Intent(this, StarBridgeVpnService::class.java).apply {
            action = StarBridgeVpnService.ACTION_START
        }
        ContextCompat.startForegroundService(this, intent)
    }

    private fun stopVpnService() {
        val intent = Intent(this, StarBridgeVpnService::class.java).apply {
            action = StarBridgeVpnService.ACTION_STOP
        }
        startService(intent)
    }

    private fun launchApkInstaller(apkFile: File) {
        try {
            if (!packageManager.canRequestPackageInstalls()) {
                pendingApkFile = apkFile
                val permIntent = Intent(
                    Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                    Uri.parse("package:$packageName")
                )
                installPermLauncher.launch(permIntent)
                return
            }
            val uri = FileProvider.getUriForFile(this, "$packageName.fileprovider", apkFile)
            val intent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, "application/vnd.android.package-archive")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            startActivity(intent)
        } catch (e: Exception) {
            android.widget.Toast.makeText(this, "拉起安装器失败: ${e.message}", android.widget.Toast.LENGTH_LONG).show()
        }
    }

    private fun resolveJs(reqId: String, ok: Boolean, jsonStr: String) {
        val quoted = JSONObject.quote(jsonStr)
        val okFlag = if (ok) "true" else "false"
        runOnUiThread {
            if (!isDestroyed) {
                webView.evaluateJavascript("window.__sbResolve(${JSONObject.quote(reqId)}, $okFlag, $quoted);", null)
            }
        }
    }

    inner class WebBridge {
        @JavascriptInterface
        fun call(reqId: String, action: String, payloadJson: String) {
            scope.launch {
                val core = CoreHolder.get(this@MainActivity)
                try {
                    val body = if (payloadJson.isBlank()) JSONObject() else JSONObject(payloadJson)
                    when (action) {
                        "state" -> {
                            val st = core.getStateSnapshot()
                            if (StarBridgeVpnService.lastError.isNotEmpty()) {
                                st.put("last_error", StarBridgeVpnService.lastError)
                            }
                            resolveJs(reqId, true, st.toString())
                        }
                        "runtime" -> {
                            val rt = core.getRuntimeSnapshot()
                            if (StarBridgeVpnService.lastError.isNotEmpty()) {
                                rt.put("last_error", StarBridgeVpnService.lastError)
                            }
                            resolveJs(reqId, true, rt.toString())
                        }
                        "logs" -> {
                            val text = core.readLogs(body.optInt("lines", 100))
                            resolveJs(reqId, true, JSONObject().put("logs", text).toString())
                        }
                        "refresh_sub" -> {
                            val res = core.refreshUnderlaySubs(body.optString("id", ""))
                            resolveJs(reqId, true, res.toString())
                        }
                        "check_update" -> {
                            val res = core.checkUpdate()
                            resolveJs(reqId, true, res.toString())
                        }
                        "apply_update" -> {
                            val apk = core.downloadUpdateApk(body.optString("apk_url", ""))
                            val needPerm = !packageManager.canRequestPackageInstalls()
                            runOnUiThread { launchApkInstaller(apk) }
                            resolveJs(
                                reqId,
                                true,
                                JSONObject().put("ok", true).put("need_perm", needPerm).toString()
                            )
                        }
                        "settings" -> {
                            val res = core.updateSettings(body)
                            resolveJs(reqId, true, res.toString())
                        }
                        "pull_free" -> {
                            val res = core.pullFreeUnderlays()
                            resolveJs(reqId, true, res.toString())
                        }
                        "test_all" -> {
                            val res = core.testPool(
                                kind = body.optString("kind", "free"),
                                targetId = body.optString("id", ""),
                                nodeName = body.optString("name", ""),
                                testSpeed = body.optBoolean("test_speed", true)
                            )
                            resolveJs(reqId, true, res.toString())
                        }
                        "select_underlay" -> {
                            core.selectUnderlay(body.optString("name", ""))
                            resolveJs(reqId, true, JSONObject().put("ok", true).toString())
                        }
                        "add_underlay" -> {
                            val res = core.addCustomUnderlays(body.optString("text", ""))
                            resolveJs(reqId, true, res.toString())
                        }
                        "del_underlay" -> {
                            core.deleteCustomUnderlay(body.optString("id", ""))
                            resolveJs(reqId, true, JSONObject().put("ok", true).toString())
                        }
                        "add_sub" -> {
                            val res = core.addUnderlaySub(body.optString("url", ""), body.optString("name", ""))
                            resolveJs(reqId, true, res.toString())
                        }
                        "del_sub" -> {
                            core.deleteUnderlaySub(body.optString("id", ""))
                            resolveJs(reqId, true, JSONObject().put("ok", true).toString())
                        }
                        "add_exit" -> {
                            val res = core.addExitNode(
                                body.optString("raw", ""),
                                body.optString("remark", ""),
                                body.optString("default_type", "socks5")
                            )
                            resolveJs(reqId, true, res.toString())
                        }
                        "del_exit" -> {
                            core.deleteExitNode(body.optString("id", ""))
                            resolveJs(reqId, true, JSONObject().put("ok", true).toString())
                        }
                        "vpngate_refresh" -> {
                            val res = core.refreshVpnGate()
                            resolveJs(reqId, true, res.toString())
                        }
                        "vpngate_test" -> {
                            val res = core.testVpnGateNodes(
                                country = body.optString("country", "ALL"),
                                maxTest = body.optInt("max_test", 12),
                                nodeId = body.optString("node_id", "")
                            )
                            resolveJs(reqId, true, res.toString())
                        }
                        "connect" -> {
                            val prep = VpnService.prepare(this@MainActivity)
                            if (prep != null) {
                                pendingConnectReqId = reqId
                                runOnUiThread { vpnPermLauncher.launch(prep) }
                            } else {
                                startVpnService()
                                resolveJs(reqId, true, JSONObject().put("ok", true).toString())
                            }
                        }
                        "disconnect" -> {
                            stopVpnService()
                            resolveJs(reqId, true, JSONObject().put("ok", true).toString())
                        }
                        "diagnose" -> {
                            val res = core.diagnose()
                            resolveJs(reqId, true, res.toString())
                        }
                        else -> resolveJs(reqId, false, JSONObject().put("error", "未知操作: $action").toString())
                    }
                } catch (e: Exception) {
                    resolveJs(reqId, false, JSONObject().put("error", e.message ?: "执行失败").toString())
                }
            }
        }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }
}
