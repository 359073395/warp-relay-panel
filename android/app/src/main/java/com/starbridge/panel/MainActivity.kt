package com.starbridge.panel

import android.Manifest
import android.annotation.SuppressLint
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebSettings
import android.webkit.WebView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.json.JSONObject

class MainActivity : AppCompatActivity() {
    private lateinit var webView: WebView
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var pendingConnectReqId: String? = null

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
