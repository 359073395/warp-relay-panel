package com.starbridge.panel

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import hev.htproxy.TProxyService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.File

class StarBridgeVpnService : VpnService() {
    companion object {
        const val ACTION_START = "com.starbridge.panel.START"
        const val ACTION_STOP = "com.starbridge.panel.STOP"
        private const val CHANNEL_ID = "starbridge_vpn"
        private const val NOTIF_ID = 1001
        @Volatile var lastError: String = ""
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tunFd: ParcelFileDescriptor? = null
    private var smartJob: Job? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }
        CoreHolder.get(this).connecting = true
        startForegroundNotif("正在连接星桥加速通道...")
        scope.launch {
            startVpn()
        }
        return START_STICKY
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            val ch = NotificationChannel(
                CHANNEL_ID,
                "星桥 VPN 运行状态",
                NotificationManager.IMPORTANCE_LOW
            )
            nm.createNotificationChannel(ch)
        }
    }

    private fun buildNotification(text: String): Notification {
        ensureChannel()
        val openIntent = Intent(this, MainActivity::class.java)
        val openPi = PendingIntent.getActivity(
            this,
            0,
            openIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val stopIntent = Intent(this, StarBridgeVpnService::class.java).apply { action = ACTION_STOP }
        val stopPi = PendingIntent.getService(
            this,
            1,
            stopIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_bridge)
            .setContentTitle("星桥 · StarBridge")
            .setContentText(text)
            .setOngoing(true)
            .setContentIntent(openPi)
            .addAction(0, "断开", stopPi)
            .build()
    }

    private fun startForegroundNotif(text: String) {
        startForeground(NOTIF_ID, buildNotification(text))
    }

    private fun updateNotif(text: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIF_ID, buildNotification(text))
    }

    private fun startVpn() {
        val core = CoreHolder.get(this)
        try {
            lastError = ""
            core.connecting = true
            core.startCore()

            val builder = Builder()
                .setSession("星桥 StarBridge")
                .setMtu(8500)
                .addAddress("198.18.0.1", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("198.18.0.2")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }
            runCatching { builder.addDisallowedApplication(packageName) }

            val pfd = builder.establish() ?: error("系统拒绝建立 VPN 虚拟网卡")
            tunFd = pfd

            val tproxyCfg = File(core.coreDir, "tproxy.yaml")
            tproxyCfg.writeText(
                """
                tunnel:
                  name: tun0
                  mtu: 8500
                  multi-queue: false
                  ipv4: 198.18.0.1
                socks5:
                  port: ${CoreManager.MIXED_PORT}
                  address: 127.0.0.1
                  udp: 'udp'
                mapdns:
                  address: 198.18.0.2
                  port: 53
                  network: 100.64.0.0
                  netmask: 255.192.0.0
                  cache-size: 10000
                misc:
                  task-stack-size: 86016
                  connect-timeout: 10000
                  read-write-timeout: 60000
                  log-file: stderr
                  log-level: warn
                """.trimIndent()
            )
            TProxyService.TProxyStartService(tproxyCfg.absolutePath, pfd.fd)
            updateNotif("已连接 · 点击查看面板或测速")

            smartJob?.cancel()
            smartJob = scope.launch {
                while (isActive && core.running) {
                    delay(3_600_000L)
                    if (!core.running) break
                    val enabled = core.getStateSnapshot()
                        .optJSONObject("settings")
                        ?.optBoolean("smart_auto_select", false) ?: false
                    if (enabled) {
                        runCatching { core.smartSelectBest() }
                    }
                }
            }
        } catch (e: Exception) {
            lastError = e.message ?: "启动失败"
            stopVpn()
        }
    }

    private fun stopVpn() {
        smartJob?.cancel()
        smartJob = null
        runCatching { TProxyService.TProxyStopService() }
        runCatching { tunFd?.close() }
        tunFd = null
        CoreHolder.get(this).stopCore()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpn()
        scope.cancel()
        super.onDestroy()
    }
}
