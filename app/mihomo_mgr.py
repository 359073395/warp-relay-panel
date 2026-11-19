"""Mihomo (Clash.Meta) 内核管理、链式配置生成、TUN/分流切换与真实出口探测。"""

from __future__ import annotations

import copy
import json
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import yaml

from . import win_proxy

MIXED_PORT = 17890
API_PORT = 19091
API_BASE = f"http://127.0.0.1:{API_PORT}"


class MihomoManager:
    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir
        self.core_dir = base_dir / "core"
        self.data_dir = base_dir / "data"
        self.exe_path = self.core_dir / "mihomo.exe"
        self.config_path = self.core_dir / "config.yaml"
        self.log_path = self.data_dir / "mihomo.log"
        self.proxy_snap_path = self.data_dir / "win_proxy_snap.json"

        self._proc: subprocess.Popen[bytes] | None = None
        self._lock = threading.Lock()
        self._log_file: Any = None
        self.active_mode: str = "system"
        self.last_error: str = ""

    def is_running(self) -> bool:
        with self._lock:
            return self._proc is not None and self._proc.poll() is None

    def _api_request(self, path: str, method: str = "GET", payload: dict[str, Any] | None = None, timeout: float = 4.0) -> Any:
        url = API_BASE + path
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Content-Type": "application/json"} if payload is not None else {}
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            return json.loads(body) if body.strip() else {}

    def _dedupe_proxies(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        used: set[str] = set()
        result: list[dict[str, Any]] = []
        reserved = {"DIRECT", "REJECT", "PASS", "COMPATIBLE", "前置通道", "前置优选", "EXIT"}
        for raw in items:
            if not isinstance(raw, dict):
                continue
            p = copy.deepcopy(raw)
            base_name = str(p.get("name") or p.get("server") or "节点").strip()
            if not base_name or base_name in reserved:
                base_name = f"节点-{base_name}"
            name = base_name
            idx = 2
            while name in used or name in reserved:
                name = f"{base_name} #{idx}"
                idx += 1
            used.add(name)
            p["name"] = name
            result.append(p)
        return result

    def build_config(
        self,
        settings: dict[str, Any],
        underlay_nodes: list[dict[str, Any]],
        exit_node: dict[str, Any] | None,
        extra_exit_nodes: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        proxy_mode = settings.get("proxy_mode", "system")  # system | tun
        route_mode = settings.get("route_mode", "bypass_cn")  # bypass_cn | global
        exit_mode = settings.get("exit_mode", "direct_underlay")  # direct_underlay | residential
        selected_underlay = str(settings.get("selected_underlay", "")).strip()

        clean_underlays = self._dedupe_proxies(underlay_nodes)
        if not clean_underlays:
            raise ValueError("当前没有任何可用的前置节点（请先扫描 WARP、刷新公益池或添加前置节点/订阅）")

        underlay_names = [p["name"] for p in clean_underlays]
        proxies: list[dict[str, Any]] = list(clean_underlays)

        proxy_groups: list[dict[str, Any]] = [
            {
                "name": "前置优选",
                "type": "url-test",
                "proxies": underlay_names,
                "url": "https://cp.cloudflare.com/generate_204",
                "interval": 180,
                "tolerance": 80,
                "lazy": False,
            },
            {
                "name": "前置通道",
                "type": "select",
                "proxies": ["前置优选"] + underlay_names,
            },
        ]

        exit_group_proxies = ["前置通道"]
        if exit_mode == "residential" and exit_node is not None:
            existing_names = {p["name"] for p in proxies}
            exit_chain_names: list[str] = []
            for raw_exit in [exit_node] + list(extra_exit_nodes or []):
                chained = copy.deepcopy(raw_exit)
                base = f"落地-{raw_exit.get('name', '住宅IP')}"
                name = base
                idx = 2
                while name in existing_names:
                    name = f"{base} #{idx}"
                    idx += 1
                existing_names.add(name)
                chained["name"] = name
                chained["dialer-proxy"] = "前置通道"
                proxies.append(chained)
                exit_chain_names.append(name)
            exit_group_proxies = exit_chain_names + ["前置通道"]

        proxy_groups.insert(
            0,
            {
                "name": "EXIT",
                "type": "select",
                "proxies": exit_group_proxies,
            },
        )

        # 如果指定了手动前置节点，也放进配置里供启动后选中
        if selected_underlay and selected_underlay not in underlay_names:
            selected_underlay = ""

        is_tun = proxy_mode == "tun"
        has_geo = (self.core_dir / "geosite.dat").exists() and (self.core_dir / "geoip.dat").exists()

        if route_mode == "bypass_cn" and has_geo:
            rules = [
                "GEOIP,private,DIRECT,no-resolve",
                "GEOSITE,cn,DIRECT",
                "GEOIP,cn,DIRECT",
                "MATCH,EXIT",
            ]
        else:
            rules = [
                "GEOIP,private,DIRECT,no-resolve",
                "MATCH,EXIT",
            ]

        cfg: dict[str, Any] = {
            "mixed-port": MIXED_PORT,
            "allow-lan": bool(settings.get("allow_lan", False)),
            "mode": "rule",
            "log-level": "info",
            "ipv6": False,
            "unified-delay": True,
            "tcp-concurrent": True,
            "external-controller": f"127.0.0.1:{API_PORT}",
            "geodata-mode": True,
            "geo-auto-update": False,
            "dns": {
                "enable": True,
                "listen": "127.0.0.1:1053",
                "enhanced-mode": "fake-ip",
                "fake-ip-range": "198.18.0.1/16",
                "fake-ip-filter": [
                    "*.lan",
                    "*.local",
                    "localhost.ptlogin2.qq.com",
                    "+.msftconnecttest.com",
                    "+.msftncsi.com",
                ],
                "default-nameserver": ["223.5.5.5", "119.29.29.29"],
                "nameserver": ["223.5.5.5", "119.29.29.29", "https://dns.alidns.com/dns-query"],
                "proxy-server-nameserver": ["223.5.5.5", "119.29.29.29"],
            },
            "tun": {
                "enable": is_tun,
                "stack": "gvisor",
                "auto-route": is_tun,
                "auto-detect-interface": is_tun,
                "dns-hijack": ["any:53", "tcp://any:53"],
                "mtu": 1280,
            },
            "proxies": proxies,
            "proxy-groups": proxy_groups,
            "rules": rules,
        }
        return cfg

    def start(
        self,
        settings: dict[str, Any],
        underlay_nodes: list[dict[str, Any]],
        exit_node: dict[str, Any] | None,
        extra_exit_nodes: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        proxy_mode = settings.get("proxy_mode", "system")
        if proxy_mode == "tun" and not win_proxy.is_admin():
            raise PermissionError("开启 TUN 全局网卡模式需要管理员权限，请先点击【以管理员身份重启面板】")

        if not self.exe_path.exists():
            raise FileNotFoundError(f"未找到内核文件: {self.exe_path}")

        self.stop()

        cfg = self.build_config(settings, underlay_nodes, exit_node, extra_exit_nodes=extra_exit_nodes)
        self.core_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False), encoding="utf-8")

        self._log_file = open(self.log_path, "w", encoding="utf-8", errors="replace")
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

        with self._lock:
            self._proc = subprocess.Popen(
                [str(self.exe_path), "-d", str(self.core_dir), "-f", str(self.config_path)],
                cwd=str(self.core_dir),
                stdout=self._log_file,
                stderr=subprocess.STDOUT,
                creationflags=creation_flags,
            )

        # 等待 Mihomo REST API 就绪
        ready = False
        deadline = time.time() + 12.0
        while time.time() < deadline:
            if not self.is_running():
                tail = self.read_logs(30)
                self.stop()
                raise RuntimeError(f"mihomo 启动后退出，请检查配置或端口占用。\n日志:\n{tail}")
            try:
                ver = self._api_request("/version", timeout=1.0)
                if ver:
                    ready = True
                    break
            except Exception:
                time.sleep(0.25)

        if not ready:
            tail = self.read_logs(30)
            self.stop()
            raise RuntimeError(f"mihomo 启动超时。\n日志:\n{tail}")

        # 若用户指定了固定前置节点，切换前置通道选择器
        strategy = settings.get("underlay_strategy", "auto")
        sel = str(settings.get("selected_underlay", "")).strip()
        if strategy == "manual" and sel:
            try:
                encoded = urllib.parse.quote("前置通道", safe="")
                self._api_request(f"/proxies/{encoded}", method="PUT", payload={"name": sel})
            except Exception:
                pass

        # 应用系统代理（仅 system 模式）
        self.active_mode = proxy_mode
        if proxy_mode == "system":
            win_proxy.set_system_proxy(MIXED_PORT, self.proxy_snap_path)
        else:
            win_proxy.restore_system_proxy(self.proxy_snap_path)

        self.last_error = ""
        return {"ok": True, "mode": proxy_mode}

    def stop(self) -> None:
        win_proxy.restore_system_proxy(self.proxy_snap_path)
        with self._lock:
            proc = self._proc
            self._proc = None
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=4)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        if self._log_file is not None:
            try:
                self._log_file.close()
            except Exception:
                pass
            self._log_file = None

    def get_runtime_status(self) -> dict[str, Any]:
        running = self.is_running()
        info: dict[str, Any] = {
            "running": running,
            "mode": self.active_mode if running else "",
            "mixed_port": MIXED_PORT,
            "current_underlay": "",
            "current_exit": "",
        }
        if not running:
            return info
        try:
            proxies = self._api_request("/proxies", timeout=1.5).get("proxies", {})
            exit_g = proxies.get("EXIT", {})
            underlay_g = proxies.get("前置通道", {})
            auto_g = proxies.get("前置优选", {})

            cur_underlay = underlay_g.get("now", "")
            if cur_underlay == "前置优选":
                best = auto_g.get("now", "")
                if best:
                    cur_underlay = f"自动优选 -> {best}"
            info["current_underlay"] = cur_underlay
            info["current_exit"] = exit_g.get("now", "")
        except Exception:
            pass
        return info

    def select_exit(self, proxy_name: str) -> bool:
        if not self.is_running():
            return False
        try:
            self._api_request("/proxies/EXIT", method="PUT", payload={"name": proxy_name}, timeout=3.0)
            return True
        except Exception:
            return False

    def probe_exit_ip(self) -> dict[str, Any]:
        if not self.is_running():
            return {"ok": False, "error": "核心未运行"}

        proxy_url = f"http://127.0.0.1:{MIXED_PORT}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
        last_err: Exception | None = None
        for attempt in range(2):
            t0 = time.perf_counter()
            try:
                req = urllib.request.Request("http://ip-api.com/json/?lang=zh-CN", headers={"User-Agent": "curl/8.0"})
                with opener.open(req, timeout=8) as resp:
                    data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                ms = int((time.perf_counter() - t0) * 1000)
                return {
                    "ok": True,
                    "ip": data.get("query", ""),
                    "country": data.get("country", ""),
                    "city": data.get("city", ""),
                    "isp": data.get("isp", "") or data.get("org", ""),
                    "latency_ms": ms,
                }
            except Exception as first_err:
                last_err = first_err
                # 兜底用 cloudflare trace
                try:
                    t1 = time.perf_counter()
                    req2 = urllib.request.Request("https://www.cloudflare.com/cdn-cgi/trace", headers={"User-Agent": "curl/8.0"})
                    with opener.open(req2, timeout=7) as resp:
                        txt = resp.read().decode("utf-8", errors="ignore")
                    ms = int((time.perf_counter() - t1) * 1000)
                    kv = dict(line.split("=", 1) for line in txt.splitlines() if "=" in line)
                    return {
                        "ok": True,
                        "ip": kv.get("ip", ""),
                        "country": kv.get("loc", ""),
                        "city": kv.get("colo", ""),
                        "isp": "Cloudflare Trace",
                        "latency_ms": ms,
                    }
                except Exception as exc2:
                    last_err = exc2
                    if attempt == 0:
                        time.sleep(0.8)
        return {"ok": False, "error": f"出口探测失败: {last_err}"}

    def test_node_delay(self, proxy_name: str, timeout_ms: int = 3500) -> int | None:
        if not self.is_running():
            return None
        try:
            encoded = urllib.parse.quote(proxy_name, safe="")
            res = self._api_request(
                f"/proxies/{encoded}/delay?timeout={timeout_ms}&url=http://cp.cloudflare.com/generate_204",
                timeout=timeout_ms / 1000.0 + 1.5,
            )
            return int(res.get("delay")) if "delay" in res else None
        except Exception:
            return None

    def read_logs(self, lines: int = 60) -> str:
        if not self.log_path.exists():
            return ""
        try:
            content = self.log_path.read_text(encoding="utf-8", errors="replace").splitlines()
            return "\n".join(content[-lines:])
        except Exception:
            return ""
