"""Mihomo (Clash.Meta) 内核管理、链式配置生成、TUN/分流切换、临时测速与真实出口探测。"""

from __future__ import annotations

import concurrent.futures
import copy
import json
import shutil
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Callable

import yaml

from . import core_updater, win_proxy, xray_bridge

MIXED_PORT = 17890
API_PORT = 19091


def pick_free_port(start: int, attempts: int = 30) -> int:
    for port in range(start, start + attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return start


def parse_custom_rules(raw_rules: Any) -> list[str]:
    """解析用户自定义分流规则，过滤空行、注释及非法 MATCH 覆盖。"""
    if isinstance(raw_rules, str):
        lines = raw_rules.splitlines()
    elif isinstance(raw_rules, list):
        lines = [str(x) for x in raw_rules]
    else:
        return []

    valid: list[str] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if line.startswith("- "):
            line = line[2:].strip()
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 3:
            continue
        if parts[0].upper() == "MATCH":
            continue
        valid.append(",".join(parts))
    return valid


class MihomoManager:
    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir.resolve()
        self.core_dir = self.base_dir / "core"
        self.data_dir = base_dir / "data"
        self.exe_path = self.core_dir / "mihomo.exe"
        self.config_path = self.core_dir / "config.yaml"
        self.log_path = self.data_dir / "mihomo.log"
        self.proxy_snap_path = self.data_dir / "win_proxy_snap.json"

        self._proc: subprocess.Popen[bytes] | None = None
        self._xray_bridge: xray_bridge.XrayBridgeProcess | None = None
        self._lock = threading.Lock()
        self._log_file: Any = None
        self.active_mode: str = "system"
        self.mixed_port: int = MIXED_PORT
        self.api_port: int = API_PORT
        self.last_error: str = ""

        # 实时流量速率采样状态
        self._last_traffic_ts: float = 0.0
        self._last_up_bytes: int = 0
        self._last_down_bytes: int = 0
        self._cleanup_temp_artifacts()

    def _cleanup_temp_artifacts(self) -> None:
        """清理异常退出遗留的临时测速配置、日志与目录。"""
        if not self.core_dir.exists():
            return
        for pat in ("temp_*.yaml", "temp_*.log", "xray_bridge_*.json", "xray_bridge_*.log"):
            for p in self.core_dir.glob(pat):
                try:
                    p.unlink(missing_ok=True)
                except Exception:
                    pass
        for pat in ("probe_tmp_*", "boot_tmp_*"):
            for d in self.core_dir.glob(pat):
                if d.is_dir():
                    shutil.rmtree(d, ignore_errors=True)

    @property
    def api_base(self) -> str:
        return f"http://127.0.0.1:{self.api_port}"

    def is_running(self) -> bool:
        with self._lock:
            return self._proc is not None and self._proc.poll() is None

    def get_core_status(self) -> dict[str, Any]:
        return core_updater.get_core_status(self.core_dir)

    def _api_request(
        self,
        path: str,
        method: str = "GET",
        payload: dict[str, Any] | None = None,
        timeout: float = 4.0,
        base_url: str | None = None,
    ) -> Any:
        url = (base_url or self.api_base) + path
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
        mixed_port: int | None = None,
        api_port: int | None = None,
    ) -> dict[str, Any]:
        proxy_mode = settings.get("proxy_mode", "system")  # system | tun
        route_mode = settings.get("route_mode", "bypass_cn")  # bypass_cn | global
        exit_mode = settings.get("exit_mode", "direct_underlay")  # direct_underlay | residential
        underlay_strategy = str(settings.get("underlay_strategy", "auto_free")).strip()
        selected_underlay = str(settings.get("selected_underlay", "")).strip()
        use_mixed_port = int(mixed_port or settings.get("mixed_port") or MIXED_PORT)
        use_api_port = int(api_port or API_PORT)

        is_direct_hop1 = underlay_strategy == "direct"
        proxies: list[dict[str, Any]] = []
        proxy_groups: list[dict[str, Any]] = []
        underlay_names: list[str] = []

        if is_direct_hop1:
            if exit_mode != "residential" or exit_node is None:
                raise ValueError("第一跳设为“直连”时，请开启第二跳并选择一个落地节点")
        else:
            clean_underlays = self._dedupe_proxies(underlay_nodes)
            if not clean_underlays:
                raise ValueError("当前没有任何可用的前置节点（请扫描 WARP、刷新公益池或添加前置节点）")

            underlay_names = [p["name"] for p in clean_underlays]
            proxies.extend(clean_underlays)
            proxy_groups.extend([
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
            ])

        exit_group_proxies = [] if is_direct_hop1 else ["前置通道"]
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
                if not is_direct_hop1:
                    chained["dialer-proxy"] = "前置通道"
                proxies.append(chained)
                exit_chain_names.append(name)
            exit_group_proxies = exit_chain_names + ([] if is_direct_hop1 else ["前置通道"])

        proxy_groups.insert(
            0,
            {
                "name": "EXIT",
                "type": "select",
                "proxies": exit_group_proxies,
            },
        )

        if selected_underlay and selected_underlay not in underlay_names:
            selected_underlay = ""

        is_tun = proxy_mode == "tun"
        has_geo = (self.core_dir / "geosite.dat").exists() and (self.core_dir / "geoip.dat").exists()
        custom_rules = parse_custom_rules(settings.get("custom_rules", ""))

        rules: list[str] = ["GEOIP,private,DIRECT,no-resolve"]
        rules.extend(custom_rules)
        if route_mode == "bypass_cn" and has_geo:
            rules.extend(["GEOSITE,cn,DIRECT", "GEOIP,cn,DIRECT"])
        rules.append("MATCH,EXIT")

        cfg: dict[str, Any] = {
            "mixed-port": use_mixed_port,
            "allow-lan": bool(settings.get("allow_lan", False)),
            "mode": "rule",
            "log-level": "info",
            "find-process-mode": "off",
            "ipv6": bool(settings.get("ipv6", False)),
            "unified-delay": True,
            "tcp-concurrent": True,
            "external-controller": f"127.0.0.1:{use_api_port}",
            "geodata-mode": True,
            "geo-auto-update": False,
            "sniffer": {
                "enable": True,
                "sniff": {
                    "HTTP": {"ports": [80, 8080]},
                    "TLS": {"ports": [443, 8443]},
                    "QUIC": {"ports": [443, 8443]},
                },
            },
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
                "fallback": ["1.1.1.1", "8.8.8.8", "https://cloudflare-dns.com/dns-query"],
                "fallback-filter": {"geoip": True, "geoip-code": "CN", "ipcidr": ["240.0.0.0/4"]},
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

    def _prepare_runtime_cfg(
        self,
        settings: dict[str, Any],
        underlay_nodes: list[dict[str, Any]],
        exit_node: dict[str, Any] | None,
        extra_exit_nodes: list[dict[str, Any]] | None,
        mixed_port: int,
        api_port: int,
    ) -> tuple[dict[str, Any], xray_bridge.XrayBridgeProcess | None]:
        strategy = str(settings.get("underlay_strategy", "auto_free")).strip()
        sel = str(settings.get("selected_underlay", "")).strip()
        eff_underlays = underlay_nodes
        if strategy == "manual" and sel:
            eff_underlays = [
                n for n in underlay_nodes
                if str(n.get("name", "")) == sel or not xray_bridge.should_bridge_via_xray(self.core_dir, n)
            ] or underlay_nodes
        cfg = self.build_config(
            settings,
            eff_underlays,
            exit_node,
            extra_exit_nodes=extra_exit_nodes,
            mixed_port=mixed_port,
            api_port=api_port,
        )
        cfg["proxies"], bridge = xray_bridge.prepare_proxies_with_xray(
            self.core_dir,
            cfg.get("proxies") or [],
            pick_free_port,
            base_port=18200,
        )
        return cfg, bridge

    def reload_config(
        self,
        settings: dict[str, Any],
        underlay_nodes: list[dict[str, Any]],
        exit_node: dict[str, Any] | None,
        extra_exit_nodes: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """不断流热重载运行中的 Mihomo 配置；若模式或端口变更则自动回退至完整重启。"""
        proxy_mode = settings.get("proxy_mode", "system")
        desired_mixed = int(settings.get("mixed_port") or MIXED_PORT)
        if (
            not self.is_running()
            or proxy_mode != self.active_mode
            or (settings.get("mixed_port") is not None and desired_mixed != self.mixed_port)
        ):
            return self.start(settings, underlay_nodes, exit_node, extra_exit_nodes=extra_exit_nodes)

        cfg, new_bridge = self._prepare_runtime_cfg(
            settings,
            underlay_nodes,
            exit_node,
            extra_exit_nodes,
            mixed_port=self.mixed_port,
            api_port=self.api_port,
        )
        try:
            if new_bridge is not None:
                new_bridge.start(proxy_url=win_proxy.get_active_proxy_url(self_port=self.mixed_port))
            self.core_dir.mkdir(parents=True, exist_ok=True)
            self.config_path.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False), encoding="utf-8")
            self._api_request(
                "/configs?force=true",
                method="PUT",
                payload={"path": str(self.config_path)},
                timeout=5.0,
            )
            old_bridge = self._xray_bridge
            self._xray_bridge = new_bridge
            if old_bridge is not None:
                try:
                    old_bridge.stop()
                except Exception:
                    pass
            strategy = settings.get("underlay_strategy", "auto")
            sel = str(settings.get("selected_underlay", "")).strip()
            if strategy == "manual" and sel:
                try:
                    encoded = urllib.parse.quote("前置通道", safe="")
                    self._api_request(f"/proxies/{encoded}", method="PUT", payload={"name": sel})
                except Exception:
                    pass
            self.last_error = ""
            return {"ok": True, "mode": self.active_mode, "mixed_port": self.mixed_port, "reloaded": True}
        except Exception:
            if new_bridge is not None:
                try:
                    new_bridge.stop()
                except Exception:
                    pass
            return self.start(settings, underlay_nodes, exit_node, extra_exit_nodes=extra_exit_nodes)

    def start(
        self,
        settings: dict[str, Any],
        underlay_nodes: list[dict[str, Any]],
        exit_node: dict[str, Any] | None,
        extra_exit_nodes: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        proxy_mode = settings.get("proxy_mode", "system")
        if proxy_mode == "tun" and not win_proxy.is_admin():
            raise PermissionError("开启 TUN 全局网卡模式需要管理员权限，请先点击【管理员重启(开TUN)】")

        if not self.exe_path.exists():
            raise FileNotFoundError(f"未找到内核文件: {self.exe_path}（请点击面板顶部【一键下载内核】）")

        self.stop()

        desired_mixed = int(settings.get("mixed_port") or MIXED_PORT)
        self.mixed_port = pick_free_port(desired_mixed)
        self.api_port = pick_free_port(API_PORT)

        cfg, bridge = self._prepare_runtime_cfg(
            settings,
            underlay_nodes,
            exit_node,
            extra_exit_nodes,
            mixed_port=self.mixed_port,
            api_port=self.api_port,
        )
        if bridge is not None:
            bridge.start(proxy_url=win_proxy.get_active_proxy_url(self_port=self.mixed_port))
            self._xray_bridge = bridge

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

        # 重置流量基线
        self._last_traffic_ts = time.time()
        self._last_up_bytes = 0
        self._last_down_bytes = 0

        # 若用户指定了固定前置节点，切换前置通道选择器
        strategy = settings.get("underlay_strategy", "auto")
        sel = str(settings.get("selected_underlay", "")).strip()
        if strategy == "manual" and sel:
            try:
                encoded = urllib.parse.quote("前置通道", safe="")
                self._api_request(f"/proxies/{encoded}", method="PUT", payload={"name": sel})
            except Exception:
                pass

        self.active_mode = proxy_mode
        if proxy_mode == "system":
            win_proxy.set_system_proxy(self.mixed_port, self.proxy_snap_path)
        else:
            win_proxy.restore_system_proxy(self.proxy_snap_path, self_port=self.mixed_port)

        self.last_error = ""
        return {"ok": True, "mode": proxy_mode, "mixed_port": self.mixed_port}

    def stop(self) -> None:
        win_proxy.restore_system_proxy(self.proxy_snap_path, self_port=self.mixed_port)
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
        if self._xray_bridge is not None:
            try:
                self._xray_bridge.stop()
            except Exception:
                pass
            self._xray_bridge = None
        self._last_traffic_ts = 0.0
        self._last_up_bytes = 0
        self._last_down_bytes = 0

    def run_temp_mihomo(
        self,
        cfg: dict[str, Any],
        worker: Callable[[str, int], Any],
        startup_timeout: float = 10.0,
    ) -> Any:
        """以独立临时端口和临时配置文件运行 Mihomo，执行完自动销毁，不干扰主连接。"""
        if not self.exe_path.exists():
            raise FileNotFoundError(f"未找到内核文件: {self.exe_path}（请先下载内核）")

        temp_mixed = pick_free_port(17950)
        temp_api = pick_free_port(19150)
        temp_cfg = copy.deepcopy(cfg)
        temp_cfg["mixed-port"] = temp_mixed
        temp_cfg["external-controller"] = f"127.0.0.1:{temp_api}"
        if "tun" in temp_cfg and isinstance(temp_cfg["tun"], dict):
            temp_cfg["tun"]["enable"] = False
        if "dns" in temp_cfg and isinstance(temp_cfg["dns"], dict):
            # 避免与主实例 1053 DNS 端口冲突
            temp_cfg["dns"]["listen"] = f"127.0.0.1:{pick_free_port(11053)}"

        temp_cfg["proxies"], temp_bridge = xray_bridge.prepare_proxies_with_xray(
            self.core_dir,
            temp_cfg.get("proxies") or [],
            pick_free_port,
            base_port=18350,
        )
        if temp_bridge is not None:
            temp_bridge.start(proxy_url=win_proxy.get_active_proxy_url(self_port=self.mixed_port))

        self.core_dir.mkdir(parents=True, exist_ok=True)
        uid = uuid.uuid4().hex[:8]
        cfg_file = self.core_dir / f"temp_{uid}.yaml"
        log_file_path = self.core_dir / f"temp_{uid}.log"
        cfg_file.write_text(yaml.safe_dump(temp_cfg, allow_unicode=True, sort_keys=False), encoding="utf-8")

        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        log_fp = open(log_file_path, "w", encoding="utf-8", errors="replace")
        proc = subprocess.Popen(
            [str(self.exe_path), "-d", str(self.core_dir), "-f", str(cfg_file)],
            cwd=str(self.core_dir),
            stdout=log_fp,
            stderr=subprocess.STDOUT,
            creationflags=creation_flags,
        )
        base_url = f"http://127.0.0.1:{temp_api}"
        try:
            deadline = time.time() + startup_timeout
            ready = False
            while time.time() < deadline:
                if proc.poll() is not None:
                    try:
                        log_fp.flush()
                        err_txt = log_file_path.read_text(encoding="utf-8", errors="replace").splitlines()[-8:]
                    except Exception:
                        err_txt = []
                    detail = "\n".join(err_txt)
                    raise RuntimeError(f"临时 Mihomo 探测进程启动失败: {detail}")
                try:
                    if self._api_request("/version", timeout=1.0, base_url=base_url):
                        ready = True
                        break
                except Exception:
                    time.sleep(0.2)
            if not ready:
                raise RuntimeError("临时 Mihomo 探测进程就绪超时")
            return worker(base_url, temp_mixed)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
            try:
                log_fp.close()
            except Exception:
                pass
            try:
                cfg_file.unlink(missing_ok=True)
                log_file_path.unlink(missing_ok=True)
            except Exception:
                pass
            if temp_bridge is not None:
                try:
                    temp_bridge.stop()
                except Exception:
                    pass

    def probe_proxies_with_temp(
        self,
        cfg: dict[str, Any],
        proxy_names: list[str],
        timeout_ms: int = 6500,
        max_workers: int = 6,
    ) -> dict[str, int | None]:
        """利用临时 Mihomo 实例并发探测一组出站节点的真实延迟。"""
        if not proxy_names:
            return {}

        def _worker(base_url: str, _mixed: int) -> dict[str, int | None]:
            def _one(pname: str) -> tuple[str, int | None]:
                delay = self.test_node_delay(pname, timeout_ms=timeout_ms, base_url=base_url)
                return pname, delay

            results: dict[str, int | None] = {}
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
                for pname, ms in pool.map(_one, proxy_names):
                    results[pname] = ms
            return results

        return self.run_temp_mihomo(cfg, _worker)

    SPEED_TEST_URLS = (
        "https://speed.cloudflare.com/__down?bytes=800000",
        "http://cachefly.cachefly.net/1mb.test",
    )

    def measure_http_download_mbps(
        self,
        proxy_url: str,
        timeout_s: float = 2.8,
        urls: tuple[str, ...] | None = None,
    ) -> float | None:
        """通过指定 HTTP 代理测量真实下载吞吐量（Mbps）。"""
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        )
        for url in (urls or self.SPEED_TEST_URLS):
            t0 = time.perf_counter()
            total_bytes = 0
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
                with opener.open(req, timeout=timeout_s) as resp:
                    while True:
                        if time.perf_counter() - t0 >= timeout_s:
                            break
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        total_bytes += len(chunk)
                elapsed = max(time.perf_counter() - t0, 0.05)
                if total_bytes >= 16384:
                    return round((total_bytes * 8) / (elapsed * 1_000_000), 2)
            except Exception:
                elapsed = time.perf_counter() - t0
                if total_bytes >= 32768 and elapsed > 0.05:
                    return round((total_bytes * 8) / (elapsed * 1_000_000), 2)
        return None

    def probe_proxies_speed_and_delay(
        self,
        cfg: dict[str, Any],
        proxy_names: list[str],
        test_speed: bool = True,
        delay_timeout_ms: int = 5000,
        max_speed_nodes: int = 6,
    ) -> dict[str, dict[str, Any]]:
        """利用临时 Mihomo 实例并发测延迟，并逐个切换 EXIT 测真实下载速度 (Mbps)。"""
        if not proxy_names:
            return {}

        def _worker(base_url: str, mixed_port: int) -> dict[str, dict[str, Any]]:
            def _one_delay(pname: str) -> tuple[str, int | None]:
                return pname, self.test_node_delay(pname, timeout_ms=delay_timeout_ms, base_url=base_url)

            out: dict[str, dict[str, Any]] = {}
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                for pname, ms in pool.map(_one_delay, proxy_names):
                    out[pname] = {"delay_ms": ms, "speed_mbps": None}

            if not test_speed:
                return out

            alive = [
                pname for pname in proxy_names
                if isinstance(out[pname]["delay_ms"], int) and out[pname]["delay_ms"] > 0
            ]
            alive.sort(key=lambda n: out[n]["delay_ms"])
            proxy_url = f"http://127.0.0.1:{mixed_port}"
            for pname in alive[:max_speed_nodes]:
                try:
                    self._api_request(
                        "/proxies/EXIT",
                        method="PUT",
                        payload={"name": pname},
                        timeout=2.0,
                        base_url=base_url,
                    )
                    out[pname]["speed_mbps"] = self.measure_http_download_mbps(proxy_url, timeout_s=2.8)
                except Exception:
                    pass
            return out

        return self.run_temp_mihomo(cfg, _worker)

    def get_runtime_status(self) -> dict[str, Any]:
        running = self.is_running()
        info: dict[str, Any] = {
            "running": running,
            "mode": self.active_mode if running else "",
            "mixed_port": self.mixed_port,
            "current_underlay": "",
            "current_exit": "",
            "up_bps": 0,
            "down_bps": 0,
            "upload_total": 0,
            "download_total": 0,
            "conn_count": 0,
            "sys_proxy_ok": True,
            "sys_proxy_server": "",
        }
        if not running:
            return info
        if self.active_mode == "system":
            chk = win_proxy.check_system_proxy(self.mixed_port)
            info["sys_proxy_ok"] = bool(chk.get("ok"))
            info["sys_proxy_server"] = str(chk.get("server") or "")
        try:
            proxies = self._api_request("/proxies", timeout=1.5).get("proxies", {})
            exit_g = proxies.get("EXIT", {})
            underlay_g = proxies.get("前置通道", {})
            auto_g = proxies.get("前置优选", {})

            cur_underlay = underlay_g.get("now", "") if underlay_g else "直连"
            if cur_underlay == "前置优选":
                best = auto_g.get("now", "")
                if best:
                    cur_underlay = f"自动优选 -> {best}"
            info["current_underlay"] = cur_underlay
            info["current_exit"] = exit_g.get("now", "")
        except Exception:
            pass

        try:
            conns = self._api_request("/connections", timeout=1.5)
            up_total = int(conns.get("uploadTotal") or 0)
            down_total = int(conns.get("downloadTotal") or 0)
            now = time.time()
            dt = now - self._last_traffic_ts if self._last_traffic_ts > 0 else 0.0
            if dt >= 0.3 and up_total >= self._last_up_bytes and down_total >= self._last_down_bytes:
                info["up_bps"] = int((up_total - self._last_up_bytes) / dt)
                info["down_bps"] = int((down_total - self._last_down_bytes) / dt)
            self._last_traffic_ts = now
            self._last_up_bytes = up_total
            self._last_down_bytes = down_total
            info["upload_total"] = up_total
            info["download_total"] = down_total
            info["conn_count"] = len(conns.get("connections") or [])
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

    def select_underlay(self, proxy_name: str) -> bool:
        if not self.is_running():
            return False
        try:
            encoded = urllib.parse.quote("前置通道", safe="")
            self._api_request(f"/proxies/{encoded}", method="PUT", payload={"name": proxy_name}, timeout=3.0)
            return True
        except Exception:
            return False

    def probe_exit_ip(self) -> dict[str, Any]:
        if not self.is_running():
            return {"ok": False, "error": "核心未运行"}

        proxy_url = f"http://127.0.0.1:{self.mixed_port}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
        last_err: Exception | None = None
        for attempt in range(2):
            t0 = time.perf_counter()
            try:
                req = urllib.request.Request(
                    "http://ip-api.com/json/?fields=status,country,city,isp,org,as,hosting,proxy,mobile,query&lang=zh-CN",
                    headers={"User-Agent": "curl/8.0"},
                )
                with opener.open(req, timeout=8) as resp:
                    data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                ms = int((time.perf_counter() - t0) * 1000)
                return {
                    "ok": True,
                    "ip": data.get("query", ""),
                    "country": data.get("country", ""),
                    "city": data.get("city", ""),
                    "isp": data.get("isp", "") or data.get("org", ""),
                    "asn": data.get("as", ""),
                    "is_hosting": bool(data.get("hosting")),
                    "is_proxy": bool(data.get("proxy")),
                    "is_mobile": bool(data.get("mobile")),
                    "latency_ms": ms,
                }
            except Exception as first_err:
                last_err = first_err
                try:
                    t1 = time.perf_counter()
                    req2 = urllib.request.Request(
                        "https://www.cloudflare.com/cdn-cgi/trace",
                        headers={"User-Agent": "curl/8.0"},
                    )
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
                        "asn": "",
                        "is_hosting": False,
                        "is_proxy": False,
                        "is_mobile": False,
                        "latency_ms": ms,
                    }
                except Exception as exc2:
                    last_err = exc2
                    if attempt == 0:
                        time.sleep(0.8)
        return {"ok": False, "error": f"出口探测失败: {last_err}"}

    def diagnose_chain(self, settings: dict[str, Any]) -> dict[str, Any]:
        """分跳诊断：分别测试第一跳前置与第二跳最终出口，准确定位断联环节。"""
        if not self.is_running():
            return {"ok": False, "error": "核心未运行"}

        runtime = self.get_runtime_status()
        strategy = str(settings.get("underlay_strategy", "auto_free"))
        use_exit = bool(settings.get("use_exit_hop", settings.get("exit_mode", "direct_underlay") != "direct_underlay"))

        if strategy == "direct":
            underlay_ok = True
            underlay_ms: int | None = 0
        else:
            underlay_ms = self.test_node_delay("前置通道", timeout_ms=5000)
            underlay_ok = underlay_ms is not None

        if not use_exit:
            exit_ok = underlay_ok
            exit_ms = underlay_ms
            fault_hop = "none" if underlay_ok else "underlay"
        else:
            if not underlay_ok and strategy != "direct":
                exit_ok = False
                exit_ms = None
                fault_hop = "underlay"
            else:
                exit_ms = self.test_node_delay("EXIT", timeout_ms=7000)
                exit_ok = exit_ms is not None
                fault_hop = "none" if exit_ok else "exit"

        probe = self.probe_exit_ip() if fault_hop == "none" else None
        return {
            "ok": True,
            "underlay_ok": underlay_ok,
            "underlay_ms": underlay_ms,
            "exit_ok": exit_ok,
            "exit_ms": exit_ms,
            "fault_hop": fault_hop,
            "current_underlay": runtime.get("current_underlay", ""),
            "current_exit": runtime.get("current_exit", ""),
            "probe": probe,
        }

    def test_node_delay(
        self,
        proxy_name: str,
        timeout_ms: int = 4500,
        base_url: str | None = None,
    ) -> int | None:
        if base_url is None and not self.is_running():
            return None
        encoded = urllib.parse.quote(proxy_name, safe="")
        for test_url in ("http://cp.cloudflare.com/generate_204", "http://www.gstatic.com/generate_204"):
            try:
                q_url = urllib.parse.quote(test_url, safe="")
                res = self._api_request(
                    f"/proxies/{encoded}/delay?timeout={timeout_ms}&url={q_url}",
                    timeout=timeout_ms / 1000.0 + 1.5,
                    base_url=base_url,
                )
                if "delay" in res:
                    return int(res["delay"])
            except Exception:
                continue
        return None

    def read_logs(self, lines: int = 60, level_filter: str = "") -> str:
        if not self.log_path.exists():
            return ""
        try:
            content = self.log_path.read_text(encoding="utf-8", errors="replace").splitlines()
            if level_filter:
                lf = level_filter.lower()
                content = [ln for ln in content if f"level={lf}" in ln.lower() or lf in ln.lower()]
            return "\n".join(content[-lines:])
        except Exception:
            return ""
