"""本地 Web 控制面板服务端与状态管理。"""

from __future__ import annotations

import atexit
import concurrent.futures
import copy
import json
import os
import signal
import sys
import threading
import time
import urllib.parse
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import yaml

from . import core_updater, mihomo_mgr, node_parser, tray, vpngate, warp_client, win_proxy


def _get_app_dirs() -> tuple[Path, Path]:
    if getattr(sys, "frozen", False):
        base_dir = Path(sys.executable).resolve().parent
        meipass = Path(getattr(sys, "_MEIPASS", base_dir))
        static_dir = meipass / "app" / "static"
    else:
        base_dir = Path(__file__).resolve().parent.parent
        static_dir = Path(__file__).resolve().parent / "static"
    return base_dir, static_dir


BASE_DIR, STATIC_DIR = _get_app_dirs()


def _get_icon_path() -> Path | None:
    candidates = []
    if getattr(sys, "frozen", False):
        meipass = Path(getattr(sys, "_MEIPASS", BASE_DIR))
        candidates.append(meipass / "assets" / "starbridge.ico")
    candidates.append(BASE_DIR / "assets" / "starbridge.ico")
    for p in candidates:
        if p.exists():
            return p
    return None
PUBLIC_REMOTE_URL = "https://raw.githubusercontent.com/359073395/subs-check-auto/main/subs/all.yaml"
PANEL_PORT = 19090

DEFAULT_SETTINGS: dict[str, Any] = {
    "proxy_mode": "system",          # system | tun
    "route_mode": "bypass_cn",       # bypass_cn | global
    "underlay_strategy": "auto_free", # auto_free | warp_only | public_only | custom_only | manual | auto | direct
    "selected_underlay": "",
    "use_exit_hop": False,
    "exit_source": "vpngate",        # vpngate | residential
    "exit_mode": "direct_underlay",  # direct_underlay | vpngate | residential (与 use_exit_hop + exit_source 同步)
    "selected_exit_id": "",
    "selected_vpngate_id": "",
    "use_awg": True,
    "enable_public_backup": True,
    "allow_lan": False,
    "ipv6": False,
    "mixed_port": mihomo_mgr.MIXED_PORT,
    "custom_rules": "",
    "minimize_to_tray": False,
    "smart_auto_select": False,
}


class PanelStore:
    def __init__(self, base_dir: Path | None = None) -> None:
        self.base_dir = base_dir or BASE_DIR
        self.data_dir = self.base_dir / "data"
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.settings_file = self.data_dir / "settings.json"
        self.warp_account_file = self.data_dir / "warp_account.json"
        self.warp_endpoints_file = self.data_dir / "warp_endpoints.json"
        self.custom_underlay_file = self.data_dir / "custom_underlays.json"
        self.underlay_subs_file = self.data_dir / "underlay_subs.json"
        self.public_backup_file = self.data_dir / "public_backups.json"
        self.exits_file = self.data_dir / "exits.json"
        self.vpngate_file = self.data_dir / "vpngate_nodes.json"

        self._lock = threading.Lock()
        self._smart_lock = threading.Lock()
        self._scheduler_started = False
        self.mgr = mihomo_mgr.MihomoManager(self.base_dir)
        self.core_dl_state: dict[str, Any] = {
            "downloading": False,
            "message": "",
            "progress": 0,
            "error": "",
        }
        self.smart_state: dict[str, Any] = {
            "running": False,
            "last_run_ts": 0.0,
            "last_run_at": "",
            "last_summary": "",
        }

    def _read_json(self, path: Path, default: Any) -> Any:
        if not path.exists():
            return default
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return default

    def _write_json(self, path: Path, data: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def get_settings(self) -> dict[str, Any]:
        s = dict(DEFAULT_SETTINGS)
        saved = self._read_json(self.settings_file, {})
        if isinstance(saved, dict):
            s.update(saved)
        return s

    def save_settings(self, patch: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            s = self.get_settings()
            for k in DEFAULT_SETTINGS:
                if k in patch:
                    val = patch[k]
                    if k == "mixed_port":
                        try:
                            port = int(val)
                            val = port if 1024 <= port <= 65535 else mihomo_mgr.MIXED_PORT
                        except (TypeError, ValueError):
                            val = mihomo_mgr.MIXED_PORT
                    s[k] = val

            # 保持 use_exit_hop / exit_source 与 exit_mode 双向一致
            if "exit_mode" in patch and "use_exit_hop" not in patch and "exit_source" not in patch:
                em = s["exit_mode"]
                if em == "direct_underlay":
                    s["use_exit_hop"] = False
                elif em in ("vpngate", "residential"):
                    s["use_exit_hop"] = True
                    s["exit_source"] = em
            else:
                if not s.get("use_exit_hop", True):
                    s["exit_mode"] = "direct_underlay"
                else:
                    src = s.get("exit_source", "vpngate")
                    s["exit_mode"] = src if src in ("vpngate", "residential") else "vpngate"

            self._write_json(self.settings_file, s)
            return s

    def _active_or_sys_proxy(self) -> str | None:
        if self.mgr.is_running():
            return f"http://127.0.0.1:{self.mgr.mixed_port}"
        return win_proxy.get_active_proxy_url(self_port=self.mgr.mixed_port)

    def get_custom_underlays(self) -> list[dict[str, Any]]:
        return self._read_json(self.custom_underlay_file, [])

    def get_underlay_subs(self) -> list[dict[str, Any]]:
        return self._read_json(self.underlay_subs_file, [])

    def get_public_backups(self) -> list[dict[str, Any]]:
        items = self._read_json(self.public_backup_file, [])
        override_path = os.environ.get("WARP_RELAY_PUBLIC_YAML", "").strip()
        if not items and override_path and Path(override_path).is_file():
            try:
                doc = yaml.safe_load(Path(override_path).read_text(encoding="utf-8", errors="ignore")) or {}
                raw_list = doc.get("proxies") or []
                items = [
                    {
                        "id": f"pub-{i}",
                        "name": f"公益-{p.get('name', i)}",
                        "proxy": p,
                    }
                    for i, p in enumerate(raw_list[:15], start=1)
                    if isinstance(p, dict)
                ]
                if items:
                    for item in items:
                        item["proxy"]["name"] = item["name"]
                    self._write_json(self.public_backup_file, items)
            except Exception:
                pass
        return items

    def get_warp_endpoints(self) -> list[dict[str, Any]]:
        raw = self._read_json(self.warp_endpoints_file, [])
        return warp_client.normalize_warp_endpoints(raw)

    def get_exits(self) -> list[dict[str, Any]]:
        return self._read_json(self.exits_file, [])

    def get_vpngate_nodes(self) -> list[dict[str, Any]]:
        return self._read_json(self.vpngate_file, [])

    def download_core(self, force: bool = False) -> dict[str, Any]:
        if self.core_dl_state.get("downloading"):
            raise RuntimeError("内核正在下载中，请稍候")

        self.core_dl_state = {
            "downloading": True,
            "message": "准备下载...",
            "progress": 5,
            "error": "",
        }
        try:
            def _progress(msg: str, pct: int) -> None:
                self.core_dl_state["message"] = msg
                self.core_dl_state["progress"] = pct

            res = core_updater.download_core_assets(
                self.mgr.core_dir,
                proxy_url=self._active_or_sys_proxy(),
                force=force,
                progress_cb=_progress,
                include_xray=True,
            )
            self.core_dl_state["downloading"] = False
            return res
        except Exception as exc:
            self.core_dl_state = {
                "downloading": False,
                "message": "下载失败",
                "progress": 0,
                "error": str(exc),
            }
            raise

    def refresh_vpngate(self) -> dict[str, Any]:
        """拉取最新免费住宅家宽节点（优先用当前通道，未连接时自动后台借用免费前置拉取）。"""
        used_relay = False
        if self.mgr.is_running():
            nodes = vpngate.fetch_vpngate_nodes(proxy_url=f"http://127.0.0.1:{self.mgr.mixed_port}")
        else:
            px = win_proxy.get_active_proxy_url(self_port=self.mgr.mixed_port)
            try:
                nodes = vpngate.fetch_vpngate_nodes(proxy_url=px, timeout=6.0)
            except Exception:
                used_relay = True
                settings = self.get_settings()
                underlays = self.assemble_underlays(settings)
                if not underlays:
                    # 即使用户选了直连或自定义为空，拉取家宽时也自动临时兜底使用免费前置
                    fallback_s = dict(settings, underlay_strategy="auto_free")
                    underlays = self.assemble_underlays(fallback_s)
                if not underlays:
                    raise RuntimeError("未能准备可用的免费前置节点用于拉取家宽列表，请先在「加速线路」拉取节点")

                cfg = self.mgr.build_config(
                    {"proxy_mode": "system", "route_mode": "global", "exit_mode": "direct_underlay", "underlay_strategy": "auto_free"},
                    underlays,
                    None,
                )

                def _fetch_via_temp_relay(base_url: str, mixed: int) -> list[dict[str, Any]]:
                    # 并发挑出几个当前真可用的前置节点，依次尝试拉取家宽列表
                    proxy_names = [p["name"] for p in cfg["proxies"][:12]]
                    alive_cands: list[tuple[int, str]] = []
                    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                        futs = {pool.submit(self.mgr.test_node_delay, pn, 3500, base_url): pn for pn in proxy_names}
                        for fut, pn in futs.items():
                            ms = fut.result()
                            if isinstance(ms, int) and ms > 0:
                                alive_cands.append((ms, pn))
                    alive_cands.sort()
                    try_names = [pn for _, pn in alive_cands[:4]] or proxy_names[:3]
                    last_exc: Exception | None = None
                    for pn in try_names:
                        try:
                            encoded = urllib.parse.quote("前置通道", safe="")
                            self.mgr._api_request(
                                f"/proxies/{encoded}",
                                method="PUT",
                                payload={"name": pn},
                                timeout=2.0,
                                base_url=base_url,
                            )
                            return vpngate.fetch_vpngate_nodes(
                                proxy_url=f"http://127.0.0.1:{mixed}",
                                timeout=10.0,
                            )
                        except Exception as exc:
                            last_exc = exc
                    raise RuntimeError(f"通过前置节点拉取免费住宅家宽失败: {last_exc}")

                nodes = self.mgr.run_temp_mihomo(cfg, _fetch_via_temp_relay)

        self._write_json(self.vpngate_file, nodes)
        s = self.get_settings()
        if nodes and not s.get("selected_vpngate_id"):
            self.save_settings({"selected_vpngate_id": nodes[0]["id"]})
        res_cnt = sum(1 for n in nodes if n.get("line_class") == "residential")
        return {"count": len(nodes), "residential_count": res_cnt, "used_relay": used_relay}

    def ensure_warp_nodes(self, use_awg: bool = True, rescan: bool = False, probe: bool = True) -> list[dict[str, Any]]:
        sys_px = self._active_or_sys_proxy()
        acct = warp_client.ensure_warp_account(self.warp_account_file, proxy_url=sys_px)
        eps = self.get_warp_endpoints()
        if rescan or not eps:
            sample_count = 16 if (rescan and probe and self.mgr.exe_path.exists()) else 10
            sampled = warp_client.sample_warp_endpoints(sample_count)
            eps = [{"ip": ip, "port": port, "delay_ms": None} for ip, port in sampled]

            if rescan and probe and self.mgr.exe_path.exists():
                ep_tuples = [(e["ip"], e["port"]) for e in eps]
                proxies = warp_client.build_warp_proxies(acct, ep_tuples, use_awg=use_awg)
                cfg = self.mgr.build_config(
                    {"proxy_mode": "system", "route_mode": "global", "exit_mode": "direct_underlay"},
                    proxies,
                    None,
                )
                delays = self.mgr.probe_proxies_with_temp(
                    cfg,
                    [p["name"] for p in proxies],
                    timeout_ms=4500,
                    max_workers=8,
                )
                for e, p in zip(eps, proxies):
                    ms = delays.get(p["name"])
                    e["delay_ms"] = ms if ms is not None else -1
                eps.sort(key=lambda x: (0 if (isinstance(x["delay_ms"], int) and x["delay_ms"] > 0) else 1, x["delay_ms"] or 99999))
                eps = eps[:10]

            self._write_json(self.warp_endpoints_file, eps)

        ep_tuples = [(str(e["ip"]), int(e["port"])) for e in eps]
        return warp_client.build_warp_proxies(acct, ep_tuples, use_awg=use_awg)

    def assemble_underlays(self, settings: dict[str, Any]) -> list[dict[str, Any]]:
        strategy = settings.get("underlay_strategy", "auto_free")
        use_awg = bool(settings.get("use_awg", True))
        enable_pub = bool(settings.get("enable_public_backup", True))

        if strategy == "direct":
            return []

        custom_nodes = [item["proxy"] for item in self.get_custom_underlays() if isinstance(item, dict) and "proxy" in item]
        sub_nodes: list[dict[str, Any]] = []
        for sub in self.get_underlay_subs():
            for p in sub.get("nodes", []):
                if isinstance(p, dict):
                    sub_nodes.append(p)

        user_all = custom_nodes + sub_nodes

        if strategy == "custom_only":
            return user_all

        def _get_pub() -> list[dict[str, Any]]:
            pub_items = self.get_public_backups()
            if not pub_items:
                try:
                    self.refresh_public_backups()
                    pub_items = self.get_public_backups()
                except Exception:
                    pub_items = []
            return [item["proxy"] for item in pub_items if isinstance(item, dict) and "proxy" in item]

        if strategy == "public_only":
            return _get_pub()

        warp_nodes: list[dict[str, Any]] = []
        try:
            warp_nodes = self.ensure_warp_nodes(use_awg=use_awg, rescan=False, probe=False)
        except Exception:
            warp_nodes = []

        if strategy == "warp_only":
            return warp_nodes

        pub_nodes = _get_pub() if enable_pub else []

        if strategy == "auto_free":
            return warp_nodes + pub_nodes

        # auto 或 manual：混合 用户自建/订阅 + WARP + 公益备胎
        return user_all + warp_nodes + pub_nodes

    def _run_vpngate_probe(self, candidates: list[dict[str, Any]]) -> dict[str, int | None]:
        """用独立临时端口测试一批 VPN Gate 节点经由前置通道的真实连通延迟。"""
        if not candidates:
            return {}
        settings = self.get_settings()
        is_direct = settings.get("underlay_strategy") == "direct"
        if is_direct:
            obs: list[dict[str, Any]] = []
            alias_to_id: dict[str, str] = {}
            for idx, n in enumerate(candidates):
                ob = vpngate.build_mihomo_openvpn_outbound(n)
                alias = f"VG_PROBE_{idx}"
                ob["name"] = alias
                obs.append(ob)
                alias_to_id[alias] = str(n["id"])
            cfg = self.mgr.build_config(
                {"proxy_mode": "system", "route_mode": "global", "exit_mode": "direct_underlay", "underlay_strategy": "auto_free"},
                obs,
                None,
            )
        else:
            underlays = self.assemble_underlays(settings)
            cfg = self.mgr.build_config(
                {"proxy_mode": "system", "route_mode": "global", "exit_mode": "direct_underlay", "underlay_strategy": "auto_free"},
                underlays,
                None,
            )
            alias_to_id = {}
            for idx, n in enumerate(candidates):
                ob = vpngate.build_mihomo_openvpn_outbound(n)
                alias = f"VG_PROBE_{idx}"
                ob["name"] = alias
                ob["dialer-proxy"] = "前置通道"
                cfg["proxies"].append(ob)
                alias_to_id[alias] = str(n["id"])

        raw_delays = self.mgr.probe_proxies_with_temp(
            cfg,
            list(alias_to_id.keys()),
            timeout_ms=6500,
            max_workers=6,
        )
        return {alias_to_id[alias]: ms for alias, ms in raw_delays.items()}

    def test_vpngate_nodes(
        self,
        country: str = "ALL",
        max_test: int = 12,
        node_id: str = "",
    ) -> dict[str, Any]:
        nodes = self.get_vpngate_nodes()
        if not nodes:
            self.refresh_vpngate()
            nodes = self.get_vpngate_nodes()

        max_test = max(1, min(int(max_test or 12), 40))

        if node_id:
            targets = [n for n in nodes if str(n.get("id")) == node_id]
            if not targets:
                raise ValueError("未找到指定的 VPN Gate 节点")
        else:
            pool_list = [
                n for n in nodes
                if (country in ("", "ALL") or n.get("country_short") == country)
            ]
            res_first = [n for n in pool_list if n.get("line_class") == "residential"]
            dc_rest = [n for n in pool_list if n.get("line_class") != "residential"]
            targets = (res_first + dc_rest)[:max_test]

        if not targets:
            raise ValueError("当前筛选条件下没有可测试的 VPN Gate 节点")

        delays = self._run_vpngate_probe(targets)
        for n in nodes:
            nid = str(n.get("id", ""))
            if nid in delays:
                ms = delays[nid]
                n["delay_ms"] = ms if ms is not None else -1

        def _sort_key(n: dict[str, Any]) -> tuple[int, float, float]:
            ms = n.get("delay_ms")
            sp = float(n.get("speed_mbps") or 0)
            if isinstance(ms, int) and ms > 0:
                return (0, -sp, float(ms))
            if ms == -1:
                return (2, -sp, 99999.0)
            return (1, -sp, 99999.0)

        if not node_id:
            nodes.sort(key=_sort_key)
        self._write_json(self.vpngate_file, nodes)

        if node_id:
            ms = delays.get(node_id)
            return {
                "tested": 1,
                "alive": 1 if ms is not None else 0,
                "best_name": targets[0]["name"],
                "best_ms": ms,
            }

        alive = [n for n in nodes if isinstance(n.get("delay_ms"), int) and n["delay_ms"] > 0]
        if country not in ("", "ALL"):
            alive_filtered = [n for n in alive if n.get("country_short") == country]
            if alive_filtered:
                alive = alive_filtered

        best = alive[0] if alive else None
        if best:
            self.save_settings({"selected_vpngate_id": best["id"]})
            if self.mgr.is_running() and self.get_settings().get("use_exit_hop"):
                self.connect()
        return {
            "tested": len(targets),
            "alive": len([v for v in delays.values() if v is not None]),
            "best_name": best["name"] if best else "",
            "best_ms": best["delay_ms"] if best else None,
        }

    def test_custom_underlays(self, item_id: str = "", test_speed: bool = False) -> dict[str, Any]:
        return self.test_hop1_pool(kind="custom", target_id=item_id, test_speed=test_speed)

    def test_hop1_pool(
        self,
        kind: str = "all",
        target_id: str = "",
        node_name: str = "",
        test_speed: bool = True,
    ) -> dict[str, Any]:
        """对第一跳节点（自建/订阅/公益/WARP）测延迟及真实下载速度 (Mbps) 并持久化结果。"""
        settings = self.get_settings()
        use_awg = bool(settings.get("use_awg", True))

        custom_items = self.get_custom_underlays()
        subs = self.get_underlay_subs()
        pub_items = self.get_public_backups()
        warp_eps = self.get_warp_endpoints()

        warp_proxies: list[dict[str, Any]] = []
        if kind in ("all", "free", "warp") and warp_eps:
            try:
                warp_proxies = self.ensure_warp_nodes(use_awg=use_awg, rescan=False, probe=False)
            except Exception:
                warp_proxies = []

        # 收集待测节点并映射到写回目标
        probes: list[tuple[str, dict[str, Any], tuple[str, Any]]] = []

        if kind in ("all", "user", "custom"):
            for item in custom_items:
                if target_id and item.get("id") != target_id:
                    continue
                if node_name and item.get("name") != node_name:
                    continue
                if isinstance(item.get("proxy"), dict):
                    probes.append((f"H1_C_{len(probes)}", item["proxy"], ("custom", item["id"])))

        if kind in ("all", "user", "sub"):
            for s_idx, sub in enumerate(subs):
                for n_idx, n in enumerate(sub.get("nodes", [])):
                    if not isinstance(n, dict):
                        continue
                    if node_name and n.get("name") != node_name:
                        continue
                    probes.append((f"H1_S_{len(probes)}", n, ("sub", (s_idx, n_idx))))

        if kind in ("all", "free", "public"):
            if not pub_items and not node_name:
                try:
                    self.refresh_public_backups()
                    pub_items = self.get_public_backups()
                except Exception:
                    pass
            for item in pub_items:
                if target_id and item.get("id") != target_id:
                    continue
                if node_name and item.get("name") != node_name:
                    continue
                if isinstance(item.get("proxy"), dict):
                    probes.append((f"H1_P_{len(probes)}", item["proxy"], ("public", item["id"])))

        if kind in ("all", "free", "warp"):
            for w_idx, wp in enumerate(warp_proxies):
                if node_name and wp.get("name") != node_name:
                    continue
                probes.append((f"H1_W_{len(probes)}", wp, ("warp", w_idx)))

        if not probes:
            raise ValueError("当前没有可测速的前置/公益节点")

        # 构造临时测速配置，使 EXIT 可直接切换到每个别名节点测真实下载速度
        probe_proxies: list[dict[str, Any]] = []
        alias_map: dict[str, tuple[str, Any]] = {}
        for alias, raw_p, ref in probes:
            p = copy.deepcopy(raw_p)
            p["name"] = alias
            probe_proxies.append(p)
            alias_map[alias] = ref

        aliases = [a for a, _, _ in probes]
        cfg = self.mgr.build_config(
            {"proxy_mode": "system", "route_mode": "global", "exit_mode": "direct_underlay", "underlay_strategy": "auto_free"},
            probe_proxies,
            None,
        )
        # 确保 EXIT 可直接切到每个待测别名
        cfg["proxy-groups"][0]["proxies"] = list(aliases)

        metrics = self.mgr.probe_proxies_speed_and_delay(
            cfg,
            aliases,
            test_speed=test_speed,
            delay_timeout_ms=5000,
            max_speed_nodes=min(len(aliases), 8),
        )

        # 写回 delay_ms 和 speed_mbps
        delays_by_id: dict[str, int | None] = {}
        speeds_by_id: dict[str, float | None] = {}
        custom_changed = sub_changed = pub_changed = warp_changed = False

        for alias, (bucket, key) in alias_map.items():
            m = metrics.get(alias, {})
            ms = m.get("delay_ms")
            sp = m.get("speed_mbps")
            val_ms = ms if ms is not None else -1

            if bucket == "custom":
                delays_by_id[str(key)] = ms
                speeds_by_id[str(key)] = sp
                for item in custom_items:
                    if item.get("id") == key:
                        item["delay_ms"] = val_ms
                        if sp is not None:
                            item["speed_mbps"] = sp
                        custom_changed = True
            elif bucket == "sub":
                s_idx, n_idx = key
                n = subs[s_idx]["nodes"][n_idx]
                n["delay_ms"] = val_ms
                if sp is not None:
                    n["speed_mbps"] = sp
                sub_changed = True
            elif bucket == "public":
                delays_by_id[str(key)] = ms
                speeds_by_id[str(key)] = sp
                for item in pub_items:
                    if item.get("id") == key:
                        item["delay_ms"] = val_ms
                        if sp is not None:
                            item["speed_mbps"] = sp
                        pub_changed = True
            elif bucket == "warp":
                if 0 <= int(key) < len(warp_eps):
                    warp_eps[int(key)]["delay_ms"] = val_ms
                    if sp is not None:
                        warp_eps[int(key)]["speed_mbps"] = sp
                    warp_changed = True

        def _rank_key(item: dict[str, Any]) -> tuple[int, float, float]:
            ms = item.get("delay_ms")
            sp = float(item.get("speed_mbps") or 0)
            if isinstance(ms, int) and ms > 0:
                return (0, -sp, float(ms))
            if ms == -1:
                return (2, 0.0, 99999.0)
            return (1, 0.0, 99999.0)

        if custom_changed:
            if not target_id and not node_name:
                custom_items.sort(key=_rank_key)
            self._write_json(self.custom_underlay_file, custom_items)
        if sub_changed:
            if not target_id and not node_name:
                for sub in subs:
                    if isinstance(sub.get("nodes"), list):
                        sub["nodes"].sort(key=_rank_key)
            self._write_json(self.underlay_subs_file, subs)
        if pub_changed:
            if not target_id and not node_name:
                pub_items.sort(key=_rank_key)
            self._write_json(self.public_backup_file, pub_items)
        if warp_changed:
            if not target_id and not node_name:
                warp_eps.sort(key=_rank_key)
            self._write_json(self.warp_endpoints_file, warp_eps)

        # 找出所有参与测速的节点中最优的一条（速度优先，其次延迟）
        best_name = ""
        best_ms: int | None = None
        best_mbps: float | None = None
        best_score = (9, 0.0, 99999.0)
        for alias, (bucket, key) in alias_map.items():
            m = metrics.get(alias, {})
            ms = m.get("delay_ms")
            if not isinstance(ms, int) or ms <= 0:
                continue
            sp = float(m.get("speed_mbps") or 0)
            cand_score = (0, -sp, float(ms))
            if cand_score < best_score:
                best_score = cand_score
                best_ms = ms
                best_mbps = m.get("speed_mbps")
                if bucket == "custom":
                    best_name = next((x["name"] for x in custom_items if x.get("id") == key), "")
                elif bucket == "sub":
                    s_idx, n_idx = key
                    best_name = subs[s_idx]["nodes"][n_idx].get("name", "")
                elif bucket == "public":
                    best_name = next((x["name"] for x in pub_items if x.get("id") == key), "")
                elif bucket == "warp":
                    prefix = "WARP-AWG" if use_awg else "WARP-WG"
                    best_name = f"{prefix}-{int(key) + 1:02d}"

        alive_cnt = sum(1 for m in metrics.values() if isinstance(m.get("delay_ms"), int) and m["delay_ms"] > 0)
        return {
            "tested": len(aliases),
            "alive": alive_cnt,
            "delays": delays_by_id,
            "speeds": speeds_by_id,
            "best_name": best_name,
            "best_ms": best_ms,
            "best_mbps": best_mbps,
        }

    def pull_free_underlays(self, auto_test: bool = False) -> dict[str, Any]:
        """一键拉取免费加速节点：WARP 端点池 + 公益节点（可选随后测速优选）。"""
        use_awg = bool(self.get_settings().get("use_awg", True))
        warp_count = 0
        pub_count = 0
        warnings: list[str] = []

        try:
            warp_nodes = self.ensure_warp_nodes(use_awg=use_awg, rescan=True, probe=False)
            warp_count = len(warp_nodes)
        except Exception as exc:
            warnings.append(f"WARP: {exc}")

        try:
            pub_res = self.refresh_public_backups()
            pub_count = int(pub_res.get("count", 0))
        except Exception as exc:
            warnings.append(f"公益: {exc}")

        if warp_count == 0 and pub_count == 0:
            raise RuntimeError("；".join(warnings) or "未能拉取到任何免费节点")

        alive = 0
        tested = 0
        best_name = ""
        best_ms: int | None = None
        best_mbps: float | None = None
        if auto_test and self.mgr.exe_path.exists():
            try:
                probe_res = self.test_hop1_pool(kind="all", test_speed=True)
                alive = int(probe_res.get("alive", 0))
                tested = int(probe_res.get("tested", 0))
                best_name = str(probe_res.get("best_name") or "")
                best_ms = probe_res.get("best_ms")
                best_mbps = probe_res.get("best_mbps")
            except Exception as exc:
                warnings.append(f"测速优选: {exc}")

        return {
            "warp_count": warp_count,
            "public_count": pub_count,
            "tested": tested,
            "alive": alive,
            "best_name": best_name,
            "best_ms": best_ms,
            "best_mbps": best_mbps,
            "warnings": warnings,
        }

    def test_exits(self, item_id: str = "") -> dict[str, Any]:
        exits = self.get_exits()
        targets = [x for x in exits if not item_id or x.get("id") == item_id]
        if not targets:
            raise ValueError("没有可测速的私人住宅 IP")

        settings = self.get_settings()
        is_direct = settings.get("underlay_strategy") == "direct"
        alias_to_id: dict[str, str] = {}
        if is_direct:
            obs: list[dict[str, Any]] = []
            for idx, item in enumerate(targets):
                ob = copy.deepcopy(item["proxy"])
                alias = f"EXIT_PROBE_{idx}"
                ob["name"] = alias
                obs.append(ob)
                alias_to_id[alias] = str(item["id"])
            cfg = self.mgr.build_config(
                {"proxy_mode": "system", "route_mode": "global", "exit_mode": "direct_underlay", "underlay_strategy": "auto_free"},
                obs,
                None,
            )
        else:
            underlays = self.assemble_underlays(settings)
            cfg = self.mgr.build_config(
                {"proxy_mode": "system", "route_mode": "global", "exit_mode": "direct_underlay", "underlay_strategy": "auto_free"},
                underlays,
                None,
            )
            for idx, item in enumerate(targets):
                ob = copy.deepcopy(item["proxy"])
                alias = f"EXIT_PROBE_{idx}"
                ob["name"] = alias
                ob["dialer-proxy"] = "前置通道"
                cfg["proxies"].append(ob)
                alias_to_id[alias] = str(item["id"])

        raw_delays = self.mgr.probe_proxies_with_temp(
            cfg,
            list(alias_to_id.keys()),
            timeout_ms=6500,
            max_workers=5,
        )
        id_delays = {alias_to_id[a]: ms for a, ms in raw_delays.items()}
        for item in exits:
            eid = str(item.get("id", ""))
            if eid in id_delays:
                ms = id_delays[eid]
                item["delay_ms"] = ms if ms is not None else -1
        self._write_json(self.exits_file, exits)
        alive = [ms for ms in id_delays.values() if ms is not None]
        return {"tested": len(targets), "alive": len(alive), "delays": id_delays}

    def get_active_exit_node(self, settings: dict[str, Any]) -> dict[str, Any] | None:
        emode = settings.get("exit_mode", "direct_underlay")
        if emode == "residential":
            sel_id = settings.get("selected_exit_id", "")
            exits = self.get_exits()
            for item in exits:
                if item.get("id") == sel_id:
                    return item.get("proxy")
            return exits[0].get("proxy") if exits else None
        if emode == "vpngate":
            sel_id = settings.get("selected_vpngate_id", "")
            vg_nodes = self.get_vpngate_nodes()
            target = None
            for n in vg_nodes:
                if n.get("id") == sel_id:
                    target = n
                    break
            if target is None and vg_nodes:
                target = vg_nodes[0]
            if target is None:
                return None
            return vpngate.build_mihomo_openvpn_outbound(target)
        return None

    def smart_select_best(self, apply_if_running: bool = True) -> dict[str, Any]:
        """智能优选：刷新可用节点 -> 并发测延迟与下载速度 -> 选中并热切换到最优节点。"""
        if not self._smart_lock.acquire(blocking=False):
            return {"ok": True, "skipped": True, "summary": self.smart_state.get("last_summary", "")}

        self.smart_state["running"] = True
        try:
            s = self.get_settings()
            strategy = str(s.get("underlay_strategy", "auto_free"))
            best_underlay = ""
            best_ms: int | None = None
            best_mbps: float | None = None
            parts: list[str] = []

            if strategy != "direct":
                if strategy in ("auto_free", "warp_only", "public_only", "auto"):
                    try:
                        self.pull_free_underlays(auto_test=False)
                    except Exception:
                        pass

                kind = {
                    "auto_free": "free",
                    "custom_only": "user",
                    "warp_only": "warp",
                    "public_only": "public",
                }.get(strategy, "all")

                if self.mgr.exe_path.exists():
                    try:
                        probe = self.test_hop1_pool(kind=kind, test_speed=True)
                        best_underlay = str(probe.get("best_name") or "")
                        best_ms = probe.get("best_ms")
                        best_mbps = probe.get("best_mbps")
                        if best_underlay:
                            spd_txt = f" · {best_mbps} Mbps" if best_mbps else ""
                            parts.append(f"加速: {best_underlay} ({best_ms}ms{spd_txt})")
                            if apply_if_running and self.mgr.is_running():
                                self.mgr.select_underlay(best_underlay)
                    except Exception:
                        pass

            best_exit = ""
            if s.get("use_exit_hop") and s.get("exit_source") == "vpngate" and self.mgr.exe_path.exists():
                try:
                    self.refresh_vpngate()
                    vg_res = self.test_vpngate_nodes(max_test=12)
                    best_exit = str(vg_res.get("best_name") or "")
                    if best_exit:
                        parts.append(f"家宽: {best_exit} ({vg_res.get('best_ms')}ms)")
                except Exception:
                    pass

            summary = " | ".join(parts) if parts else "暂无可用测速结果"
            now = time.time()
            self.smart_state = {
                "running": False,
                "last_run_ts": now,
                "last_run_at": time.strftime("%H:%M", time.localtime(now)),
                "last_summary": summary,
            }
            return {
                "ok": True,
                "best_underlay": best_underlay,
                "best_ms": best_ms,
                "best_mbps": best_mbps,
                "best_exit": best_exit,
                "summary": summary,
            }
        finally:
            self.smart_state["running"] = False
            self._smart_lock.release()

    def start_smart_scheduler(self, interval_sec: int = 3600) -> None:
        if self._scheduler_started:
            return
        self._scheduler_started = True

        def _loop() -> None:
            while True:
                time.sleep(60)
                try:
                    s = self.get_settings()
                    if not s.get("smart_auto_select"):
                        continue
                    last_ts = float(self.smart_state.get("last_run_ts") or 0.0)
                    if last_ts == 0.0:
                        self.smart_state["last_run_ts"] = time.time()
                        continue
                    if time.time() - last_ts >= interval_sec:
                        self.smart_select_best(apply_if_running=True)
                except Exception:
                    pass

        threading.Thread(target=_loop, daemon=True).start()

    def connect(self, smart_pick: bool = False) -> dict[str, Any]:
        settings = self.get_settings()
        smart_best_underlay = ""
        if smart_pick and settings.get("smart_auto_select"):
            s_res = self.smart_select_best(apply_if_running=False)
            smart_best_underlay = str(s_res.get("best_underlay") or "")
            settings = self.get_settings()

        strategy = settings.get("underlay_strategy", "auto_free")
        emode = settings.get("exit_mode", "direct_underlay")
        if strategy == "direct" and emode == "direct_underlay":
            raise ValueError("第一跳设为“直连”时，请开启第二跳并选择一个落地节点。")

        underlays = self.assemble_underlays(settings)
        if emode == "vpngate" and not self.get_vpngate_nodes():
            self.refresh_vpngate()
        exit_node = self.get_active_exit_node(settings)
        if emode == "residential" and exit_node is None:
            raise ValueError("已开启第二跳“我的私人住宅 IP”，请先添加一个住宅 IP。")
        if emode == "vpngate" and exit_node is None:
            raise ValueError("VPN Gate 节点列表为空，请先刷新家宽列表。")

        extra_exits: list[dict[str, Any]] = []
        cand_id_by_ob_name: dict[str, str] = {}
        if emode == "vpngate" and exit_node is not None:
            sel_id = settings.get("selected_vpngate_id", "")
            vg_nodes = self.get_vpngate_nodes()
            res_cands = [n for n in vg_nodes if n.get("line_class") == "residential" and n.get("id") != sel_id]
            dc_cands = [n for n in vg_nodes if n.get("line_class") != "residential" and n.get("id") != sel_id]
            for idx, cand in enumerate((res_cands + dc_cands)[:5], start=1):
                ob = vpngate.build_mihomo_openvpn_outbound(cand)
                ob["name"] = f"{cand['name']} (备{idx})"
                extra_exits.append(ob)
                cand_id_by_ob_name[f"落地-{ob['name']}"] = str(cand["id"])

        patched_settings = dict(settings)
        if emode == "vpngate":
            patched_settings["exit_mode"] = "residential"
        res = self.mgr.start(patched_settings, underlays, exit_node, extra_exit_nodes=extra_exits)
        if smart_best_underlay and strategy != "direct":
            self.mgr.select_underlay(smart_best_underlay)

        if emode == "vpngate" and exit_node is not None:
            primary_proxy_name = f"落地-{exit_node.get('name', '住宅IP')}"
            ms = self.mgr.test_node_delay(primary_proxy_name, timeout_ms=7000)
            if ms is None and cand_id_by_ob_name:
                def _test_alt(pname: str) -> tuple[str, int | None]:
                    return pname, self.mgr.test_node_delay(pname, timeout_ms=7000)

                best_name = ""
                best_ms = 999999
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
                    for pname, alt_ms in pool.map(_test_alt, list(cand_id_by_ob_name.keys())):
                        if alt_ms is not None and alt_ms < best_ms:
                            best_ms = alt_ms
                            best_name = pname
                if best_name:
                    self.mgr.select_exit(best_name)
                    new_id = cand_id_by_ob_name[best_name]
                    self.save_settings({"selected_vpngate_id": new_id})
                    res["auto_switched"] = best_name
                    res["delay_ms"] = best_ms
            elif ms is not None:
                res["delay_ms"] = ms
        return res

    def disconnect(self) -> dict[str, Any]:
        self.mgr.stop()
        return {"ok": True}

    def diagnose(self) -> dict[str, Any]:
        return self.mgr.diagnose_chain(self.get_settings())

    def select_underlay(self, name: str) -> dict[str, Any]:
        target = name.strip()
        if not target:
            raise ValueError("前置节点名称不能为空")
        new_s = self.save_settings({"underlay_strategy": "manual", "selected_underlay": target})
        if self.mgr.is_running():
            if not self.mgr.select_underlay(target):
                self.connect()
        return {"ok": True, "settings": new_s}

    def add_custom_underlays(self, text: str) -> dict[str, Any]:
        added = 0
        items = self.get_custom_underlays()
        parsed_list: list[dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            p = node_parser.parse_proxy_uri(line) or node_parser.parse_residential_line(line)
            if p:
                parsed_list.append(p)
        if not parsed_list and text.strip():
            parsed_list = node_parser.parse_subscription_content(text)
        for p in parsed_list:
            items.append({
                "id": uuid.uuid4().hex[:8],
                "name": p.get("name", "自定义前置"),
                "type": p.get("type", ""),
                "server": p.get("server", ""),
                "port": p.get("port", ""),
                "proxy": p,
            })
            added += 1
        if added == 0:
            raise ValueError("未识别到有效的节点链接（支持 vless/vmess/trojan/ss/hy2/socks5/http/YAML/Base64）")
        self._write_json(self.custom_underlay_file, items)
        return {"added": added}

    def edit_custom_underlay(self, item_id: str, name: str) -> None:
        new_name = name.strip()
        if not new_name:
            raise ValueError("节点名称不能为空")
        items = self.get_custom_underlays()
        found = False
        for item in items:
            if item.get("id") == item_id:
                item["name"] = new_name
                if isinstance(item.get("proxy"), dict):
                    item["proxy"]["name"] = new_name
                found = True
                break
        if not found:
            raise ValueError("未找到指定前置节点")
        self._write_json(self.custom_underlay_file, items)

    def delete_custom_underlay(self, item_id: str) -> None:
        items = [x for x in self.get_custom_underlays() if x.get("id") != item_id]
        self._write_json(self.custom_underlay_file, items)

    def add_underlay_sub(self, name: str, url: str) -> dict[str, Any]:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            raise ValueError("请输入以 http:// 或 https:// 开头的订阅链接")
        px = self._active_or_sys_proxy()
        nodes = node_parser.fetch_subscription(url, proxy_url=px)
        subs = self.get_underlay_subs()
        sub_name = name.strip() or f"订阅-{len(subs)+1}"
        for n in nodes:
            n["name"] = f"[{sub_name}] {n.get('name', '节点')}"
        subs.append({
            "id": uuid.uuid4().hex[:8],
            "name": sub_name,
            "url": url,
            "count": len(nodes),
            "nodes": nodes,
            "updated_at": time.strftime("%Y-%m-%d %H:%M"),
        })
        self._write_json(self.underlay_subs_file, subs)
        return {"count": len(nodes)}

    def refresh_underlay_subs(self) -> dict[str, Any]:
        subs = self.get_underlay_subs()
        px = self._active_or_sys_proxy()
        updated = 0
        for sub in subs:
            try:
                nodes = node_parser.fetch_subscription(sub["url"], proxy_url=px)
                for n in nodes:
                    n["name"] = f"[{sub['name']}] {n.get('name', '节点')}"
                sub["nodes"] = nodes
                sub["count"] = len(nodes)
                sub["updated_at"] = time.strftime("%Y-%m-%d %H:%M")
                updated += 1
            except Exception:
                pass
        self._write_json(self.underlay_subs_file, subs)
        return {"updated": updated, "total": len(subs)}

    def delete_underlay_sub(self, sub_id: str) -> None:
        subs = [s for s in self.get_underlay_subs() if s.get("id") != sub_id]
        self._write_json(self.underlay_subs_file, subs)

    def refresh_public_backups(self) -> dict[str, Any]:
        override_path = os.environ.get("WARP_RELAY_PUBLIC_YAML", "").strip()
        items: list[dict[str, Any]] = []
        if override_path and Path(override_path).is_file():
            doc = yaml.safe_load(Path(override_path).read_text(encoding="utf-8", errors="ignore")) or {}
            raw_list = doc.get("proxies") or []
            items = [
                {"id": f"pub-{i}", "name": f"公益-{p.get('name', i)}", "proxy": p}
                for i, p in enumerate(raw_list[:15], start=1)
                if isinstance(p, dict)
            ]
        else:
            px = self._active_or_sys_proxy()
            raw_list = node_parser.fetch_subscription(PUBLIC_REMOTE_URL, proxy_url=px)
            items = [
                {"id": f"pub-{i}", "name": f"公益-{p.get('name', i)}", "proxy": p}
                for i, p in enumerate(raw_list[:15], start=1)
            ]
        for item in items:
            item["proxy"]["name"] = item["name"]
        self._write_json(self.public_backup_file, items)
        return {"count": len(items)}

    def add_exit_node(self, raw_text: str, remark: str = "", default_type: str = "socks5") -> dict[str, Any]:
        exits = self.get_exits()
        added = 0
        last_id = ""
        for line in raw_text.splitlines():
            line = line.strip()
            if not line:
                continue
            p = node_parser.parse_residential_line(line, default_type=default_type, remark=remark)
            if p:
                eid = uuid.uuid4().hex[:8]
                exits.append({
                    "id": eid,
                    "name": p.get("name", "住宅IP"),
                    "type": p.get("type", default_type),
                    "server": p.get("server", ""),
                    "port": p.get("port", ""),
                    "proxy": p,
                })
                added += 1
                last_id = eid
        if added == 0:
            raise ValueError("未能识别该落地 IP 格式，请按 IP:端口:账号:密码 或 socks5://账号:密码@IP:端口 输入")
        self._write_json(self.exits_file, exits)
        if last_id:
            self.save_settings({"selected_exit_id": last_id, "exit_mode": "residential"})
        return {"added": added, "selected_exit_id": last_id}

    def edit_exit_node(self, item_id: str, name: str) -> None:
        new_name = name.strip()
        if not new_name:
            raise ValueError("住宅节点名称不能为空")
        exits = self.get_exits()
        found = False
        for item in exits:
            if item.get("id") == item_id:
                item["name"] = new_name
                if isinstance(item.get("proxy"), dict):
                    item["proxy"]["name"] = new_name
                found = True
                break
        if not found:
            raise ValueError("未找到指定的住宅节点")
        self._write_json(self.exits_file, exits)

    def delete_exit_node(self, item_id: str) -> None:
        exits = [x for x in self.get_exits() if x.get("id") != item_id]
        self._write_json(self.exits_file, exits)
        s = self.get_settings()
        if s.get("selected_exit_id") == item_id:
            self.save_settings({"selected_exit_id": exits[0]["id"] if exits else ""})

    def get_full_state(self, log_filter: str = "") -> dict[str, Any]:
        settings = self.get_settings()
        exits = self.get_exits()
        custom_underlays = self.get_custom_underlays()
        underlay_subs = [
            {k: v for k, v in s.items() if k != "nodes"}
            for s in self.get_underlay_subs()
        ]
        pub = self.get_public_backups()
        warp_eps = self.get_warp_endpoints()

        sub_underlays: list[dict[str, Any]] = []
        all_underlay_names: list[str] = []
        for x in custom_underlays:
            all_underlay_names.append(x["name"])
        for s in self.get_underlay_subs():
            for n in s.get("nodes", []):
                nm = n.get("name", "")
                if nm:
                    all_underlay_names.append(nm)
                    sub_underlays.append({
                        "name": nm,
                        "type": n.get("type", ""),
                        "server": n.get("server", ""),
                        "port": n.get("port", ""),
                        "delay_ms": n.get("delay_ms"),
                        "speed_mbps": n.get("speed_mbps"),
                    })
        for i, _ in enumerate(warp_eps, start=1):
            prefix = "WARP-AWG" if settings.get("use_awg", True) else "WARP-WG"
            all_underlay_names.append(f"{prefix}-{i:02d}")
        if settings.get("enable_public_backup", True):
            for x in pub:
                all_underlay_names.append(x.get("name", ""))

        public_backups_meta = [
            {
                "id": x.get("id", ""),
                "name": x.get("name", ""),
                "type": (x.get("proxy") or {}).get("type", ""),
                "server": (x.get("proxy") or {}).get("server", ""),
                "port": (x.get("proxy") or {}).get("port", ""),
                "delay_ms": x.get("delay_ms"),
                "speed_mbps": x.get("speed_mbps"),
            }
            for x in pub
        ]

        return {
            "settings": settings,
            "is_admin": win_proxy.is_admin(),
            "core_status": self.mgr.get_core_status(),
            "core_download": dict(self.core_dl_state),
            "smart_status": dict(self.smart_state),
            "runtime": self.mgr.get_runtime_status(),
            "warp": {
                "has_account": self.warp_account_file.exists(),
                "endpoint_count": len(warp_eps),
                "endpoints": warp_eps,
            },
            "custom_underlays": [{k: v for k, v in x.items() if k != "proxy"} for x in custom_underlays],
            "sub_underlays": sub_underlays,
            "underlay_subs": underlay_subs,
            "public_backups": public_backups_meta,
            "public_backups_count": len(pub),
            "underlay_names": all_underlay_names,
            "exits": [{k: v for k, v in x.items() if k != "proxy"} for x in exits],
            "vpngate_nodes": [
                {k: v for k, v in n.items() if k != "profile"}
                for n in self.get_vpngate_nodes()
            ],
            "logs": self.mgr.read_logs(80, level_filter=log_filter),
        }


STORE = PanelStore()


def create_handler(store: PanelStore) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:
            pass

        def _send_json(self, obj: Any, status: int = 200) -> None:
            raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)

        def _read_body_json(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length <= 0:
                return {}
            raw = self.rfile.read(length).decode("utf-8", errors="ignore")
            return json.loads(raw) if raw.strip() else {}

        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            if parsed.path in ("/", "/index.html"):
                html_file = STATIC_DIR / "index.html"
                raw = html_file.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return

            if parsed.path == "/starbridge.png":
                png_file = STATIC_DIR / "starbridge.png"
                if png_file.exists():
                    raw = png_file.read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Type", "image/png")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    return

            if parsed.path == "/favicon.ico":
                ico_file = _get_icon_path()
                if ico_file and ico_file.exists():
                    raw = ico_file.read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Type", "image/x-icon")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    return

            if parsed.path == "/api/state":
                log_filter = (qs.get("log_filter") or [""])[0]
                self._send_json(store.get_full_state(log_filter=log_filter))
                return

            if parsed.path == "/api/core/status":
                self._send_json({
                    "ok": True,
                    "core_status": store.mgr.get_core_status(),
                    "core_download": dict(store.core_dl_state),
                })
                return

            if parsed.path == "/api/logs":
                level = (qs.get("level") or [""])[0]
                lines = int((qs.get("lines") or ["100"])[0] or 100)
                self._send_json({"ok": True, "logs": store.mgr.read_logs(lines, level_filter=level)})
                return

            self._send_json({"error": "Not Found"}, status=404)

        def do_POST(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            try:
                body = self._read_body_json()
                if path == "/api/settings":
                    new_s = store.save_settings(body)
                    if store.mgr.is_running() and body.get("auto_apply", True):
                        store.connect()
                    self._send_json({"ok": True, "settings": new_s})
                elif path == "/api/connect":
                    self._send_json(store.connect(smart_pick=bool(body.get("smart_pick", False))))
                elif path == "/api/smart_select":
                    self._send_json(store.smart_select_best(apply_if_running=True))
                elif path == "/api/disconnect":
                    self._send_json(store.disconnect())
                elif path == "/api/probe":
                    self._send_json(store.mgr.probe_exit_ip())
                elif path == "/api/diagnose":
                    self._send_json(store.diagnose())
                elif path == "/api/core/download":
                    res = store.download_core(force=bool(body.get("force", False)))
                    self._send_json(res)
                elif path == "/api/warp/scan":
                    use_awg = bool(store.get_settings().get("use_awg", True))
                    probe = bool(body.get("probe", True))
                    nodes = store.ensure_warp_nodes(use_awg=use_awg, rescan=True, probe=probe)
                    self._send_json({"ok": True, "count": len(nodes)})
                elif path == "/api/public/refresh":
                    res = store.refresh_public_backups()
                    self._send_json({"ok": True, **res})
                elif path == "/api/public/test":
                    res = store.test_hop1_pool(
                        kind="public",
                        target_id=str(body.get("id", "")),
                        test_speed=bool(body.get("test_speed", True)),
                    )
                    self._send_json({"ok": True, **res})
                elif path == "/api/vpngate/refresh":
                    res = store.refresh_vpngate()
                    if bool(body.get("auto_test", False)) and store.mgr.exe_path.exists():
                        try:
                            t_res = store.test_vpngate_nodes(
                                country=str(body.get("country", "ALL")),
                                max_test=int(body.get("max_test", 12)),
                            )
                            res.update(t_res)
                        except Exception:
                            pass
                    self._send_json({"ok": True, **res})
                elif path == "/api/vpngate/test":
                    res = store.test_vpngate_nodes(
                        country=str(body.get("country", "ALL")),
                        max_test=int(body.get("max_test", 12)),
                        node_id=str(body.get("node_id", "")),
                    )
                    self._send_json({"ok": True, **res})
                elif path == "/api/underlay/add":
                    res = store.add_custom_underlays(str(body.get("text", "")))
                    self._send_json({"ok": True, **res})
                elif path == "/api/underlay/pull":
                    res = store.pull_free_underlays(auto_test=bool(body.get("auto_test", False)))
                    self._send_json({"ok": True, **res})
                elif path == "/api/underlay/select":
                    self._send_json(store.select_underlay(str(body.get("name", ""))))
                elif path == "/api/underlay/edit":
                    store.edit_custom_underlay(str(body.get("id", "")), str(body.get("name", "")))
                    self._send_json({"ok": True})
                elif path == "/api/underlay/test":
                    res = store.test_hop1_pool(
                        kind=str(body.get("kind", "custom")),
                        target_id=str(body.get("id", "")),
                        node_name=str(body.get("name", "")),
                        test_speed=bool(body.get("test_speed", True)),
                    )
                    self._send_json({"ok": True, **res})
                elif path == "/api/underlay/test_all":
                    res = store.test_hop1_pool(
                        kind=str(body.get("kind", "all")),
                        test_speed=bool(body.get("test_speed", True)),
                    )
                    self._send_json({"ok": True, **res})
                elif path == "/api/underlay/delete":
                    store.delete_custom_underlay(str(body.get("id", "")))
                    self._send_json({"ok": True})
                elif path == "/api/underlay/sub/add":
                    res = store.add_underlay_sub(str(body.get("name", "")), str(body.get("url", "")))
                    self._send_json({"ok": True, **res})
                elif path == "/api/underlay/sub/refresh":
                    res = store.refresh_underlay_subs()
                    self._send_json({"ok": True, **res})
                elif path == "/api/underlay/sub/delete":
                    store.delete_underlay_sub(str(body.get("id", "")))
                    self._send_json({"ok": True})
                elif path == "/api/exit/add":
                    res = store.add_exit_node(
                        str(body.get("raw", "")),
                        remark=str(body.get("remark", "")),
                        default_type=str(body.get("default_type", "socks5")),
                    )
                    self._send_json({"ok": True, **res})
                elif path == "/api/exit/edit":
                    store.edit_exit_node(str(body.get("id", "")), str(body.get("name", "")))
                    self._send_json({"ok": True})
                elif path == "/api/exit/test":
                    res = store.test_exits(item_id=str(body.get("id", "")))
                    self._send_json({"ok": True, **res})
                elif path == "/api/exit/delete":
                    store.delete_exit_node(str(body.get("id", "")))
                    self._send_json({"ok": True})
                elif path == "/api/delay/test":
                    target = str(body.get("name", "EXIT"))
                    delay = store.mgr.test_node_delay(target)
                    self._send_json({"ok": delay is not None, "delay_ms": delay})
                elif path == "/api/elevate":
                    if win_proxy.is_admin():
                        self._send_json({"ok": True, "already_admin": True})
                        return
                    store.disconnect()
                    entry = BASE_DIR / "run_panel.py"
                    ok = win_proxy.relaunch_as_admin(entry)
                    if ok:
                        self._send_json({"ok": True})
                        def _quit_soon() -> None:
                            time.sleep(0.25)
                            os._exit(0)
                        threading.Thread(target=_quit_soon, daemon=True).start()
                    else:
                        self._send_json({"ok": False, "error": "未获得管理员授权"}, status=400)
                else:
                    self._send_json({"error": "Not Found"}, status=404)
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=400)

    return Handler


def _cleanup() -> None:
    try:
        STORE.mgr.stop()
    except Exception:
        pass


def main() -> None:
    atexit.register(_cleanup)
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, lambda *_: sys.exit(0))
        except Exception:
            pass

    STORE.start_smart_scheduler(interval_sec=3600)
    port = mihomo_mgr.pick_free_port(PANEL_PORT, attempts=20)
    server = ThreadingHTTPServer(("127.0.0.1", port), create_handler(STORE))
    url = f"http://127.0.0.1:{port}"
    print(f"极简中文控制台已启动: {url} (关闭窗口将自动断开并恢复网络)")

    srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
    srv_thread.start()

    use_browser = "--browser" in sys.argv
    if not use_browser:
        try:
            import webview  # type: ignore

            force_exit = False
            window = webview.create_window(
                "星桥 · StarBridge",
                url,
                width=920,
                height=620,
                min_size=(780, 540),
                background_color="#090e1a",
            )

            def _show_win() -> None:
                try:
                    window.restore()
                    window.show()
                except Exception:
                    pass

            def _toggle_conn() -> None:
                try:
                    if STORE.mgr.is_running():
                        STORE.disconnect()
                    else:
                        STORE.connect()
                except Exception:
                    pass

            def _force_quit() -> None:
                nonlocal force_exit
                force_exit = True
                try:
                    tray_icon.stop()
                except Exception:
                    pass
                _cleanup()
                try:
                    window.destroy()
                except Exception:
                    pass
                os._exit(0)

            tray_icon = tray.TrayIcon(
                tooltip="星桥 · StarBridge",
                on_show=_show_win,
                on_toggle=_toggle_conn,
                on_exit=_force_quit,
                is_connected_fn=STORE.mgr.is_running,
                icon_path=_get_icon_path(),
            )

            def _on_closing() -> bool:
                if not force_exit and STORE.get_settings().get("minimize_to_tray"):
                    try:
                        window.hide()
                    except Exception:
                        pass
                    return False
                return True

            window.events.closing += _on_closing
            tray_icon.start()
            webview.start()
            tray_icon.stop()
            _cleanup()
            server.shutdown()
            server.server_close()
            return
        except Exception as exc:
            print(f"桌面窗口初始化回退至浏览器模式: {exc}")

    if "--no-browser" not in sys.argv:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        while srv_thread.is_alive():
            srv_thread.join(timeout=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        _cleanup()
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
