"""本地 Web 控制面板服务端与状态管理。"""

from __future__ import annotations

import atexit
import concurrent.futures
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

from . import mihomo_mgr, node_parser, vpngate, warp_client, win_proxy

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
DATA_DIR = BASE_DIR / "data"
PUBLIC_LOCAL_ALL = Path(r"f:\antigravity\subs-check-auto\subs\all.yaml")
PUBLIC_REMOTE_URL = "https://raw.githubusercontent.com/359073395/subs-check-auto/main/subs/all.yaml"

PANEL_PORT = 19090

DEFAULT_SETTINGS: dict[str, Any] = {
    "proxy_mode": "system",          # system | tun
    "route_mode": "bypass_cn",       # bypass_cn | global
    "underlay_strategy": "auto",     # auto | custom_only | warp_only | manual
    "selected_underlay": "",
    "exit_mode": "vpngate",          # direct_underlay | vpngate | residential
    "selected_exit_id": "",
    "selected_vpngate_id": "",
    "use_awg": True,
    "enable_public_backup": True,
}


class PanelStore:
    def __init__(self) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.settings_file = DATA_DIR / "settings.json"
        self.warp_account_file = DATA_DIR / "warp_account.json"
        self.warp_endpoints_file = DATA_DIR / "warp_endpoints.json"
        self.custom_underlay_file = DATA_DIR / "custom_underlays.json"
        self.underlay_subs_file = DATA_DIR / "underlay_subs.json"
        self.public_backup_file = DATA_DIR / "public_backups.json"
        self.exits_file = DATA_DIR / "exits.json"
        self.vpngate_file = DATA_DIR / "vpngate_nodes.json"

        self._lock = threading.Lock()
        self.mgr = mihomo_mgr.MihomoManager(BASE_DIR)

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
                    s[k] = patch[k]
            self._write_json(self.settings_file, s)
            return s

    def get_custom_underlays(self) -> list[dict[str, Any]]:
        return self._read_json(self.custom_underlay_file, [])

    def get_underlay_subs(self) -> list[dict[str, Any]]:
        return self._read_json(self.underlay_subs_file, [])

    def get_public_backups(self) -> list[dict[str, Any]]:
        items = self._read_json(self.public_backup_file, [])
        if not items and PUBLIC_LOCAL_ALL.exists():
            try:
                doc = yaml.safe_load(PUBLIC_LOCAL_ALL.read_text(encoding="utf-8", errors="ignore")) or {}
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
                    self._write_json(self.public_backup_file, items)
            except Exception:
                pass
        return items

    def get_warp_endpoints(self) -> list[list[Any]]:
        return self._read_json(self.warp_endpoints_file, [])

    def get_exits(self) -> list[dict[str, Any]]:
        return self._read_json(self.exits_file, [])

    def get_vpngate_nodes(self) -> list[dict[str, Any]]:
        return self._read_json(self.vpngate_file, [])

    def refresh_vpngate(self) -> dict[str, Any]:
        """拉取最新 VPN Gate 家宽/志愿节点（优先用当前通道，未连接时自动临时借用 WARP 前置拉取）。"""
        if self.mgr.is_running():
            nodes = vpngate.fetch_vpngate_nodes(proxy_url=f"http://127.0.0.1:{mihomo_mgr.MIXED_PORT}")
        else:
            # 先尝试直连或系统代理，失败则临时启动纯前置通道拉取
            px = win_proxy.get_active_proxy_url()
            try:
                nodes = vpngate.fetch_vpngate_nodes(proxy_url=px)
            except Exception:
                settings = self.get_settings()
                temp_settings = dict(settings, proxy_mode="tun_off_temp", exit_mode="direct_underlay")
                # 启动纯本地端口（不修改系统代理）的临时 Mihomo 用于拉取 VPN Gate
                underlays = self.assemble_underlays(settings)
                cfg = self.mgr.build_config(
                    {"proxy_mode": "system", "route_mode": "global", "exit_mode": "direct_underlay"},
                    underlays,
                    None,
                )
                self.mgr.core_dir.mkdir(parents=True, exist_ok=True)
                self.mgr.config_path.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False), encoding="utf-8")
                import subprocess
                proc = subprocess.Popen(
                    [str(self.mgr.exe_path), "-d", str(self.mgr.core_dir), "-f", str(self.mgr.config_path)],
                    cwd=str(self.mgr.core_dir),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                try:
                    deadline = time.time() + 10.0
                    while time.time() < deadline:
                        try:
                            if self.mgr._api_request("/version", timeout=1.0):
                                break
                        except Exception:
                            time.sleep(0.25)
                    nodes = vpngate.fetch_vpngate_nodes(proxy_url=f"http://127.0.0.1:{mihomo_mgr.MIXED_PORT}")
                finally:
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except Exception:
                        proc.kill()

        self._write_json(self.vpngate_file, nodes)
        s = self.get_settings()
        if nodes and not s.get("selected_vpngate_id"):
            self.save_settings({"selected_vpngate_id": nodes[0]["id"]})
        res_cnt = sum(1 for n in nodes if n.get("line_class") == "residential")
        return {"count": len(nodes), "residential_count": res_cnt}

    def ensure_warp_nodes(self, use_awg: bool = True, rescan: bool = False) -> list[dict[str, Any]]:
        sys_px = win_proxy.get_active_proxy_url()
        acct = warp_client.ensure_warp_account(self.warp_account_file, proxy_url=sys_px)
        eps = self.get_warp_endpoints()
        if rescan or not eps:
            sampled = warp_client.sample_warp_endpoints(10)
            eps = [[ip, port] for ip, port in sampled]
            self._write_json(self.warp_endpoints_file, eps)
        ep_tuples = [(str(ip), int(port)) for ip, port in eps]
        return warp_client.build_warp_proxies(acct, ep_tuples, use_awg=use_awg)

    def assemble_underlays(self, settings: dict[str, Any]) -> list[dict[str, Any]]:
        strategy = settings.get("underlay_strategy", "auto")
        use_awg = bool(settings.get("use_awg", True))
        enable_pub = bool(settings.get("enable_public_backup", True))

        custom_nodes = [item["proxy"] for item in self.get_custom_underlays() if isinstance(item, dict) and "proxy" in item]
        sub_nodes: list[dict[str, Any]] = []
        for sub in self.get_underlay_subs():
            for p in sub.get("nodes", []):
                if isinstance(p, dict):
                    sub_nodes.append(p)

        user_all = custom_nodes + sub_nodes

        if strategy == "custom_only":
            return user_all

        warp_nodes: list[dict[str, Any]] = []
        try:
            warp_nodes = self.ensure_warp_nodes(use_awg=use_awg, rescan=False)
        except Exception:
            warp_nodes = []

        if strategy == "warp_only":
            return warp_nodes

        pub_nodes: list[dict[str, Any]] = []
        if enable_pub:
            pub_nodes = [item["proxy"] for item in self.get_public_backups() if isinstance(item, dict) and "proxy" in item]

        # auto 或 manual：混合 用户自建/订阅 + WARP + 公益备胎
        return user_all + warp_nodes + pub_nodes

    def _run_vpngate_probe(self, candidates: list[dict[str, Any]]) -> dict[str, int | None]:
        """用独立临时端口测试一批 VPN Gate 节点经由前置通道的真实连通延迟。"""
        import subprocess
        import urllib.request

        if not candidates:
            return {}
        underlays = self.assemble_underlays(self.get_settings())
        cfg = self.mgr.build_config(
            {"proxy_mode": "system", "route_mode": "global", "exit_mode": "direct_underlay"},
            underlays,
            None,
        )
        cfg["mixed-port"] = 17899
        cfg["external-controller"] = "127.0.0.1:19099"
        cfg["tun"]["enable"] = False

        alias_to_id: dict[str, str] = {}
        for idx, n in enumerate(candidates):
            ob = vpngate.build_mihomo_openvpn_outbound(n)
            alias = f"VG_PROBE_{idx}"
            ob["name"] = alias
            ob["dialer-proxy"] = "前置通道"
            cfg["proxies"].append(ob)
            alias_to_id[alias] = str(n["id"])

        probe_cfg = self.mgr.core_dir / "probe_config.yaml"
        self.mgr.core_dir.mkdir(parents=True, exist_ok=True)
        probe_cfg.write_text(yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False), encoding="utf-8")

        proc = subprocess.Popen(
            [str(self.mgr.exe_path), "-d", str(self.mgr.core_dir), "-f", str(probe_cfg)],
            cwd=str(self.mgr.core_dir),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        results: dict[str, int | None] = {}
        try:
            deadline = time.time() + 10.0
            while time.time() < deadline:
                try:
                    with opener.open("http://127.0.0.1:19099/version", timeout=1.0) as r:
                        if r.status == 200:
                            break
                except Exception:
                    time.sleep(0.25)

            def _probe_one(alias: str) -> tuple[str, int | None]:
                url = f"http://127.0.0.1:19099/proxies/{urllib.parse.quote(alias, safe='')}/delay?timeout=6500&url=http://cp.cloudflare.com/generate_204"
                try:
                    with opener.open(url, timeout=8.0) as resp:
                        data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                        return alias_to_id[alias], (int(data["delay"]) if "delay" in data else None)
                except Exception:
                    return alias_to_id[alias], None

            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                for nid, ms in pool.map(_probe_one, list(alias_to_id.keys())):
                    results[nid] = ms
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
            try:
                probe_cfg.unlink(missing_ok=True)
            except Exception:
                pass
        return results

    def test_vpngate_nodes(self, country: str = "ALL", max_test: int = 12) -> dict[str, Any]:
        nodes = self.get_vpngate_nodes()
        if not nodes:
            self.refresh_vpngate()
            nodes = self.get_vpngate_nodes()
        pool_list = [
            n for n in nodes
            if (country in ("", "ALL") or n.get("country_short") == country)
        ]
        # 优先测家宽节点
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

        def _sort_key(n: dict[str, Any]) -> tuple[int, int, float]:
            ms = n.get("delay_ms")
            is_res = 0 if n.get("line_class") == "residential" else 1
            if isinstance(ms, int) and ms > 0:
                return (0, is_res, float(ms))
            if ms == -1:
                return (2, is_res, -float(n.get("speed_mbps", 0)))
            return (1, is_res, -float(n.get("speed_mbps", 0)))

        nodes.sort(key=_sort_key)
        self._write_json(self.vpngate_file, nodes)

        alive = [n for n in nodes if isinstance(n.get("delay_ms"), int) and n["delay_ms"] > 0]
        if country not in ("", "ALL"):
            alive_filtered = [n for n in alive if n.get("country_short") == country]
            if alive_filtered:
                alive = alive_filtered

        best = alive[0] if alive else None
        if best:
            self.save_settings({"selected_vpngate_id": best["id"], "exit_mode": "vpngate"})
            if self.mgr.is_running():
                self.connect()
        return {
            "tested": len(targets),
            "alive": len([v for v in delays.values() if v is not None]),
            "best_name": best["name"] if best else "",
            "best_ms": best["delay_ms"] if best else None,
        }

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

    def connect(self) -> dict[str, Any]:
        settings = self.get_settings()
        underlays = self.assemble_underlays(settings)
        emode = settings.get("exit_mode", "direct_underlay")
        if emode == "vpngate" and not self.get_vpngate_nodes():
            self.refresh_vpngate()
        exit_node = self.get_active_exit_node(settings)
        if emode == "residential" and exit_node is None:
            raise ValueError("已选择“我的私有住宅 IP”，请先在自定义页面添加一个落地 IP。")
        if emode == "vpngate" and exit_node is None:
            raise ValueError("VPN Gate 节点列表为空，请先点击【刷新家宽列表】。")

        # vpngate 模式额外附带最多 5 个家宽备选，防止单个志愿节点掉线导致连不上
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

        # mihomo_mgr.build_config 将 vpngate 与 residential 均视为带 dialer-proxy 的落地出口
        patched_settings = dict(settings)
        if emode == "vpngate":
            patched_settings["exit_mode"] = "residential"
        res = self.mgr.start(patched_settings, underlays, exit_node, extra_exit_nodes=extra_exits)

        # 对 vpngate 进行轻量预热检查：若主选节点超时，自动切到可用的备选家宽节点
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

    def add_custom_underlays(self, text: str) -> dict[str, Any]:
        added = 0
        items = self.get_custom_underlays()
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            p = node_parser.parse_proxy_uri(line) or node_parser.parse_residential_line(line)
            if p:
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
            raise ValueError("未识别到有效的节点链接（支持 vless/vmess/trojan/ss/hy2/socks5/http）")
        self._write_json(self.custom_underlay_file, items)
        return {"added": added}

    def delete_custom_underlay(self, item_id: str) -> None:
        items = [x for x in self.get_custom_underlays() if x.get("id") != item_id]
        self._write_json(self.custom_underlay_file, items)

    def add_underlay_sub(self, name: str, url: str) -> dict[str, Any]:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            raise ValueError("请输入以 http:// 或 https:// 开头的订阅链接")
        px = win_proxy.get_active_proxy_url()
        if self.mgr.is_running():
            px = f"http://127.0.0.1:{mihomo_mgr.MIXED_PORT}"
        nodes = node_parser.fetch_subscription(url, proxy_url=px)
        subs = self.get_underlay_subs()
        sub_name = name.strip() or f"订阅-{len(subs)+1}"
        # 给订阅里的节点加上前缀，便于识别
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
        px = f"http://127.0.0.1:{mihomo_mgr.MIXED_PORT}" if self.mgr.is_running() else win_proxy.get_active_proxy_url()
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
        items: list[dict[str, Any]] = []
        if PUBLIC_LOCAL_ALL.exists():
            doc = yaml.safe_load(PUBLIC_LOCAL_ALL.read_text(encoding="utf-8", errors="ignore")) or {}
            raw_list = doc.get("proxies") or []
            items = [
                {"id": f"pub-{i}", "name": f"公益-{p.get('name', i)}", "proxy": p}
                for i, p in enumerate(raw_list[:15], start=1)
                if isinstance(p, dict)
            ]
        else:
            px = f"http://127.0.0.1:{mihomo_mgr.MIXED_PORT}" if self.mgr.is_running() else win_proxy.get_active_proxy_url()
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

    def delete_exit_node(self, item_id: str) -> None:
        exits = [x for x in self.get_exits() if x.get("id") != item_id]
        self._write_json(self.exits_file, exits)
        s = self.get_settings()
        if s.get("selected_exit_id") == item_id:
            self.save_settings({"selected_exit_id": exits[0]["id"] if exits else ""})

    def get_full_state(self) -> dict[str, Any]:
        settings = self.get_settings()
        exits = self.get_exits()
        custom_underlays = self.get_custom_underlays()
        underlay_subs = [
            {k: v for k, v in s.items() if k != "nodes"}
            for s in self.get_underlay_subs()
        ]
        pub = self.get_public_backups()
        warp_eps = self.get_warp_endpoints()

        # 汇总前置名称列表（供手动指定下拉框）
        all_underlay_names: list[str] = []
        for x in custom_underlays:
            all_underlay_names.append(x["name"])
        for s in self.get_underlay_subs():
            for n in s.get("nodes", []):
                all_underlay_names.append(n.get("name", ""))
        for i, _ in enumerate(warp_eps, start=1):
            prefix = "WARP-AWG" if settings.get("use_awg", True) else "WARP-WG"
            all_underlay_names.append(f"{prefix}-{i:02d}")
        if settings.get("enable_public_backup", True):
            for x in pub:
                all_underlay_names.append(x.get("name", ""))

        return {
            "settings": settings,
            "is_admin": win_proxy.is_admin(),
            "runtime": self.mgr.get_runtime_status(),
            "warp": {
                "has_account": self.warp_account_file.exists(),
                "endpoint_count": len(warp_eps),
                "endpoints": warp_eps,
            },
            "custom_underlays": [{k: v for k, v in x.items() if k != "proxy"} for x in custom_underlays],
            "underlay_subs": underlay_subs,
            "public_backups_count": len(pub),
            "underlay_names": all_underlay_names,
            "exits": [{k: v for k, v in x.items() if k != "proxy"} for x in exits],
            "vpngate_nodes": [
                {k: v for k, v in n.items() if k != "profile"}
                for n in self.get_vpngate_nodes()
            ],
            "logs": self.mgr.read_logs(40),
        }


STORE = PanelStore()


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
        if parsed.path in ("/", "/index.html"):
            html_file = STATIC_DIR / "index.html"
            raw = html_file.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        if parsed.path == "/api/state":
            self._send_json(STORE.get_full_state())
            return

        self._send_json({"error": "Not Found"}, status=404)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        try:
            body = self._read_body_json()
            if path == "/api/settings":
                new_s = STORE.save_settings(body)
                if STORE.mgr.is_running() and body.get("auto_apply", True):
                    STORE.connect()
                self._send_json({"ok": True, "settings": new_s})
            elif path == "/api/connect":
                res = STORE.connect()
                self._send_json(res)
            elif path == "/api/disconnect":
                self._send_json(STORE.disconnect())
            elif path == "/api/probe":
                self._send_json(STORE.mgr.probe_exit_ip())
            elif path == "/api/warp/scan":
                use_awg = bool(STORE.get_settings().get("use_awg", True))
                nodes = STORE.ensure_warp_nodes(use_awg=use_awg, rescan=True)
                self._send_json({"ok": True, "count": len(nodes)})
            elif path == "/api/public/refresh":
                res = STORE.refresh_public_backups()
                self._send_json({"ok": True, **res})
            elif path == "/api/vpngate/refresh":
                res = STORE.refresh_vpngate()
                self._send_json({"ok": True, **res})
            elif path == "/api/vpngate/test":
                res = STORE.test_vpngate_nodes(country=str(body.get("country", "ALL")))
                self._send_json({"ok": True, **res})
            elif path == "/api/underlay/add":
                res = STORE.add_custom_underlays(str(body.get("text", "")))
                self._send_json({"ok": True, **res})
            elif path == "/api/underlay/delete":
                STORE.delete_custom_underlay(str(body.get("id", "")))
                self._send_json({"ok": True})
            elif path == "/api/underlay/sub/add":
                res = STORE.add_underlay_sub(str(body.get("name", "")), str(body.get("url", "")))
                self._send_json({"ok": True, **res})
            elif path == "/api/underlay/sub/refresh":
                res = STORE.refresh_underlay_subs()
                self._send_json({"ok": True, **res})
            elif path == "/api/underlay/sub/delete":
                STORE.delete_underlay_sub(str(body.get("id", "")))
                self._send_json({"ok": True})
            elif path == "/api/exit/add":
                res = STORE.add_exit_node(
                    str(body.get("raw", "")),
                    remark=str(body.get("remark", "")),
                    default_type=str(body.get("default_type", "socks5")),
                )
                self._send_json({"ok": True, **res})
            elif path == "/api/exit/delete":
                STORE.delete_exit_node(str(body.get("id", "")))
                self._send_json({"ok": True})
            elif path == "/api/delay/test":
                target = str(body.get("name", "EXIT"))
                delay = STORE.mgr.test_node_delay(target)
                self._send_json({"ok": delay is not None, "delay_ms": delay})
            elif path == "/api/elevate":
                if win_proxy.is_admin():
                    self._send_json({"ok": True, "already_admin": True})
                    return
                STORE.disconnect()
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


def _cleanup() -> None:
    try:
        STORE.mgr.stop()
    except Exception:
        pass


def _pick_free_port(start: int = PANEL_PORT) -> int:
    import socket
    for p in range(start, start + 20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    return start


def main() -> None:
    atexit.register(_cleanup)
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, lambda *_: sys.exit(0))
        except Exception:
            pass

    port = _pick_free_port(PANEL_PORT)
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}"
    print(f"极简中文控制台已启动: {url} (关闭窗口将自动断开并恢复网络)")

    srv_thread = threading.Thread(target=server.serve_forever, daemon=True)
    srv_thread.start()

    use_browser = "--browser" in sys.argv
    if not use_browser:
        try:
            import webview  # type: ignore

            webview.create_window(
                "极简防失联 · 住宅链式控制台",
                url,
                width=1060,
                height=780,
                min_size=(840, 620),
            )
            webview.start()
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
