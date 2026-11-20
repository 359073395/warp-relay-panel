"""Xray-core 桥接模块：为 mKCP / QUIC / VLESS 加密 / XHTTP(extra) 等 Xray 专属节点提供本地 SOCKS5 桥接。"""

from __future__ import annotations

import copy
import json
import socket
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from . import core_updater, node_parser


def _build_stream_settings(node: dict[str, Any]) -> dict[str, Any]:
    net = str(node.get("network") or "tcp").lower()
    stream: dict[str, Any] = {}

    if net == "ws":
        wopts = node.get("ws-opts") or {}
        if wopts.get("v2ray-http-upgrade"):
            stream["network"] = "httpupgrade"
            hu: dict[str, Any] = {"path": str(wopts.get("path") or "/")}
            host = (wopts.get("headers") or {}).get("Host")
            if host:
                hu["host"] = str(host)
            stream["httpupgradeSettings"] = hu
        else:
            stream["network"] = "ws"
            ws: dict[str, Any] = {"path": str(wopts.get("path") or "/")}
            headers = wopts.get("headers") or {}
            if headers:
                ws["headers"] = dict(headers)
            stream["wsSettings"] = ws
    elif net == "xhttp":
        xopts = node.get("xhttp-opts") or {}
        stream["network"] = "xhttp"
        xs: dict[str, Any] = {"path": str(xopts.get("path") or "/")}
        if xopts.get("host"):
            xs["host"] = str(xopts["host"])
        if xopts.get("mode"):
            xs["mode"] = str(xopts["mode"])
        if xopts.get("extra"):
            xs["extra"] = xopts["extra"]
        stream["xhttpSettings"] = xs
    elif net == "kcp":
        kopts = node.get("kcp-opts") or {}
        stream["network"] = "kcp"
        ks: dict[str, Any] = {
            "header": {"type": str(kopts.get("header-type") or "none")},
        }
        if kopts.get("seed"):
            ks["seed"] = str(kopts["seed"])
        stream["kcpSettings"] = ks
    elif net == "quic":
        qopts = node.get("quic-opts") or {}
        stream["network"] = "quic"
        stream["quicSettings"] = {
            "security": str(qopts.get("security") or "none"),
            "key": str(qopts.get("key") or ""),
            "header": {"type": str(qopts.get("header-type") or "none")},
        }
    elif net == "grpc":
        gopts = node.get("grpc-opts") or {}
        stream["network"] = "grpc"
        stream["grpcSettings"] = {
            "serviceName": str(gopts.get("grpc-service-name") or ""),
        }
    elif net == "h2":
        hopts = node.get("h2-opts") or {}
        stream["network"] = "h2"
        stream["httpSettings"] = {
            "path": str(hopts.get("path") or "/"),
            "host": list(hopts.get("host") or []),
        }
    elif net == "http":
        hopts = node.get("http-opts") or {}
        stream["network"] = "tcp"
        paths = hopts.get("path") or ["/"]
        headers = hopts.get("headers") or {}
        stream["tcpSettings"] = {
            "header": {
                "type": "http",
                "request": {
                    "path": paths if isinstance(paths, list) else [str(paths)],
                    "headers": headers,
                },
            }
        }
    else:
        stream["network"] = "tcp"

    ropts = node.get("reality-opts")
    if isinstance(ropts, dict) and ropts.get("public-key"):
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "publicKey": str(ropts["public-key"]),
            "shortId": str(ropts.get("short-id") or ""),
            "serverName": str(node.get("servername") or node.get("sni") or ""),
            "fingerprint": str(node.get("client-fingerprint") or "chrome"),
            "spiderX": str(ropts.get("spider-x") or ""),
        }
    elif node.get("tls") or node.get("type") == "trojan":
        stream["security"] = "tls"
        tls_cfg: dict[str, Any] = {}
        sni = node.get("servername") or node.get("sni")
        if sni:
            tls_cfg["serverName"] = str(sni)
        if node.get("skip-cert-verify"):
            tls_cfg["allowInsecure"] = True
        if node.get("client-fingerprint"):
            tls_cfg["fingerprint"] = str(node["client-fingerprint"])
        if node.get("alpn"):
            tls_cfg["alpn"] = list(node["alpn"])
        stream["tlsSettings"] = tls_cfg
    else:
        stream["security"] = "none"

    return stream


def build_xray_outbound(node: dict[str, Any], tag: str) -> dict[str, Any]:
    ptype = str(node.get("type") or "").lower()
    server = str(node.get("server") or "")
    port = int(node.get("port") or 0)
    stream = _build_stream_settings(node)

    if ptype == "vless":
        user: dict[str, Any] = {
            "id": str(node.get("uuid") or ""),
            "encryption": str(node.get("encryption") or "none"),
        }
        if node.get("flow"):
            user["flow"] = str(node["flow"])
        return {
            "tag": tag,
            "protocol": "vless",
            "settings": {"vnext": [{"address": server, "port": port, "users": [user]}]},
            "streamSettings": stream,
        }

    if ptype == "vmess":
        return {
            "tag": tag,
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": server,
                    "port": port,
                    "users": [{
                        "id": str(node.get("uuid") or ""),
                        "alterId": int(node.get("alterId") or 0),
                        "security": str(node.get("cipher") or "auto"),
                    }],
                }]
            },
            "streamSettings": stream,
        }

    if ptype == "trojan":
        return {
            "tag": tag,
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": server,
                    "port": port,
                    "password": str(node.get("password") or ""),
                }]
            },
            "streamSettings": stream,
        }

    if ptype == "ss":
        return {
            "tag": tag,
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": server,
                    "port": port,
                    "method": str(node.get("cipher") or ""),
                    "password": str(node.get("password") or ""),
                }]
            },
            "streamSettings": stream,
        }

    raise ValueError(f"Xray 桥接暂不支持协议类型: {ptype}")


def build_xray_bridge_config(entries: list[tuple[str, int, dict[str, Any]]]) -> dict[str, Any]:
    inbounds: list[dict[str, Any]] = []
    outbounds: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []

    for idx, (tag, port, node) in enumerate(entries):
        in_tag = f"in_{idx}"
        inbounds.append({
            "tag": in_tag,
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
        })
        outbounds.append(build_xray_outbound(node, tag))
        rules.append({
            "type": "field",
            "inboundTag": [in_tag],
            "outboundTag": tag,
        })

    return {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }


class XrayBridgeProcess:
    def __init__(self, core_dir: Path, entries: list[tuple[str, int, dict[str, Any]]]) -> None:
        self.core_dir = core_dir
        self.entries = entries
        self._proc: subprocess.Popen[bytes] | None = None
        self._cfg_file: Path | None = None
        self._log_file: Path | None = None
        self._log_fp: Any = None

    def start(self, proxy_url: str | None = None) -> None:
        xray_exe = core_updater.ensure_xray_exe(self.core_dir, proxy_url=proxy_url).resolve()
        core_abs = self.core_dir.resolve()
        cfg = build_xray_bridge_config(self.entries)
        uid = uuid.uuid4().hex[:8]
        self._cfg_file = core_abs / f"xray_bridge_{uid}.json"
        self._log_file = core_abs / f"xray_bridge_{uid}.log"
        self._cfg_file.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")

        self._log_fp = open(self._log_file, "w", encoding="utf-8", errors="replace")
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self._proc = subprocess.Popen(
            [str(xray_exe), "run", "-c", str(self._cfg_file)],
            cwd=str(core_abs),
            stdout=self._log_fp,
            stderr=subprocess.STDOUT,
            creationflags=creation_flags,
        )

        # 等待所有本地 SOCKS5 桥接端口监听就绪
        ports = [port for _, port, _ in self.entries]
        deadline = time.time() + 8.0
        while time.time() < deadline:
            if self._proc.poll() is not None:
                self._log_fp.flush()
                err = ""
                try:
                    err = self._log_file.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    pass
                self.stop()
                raise RuntimeError(f"Xray 桥接内核启动失败: {err[-400:]}")
            all_up = True
            for p in ports:
                try:
                    with socket.create_connection(("127.0.0.1", p), timeout=0.3):
                        pass
                except OSError:
                    all_up = False
                    break
            if all_up:
                return
            time.sleep(0.15)

        self.stop()
        raise RuntimeError("Xray 桥接端口启动超时")

    def stop(self) -> None:
        proc = self._proc
        self._proc = None
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        if self._log_fp is not None:
            try:
                self._log_fp.close()
            except Exception:
                pass
            self._log_fp = None
        for f in (self._cfg_file, self._log_file):
            if f is not None:
                try:
                    f.unlink(missing_ok=True)
                except Exception:
                    pass
        self._cfg_file = None
        self._log_file = None


def should_bridge_via_xray(core_dir: Path, node: dict[str, Any]) -> bool:
    """判断节点是否应通过 Xray-core 桥接（含 Xray 专属协议及当 xray.exe 就绪时的 Reality / XHTTP 节点）。"""
    if node_parser.is_xray_only_node(node):
        return True
    xray_exists = (core_dir / "xray.exe").is_file()
    if not xray_exists:
        return False
    if isinstance(node.get("reality-opts"), dict) and node["reality-opts"].get("public-key"):
        return True
    if str(node.get("network") or "").lower() == "xhttp":
        return True
    return False


def prepare_proxies_with_xray(
    core_dir: Path,
    proxies: list[dict[str, Any]],
    pick_port_fn: Callable[[int], int],
    base_port: int = 18200,
) -> tuple[list[dict[str, Any]], XrayBridgeProcess | None]:
    """将列表中需要 Xray-core 协议的节点自动转为本地 SOCKS5 桥接节点。"""
    entries: list[tuple[str, int, dict[str, Any]]] = []
    out_proxies: list[dict[str, Any]] = []
    used_ports: set[int] = set()
    next_port = base_port

    for idx, raw_p in enumerate(proxies):
        p = copy.deepcopy(raw_p)
        if should_bridge_via_xray(core_dir, p):
            port = pick_port_fn(next_port)
            while port in used_ports:
                next_port = port + 1
                port = pick_port_fn(next_port)
            used_ports.add(port)
            next_port = port + 1
            tag = f"xr_{idx}"
            entries.append((tag, port, p))
            out_proxies.append({
                "name": p["name"],
                "type": "socks5",
                "server": "127.0.0.1",
                "port": port,
                "udp": True,
            })
        else:
            out_proxies.append(p)

    if not entries:
        return out_proxies, None
    return out_proxies, XrayBridgeProcess(core_dir, entries)
