"""通用节点与订阅解析器：支持 VLESS / VMess / Trojan / SS / Hysteria2 / SOCKS5 / HTTP / Clash YAML / Base64。"""

from __future__ import annotations

import base64
import json
import re
import urllib.parse
import urllib.request
from typing import Any

import yaml


def _b64_decode_str(s: str) -> str:
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", errors="ignore")


def _parse_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def parse_residential_line(line: str, default_type: str = "socks5", remark: str = "") -> dict[str, Any] | None:
    """解析住宅 IP 常见格式：
    - socks5://user:pass@ip:port#备注
    - http://user:pass@ip:port#备注
    - ip:port:user:pass
    - ip:port
    - 完整节点 URI (vless://, trojan://, vmess://, ss://, hy2://)
    """
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None

    # 若本身是完整节点链接，走通用解析
    if re.match(r"^(vless|vmess|trojan|ss|hysteria2|hy2|socks5|socks|http|https)://", raw, re.I):
        node = parse_proxy_uri(raw)
        if node and remark:
            node["name"] = remark
        return node

    # 处理 user:pass@ip:port
    if "@" in raw and "://" not in raw:
        node = parse_proxy_uri(f"{default_type}://{raw}")
        if node and remark:
            node["name"] = remark
        return node

    # 处理 ip:port:user:pass 或 ip:port
    parts = raw.split(":")
    if len(parts) == 2 and parts[1].isdigit():
        host, port = parts[0].strip(), int(parts[1])
        return {
            "name": remark or f"住宅-{host}",
            "type": default_type,
            "server": host,
            "port": port,
            "udp": True,
        }
    if len(parts) >= 4 and parts[1].isdigit():
        host = parts[0].strip()
        port = int(parts[1])
        user = parts[2]
        password = ":".join(parts[3:])
        return {
            "name": remark or f"住宅-{host}",
            "type": default_type,
            "server": host,
            "port": port,
            "username": user,
            "password": password,
            "udp": True,
        }
    return None


def parse_proxy_uri(uri: str) -> dict[str, Any] | None:
    uri = uri.strip()
    if not uri:
        return None

    lower = uri.lower()
    if lower.startswith("vmess://"):
        return _parse_vmess(uri)
    if lower.startswith("vless://"):
        return _parse_vless(uri)
    if lower.startswith("trojan://"):
        return _parse_trojan(uri)
    if lower.startswith("ss://"):
        return _parse_ss(uri)
    if lower.startswith(("hysteria2://", "hy2://")):
        return _parse_hy2(uri)
    if lower.startswith(("socks5://", "socks://", "http://", "https://")):
        return _parse_socks_http(uri)
    return None


def _parse_vmess(uri: str) -> dict[str, Any] | None:
    payload = uri[8:].split("#", 1)[0].strip()
    try:
        data = json.loads(_b64_decode_str(payload))
    except Exception:
        return None
    server = str(data.get("add", "")).strip()
    port = _parse_int(data.get("port"))
    uuid = str(data.get("id", "")).strip()
    if not server or not port or not uuid:
        return None

    net = str(data.get("net", "tcp")).lower() or "tcp"
    tls_val = str(data.get("tls", "")).lower() == "tls"
    node: dict[str, Any] = {
        "name": str(data.get("ps") or f"vmess-{server}").strip(),
        "type": "vmess",
        "server": server,
        "port": port,
        "uuid": uuid,
        "alterId": _parse_int(data.get("aid"), 0),
        "cipher": str(data.get("scy") or "auto"),
        "udp": True,
    }
    if tls_val:
        node["tls"] = True
        sni = str(data.get("sni") or data.get("host") or "").strip()
        if sni:
            node["servername"] = sni
    if net == "ws":
        node["network"] = "ws"
        ws_opts: dict[str, Any] = {"path": str(data.get("path") or "/")}
        host = str(data.get("host") or "").strip()
        if host:
            ws_opts["headers"] = {"Host": host}
        node["ws-opts"] = ws_opts
    elif net == "grpc":
        node["network"] = "grpc"
        if data.get("path"):
            node["grpc-opts"] = {"grpc-service-name": str(data.get("path"))}
    return node


def _parse_vless(uri: str) -> dict[str, Any] | None:
    u = urllib.parse.urlparse(uri)
    if not u.hostname or not u.port or not u.username:
        return None
    qs = urllib.parse.parse_qs(u.query)
    q = lambda k, d="": (qs.get(k) or [d])[0]

    name = urllib.parse.unquote(u.fragment).strip() or f"vless-{u.hostname}"
    sec = q("security", "none").lower()
    net = q("type", "tcp").lower()
    if net == "raw":
        net = "tcp"

    node: dict[str, Any] = {
        "name": name,
        "type": "vless",
        "server": u.hostname,
        "port": u.port,
        "uuid": urllib.parse.unquote(u.username),
        "udp": True,
        "network": net,
    }
    if q("flow"):
        node["flow"] = q("flow")
    if q("packetEncoding"):
        node["packet-encoding"] = q("packetEncoding")

    if sec in ("tls", "reality"):
        node["tls"] = True
        if q("sni"):
            node["servername"] = q("sni")
        if q("fp"):
            node["client-fingerprint"] = q("fp")
        if q("allowInsecure") in ("1", "true"):
            node["skip-cert-verify"] = True
        if q("alpn"):
            node["alpn"] = [x.strip() for x in q("alpn").split(",") if x.strip()]

    if sec == "reality":
        ropts: dict[str, Any] = {}
        if q("pbk"):
            ropts["public-key"] = q("pbk")
        if q("sid"):
            ropts["short-id"] = q("sid")
        if ropts:
            node["reality-opts"] = ropts

    if net == "ws":
        ws_opts: dict[str, Any] = {"path": q("path", "/")}
        if q("host"):
            ws_opts["headers"] = {"Host": q("host")}
        node["ws-opts"] = ws_opts
    elif net == "grpc" and q("serviceName"):
        node["grpc-opts"] = {"grpc-service-name": q("serviceName")}
    return node


def _parse_trojan(uri: str) -> dict[str, Any] | None:
    u = urllib.parse.urlparse(uri)
    if not u.hostname or not u.port or not u.username:
        return None
    qs = urllib.parse.parse_qs(u.query)
    q = lambda k, d="": (qs.get(k) or [d])[0]

    name = urllib.parse.unquote(u.fragment).strip() or f"trojan-{u.hostname}"
    node: dict[str, Any] = {
        "name": name,
        "type": "trojan",
        "server": u.hostname,
        "port": u.port,
        "password": urllib.parse.unquote(u.username),
        "udp": True,
    }
    if q("sni"):
        node["sni"] = q("sni")
    if q("allowInsecure") in ("1", "true"):
        node["skip-cert-verify"] = True
    if q("fp"):
        node["client-fingerprint"] = q("fp")
    net = q("type", "tcp").lower()
    if net == "ws":
        node["network"] = "ws"
        ws_opts: dict[str, Any] = {"path": q("path", "/")}
        if q("host"):
            ws_opts["headers"] = {"Host": q("host")}
        node["ws-opts"] = ws_opts
    elif net == "grpc" and q("serviceName"):
        node["network"] = "grpc"
        node["grpc-opts"] = {"grpc-service-name": q("serviceName")}
    return node


def _parse_ss(uri: str) -> dict[str, Any] | None:
    u = urllib.parse.urlparse(uri)
    name = urllib.parse.unquote(u.fragment).strip()
    if u.hostname and u.port and u.username:
        user_info = urllib.parse.unquote(u.username)
        if ":" not in user_info:
            user_info = _b64_decode_str(user_info)
        if ":" not in user_info:
            return None
        cipher, password = user_info.split(":", 1)
        return {
            "name": name or f"ss-{u.hostname}",
            "type": "ss",
            "server": u.hostname,
            "port": u.port,
            "cipher": cipher,
            "password": password,
            "udp": True,
        }
    # 兼容 ss://base64(method:pass@host:port)#name
    body = uri[5:].split("#", 1)[0].strip()
    try:
        decoded = _b64_decode_str(body)
        if "@" in decoded:
            cred, addr = decoded.rsplit("@", 1)
            cipher, password = cred.split(":", 1)
            host, port_s = addr.rsplit(":", 1)
            return {
                "name": name or f"ss-{host}",
                "type": "ss",
                "server": host,
                "port": int(port_s),
                "cipher": cipher,
                "password": password,
                "udp": True,
            }
    except Exception:
        return None
    return None


def _parse_hy2(uri: str) -> dict[str, Any] | None:
    norm = "hysteria2://" + uri.split("://", 1)[1]
    u = urllib.parse.urlparse(norm)
    if not u.hostname or not u.port:
        return None
    qs = urllib.parse.parse_qs(u.query)
    q = lambda k, d="": (qs.get(k) or [d])[0]
    password = urllib.parse.unquote(u.username or "")
    if u.password:
        password = f"{password}:{urllib.parse.unquote(u.password)}"
    node: dict[str, Any] = {
        "name": urllib.parse.unquote(u.fragment).strip() or f"hy2-{u.hostname}",
        "type": "hysteria2",
        "server": u.hostname,
        "port": u.port,
        "password": password,
    }
    if q("sni"):
        node["sni"] = q("sni")
    if q("insecure") in ("1", "true"):
        node["skip-cert-verify"] = True
    if q("obfs"):
        node["obfs"] = q("obfs")
        if q("obfs-password"):
            node["obfs-password"] = q("obfs-password")
    return node


def _parse_socks_http(uri: str) -> dict[str, Any] | None:
    u = urllib.parse.urlparse(uri)
    if not u.hostname or not u.port:
        return None
    scheme = u.scheme.lower()
    ptype = "socks5" if scheme in ("socks5", "socks") else "http"
    node: dict[str, Any] = {
        "name": urllib.parse.unquote(u.fragment).strip() or f"{ptype}-{u.hostname}",
        "type": ptype,
        "server": u.hostname,
        "port": u.port,
        "udp": True,
    }
    if scheme == "https":
        node["tls"] = True
    if u.username is not None:
        node["username"] = urllib.parse.unquote(u.username)
    if u.password is not None:
        node["password"] = urllib.parse.unquote(u.password)
    return node


def parse_subscription_content(text: str) -> list[dict[str, Any]]:
    """从 Clash YAML、Base64 或明文 URI 文本中解析出 Mihomo 节点字典列表。"""
    raw = text.strip()
    if not raw:
        return []

    # 1. 尝试 YAML
    if "proxies:" in raw or raw.lstrip().startswith("- name:"):
        try:
            doc = yaml.safe_load(raw)
            if isinstance(doc, dict) and isinstance(doc.get("proxies"), list):
                return [p for p in doc["proxies"] if isinstance(p, dict) and p.get("server") and p.get("type")]
            if isinstance(doc, list):
                return [p for p in doc if isinstance(p, dict) and p.get("server") and p.get("type")]
        except Exception:
            pass

    # 2. 尝试直接解析 URI 行，若没有则尝试 Base64 解码
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    uri_lines = [ln for ln in lines if "://" in ln]
    if not uri_lines:
        try:
            decoded = _b64_decode_str(raw)
            uri_lines = [ln.strip() for ln in decoded.splitlines() if "://" in ln]
        except Exception:
            uri_lines = []

    nodes: list[dict[str, Any]] = []
    for ln in uri_lines:
        parsed = parse_proxy_uri(ln)
        if parsed:
            nodes.append(parsed)
    return nodes


def fetch_subscription(url: str, proxy_url: str | None = None) -> list[dict[str, Any]]:
    """拉取远程订阅（自动尝试直连 -> 系统代理 -> GitHub 镜像）。"""
    candidates = [url]
    if "raw.githubusercontent.com/" in url or "github.com/" in url:
        candidates.append("https://gh-proxy.com/" + url)

    proxies_to_try = [None, proxy_url] if proxy_url else [None]
    last_err: Exception | None = None

    for target in candidates:
        for px in proxies_to_try:
            try:
                req = urllib.request.Request(target, headers={"User-Agent": "clash.meta/1.19"})
                handler = urllib.request.ProxyHandler({"http": px, "https": px} if px else {})
                opener = urllib.request.build_opener(handler)
                with opener.open(req, timeout=15) as resp:
                    body = resp.read().decode("utf-8", errors="ignore")
                nodes = parse_subscription_content(body)
                if nodes:
                    return nodes
            except Exception as exc:
                last_err = exc
    if last_err:
        raise RuntimeError(f"订阅拉取或解析失败: {last_err}")
    raise RuntimeError("订阅内容为空或未识别到有效节点")
