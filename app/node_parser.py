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
    - ip:port:user:pass / [ipv6]:port:user:pass
    - ip:port / [ipv6]:port
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

    # 提取末尾 #备注（针对非 URI 文本格式）
    inline_remark = ""
    if "#" in raw and "://" not in raw:
        body, frag = raw.split("#", 1)
        if body.strip():
            raw = body.strip()
            inline_remark = urllib.parse.unquote(frag.strip())
    final_remark = remark.strip() or inline_remark

    # 处理 user:pass@ip:port
    if "@" in raw and "://" not in raw:
        node = parse_proxy_uri(f"{default_type}://{raw}")
        if node and final_remark:
            node["name"] = final_remark
        return node

    # 处理 [ipv6]:port 或 [ipv6]:port:user:pass
    m_v6 = re.match(r"^\[([^\]]+)\]:(\d+)(?::([^:]+):(.*))?$", raw)
    if m_v6:
        host, port_s, user, password = m_v6.groups()
        node: dict[str, Any] = {
            "name": final_remark or f"住宅-{host}",
            "type": default_type,
            "server": host.strip(),
            "port": int(port_s),
            "udp": True,
        }
        if user is not None:
            node["username"] = user
            node["password"] = password or ""
        return node

    # 处理 ip:port:user:pass 或 ip:port
    parts = raw.split(":")
    if len(parts) == 2 and parts[1].isdigit():
        host, port = parts[0].strip(), int(parts[1])
        if not host or not (1 <= port <= 65535):
            return None
        return {
            "name": final_remark or f"住宅-{host}",
            "type": default_type,
            "server": host,
            "port": port,
            "udp": True,
        }
    if len(parts) >= 4 and parts[1].isdigit():
        host = parts[0].strip()
        port = int(parts[1])
        if not host or not (1 <= port <= 65535):
            return None
        user = parts[2]
        password = ":".join(parts[3:])
        return {
            "name": final_remark or f"住宅-{host}",
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
    try:
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
        if lower.startswith("tuic://"):
            return _parse_tuic(uri)
        if lower.startswith("anytls://"):
            return _parse_anytls(uri)
        if lower.startswith(("wireguard://", "wg://")):
            return _parse_wireguard(uri)
        if lower.startswith(("socks5://", "socks://", "http://", "https://")):
            return _parse_socks_http(uri)
    except ValueError:
        return None
    return None


def is_xray_only_node(node: dict[str, Any]) -> bool:
    """判断节点是否依赖 Xray-core 专属传输或加密（Mihomo 不支持直接拨号）。"""
    if not isinstance(node, dict):
        return False
    net = str(node.get("network") or "").lower()
    if net in ("kcp", "quic"):
        return True
    if node.get("type") == "vless" and str(node.get("encryption") or "").lower() not in ("", "none"):
        return True
    if net == "xhttp":
        xopts = node.get("xhttp-opts") or {}
        if isinstance(xopts, dict) and xopts.get("extra"):
            return True
    return False


def _is_truthy(val: Any) -> bool:
    return str(val or "").strip().lower() in ("1", "true", "yes", "on")


def _apply_transport_opts(
    node: dict[str, Any],
    net: str,
    path: str = "/",
    host: str = "",
    service_name: str = "",
    header_type: str = "",
    mode: str = "",
    seed: str = "",
    quic_security: str = "",
    quic_key: str = "",
    extra_json: str = "",
) -> None:
    net = (net or "tcp").lower()
    if net in ("raw", "tcp"):
        if header_type.lower() == "http":
            node["network"] = "http"
            http_opts: dict[str, Any] = {"path": [path or "/"]}
            if host:
                http_opts["headers"] = {"Host": [h.strip() for h in host.split(",") if h.strip()]}
            node["http-opts"] = http_opts
        else:
            node["network"] = "tcp"
        return

    if net == "ws":
        node["network"] = "ws"
        ws_opts: dict[str, Any] = {"path": path or "/"}
        if host:
            ws_opts["headers"] = {"Host": host}
        node["ws-opts"] = ws_opts
    elif net == "httpupgrade":
        node["network"] = "ws"
        ws_opts = {"path": path or "/", "v2ray-http-upgrade": True}
        if host:
            ws_opts["headers"] = {"Host": host}
        node["ws-opts"] = ws_opts
    elif net in ("xhttp", "splithttp"):
        node["network"] = "xhttp"
        xhttp_opts: dict[str, Any] = {"path": path or "/"}
        if host:
            xhttp_opts["host"] = host
        if mode:
            xhttp_opts["mode"] = mode
        if extra_json:
            try:
                xhttp_opts["extra"] = json.loads(extra_json)
            except Exception:
                xhttp_opts["extra"] = extra_json
        node["xhttp-opts"] = xhttp_opts
    elif net == "kcp":
        node["network"] = "kcp"
        kcp_opts: dict[str, Any] = {"header-type": header_type or "none"}
        if seed:
            kcp_opts["seed"] = seed
        node["kcp-opts"] = kcp_opts
    elif net == "quic":
        node["network"] = "quic"
        node["quic-opts"] = {
            "security": quic_security or "none",
            "key": quic_key or "",
            "header-type": header_type or "none",
        }
    elif net == "h2":
        node["network"] = "h2"
        h2_opts: dict[str, Any] = {"path": path or "/"}
        if host:
            h2_opts["host"] = [h.strip() for h in host.split(",") if h.strip()]
        node["h2-opts"] = h2_opts
    elif net == "grpc":
        node["network"] = "grpc"
        if service_name or path:
            node["grpc-opts"] = {"grpc-service-name": service_name or path}
    else:
        node["network"] = net


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
    tls_val = str(data.get("tls", "")).lower() in ("tls", "true", "1")
    host = str(data.get("host") or "").strip()
    path = str(data.get("path") or "/").strip()
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
        sni = str(data.get("sni") or host).strip()
        if sni:
            node["servername"] = sni
        if _is_truthy(data.get("allowInsecure")) or _is_truthy(data.get("insecure")):
            node["skip-cert-verify"] = True
        if data.get("fp"):
            node["client-fingerprint"] = str(data["fp"]).strip()
        if data.get("alpn"):
            node["alpn"] = [x.strip() for x in str(data["alpn"]).split(",") if x.strip()]

    _apply_transport_opts(
        node,
        net=net,
        path=path,
        host=host,
        service_name=path if net == "grpc" else "",
        header_type=str(data.get("type") or ""),
        seed=str(data.get("path") or "") if net == "kcp" else "",
        quic_security=host if net == "quic" else "",
        quic_key=path if net == "quic" else "",
    )
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

    node: dict[str, Any] = {
        "name": name,
        "type": "vless",
        "server": u.hostname,
        "port": u.port,
        "uuid": urllib.parse.unquote(u.username),
        "udp": True,
    }
    if q("flow"):
        node["flow"] = q("flow")
    if q("encryption") and q("encryption").lower() != "none":
        node["encryption"] = q("encryption")
    if q("packetEncoding"):
        node["packet-encoding"] = q("packetEncoding")

    if sec in ("tls", "reality"):
        node["tls"] = True
        sni = q("sni") or q("host")
        if sni:
            node["servername"] = sni
        fp = q("fp") or ("chrome" if sec == "reality" else "")
        if fp:
            node["client-fingerprint"] = fp
        if _is_truthy(q("allowInsecure")) or _is_truthy(q("insecure")):
            node["skip-cert-verify"] = True
        if q("alpn"):
            node["alpn"] = [x.strip() for x in q("alpn").split(",") if x.strip()]

    if sec == "reality":
        ropts: dict[str, Any] = {}
        if q("pbk"):
            ropts["public-key"] = q("pbk")
        if q("sid"):
            ropts["short-id"] = q("sid")
        if q("spx"):
            ropts["spider-x"] = q("spx")
        if ropts:
            node["reality-opts"] = ropts

    _apply_transport_opts(
        node,
        net=net,
        path=q("path", "/"),
        host=q("host"),
        service_name=q("serviceName"),
        header_type=q("headerType"),
        mode=q("mode"),
        seed=q("seed"),
        quic_security=q("quicSecurity"),
        quic_key=q("key"),
        extra_json=q("extra"),
    )
    return node


def _parse_trojan(uri: str) -> dict[str, Any] | None:
    u = urllib.parse.urlparse(uri)
    if not u.hostname or not u.port or not u.username:
        return None
    qs = urllib.parse.parse_qs(u.query)
    q = lambda k, d="": (qs.get(k) or [d])[0]

    name = urllib.parse.unquote(u.fragment).strip() or f"trojan-{u.hostname}"
    sec = q("security", "tls").lower()
    node: dict[str, Any] = {
        "name": name,
        "type": "trojan",
        "server": u.hostname,
        "port": u.port,
        "password": urllib.parse.unquote(u.username),
        "udp": True,
    }
    sni = q("sni") or q("host")
    if sni:
        node["sni"] = sni
    if _is_truthy(q("allowInsecure")) or _is_truthy(q("insecure")):
        node["skip-cert-verify"] = True
    fp = q("fp") or ("chrome" if sec == "reality" else "")
    if fp:
        node["client-fingerprint"] = fp
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

    net = q("type", "tcp").lower()
    if net != "tcp" or q("headerType"):
        _apply_transport_opts(
            node,
            net=net,
            path=q("path", "/"),
            host=q("host"),
            service_name=q("serviceName"),
            header_type=q("headerType"),
            mode=q("mode"),
        )
    return node


def _apply_ss_plugin(node: dict[str, Any], plugin_str: str) -> None:
    if not plugin_str:
        return
    parts = [p.strip() for p in plugin_str.split(";") if p.strip()]
    if not parts:
        return
    raw_name = parts[0].lower()
    opts: dict[str, Any] = {}
    for kv in parts[1:]:
        if "=" in kv:
            k, v = kv.split("=", 1)
            opts[k.strip()] = v.strip()
        else:
            opts[kv] = True

    if raw_name in ("obfs-local", "simple-obfs", "obfs"):
        node["plugin"] = "obfs"
        p_opts: dict[str, Any] = {}
        if opts.get("obfs"):
            p_opts["mode"] = opts["obfs"]
        if opts.get("obfs-host"):
            p_opts["host"] = opts["obfs-host"]
        if p_opts:
            node["plugin-opts"] = p_opts
    elif raw_name == "v2ray-plugin":
        node["plugin"] = "v2ray-plugin"
        p_opts = {"mode": opts.get("mode", "websocket")}
        if opts.get("host"):
            p_opts["host"] = opts["host"]
        if opts.get("path"):
            p_opts["path"] = opts["path"]
        if "tls" in opts:
            p_opts["tls"] = True
        node["plugin-opts"] = p_opts


def _parse_ss(uri: str) -> dict[str, Any] | None:
    u = urllib.parse.urlparse(uri)
    qs = urllib.parse.parse_qs(u.query)
    plugin_str = (qs.get("plugin") or [""])[0]
    name = urllib.parse.unquote(u.fragment).strip()
    if u.hostname and u.port and u.username:
        user_info = urllib.parse.unquote(u.username)
        if ":" not in user_info:
            user_info = _b64_decode_str(user_info)
        if ":" not in user_info:
            return None
        cipher, password = user_info.split(":", 1)
        node: dict[str, Any] = {
            "name": name or f"ss-{u.hostname}",
            "type": "ss",
            "server": u.hostname,
            "port": u.port,
            "cipher": cipher,
            "password": password,
            "udp": True,
        }
        _apply_ss_plugin(node, plugin_str)
        return node
    # 兼容 ss://base64(method:pass@host:port)#name
    body = uri[5:].split("#", 1)[0].split("?", 1)[0].strip()
    try:
        decoded = _b64_decode_str(body)
        if "@" in decoded:
            cred, addr = decoded.rsplit("@", 1)
            cipher, password = cred.split(":", 1)
            host, port_s = addr.rsplit(":", 1)
            node = {
                "name": name or f"ss-{host}",
                "type": "ss",
                "server": host,
                "port": int(port_s),
                "cipher": cipher,
                "password": password,
                "udp": True,
            }
            _apply_ss_plugin(node, plugin_str)
            return node
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
    if _is_truthy(q("insecure")) or _is_truthy(q("allowInsecure")):
        node["skip-cert-verify"] = True
    if q("alpn"):
        node["alpn"] = [x.strip() for x in q("alpn").split(",") if x.strip()]
    if q("mport"):
        node["ports"] = q("mport")
    if q("pinSHA256"):
        node["fingerprint"] = q("pinSHA256")
    if q("obfs") and q("obfs") != "none":
        node["obfs"] = q("obfs")
        if q("obfs-password"):
            node["obfs-password"] = q("obfs-password")
    return node


def _parse_tuic(uri: str) -> dict[str, Any] | None:
    u = urllib.parse.urlparse(uri)
    if not u.hostname or not u.port or not u.username:
        return None
    qs = urllib.parse.parse_qs(u.query)
    q = lambda k, d="": (qs.get(k) or [d])[0]
    node: dict[str, Any] = {
        "name": urllib.parse.unquote(u.fragment).strip() or f"tuic-{u.hostname}",
        "type": "tuic",
        "server": u.hostname,
        "port": u.port,
        "uuid": urllib.parse.unquote(u.username),
        "password": urllib.parse.unquote(u.password or ""),
        "congestion-controller": q("congestion_control", "bbr"),
        "udp-relay-mode": q("udp_relay_mode", "native"),
        "reduce-rtt": True,
    }
    if q("sni"):
        node["sni"] = q("sni")
    if q("alpn"):
        node["alpn"] = [x.strip() for x in q("alpn").split(",") if x.strip()]
    if _is_truthy(q("allow_insecure")) or _is_truthy(q("allowInsecure")) or _is_truthy(q("insecure")):
        node["skip-cert-verify"] = True
    return node


def _parse_anytls(uri: str) -> dict[str, Any] | None:
    u = urllib.parse.urlparse(uri)
    if not u.hostname or not u.port:
        return None
    qs = urllib.parse.parse_qs(u.query)
    q = lambda k, d="": (qs.get(k) or [d])[0]
    password = urllib.parse.unquote(u.username or "")
    if u.password:
        password = f"{password}:{urllib.parse.unquote(u.password)}"
    node: dict[str, Any] = {
        "name": urllib.parse.unquote(u.fragment).strip() or f"anytls-{u.hostname}",
        "type": "anytls",
        "server": u.hostname,
        "port": u.port,
        "password": password,
        "udp": True,
    }
    if q("sni"):
        node["sni"] = q("sni")
    if _is_truthy(q("insecure")) or _is_truthy(q("allowInsecure")):
        node["skip-cert-verify"] = True
    if q("fp"):
        node["client-fingerprint"] = q("fp")
    if q("alpn"):
        node["alpn"] = [x.strip() for x in q("alpn").split(",") if x.strip()]
    return node


def _parse_wireguard(uri: str) -> dict[str, Any] | None:
    norm = "wireguard://" + uri.split("://", 1)[1]
    u = urllib.parse.urlparse(norm)
    if not u.hostname or not u.port or not u.username:
        return None
    qs = urllib.parse.parse_qs(u.query)
    q = lambda k, d="": (qs.get(k) or [d])[0]
    addr_raw = q("address", "172.16.0.2/32")
    ip_v4 = addr_raw.split(",")[0].split("/")[0].strip()
    peer: dict[str, Any] = {
        "server": u.hostname,
        "port": u.port,
        "public-key": urllib.parse.unquote(q("publickey") or q("pbk")),
        "allowed-ips": ["0.0.0.0/0"],
    }
    if q("presharedkey") or q("psk"):
        peer["pre-shared-key"] = urllib.parse.unquote(q("presharedkey") or q("psk"))
    if q("reserved"):
        parts = [int(x.strip()) for x in q("reserved").split(",") if x.strip().isdigit()]
        if parts:
            peer["reserved"] = parts
    node: dict[str, Any] = {
        "name": urllib.parse.unquote(u.fragment).strip() or f"wg-{u.hostname}",
        "type": "wireguard",
        "private-key": urllib.parse.unquote(u.username),
        "ip": ip_v4,
        "peers": [peer],
        "mtu": int(q("mtu") or 1280),
        "udp": True,
    }
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


def _clean_clash_proxies(raw_list: list[Any]) -> list[dict[str, Any]]:
    cleaned: list[dict[str, Any]] = []
    for p in raw_list:
        if not isinstance(p, dict):
            continue
        if not p.get("server") or not p.get("type"):
            continue
        port = _parse_int(p.get("port"))
        if port <= 0 or port > 65535:
            continue
        item = dict(p)
        item["port"] = port
        cleaned.append(item)
    return cleaned


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
                return _clean_clash_proxies(doc["proxies"])
            if isinstance(doc, list):
                return _clean_clash_proxies(doc)
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

    proxies_to_try = [proxy_url, None] if proxy_url else [None]
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
