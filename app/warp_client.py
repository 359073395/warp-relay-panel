"""Cloudflare WARP 免费账号注册与优选端点池生成（纯 Python 零额外加密依赖）。"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import random
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

# RFC 7748 Curve25519 常量
_P = (1 << 255) - 19
_A24 = 121665

# 来自 Cloudflare WARP / xehn poolsV4 的优选端点网段
WARP_IPV4_CIDRS = [
    "162.159.192.0/24",
    "162.159.195.0/24",
    "188.114.96.0/24",
    "188.114.97.0/24",
    "188.114.98.0/24",
    "188.114.99.0/24",
    "8.6.112.0/24",
    "8.34.70.0/24",
    "8.34.146.0/24",
    "8.35.211.0/24",
    "8.39.125.0/24",
    "8.39.204.0/24",
    "8.39.214.0/24",
    "8.47.69.0/24",
]

WARP_PORTS = [2408, 500, 1701, 4500, 894, 908, 942, 1018]

DEFAULT_WARP_PUBKEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
AWG_I1_DEFAULT = "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>"


def _cswap(swap: int, x_2: int, x_3: int) -> tuple[int, int]:
    dummy = swap * ((x_2 ^ x_3) & ((1 << 256) - 1))
    return x_2 ^ dummy, x_3 ^ dummy


def _x25519(k_bytes: bytes, u_bytes: bytes) -> bytes:
    k_list = bytearray(k_bytes)
    k_list[0] &= 248
    k_list[31] &= 127
    k_list[31] |= 64
    k = int.from_bytes(k_list, "little")

    u_list = bytearray(u_bytes)
    u_list[31] &= 127
    u = int.from_bytes(u_list, "little") % _P

    x_1 = u
    x_2, z_2 = 1, 0
    x_3, z_3 = u, 1
    swap = 0

    for t in range(254, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        x_2, x_3 = _cswap(swap, x_2, x_3)
        z_2, z_3 = _cswap(swap, z_2, z_3)
        swap = k_t

        a = (x_2 + z_2) % _P
        aa = (a * a) % _P
        b = (x_2 - z_2) % _P
        bb = (b * b) % _P
        e = (aa - bb) % _P
        c = (x_3 + z_3) % _P
        d = (x_3 - z_3) % _P
        da = (d * a) % _P
        cb = (c * b) % _P
        x_3 = pow((da + cb) % _P, 2, _P)
        z_3 = (x_1 * pow((da - cb) % _P, 2, _P)) % _P
        x_2 = (aa * bb) % _P
        z_2 = (e * ((aa + _A24 * e) % _P)) % _P

    x_2, x_3 = _cswap(swap, x_2, x_3)
    z_2, z_3 = _cswap(swap, z_2, z_3)
    res = (x_2 * pow(z_2, _P - 2, _P)) % _P
    return res.to_bytes(32, "little")


def generate_wg_keypair() -> tuple[str, str]:
    priv = bytearray(os.urandom(32))
    priv[0] &= 248
    priv[31] &= 127
    priv[31] |= 64
    priv_bytes = bytes(priv)
    basepoint = (9).to_bytes(32, "little")
    pub_bytes = _x25519(priv_bytes, basepoint)
    return base64.b64encode(priv_bytes).decode("ascii"), base64.b64encode(pub_bytes).decode("ascii")


def _http_json(url: str, method: str, payload: dict[str, Any], token: str = "", proxy_url: str | None = None) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json; charset=UTF-8",
        "CF-Client-Version": "a-6.11-2223",
        "User-Agent": "okhttp/3.12.1",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    handlers = []
    if proxy_url:
        handlers.append(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
    else:
        handlers.append(urllib.request.ProxyHandler({}))
    opener = urllib.request.build_opener(*handlers)
    with opener.open(req, timeout=12) as resp:
        return json.loads(resp.read().decode("utf-8"))


def register_warp_account(proxy_url: str | None = None) -> dict[str, Any]:
    priv, pub = generate_wg_keypair()
    endpoints = [
        "https://api.cloudflareclient.com/v0a4005/reg",
        "https://edge-client-api.vercel.app/v0a4005/reg",
    ]
    proxies_to_try = [None, proxy_url] if proxy_url else [None]

    last_err: Exception | None = None
    for base in endpoints:
        for px in proxies_to_try:
            try:
                reg = _http_json(base, "POST", {"key": pub}, proxy_url=px)
                acc_id = reg["id"]
                token = reg["token"]
                _http_json(f"{base}/{acc_id}", "PATCH", {"warp_enabled": True}, token=token, proxy_url=px)
                cfg = reg.get("config", {})
                peers = cfg.get("peers") or [{}]
                addrs = cfg.get("interface", {}).get("addresses", {})
                return {
                    "id": acc_id,
                    "token": token,
                    "private_key": priv,
                    "peer_public_key": peers[0].get("public_key", DEFAULT_WARP_PUBKEY),
                    "ipv4": addrs.get("v4", "172.16.0.2"),
                    "ipv6": addrs.get("v6", ""),
                }
            except Exception as exc:
                last_err = exc
    raise RuntimeError(f"WARP 账号注册失败: {last_err}")


def ensure_warp_account(account_file: Path, proxy_url: str | None = None) -> dict[str, Any]:
    if account_file.exists():
        try:
            data = json.loads(account_file.read_text(encoding="utf-8"))
            if data.get("private_key") and data.get("peer_public_key"):
                return data
        except Exception:
            pass
    acct = register_warp_account(proxy_url=proxy_url)
    account_file.parent.mkdir(parents=True, exist_ok=True)
    account_file.write_text(json.dumps(acct, indent=2, ensure_ascii=False), encoding="utf-8")
    return acct


def sample_warp_endpoints(count: int = 12) -> list[tuple[str, int]]:
    """从 Cloudflare 多段 WARP IPv4 池中抽样生成不重复的候选端点列表。"""
    candidates: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    cidrs = list(WARP_IPV4_CIDRS)
    random.shuffle(cidrs)
    attempts = 0
    while len(candidates) < count and attempts < count * 5:
        idx = attempts
        attempts += 1
        net = ipaddress.ip_network(cidrs[idx % len(cidrs)])
        host_offset = random.randint(1, net.num_addresses - 2)
        ip_str = str(net.network_address + host_offset)
        port = WARP_PORTS[idx % len(WARP_PORTS)]
        pair = (ip_str, port)
        if pair not in seen:
            seen.add(pair)
            candidates.append(pair)
    return candidates


def normalize_warp_endpoints(raw_eps: list[Any]) -> list[dict[str, Any]]:
    """兼容旧版 [ip, port] 列表与新版 {ip, port, delay_ms, speed_mbps} 字典列表。"""
    out: list[dict[str, Any]] = []
    for item in raw_eps or []:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            out.append({"ip": str(item[0]), "port": int(item[1]), "delay_ms": None, "speed_mbps": None})
        elif isinstance(item, dict) and item.get("ip") and item.get("port"):
            delay = item.get("delay_ms")
            speed = item.get("speed_mbps")
            out.append({
                "ip": str(item["ip"]),
                "port": int(item["port"]),
                "delay_ms": int(delay) if isinstance(delay, (int, float)) else None,
                "speed_mbps": round(float(speed), 2) if isinstance(speed, (int, float)) else None,
            })
    return out


def build_warp_proxies(account: dict[str, Any], endpoints: list[tuple[str, int]], use_awg: bool = True) -> list[dict[str, Any]]:
    proxies: list[dict[str, Any]] = []
    jc = random.randint(4, 6)
    jmin = random.randint(15, 35)
    jmax = jmin + random.randint(25, 60)

    for i, (host, port) in enumerate(endpoints, start=1):
        p: dict[str, Any] = {
            "name": f"WARP-{'AWG' if use_awg else 'WG'}-{i:02d}",
            "type": "wireguard",
            "private-key": account["private_key"],
            "ip": account.get("ipv4", "172.16.0.2"),
            "peers": [
                {
                    "server": host,
                    "port": port,
                    "public-key": account.get("peer_public_key", DEFAULT_WARP_PUBKEY),
                    "allowed-ips": ["0.0.0.0/0"],
                    "persistent-keepalive": 25,
                }
            ],
            "mtu": 1280,
            "udp": True,
            "remote-dns-resolve": True,
            "dns": ["223.5.5.5", "119.29.29.29", "1.1.1.1", "1.0.0.1"],
        }
        if use_awg:
            p["amnezia-wg-option"] = {
                "jc": jc,
                "jmin": jmin,
                "jmax": jmax,
                "s1": 0,
                "s2": 0,
                "h1": 1,
                "h2": 2,
                "h3": 3,
                "h4": 4,
                "i1": AWG_I1_DEFAULT,
            }
        proxies.append(p)
    return proxies
