"""VPN Gate 免费志愿家宽节点拉取、家宽/机房智能分类与 Mihomo OpenVPN 出站构建。"""

from __future__ import annotations

import base64
import concurrent.futures
import csv
import io
import json
import time
import urllib.request
from typing import Any

VPNGATE_API_URL = "https://www.vpngate.net/api/iphone/"
VPNGATE_API_URLS = (
    "https://www.vpngate.net/api/iphone/",
    "http://www.vpngate.net/api/iphone/",
)
IP_API_BATCH_URL = "http://ip-api.com/batch?fields=status,countryCode,isp,org,as,mobile,proxy,hosting,query"
IPWHO_ENDPOINT = "https://ipwho.is/"

# 为欧美地区保留候选保底配额，避免 VPN Gate 热门前排被日韩高分节点占满后被截断
PRIORITY_WESTERN_COUNTRIES = frozenset({
    "US", "CA", "GB", "UK", "DE", "FR", "NL", "CH", "SE", "IT",
    "ES", "AU", "NZ", "IE", "AT", "BE", "NO", "FI", "PL", "RO", "CZ",
})

HARD_DC_ASNS = {
    16509, 14618, 15169, 396982, 8075, 13335, 14061, 20473, 63949, 16276,
    24940, 51167, 9009, 36352, 53667, 29802, 40676, 46844, 62240,
}

RESIDENTIAL_BRANDS = (
    "korea telecom", "kt corporation", "sk broadband", "skb-as-kr", "lg u+", "lgu+", "lg uplus",
    "softbank", "kddi", "comcast", "charter", "spectrum", "frontier", "fidium",
    "consolidated communications", "so-net", "sony network communications", "jcom",
    "chubu telecommunications", "commufa", "ctcx", "asahi net", "asahi-net", "ocn",
    "ntt-me", "wakwak", "xephion", "rostelecom", "er-telecom", "wave broadband",
    "lg powercomm", "powervis", "lg hellovision", "hellovision", "cjckn",
    "biglobe", "plala", "nifty", "@nifty", "orange", "etisalat", "arteria",
    "hawaiian telcom", "tt dotcom", "ttnet",
)

DC_KEYWORDS = (
    "hosting", "cloud", "server", "datacenter", "data center", "data-centre", "colocation",
    " vps", "vps ", "dedicated", " idc", "amazon", "google llc", "microsoft", "oracle",
    "digitalocean", "linode", "vultr", "hetzner", "ovh", "contabo", "alibaba", "tencent",
    "cloudflare", "choopa", "leaseweb", "m247", "psychz", "quadranet", "colocrossing",
)

COUNTRY_FLAGS = {
    "JP": "🇯🇵", "KR": "🇰🇷", "US": "🇺🇸", "TW": "🇹🇼", "HK": "🇭🇰",
    "SG": "🇸🇬", "GB": "🇬🇧", "UK": "🇬🇧", "DE": "🇩🇪", "FR": "🇫🇷", "CA": "🇨🇦",
    "AU": "🇦🇺", "NL": "🇳🇱", "TH": "🇹🇭", "VN": "🇻🇳", "ID": "🇮🇩",
    "IN": "🇮🇳", "BR": "🇧🇷", "RU": "🇷🇺", "RO": "🇷🇴", "CH": "🇨🇭",
    "SE": "🇸🇪", "IT": "🇮🇹", "ES": "🇪🇸", "PL": "🇵🇱", "NO": "🇳🇴",
    "FI": "🇫🇮", "UA": "🇺🇦", "NZ": "🇳🇿", "IE": "🇮🇪", "AT": "🇦🇹",
    "BE": "🇧🇪", "CZ": "🇨🇿",
}


def _parse_asn(as_str: str) -> int:
    s = (as_str or "").strip().upper()
    if not s.startswith("AS"):
        return 0
    digits = []
    for ch in s[2:]:
        if ch.isdigit():
            digits.append(ch)
        else:
            break
    return int("".join(digits)) if digits else 0


def parse_ovpn_profile(raw_text: str) -> dict[str, Any] | None:
    blocks: dict[str, str] = {}
    cur_tag = ""
    buf: list[str] = []
    prof: dict[str, Any] = {
        "proto": "tcp",
        "dev": "tun",
    }

    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("<") and line.endswith(">") and not line.startswith("</"):
            cur_tag = line[1:-1].strip().lower()
            buf = []
            continue
        if line.startswith("</"):
            if cur_tag:
                blocks[cur_tag] = "\n".join(buf) + "\n"
            cur_tag = ""
            continue
        if cur_tag:
            buf.append(line)
            continue

        parts = line.split()
        if not parts:
            continue
        cmd = parts[0].lower()
        if cmd == "remote" and len(parts) >= 3 and "server" not in prof:
            if parts[2].isdigit():
                prof["server"] = parts[1]
                prof["port"] = int(parts[2])
        elif cmd == "proto" and len(parts) >= 2:
            prof["proto"] = "udp" if "udp" in parts[1].lower() else "tcp"
        elif cmd == "dev" and len(parts) >= 2:
            prof["dev"] = parts[1]
        elif cmd == "cipher" and len(parts) >= 2:
            prof["cipher"] = parts[1]
        elif cmd == "data-ciphers" and len(parts) >= 2:
            prof["data-ciphers"] = [x for x in parts[1].split(":") if x]
        elif cmd == "auth" and len(parts) >= 2:
            prof["auth"] = parts[1]
        elif cmd == "key-direction" and len(parts) >= 2:
            prof["key-direction"] = parts[1]
        elif cmd == "comp-lzo":
            val = parts[1].lower() if len(parts) >= 2 else "yes"
            if val != "no":
                prof["comp-lzo"] = val
        elif cmd == "tun-mtu" or cmd == "mtu":
            if len(parts) >= 2 and parts[1].isdigit():
                prof["mtu"] = int(parts[1])

    if "server" not in prof or "port" not in prof:
        return None
    if "ca" in blocks:
        prof["ca"] = blocks["ca"]
    if "cert" in blocks:
        prof["cert"] = blocks["cert"]
    if "key" in blocks:
        prof["key"] = blocks["key"]
    if "tls-auth" in blocks:
        prof["tls-auth"] = blocks["tls-auth"]
    if "tls-crypt" in blocks:
        prof["tls-crypt"] = blocks["tls-crypt"]
    if "tls-crypt-v2" in blocks:
        prof["tls-crypt-v2"] = blocks["tls-crypt-v2"]
    return prof


def _classify_node(host_name: str, info: dict[str, Any] | None) -> tuple[str, str]:
    """返回 (class: residential|datacenter, isp_label)。"""
    if host_name.lower().startswith("public-vpn"):
        return "datacenter", "PublicVPN"
    if not info or info.get("status") != "success":
        return "residential", ""

    isp = str(info.get("isp") or info.get("org") or "").strip()
    blob = f"{info.get('isp', '')} {info.get('org', '')} {info.get('as', '')}".lower()
    asn = _parse_asn(str(info.get("as", "")))
    if asn in HARD_DC_ASNS:
        return "datacenter", isp

    dc_groups = 0
    if info.get("hosting"):
        dc_groups += 1
    if any(k in blob for k in DC_KEYWORDS):
        dc_groups += 1
    is_res_brand = any(b in blob for b in RESIDENTIAL_BRANDS) or bool(info.get("mobile"))

    if dc_groups >= 2 or info.get("hosting") or (dc_groups >= 1 and not is_res_brand):
        return "datacenter", isp
    return "residential", isp


def build_mihomo_openvpn_outbound(node: dict[str, Any]) -> dict[str, Any]:
    prof = dict(node["profile"])
    if prof.get("proto") == "udp" and (not prof.get("mtu") or prof["mtu"] > 1200):
        prof["mtu"] = 1200

    out: dict[str, Any] = {
        "name": node["name"],
        "type": "openvpn",
        "server": prof["server"],
        "port": int(prof["port"]),
        "proto": prof.get("proto", "tcp"),
        "dev": prof.get("dev", "tun"),
        "udp": True,
        "handshake-timeout": 20,
    }
    for key in (
        "cipher", "data-ciphers", "auth", "ca", "cert", "key",
        "tls-auth", "tls-crypt", "tls-crypt-v2", "key-direction", "comp-lzo", "mtu",
    ):
        if key in prof and prof[key]:
            out[key] = prof[key]
    return out


def _select_candidates(parsed_nodes: list[dict[str, Any]], max_nodes: int) -> list[dict[str, Any]]:
    """按 TCP 优先与评分排序筛选候选池，同时为欧美地区保留保底配额。"""
    cap = max(1, int(max_nodes))

    def _node_rank(n: dict[str, Any]) -> tuple[int, int, float]:
        return (0 if n.get("proto") == "tcp" else 1, -int(n.get("score") or 0), -float(n.get("speed_mbps") or 0.0))

    western = sorted(
        [n for n in parsed_nodes if str(n.get("country_short", "")).upper() in PRIORITY_WESTERN_COUNTRIES],
        key=_node_rank,
    )
    others = sorted(
        [n for n in parsed_nodes if str(n.get("country_short", "")).upper() not in PRIORITY_WESTERN_COUNTRIES],
        key=_node_rank,
    )
    if len(parsed_nodes) <= cap:
        return sorted(parsed_nodes, key=_node_rank)

    western_quota = max(1, cap // 2)
    picked_western = western[:western_quota]
    remain = cap - len(picked_western)
    picked_others = others[:remain]
    leftover_western = western[western_quota:western_quota + max(0, remain - len(picked_others))]
    return sorted(picked_western + picked_others + leftover_western, key=_node_rank)


def _crosscheck_ipwho(
    opener: urllib.request.OpenerDirector,
    ips: list[str],
    timeout: float = 5.0,
    total_budget_sec: float = 8.0,
) -> set[str]:
    """用 ipwho.is 对疑似家宽 IP 做第二源交叉核验，返回确认为机房的 IP 集合（失败则跳过，不阻塞）。"""
    dc_ips: set[str] = set()
    uniq = [ip for ip in dict.fromkeys(ips) if ip][:30]
    if not uniq:
        return dc_ips

    deadline = time.monotonic() + total_budget_sec

    def _check_one(ip: str) -> str | None:
        if time.monotonic() >= deadline:
            return None
        try:
            req = urllib.request.Request(f"{IPWHO_ENDPOINT}{ip}", headers={"User-Agent": "curl/8.0"})
            with opener.open(req, timeout=timeout) as resp:
                data = json.loads(resp.read(65536).decode("utf-8", errors="ignore"))
            if not isinstance(data, dict) or not data.get("success"):
                return None
            conn = data.get("connection") or {}
            asn = int(conn.get("asn") or 0)
            isp = str(conn.get("isp") or "")
            org = str(conn.get("org") or "")
            blob = f"{isp} {org}".lower()
            is_res_brand = any(b in blob for b in RESIDENTIAL_BRANDS)
            if asn in HARD_DC_ASNS or (any(k in blob for k in DC_KEYWORDS) and not is_res_brand):
                return ip
        except Exception:
            return None
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        futs = [pool.submit(_check_one, ip) for ip in uniq]
        for fut in concurrent.futures.as_completed(futs, timeout=max(1.0, total_budget_sec + 1.0)):
            try:
                hit = fut.result()
                if hit:
                    dc_ips.add(hit)
            except Exception:
                pass
    return dc_ips


def fetch_vpngate_nodes(proxy_url: str | None = None, max_nodes: int = 200, timeout: float = 12.0) -> list[dict[str, Any]]:
    """拉取并解析 VPN Gate 列表：扩大候选池至 200、保留欧美配额、TCP 优先并双源核验家宽。"""
    handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url} if proxy_url else {})
    opener = urllib.request.build_opener(handler)
    raw_csv = ""
    last_err: Exception | None = None
    for api_url in VPNGATE_API_URLS:
        try:
            req = urllib.request.Request(api_url, headers={"User-Agent": "curl/8.0"})
            with opener.open(req, timeout=timeout) as resp:
                raw_csv = resp.read().decode("utf-8", errors="ignore")
            if raw_csv.strip():
                break
        except Exception as exc:
            last_err = exc
    if not raw_csv.strip():
        raise RuntimeError(f"拉取免费家宽列表失败: {last_err}")

    lines = [ln for ln in raw_csv.splitlines() if ln.strip() and not ln.startswith("*")]
    if not lines:
        raise RuntimeError("VPN Gate 返回内容为空")

    # 去掉首行 '#' 注释头前缀
    if lines[0].startswith("#"):
        lines[0] = lines[0][1:]

    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    parsed_nodes: list[dict[str, Any]] = []

    for row in reader:
        b64 = (row.get("OpenVPN_ConfigData_Base64") or "").strip()
        if not b64:
            continue
        try:
            ovpn_text = base64.b64decode(b64).decode("utf-8", errors="ignore")
        except Exception:
            continue
        prof = parse_ovpn_profile(ovpn_text)
        if not prof:
            continue

        cc = (row.get("CountryShort") or "GL").strip().upper()
        ip = (row.get("IP") or prof["server"]).strip()
        try:
            score = int(row.get("Score") or 0)
        except ValueError:
            score = 0
        try:
            speed = int(row.get("Speed") or 0)
        except ValueError:
            speed = 0
        try:
            ping = int(row.get("Ping") or 999)
        except ValueError:
            ping = 999

        parsed_nodes.append({
            "id": f"vg-{cc.lower()}-{ip}-{prof['port']}",
            "host_name": (row.get("HostName") or "").strip(),
            "ip": ip,
            "port": prof["port"],
            "proto": prof["proto"],
            "country_short": cc,
            "country_long": (row.get("CountryLong") or cc).strip(),
            "score": score,
            "speed_mbps": round(speed / 1_000_000, 1),
            "ping": ping,
            "operator": (row.get("Operator") or "").strip(),
            "profile": prof,
        })

    # 按 TCP 优先与评分截断候选池（为欧美保留配额），再批量查 ip-api 识别家宽
    candidates = _select_candidates(parsed_nodes, max_nodes=max_nodes)

    # 批量查 ip-api 识别家宽 vs 机房
    uniq_ips = list(dict.fromkeys(n["ip"] for n in candidates if n["ip"]))
    ip_info: dict[str, dict[str, Any]] = {}
    for start in range(0, len(uniq_ips), 100):
        batch = uniq_ips[start:start + 100]
        try:
            req_ip = urllib.request.Request(
                IP_API_BATCH_URL,
                data=json.dumps(batch).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with opener.open(req_ip, timeout=12) as resp_ip:
                rows = json.loads(resp_ip.read().decode("utf-8", errors="ignore"))
            if isinstance(rows, list):
                for r in rows:
                    if isinstance(r, dict) and r.get("query"):
                        ip_info[r["query"]] = r
        except Exception:
            pass

    # 第一轮分类
    for n in candidates:
        cls, isp = _classify_node(n["host_name"], ip_info.get(n["ip"]))
        n["line_class"] = cls
        n["isp"] = isp or n["operator"] or "志愿节点"

    # 第二源 ipwho.is 交叉复核（优先复核欧美及待确认家宽候选）
    res_ips = [
        n["ip"] for n in candidates
        if n["line_class"] == "residential" and n["ip"]
        and not any(b in str(n.get("isp", "")).lower() for b in RESIDENTIAL_BRANDS)
    ]
    if res_ips:
        dc_hits = _crosscheck_ipwho(opener, res_ips)
        if dc_hits:
            for n in candidates:
                if n["ip"] in dc_hits:
                    n["line_class"] = "datacenter"

    # 家宽优先、TCP 优先、高分优先
    candidates.sort(
        key=lambda x: (
            0 if x["line_class"] == "residential" else 1,
            0 if x.get("proto") == "tcp" else 1,
            -x["score"],
            -x["speed_mbps"],
        )
    )

    counter: dict[tuple[str, str], int] = {}
    for n in candidates:
        cls_cn = "家宽" if n["line_class"] == "residential" else "机房"
        key = (n["country_short"], cls_cn)
        counter[key] = counter.get(key, 0) + 1
        flag = COUNTRY_FLAGS.get(n["country_short"], "🌐")
        n["name"] = f"{flag} {n['country_short']} {cls_cn} {counter[key]:02d}"

    return candidates
