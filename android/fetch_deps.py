"""Fetch prebuilt Android native cores (mihomo, xray, hev-socks5-tunnel, GeoIP) for CI builds."""

from __future__ import annotations

import gzip
import io
import json
import os
import re
import urllib.request
import zipfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
APP_DIR = ROOT / "app"
LIBS_DIR = APP_DIR / "libs"
JNI_ARM64 = APP_DIR / "src" / "main" / "jniLibs" / "arm64-v8a"
ASSETS_CORE = APP_DIR / "src" / "main" / "assets" / "core"

GEO_BASE_URL = "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download"


def _download(url: str, timeout: float = 60.0) -> bytes:
    headers = {"User-Agent": "StarBridge-Android-CI/1.0"}
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token and "api.github.com" in url:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _release_assets(repo: str) -> list[dict[str, Any]]:
    raw = _download(f"https://api.github.com/repos/{repo}/releases/latest", timeout=30.0)
    data = json.loads(raw.decode("utf-8"))
    return list(data.get("assets") or [])


def select_mihomo_android_asset(assets: list[dict[str, Any]]) -> dict[str, Any]:
    for pattern in (
        r"^mihomo-android-arm64-v8-compatible-v[^/]+\.gz$",
        r"^mihomo-android-arm64-v8-v[^/]+\.gz$",
        r"^mihomo-android-arm64-v8[^/]*\.gz$",
    ):
        for asset in assets:
            name = str(asset.get("name", ""))
            if "alpha" in name.lower():
                continue
            if re.match(pattern, name):
                return asset
    raise RuntimeError("No matching mihomo android arm64-v8 .gz asset found")


def select_xray_android_asset(assets: list[dict[str, Any]]) -> dict[str, Any]:
    for asset in assets:
        if str(asset.get("name", "")) == "Xray-android-arm64-v8a.zip":
            return asset
    raise RuntimeError("No Xray-android-arm64-v8a.zip asset found")


def select_tproxy_aar_asset(assets: list[dict[str, Any]]) -> dict[str, Any]:
    for asset in assets:
        name = str(asset.get("name", ""))
        if name.endswith(".aar") and "hev-socks5-tunnel" in name:
            return asset
    for asset in assets:
        if str(asset.get("name", "")).endswith(".aar"):
            return asset
    raise RuntimeError("No hev-socks5-tunnel .aar asset found")


def main() -> None:
    LIBS_DIR.mkdir(parents=True, exist_ok=True)
    JNI_ARM64.mkdir(parents=True, exist_ok=True)
    ASSETS_CORE.mkdir(parents=True, exist_ok=True)

    print("==> Fetching hev-socks5-tunnel.aar...")
    tproxy_asset = select_tproxy_aar_asset(_release_assets("heiher/hev-socks5-tunnel"))
    (LIBS_DIR / "hev-socks5-tunnel.aar").write_bytes(_download(tproxy_asset["browser_download_url"]))
    print(f"    Saved {tproxy_asset['name']}")

    print("==> Fetching mihomo android arm64 binary...")
    mihomo_asset = select_mihomo_android_asset(_release_assets("MetaCubeX/mihomo"))
    mihomo_gz = _download(mihomo_asset["browser_download_url"])
    mihomo_out = JNI_ARM64 / "libmihomo.so"
    mihomo_out.write_bytes(gzip.decompress(mihomo_gz))
    os.chmod(mihomo_out, 0o755)
    print(f"    Extracted {mihomo_asset['name']} -> {mihomo_out}")

    print("==> Fetching xray android arm64 binary...")
    xray_asset = select_xray_android_asset(_release_assets("XTLS/Xray-core"))
    xray_zip = _download(xray_asset["browser_download_url"])
    with zipfile.ZipFile(io.BytesIO(xray_zip)) as zf:
        member = next((n for n in zf.namelist() if n.endswith("/xray") or n == "xray"), None)
        if not member:
            raise RuntimeError("xray binary not found in Xray-android-arm64-v8a.zip")
        xray_out = JNI_ARM64 / "libxray.so"
        xray_out.write_bytes(zf.read(member))
        os.chmod(xray_out, 0o755)
    print(f"    Extracted {xray_asset['name']} -> {xray_out}")

    print("==> Fetching GeoIP / GeoSite rule databases...")
    for fname in ("geosite.dat", "geoip.dat", "geoip.metadb"):
        raw = _download(f"{GEO_BASE_URL}/{fname}")
        (ASSETS_CORE / fname).write_bytes(raw)
        print(f"    Saved {fname} ({len(raw)} bytes)")


if __name__ == "__main__":
    main()
