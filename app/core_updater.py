"""Mihomo 内核与 GeoIP/GeoSite 规则库检测及一键下载模块。"""

from __future__ import annotations

import io
import json
import re
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Callable

MIHOMO_LATEST_API = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
MIHOMO_RELEASES_ATOM = "https://github.com/MetaCubeX/mihomo/releases.atom"
XRAY_LATEST_API = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
XRAY_RELEASES_ATOM = "https://github.com/XTLS/Xray-core/releases.atom"
GEO_BASE_URL = "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download"
GH_MIRRORS = ["", "https://gh-proxy.com/"]

GEO_FILES = ("geosite.dat", "geoip.dat", "geoip.metadb")


def get_core_status(core_dir: Path) -> dict[str, Any]:
    """检查内核与规则库文件是否就绪。"""
    exe_path = core_dir / "mihomo.exe"
    files: dict[str, dict[str, Any]] = {}
    for name in ("mihomo.exe", "xray.exe", *GEO_FILES):
        p = core_dir / name
        exists = p.is_file() and p.stat().st_size > 0
        files[name] = {
            "exists": exists,
            "size_mb": round(p.stat().st_size / (1024 * 1024), 2) if exists else 0.0,
        }
    has_exe = files["mihomo.exe"]["exists"]
    has_xray = files["xray.exe"]["exists"]
    has_geo = all(files[n]["exists"] for n in GEO_FILES)
    return {
        "ready": has_exe,
        "has_exe": has_exe,
        "has_xray": has_xray,
        "has_geo": has_geo,
        "exe_path": str(exe_path),
        "files": files,
    }


def _open_url(url: str, proxy_url: str | None = None, timeout: float = 30.0) -> bytes:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "WarpRelayPanel/1.1"},
    )
    handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url} if proxy_url else {})
    opener = urllib.request.build_opener(handler)
    with opener.open(req, timeout=timeout) as resp:
        return resp.read()


def _download_with_mirrors(
    url: str,
    proxy_url: str | None = None,
    timeout: float = 45.0,
) -> bytes:
    proxies_to_try = [proxy_url, None] if proxy_url else [None]
    last_err: Exception | None = None
    for mirror in GH_MIRRORS:
        target = f"{mirror}{url}" if mirror else url
        for px in proxies_to_try:
            try:
                return _open_url(target, proxy_url=px, timeout=timeout)
            except Exception as exc:
                last_err = exc
    raise RuntimeError(f"下载失败 ({url}): {last_err}")


def _resolve_tag_via_atom(atom_url: str, proxy_url: str | None = None) -> str | None:
    urls: list[tuple[str, str | None]] = []
    if proxy_url:
        urls.append((atom_url, proxy_url))
    for prefix in GH_MIRRORS:
        urls.append((f"{prefix}{atom_url}" if prefix else atom_url, None))
    for u, px in urls:
        try:
            raw = _open_url(u, proxy_url=px, timeout=12.0).decode("utf-8", errors="ignore")
            m = re.search(r"releases/tag/(v?\d+(?:\.\d+)+(?:-[\w.]+)?)", raw)
            if m:
                return m.group(1)
        except Exception:
            continue
    return None


def _resolve_mihomo_zip_url(proxy_url: str | None = None) -> tuple[str, str]:
    """查询最新 Mihomo Windows amd64 发行版 zip 地址与版本号。"""
    proxies_to_try = [proxy_url, None] if proxy_url else [None]
    last_err: Exception | None = None
    release: dict[str, Any] | None = None
    for px in proxies_to_try:
        try:
            raw = _open_url(MIHOMO_LATEST_API, proxy_url=px, timeout=15.0)
            release = json.loads(raw.decode("utf-8", errors="ignore"))
            break
        except Exception as exc:
            last_err = exc

    if not release:
        atom_tag = _resolve_tag_via_atom(MIHOMO_RELEASES_ATOM, proxy_url=proxy_url)
        if atom_tag:
            dl = f"https://github.com/MetaCubeX/mihomo/releases/download/{atom_tag}/mihomo-windows-amd64-compatible-{atom_tag}.zip"
            return dl, atom_tag
        raise RuntimeError(f"获取 Mihomo 最新版本信息失败: {last_err}")

    tag = str(release.get("tag_name") or "latest")
    assets = release.get("assets") or []

    # 优先选择 compatible 版本，兼容老旧 CPU；其次标准 amd64 zip
    preferred_prefixes = (
        "mihomo-windows-amd64-compatible-",
        "mihomo-windows-amd64-v1-",
        "mihomo-windows-amd64-",
    )
    for prefix in preferred_prefixes:
        for asset in assets:
            name = str(asset.get("name") or "")
            if name.startswith(prefix) and name.endswith(".zip") and "alpha" not in name.lower():
                dl = str(asset.get("browser_download_url") or "")
                if dl:
                    return dl, tag

    raise RuntimeError("未在 Mihomo Release 中找到适用于 Windows amd64 的压缩包")


def _resolve_xray_zip_url(proxy_url: str | None = None) -> tuple[str, str]:
    """查询最新 Xray-core Windows 64 位压缩包地址。"""
    proxies_to_try = [proxy_url, None] if proxy_url else [None]
    last_err: Exception | None = None
    release: dict[str, Any] | None = None
    for px in proxies_to_try:
        try:
            raw = _open_url(XRAY_LATEST_API, proxy_url=px, timeout=15.0)
            release = json.loads(raw.decode("utf-8", errors="ignore"))
            break
        except Exception as exc:
            last_err = exc

    if not release:
        atom_tag = _resolve_tag_via_atom(XRAY_RELEASES_ATOM, proxy_url=proxy_url)
        if atom_tag:
            dl = f"https://github.com/XTLS/Xray-core/releases/download/{atom_tag}/Xray-windows-64.zip"
            return dl, atom_tag
        raise RuntimeError(f"获取 Xray-core 最新版本信息失败: {last_err}")

    tag = str(release.get("tag_name") or "latest")
    for asset in release.get("assets") or []:
        name = str(asset.get("name") or "")
        if name == "Xray-windows-64.zip" or (name.startswith("Xray-windows-64") and name.endswith(".zip")):
            dl = str(asset.get("browser_download_url") or "")
            if dl:
                return dl, tag
    raise RuntimeError("未在 Xray-core Release 中找到 Xray-windows-64.zip")


def ensure_xray_exe(core_dir: Path, proxy_url: str | None = None, force: bool = False) -> Path:
    """确保 core/xray.exe 存在（用于桥接 mKCP / QUIC / VLESS 加密等 Xray 专属协议）。"""
    core_dir.mkdir(parents=True, exist_ok=True)
    target = core_dir / "xray.exe"
    if not force and target.is_file() and target.stat().st_size > 0:
        return target

    zip_url, _ver = _resolve_xray_zip_url(proxy_url=proxy_url)
    zip_bytes = _download_with_mirrors(zip_url, proxy_url=proxy_url, timeout=90.0)
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        exe_member = None
        for info in zf.infolist():
            if Path(info.filename).name.lower() == "xray.exe":
                exe_member = info
                break
        if exe_member is None:
            raise RuntimeError("Xray 压缩包中未找到 xray.exe")
        with zf.open(exe_member, "r") as src:
            target.write_bytes(src.read())
    return target


def download_core_assets(
    core_dir: Path,
    proxy_url: str | None = None,
    force: bool = False,
    progress_cb: Callable[[str, int], None] | None = None,
    include_xray: bool = False,
) -> dict[str, Any]:
    """下载缺失的 mihomo.exe、可选 xray.exe 与 GeoIP/GeoSite 规则文件。"""
    core_dir.mkdir(parents=True, exist_ok=True)
    status = get_core_status(core_dir)
    downloaded: list[str] = []
    version = ""

    def _report(msg: str, pct: int) -> None:
        if progress_cb:
            progress_cb(msg, pct)

    if force or not status["has_exe"]:
        _report("正在查询 Mihomo 最新版本...", 10)
        zip_url, version = _resolve_mihomo_zip_url(proxy_url=proxy_url)
        _report(f"正在下载 Mihomo {version}...", 25)
        zip_bytes = _download_with_mirrors(zip_url, proxy_url=proxy_url, timeout=90.0)
        _report("正在解压 mihomo.exe...", 50)
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            exe_member = None
            for info in zf.infolist():
                base = Path(info.filename).name.lower()
                if base.startswith("mihomo") and base.endswith(".exe"):
                    exe_member = info
                    break
            if exe_member is None:
                raise RuntimeError("压缩包中未找到 mihomo*.exe")
            target_exe = core_dir / "mihomo.exe"
            with zf.open(exe_member, "r") as src:
                target_exe.write_bytes(src.read())
        downloaded.append("mihomo.exe")

    geo_targets = [
        name for name in GEO_FILES
        if force or not status["files"][name]["exists"]
    ]
    for idx, name in enumerate(geo_targets):
        pct = 55 + int((idx / max(1, len(geo_targets))) * 30)
        _report(f"正在下载规则库 {name}...", pct)
        data = _download_with_mirrors(f"{GEO_BASE_URL}/{name}", proxy_url=proxy_url, timeout=60.0)
        if len(data) < 1024:
            raise RuntimeError(f"下载的 {name} 文件异常过小 ({len(data)} bytes)")
        (core_dir / name).write_bytes(data)
        downloaded.append(name)

    if include_xray and (force or not status["has_xray"]):
        _report("正在下载 Xray 辅助内核（支持 mKCP / QUIC 等专属协议）...", 90)
        ensure_xray_exe(core_dir, proxy_url=proxy_url, force=force)
        downloaded.append("xray.exe")

    _report("内核与规则库就绪", 100)
    return {
        "ok": True,
        "version": version,
        "downloaded": downloaded,
        "status": get_core_status(core_dir),
    }
