"""Windows 桌面端检查更新与一键静默覆盖升级模块。"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Any, Callable

APP_VERSION = "2.2.7"
GITHUB_LATEST_API = "https://api.github.com/repos/359073395/warp-relay-panel/releases/latest"
GITHUB_RELEASES_ATOM = "https://github.com/359073395/warp-relay-panel/releases.atom"
GH_MIRRORS = ["", "https://gh-proxy.com/"]


def parse_version(raw: str) -> tuple[int, ...]:
    nums = re.findall(r"\d+", str(raw or ""))
    if not nums:
        return (0,)
    return tuple(int(x) for x in nums[:4])


def is_newer_version(remote_tag: str, current_version: str = APP_VERSION) -> bool:
    r = list(parse_version(remote_tag))
    c = list(parse_version(current_version))
    max_len = max(len(r), len(c))
    r.extend([0] * (max_len - len(r)))
    c.extend([0] * (max_len - len(c)))
    return tuple(r) > tuple(c)


def _open_url(url: str, proxy_url: str | None = None, timeout: float = 15.0):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": f"StarBridge/{APP_VERSION}",
            "Accept": "application/vnd.github+json",
        },
    )
    handlers = []
    if proxy_url:
        handlers.append(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
    else:
        handlers.append(urllib.request.ProxyHandler({}))
    opener = urllib.request.build_opener(*handlers)
    return opener.open(req, timeout=timeout)


def _check_via_atom(proxy_url: str | None = None) -> dict[str, Any] | None:
    urls: list[tuple[str, str | None]] = []
    if proxy_url:
        urls.append((GITHUB_RELEASES_ATOM, proxy_url))
    for prefix in GH_MIRRORS:
        urls.append((f"{prefix}{GITHUB_RELEASES_ATOM}" if prefix else GITHUB_RELEASES_ATOM, None))
    for u, px in urls:
        try:
            with _open_url(u, proxy_url=px, timeout=10.0) as resp:
                xml_head = resp.read(24000).decode("utf-8", errors="ignore")
            m = re.search(r"releases/tag/(v?\d+(?:\.\d+)+)", xml_head)
            if m:
                tag = m.group(1)
                base_dl = f"https://github.com/359073395/warp-relay-panel/releases/download/{tag}"
                return {
                    "tag_name": tag,
                    "body": "",
                    "html_url": f"https://github.com/359073395/warp-relay-panel/releases/tag/{tag}",
                    "assets": [
                        {"name": "StarBridge-Setup.exe", "browser_download_url": f"{base_dl}/StarBridge-Setup.exe"},
                        {"name": "StarBridge-android-arm64.apk", "browser_download_url": f"{base_dl}/StarBridge-android-arm64.apk"},
                    ],
                }
        except Exception:
            continue
    return None


def check_latest_release(
    proxy_url: str | None = None,
    current_version: str = APP_VERSION,
) -> dict[str, Any]:
    proxies_to_try = [proxy_url, None] if proxy_url else [None]
    last_err: Exception | None = None
    data: dict[str, Any] | None = None
    for px in proxies_to_try:
        try:
            with _open_url(GITHUB_LATEST_API, proxy_url=px, timeout=10.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            break
        except Exception as exc:
            last_err = exc
    if data is None:
        data = _check_via_atom(proxy_url=proxy_url)
    if data is None:
        raise RuntimeError(f"检查更新失败: {last_err}")

    tag = str(data.get("tag_name") or "").strip()
    latest_ver = tag.lstrip("vV") or "0.0.0"
    assets = data.get("assets") or []
    win_url = ""
    apk_url = ""
    for a in assets:
        name = str(a.get("name") or "")
        dl = str(a.get("browser_download_url") or "")
        if name == "StarBridge-Setup.exe":
            win_url = dl
        elif name == "StarBridge-android-arm64.apk":
            apk_url = dl

    return {
        "ok": True,
        "current_version": current_version,
        "latest_version": latest_ver,
        "tag_name": tag,
        "has_update": is_newer_version(latest_ver, current_version),
        "release_notes": str(data.get("body") or "")[:800],
        "html_url": str(data.get("html_url") or ""),
        "win_setup_url": win_url,
        "apk_url": apk_url,
        "can_self_update": bool(win_url and getattr(sys, "frozen", False)),
    }


def download_setup_exe(
    url: str,
    dest: Path,
    proxy_url: str | None = None,
    progress_cb: Callable[[int, str], None] | None = None,
) -> Path:
    if not url:
        raise ValueError("未提供安装包下载地址")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".tmp")

    attempts: list[tuple[str, str | None]] = []
    if proxy_url:
        attempts.append((url, proxy_url))
    for prefix in GH_MIRRORS:
        attempts.append((f"{prefix}{url}" if prefix else url, None))

    last_err: Exception | None = None
    for target_url, px in attempts:
        try:
            if progress_cb:
                progress_cb(1, "正在连接下载服务器...")
            with _open_url(target_url, proxy_url=px, timeout=60.0) as resp:
                total = int(resp.headers.get("Content-Length") or 0)
                downloaded = 0
                with tmp.open("wb") as fp:
                    while True:
                        chunk = resp.read(1024 * 128)
                        if not chunk:
                            break
                        fp.write(chunk)
                        downloaded += len(chunk)
                        if progress_cb and total > 0:
                            pct = min(99, max(1, int(downloaded * 100 / total)))
                            progress_cb(pct, f"已下载 {downloaded / (1024 * 1024):.1f} / {total / (1024 * 1024):.1f} MB")
            head = tmp.read_bytes()[:2]
            if head != b"MZ":
                raise RuntimeError("下载的安装包无效（非 Windows 可执行文件）")
            tmp.replace(dest)
            if progress_cb:
                progress_cb(100, "下载完成，准备升级...")
            return dest
        except Exception as exc:
            last_err = exc
            tmp.unlink(missing_ok=True)

    raise RuntimeError(f"下载安装包失败: {last_err}")


def launch_windows_silent_upgrade(
    setup_exe: Path,
    install_dir: Path,
    wait_pid: int | None = None,
) -> None:
    if sys.platform != "win32":
        return
    pid = int(wait_pid or os.getpid())
    s_exe = str(setup_exe).replace("'", "''")
    s_dir = str(install_dir).replace("'", "''")
    target_exe = str((install_dir / "StarBridge.exe").resolve()).replace("'", "''")
    log_path = str((Path(setup_exe).resolve().parent / "StarBridge-Update.log")).replace("'", "''")
    ps_script = (
        f"$log = '{log_path}'; "
        "try { "
        f"try {{ Wait-Process -Id {pid} -Timeout 15 -ErrorAction SilentlyContinue }} catch {{}}; "
        f"$targetExe = '{target_exe}'; "
        "$deadline = (Get-Date).AddSeconds(10); "
        "while ((Get-Date) -lt $deadline) { "
        "  $alive = Get-Process -Name 'StarBridge' -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $targetExe }; "
        "  if (-not $alive) { break }; "
        "  Start-Sleep -Milliseconds 300 "
        "}; "
        "Start-Sleep -Milliseconds 400; "
        f"Start-Process -FilePath '{s_exe}' -ArgumentList '--silent','--dir','{s_dir}','--no-desktop','--no-start-menu','--launch'; "
        "'launched' | Out-File -FilePath $log -Encoding utf8 "
        "} catch { "
        "$_ | Out-File -FilePath $log -Encoding utf8 "
        "}"
    )
    encoded = base64.b64encode(ps_script.encode("utf-16le")).decode("ascii")
    # CREATE_NO_WINDOW and DETACHED_PROCESS are mutually exclusive on Windows;
    # combining them causes powershell.exe to exit silently without running.
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    subprocess.Popen(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-WindowStyle",
            "Hidden",
            "-EncodedCommand",
            encoded,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        creationflags=creation_flags,
    )
