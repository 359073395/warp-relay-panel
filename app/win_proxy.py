"""Windows 系统代理读取/设置/恢复 与 管理员权限(UAC)辅助。"""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import winreg
from pathlib import Path
from typing import Any

_INTERNET_SETTINGS_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_INTERNET_OPTION_SETTINGS_CHANGED = 39
_INTERNET_OPTION_REFRESH = 37


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin(script_path: Path | None = None) -> bool:
    """触发 UAC 提权以管理员身份重启面板。"""
    if getattr(sys, "frozen", False):
        exe = sys.executable
        params = ""
        workdir = str(Path(exe).resolve().parent)
    else:
        exe = sys.executable
        target = script_path or Path(__file__).resolve().parent.parent / "run_panel.py"
        params = f'"{target}"'
        workdir = str(target.parent)
    ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, workdir, 1)
    return int(ret) > 32


def _notify_wininet() -> None:
    try:
        wininet = ctypes.windll.wininet
        wininet.InternetSetOptionW(0, _INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        wininet.InternetSetOptionW(0, _INTERNET_OPTION_REFRESH, 0, 0)
    except Exception:
        pass


def get_active_proxy_url(self_port: int = 17890) -> str | None:
    """若当前系统代理已开启且非本面板端口，返回 http://host:port。"""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INTERNET_SETTINGS_PATH, 0, winreg.KEY_READ) as k:
            enable, _ = winreg.QueryValueEx(k, "ProxyEnable")
            if int(enable) != 1:
                return None
            srv, _ = winreg.QueryValueEx(k, "ProxyServer")
            srv = str(srv).strip()
            if srv and f":{self_port}" not in srv:
                return f"http://{srv}" if "://" not in srv else srv
    except Exception:
        return None
    return None


def check_system_proxy(self_port: int = 17890) -> dict[str, Any]:
    """检查当前 Windows 系统代理是否仍开启并指向指定本地端口。"""
    target = f"127.0.0.1:{self_port}"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INTERNET_SETTINGS_PATH, 0, winreg.KEY_READ) as k:
            try:
                enable = int(winreg.QueryValueEx(k, "ProxyEnable")[0])
            except FileNotFoundError:
                enable = 0
            try:
                srv = str(winreg.QueryValueEx(k, "ProxyServer")[0]).strip()
            except FileNotFoundError:
                srv = ""
        return {"ok": (enable == 1 and srv == target), "enable": enable, "server": srv}
    except Exception:
        return {"ok": False, "enable": 0, "server": ""}


def reclaim_system_proxy(port: int) -> None:
    """在不覆写原始快照的前提下重新接管系统代理（用于防止其他软件关闭/重置 ProxyEnable）。"""
    target = f"127.0.0.1:{port}"
    bypass = "<local>;localhost;127.*;10.*;172.16.*;192.168.*"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INTERNET_SETTINGS_PATH, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, target)
        winreg.SetValueEx(k, "ProxyOverride", 0, winreg.REG_SZ, bypass)
        try:
            winreg.DeleteValue(k, "AutoConfigURL")
        except FileNotFoundError:
            pass
    _notify_wininet()


_SINGLE_INSTANCE_MUTEX = None


def try_acquire_single_instance(name: str = "Local\\StarBridgePanelMutex") -> bool:
    """尝试获取单实例命名互斥锁；已存在实例时返回 False。"""
    global _SINGLE_INSTANCE_MUTEX
    if sys.platform != "win32":
        return True
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.CreateMutexW(None, False, str(name))
        err = kernel32.GetLastError()
        if not handle:
            return True
        if err == 183:  # ERROR_ALREADY_EXISTS
            kernel32.CloseHandle(handle)
            return False
        _SINGLE_INSTANCE_MUTEX = handle
        return True
    except Exception:
        return True


def is_system_light_theme() -> bool:
    """检测 Windows 当前应用外观是否为浅色模式（AppsUseLightTheme=1）。"""
    if sys.platform != "win32":
        return False
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
            0,
            winreg.KEY_READ,
        ) as k:
            val, _ = winreg.QueryValueEx(k, "AppsUseLightTheme")
            return bool(int(val))
    except Exception:
        return True


def set_window_theme(hwnd: int, dark: bool) -> bool:
    """设置 Windows 标题栏深浅色模式（DWMWA_USE_IMMERSIVE_DARK_MODE=20）。"""
    if sys.platform != "win32" or not hwnd:
        return False
    try:
        dwm = ctypes.windll.dwmapi
        hr = int(dwm.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(ctypes.c_int(1 if dark else 0)), 4))
        return hr == 0
    except Exception:
        return False


def enable_acrylic_backdrop(hwnd: int, dark: bool | None = None) -> bool:
    """在 Windows 11 启用原生 Acrylic 半透明亚克力磨砂窗体背景。"""
    if sys.platform != "win32" or not hwnd:
        return False
    try:
        class _MARGINS(ctypes.Structure):
            _fields_ = [
                ("left", ctypes.c_int),
                ("right", ctypes.c_int),
                ("top", ctypes.c_int),
                ("bottom", ctypes.c_int),
            ]

        is_dark = (not is_system_light_theme()) if dark is None else bool(dark)
        dwm = ctypes.windll.dwmapi
        dwm.DwmExtendFrameIntoClientArea(hwnd, ctypes.byref(_MARGINS(-1, -1, -1, -1)))
        dwm.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(ctypes.c_int(1 if is_dark else 0)), 4)
        hr = int(dwm.DwmSetWindowAttribute(hwnd, 38, ctypes.byref(ctypes.c_int(3)), 4))
        return hr == 0
    except Exception:
        return False


def _read_snapshot() -> dict[str, Any]:
    snap: dict[str, Any] = {"enable": 0, "server": "", "override": "", "auto_config": ""}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INTERNET_SETTINGS_PATH, 0, winreg.KEY_READ) as k:
            for reg_key, field in (
                ("ProxyEnable", "enable"),
                ("ProxyServer", "server"),
                ("ProxyOverride", "override"),
                ("AutoConfigURL", "auto_config"),
            ):
                try:
                    val, _ = winreg.QueryValueEx(k, reg_key)
                    snap[field] = val
                except FileNotFoundError:
                    pass
    except Exception:
        pass
    return snap


def set_system_proxy(port: int, snapshot_file: Path) -> None:
    snap = _read_snapshot()
    target = f"127.0.0.1:{port}"
    # 若上次异常退出残留的是本软件端口，恢复基线设为直连
    if snap.get("server") == target:
        snap["enable"] = 0
        snap["server"] = ""

    snapshot_file.parent.mkdir(parents=True, exist_ok=True)
    snapshot_file.write_text(json.dumps(snap, ensure_ascii=False, indent=2), encoding="utf-8")

    bypass = "<local>;localhost;127.*;10.*;172.16.*;192.168.*"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INTERNET_SETTINGS_PATH, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, target)
        winreg.SetValueEx(k, "ProxyOverride", 0, winreg.REG_SZ, bypass)
        try:
            winreg.DeleteValue(k, "AutoConfigURL")
        except FileNotFoundError:
            pass
    _notify_wininet()


def restore_system_proxy(snapshot_file: Path, self_port: int = 17890) -> None:
    if not snapshot_file.exists():
        # 若没有快照但当前指向我们自己的端口，仍主动清零
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INTERNET_SETTINGS_PATH, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as k:
                try:
                    srv, _ = winreg.QueryValueEx(k, "ProxyServer")
                    if str(srv).startswith(f"127.0.0.1:{self_port}"):
                        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                except FileNotFoundError:
                    pass
        except Exception:
            pass
        _notify_wininet()
        return

    try:
        snap = json.loads(snapshot_file.read_text(encoding="utf-8"))
    except Exception:
        snap = {"enable": 0, "server": "", "override": "", "auto_config": ""}

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INTERNET_SETTINGS_PATH, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, int(snap.get("enable", 0)))
        if snap.get("server"):
            winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, str(snap["server"]))
        else:
            try:
                winreg.DeleteValue(k, "ProxyServer")
            except FileNotFoundError:
                pass
        if snap.get("override"):
            winreg.SetValueEx(k, "ProxyOverride", 0, winreg.REG_SZ, str(snap["override"]))
        if snap.get("auto_config"):
            winreg.SetValueEx(k, "AutoConfigURL", 0, winreg.REG_SZ, str(snap["auto_config"]))

    try:
        snapshot_file.unlink()
    except Exception:
        pass
    _notify_wininet()
