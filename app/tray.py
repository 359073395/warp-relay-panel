"""Windows 原生系统托盘图标（纯 ctypes 实现，零额外第三方依赖）。"""

from __future__ import annotations

import ctypes
import sys
import threading
from ctypes import wintypes
from pathlib import Path
from typing import Callable

_WM_USER = 0x0400
_WM_TRAYICON = _WM_USER + 20
_WM_COMMAND = 0x0111
_WM_DESTROY = 0x0002
_WM_LBUTTONUP = 0x0202
_WM_LBUTTONDBLCLK = 0x0203
_WM_RBUTTONUP = 0x0205

_NIM_ADD = 0x00000000
_NIM_MODIFY = 0x00000001
_NIM_DELETE = 0x00000002
_NIF_MESSAGE = 0x00000001
_NIF_ICON = 0x00000002
_NIF_TIP = 0x00000004

_TPM_LEFTALIGN = 0x0000
_TPM_BOTTOMALIGN = 0x0020
_TPM_RIGHTBUTTON = 0x0002
_MF_STRING = 0x0000
_MF_SEPARATOR = 0x0800
_IDI_APPLICATION = 32512
_IMAGE_ICON = 1
_LR_LOADFROMFILE = 0x0010
_LR_DEFAULTSIZE = 0x0040

_ID_SHOW = 1001
_ID_TOGGLE = 1002
_ID_RECLAIM = 1003
_ID_EXIT = 1004


class _NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("hWnd", wintypes.HWND),
        ("uID", wintypes.UINT),
        ("uFlags", wintypes.UINT),
        ("uCallbackMessage", wintypes.UINT),
        ("hIcon", wintypes.HICON),
        ("szTip", wintypes.WCHAR * 128),
        ("dwState", wintypes.DWORD),
        ("dwStateMask", wintypes.DWORD),
        ("szInfo", wintypes.WCHAR * 256),
        ("uVersion", wintypes.UINT),
        ("szInfoTitle", wintypes.WCHAR * 64),
        ("dwInfoFlags", wintypes.DWORD),
        ("guidItem", ctypes.c_byte * 16),
        ("hBalloonIcon", wintypes.HICON),
    ]


class _POINT(ctypes.Structure):
    _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]


WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_longlong, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)


class _WNDCLASSW(ctypes.Structure):
    _fields_ = [
        ("style", wintypes.UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HICON),
        ("hCursor", wintypes.HANDLE),
        ("hbrBackground", wintypes.HBRUSH),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
    ]


class TrayIcon:
    def __init__(
        self,
        tooltip: str,
        on_show: Callable[[], None],
        on_toggle: Callable[[], None],
        on_exit: Callable[[], None],
        is_connected_fn: Callable[[], bool],
        icon_path: str | Path | None = None,
        icon_paths: dict[str, str | Path] | None = None,
        on_reclaim_proxy: Callable[[], None] | None = None,
    ) -> None:
        self.tooltip = tooltip[:120]
        self.on_show = on_show
        self.on_toggle = on_toggle
        self.on_exit = on_exit
        self.on_reclaim_proxy = on_reclaim_proxy
        self.is_connected_fn = is_connected_fn
        self.icon_path = str(icon_path) if icon_path else None
        self.icon_paths: dict[str, str] = {
            k: str(v) for k, v in (icon_paths or {}).items() if v
        }
        if self.icon_path and "idle" not in self.icon_paths:
            self.icon_paths["idle"] = self.icon_path
        self._hwnd: wintypes.HWND | None = None
        self._thread: threading.Thread | None = None
        self._nid: _NOTIFYICONDATAW | None = None
        self._custom_hicon: wintypes.HICON | None = None
        self._state_hicons: dict[str, wintypes.HICON] = {}
        self._state: str = "idle"
        self._wndproc_ref: WNDPROC | None = None
        self._started = threading.Event()

    def start(self) -> None:
        if sys.platform != "win32":
            return
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        self._started.wait(timeout=2.0)

    def set_state(self, state: str, tooltip: str | None = None) -> None:
        """动态切换托盘图标颜色与悬停提示（idle / connecting / connected / warning）。"""
        self._state = state
        if tooltip:
            self.tooltip = tooltip[:120]
        if sys.platform != "win32" or not self._hwnd or self._nid is None:
            return
        try:
            hicon = (
                self._state_hicons.get(state)
                or self._state_hicons.get("idle")
                or self._custom_hicon
            )
            if hicon:
                self._nid.hIcon = hicon
            self._nid.szTip = self.tooltip
            self._nid.uFlags = _NIF_MESSAGE | _NIF_ICON | _NIF_TIP
            ctypes.windll.shell32.Shell_NotifyIconW(_NIM_MODIFY, ctypes.byref(self._nid))
        except Exception:
            pass

    def stop(self) -> None:
        if sys.platform != "win32":
            return
        hwnd = self._hwnd
        if hwnd:
            try:
                user32 = ctypes.windll.user32
                if self._nid is not None:
                    ctypes.windll.shell32.Shell_NotifyIconW(_NIM_DELETE, ctypes.byref(self._nid))
                seen: set[int] = set()
                for hi in [self._custom_hicon, *self._state_hicons.values()]:
                    if hi and int(hi) not in seen:
                        seen.add(int(hi))
                        user32.DestroyIcon(hi)
                self._custom_hicon = None
                self._state_hicons.clear()
                user32.PostMessageW(hwnd, _WM_DESTROY, 0, 0)
            except Exception:
                pass
        self._hwnd = None

    def _show_menu(self, hwnd: wintypes.HWND) -> None:
        user32 = ctypes.windll.user32
        hmenu = user32.CreatePopupMenu()
        if not hmenu:
            return
        try:
            toggle_label = "断开连接" if self.is_connected_fn() else "一键连接"
            user32.AppendMenuW(hmenu, _MF_STRING, _ID_SHOW, "打开控制面板")
            user32.AppendMenuW(hmenu, _MF_STRING, _ID_TOGGLE, toggle_label)
            if self.on_reclaim_proxy is not None and self.is_connected_fn():
                user32.AppendMenuW(hmenu, _MF_STRING, _ID_RECLAIM, "恢复系统代理")
            user32.AppendMenuW(hmenu, _MF_SEPARATOR, 0, None)
            user32.AppendMenuW(hmenu, _MF_STRING, _ID_EXIT, "退出并恢复系统代理")

            pt = _POINT()
            user32.GetCursorPos(ctypes.byref(pt))
            user32.SetForegroundWindow(hwnd)
            user32.TrackPopupMenu(
                hmenu,
                _TPM_LEFTALIGN | _TPM_BOTTOMALIGN | _TPM_RIGHTBUTTON,
                pt.x,
                pt.y,
                0,
                hwnd,
                None,
            )
            user32.PostMessageW(hwnd, 0, 0, 0)
        finally:
            user32.DestroyMenu(hmenu)

    def _run_loop(self) -> None:
        try:
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            shell32 = ctypes.windll.shell32

            user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
            user32.DefWindowProcW.restype = ctypes.c_longlong
            user32.LoadImageW.argtypes = [
                wintypes.HINSTANCE,
                wintypes.LPCWSTR,
                wintypes.UINT,
                ctypes.c_int,
                ctypes.c_int,
                wintypes.UINT,
            ]
            user32.LoadImageW.restype = wintypes.HICON

            hinst = kernel32.GetModuleHandleW(None)
            cls_name = f"StarBridgeTray_{id(self)}"

            def _wnd_proc(hwnd: wintypes.HWND, msg: int, wparam: int, lparam: int) -> int:
                if msg == _WM_TRAYICON:
                    if lparam in (_WM_LBUTTONUP, _WM_LBUTTONDBLCLK):
                        threading.Thread(target=self.on_show, daemon=True).start()
                    elif lparam == _WM_RBUTTONUP:
                        self._show_menu(hwnd)
                    return 0
                if msg == _WM_COMMAND:
                    cmd = wparam & 0xFFFF
                    if cmd == _ID_SHOW:
                        threading.Thread(target=self.on_show, daemon=True).start()
                    elif cmd == _ID_TOGGLE:
                        threading.Thread(target=self.on_toggle, daemon=True).start()
                    elif cmd == _ID_RECLAIM and self.on_reclaim_proxy is not None:
                        threading.Thread(target=self.on_reclaim_proxy, daemon=True).start()
                    elif cmd == _ID_EXIT:
                        threading.Thread(target=self.on_exit, daemon=True).start()
                    return 0
                if msg == _WM_DESTROY:
                    user32.PostQuitMessage(0)
                    return 0
                return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

            self._wndproc_ref = WNDPROC(_wnd_proc)
            wc = _WNDCLASSW()
            wc.lpfnWndProc = self._wndproc_ref
            wc.hInstance = hinst
            wc.lpszClassName = cls_name
            user32.RegisterClassW(ctypes.byref(wc))

            hwnd = user32.CreateWindowExW(
                0, cls_name, cls_name, 0, 0, 0, 0, 0, None, None, hinst, None
            )
            self._hwnd = hwnd
            if not hwnd:
                self._started.set()
                return

            for st_name, st_path in self.icon_paths.items():
                if st_path and Path(st_path).exists():
                    loaded = user32.LoadImageW(
                        None,
                        st_path,
                        _IMAGE_ICON,
                        32,
                        32,
                        _LR_LOADFROMFILE,
                    )
                    if loaded:
                        self._state_hicons[st_name] = loaded
            hicon = (
                self._state_hicons.get(self._state)
                or self._state_hicons.get("idle")
            )
            if not hicon and self.icon_path and Path(self.icon_path).exists():
                loaded = user32.LoadImageW(
                    None,
                    self.icon_path,
                    _IMAGE_ICON,
                    32,
                    32,
                    _LR_LOADFROMFILE,
                )
                if loaded:
                    self._custom_hicon = loaded
                    hicon = loaded
            if not hicon:
                hicon = user32.LoadIconW(None, ctypes.cast(_IDI_APPLICATION, wintypes.LPCWSTR))
            nid = _NOTIFYICONDATAW()
            nid.cbSize = ctypes.sizeof(_NOTIFYICONDATAW)
            nid.hWnd = hwnd
            nid.uID = 1
            nid.uFlags = _NIF_MESSAGE | _NIF_ICON | _NIF_TIP
            nid.uCallbackMessage = _WM_TRAYICON
            nid.hIcon = hicon
            nid.szTip = self.tooltip
            self._nid = nid
            shell32.Shell_NotifyIconW(_NIM_ADD, ctypes.byref(nid))
            self._started.set()

            msg = wintypes.MSG()
            while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
        except Exception:
            self._started.set()
