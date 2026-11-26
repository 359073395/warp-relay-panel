import argparse
import base64
import os
import shutil
import subprocess
import sys
import threading
import zipfile
from pathlib import Path
from typing import Callable


APP_NAME = "StarBridge"
DISPLAY_NAME = "星桥 · StarBridge"
PAYLOAD_FILENAME = "StarBridge-win64.zip"


def resolve_icon_path() -> Path | None:
    candidates = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(meipass) / "assets" / "starbridge.ico")
    here = Path(__file__).resolve().parent
    candidates.append(here / "assets" / "starbridge.ico")
    for p in candidates:
        if p.exists():
            return p
    return None


def resolve_payload_path() -> Path:
    candidates = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(meipass) / PAYLOAD_FILENAME)
    here = Path(__file__).resolve().parent
    candidates.extend([
        here / PAYLOAD_FILENAME,
        here / "release" / PAYLOAD_FILENAME,
        Path.cwd() / PAYLOAD_FILENAME,
        Path.cwd() / "release" / PAYLOAD_FILENAME,
    ])
    for p in candidates:
        if p.exists():
            return p
    raise FileNotFoundError(f"未找到安装包载荷文件：{PAYLOAD_FILENAME}")


def default_install_dir() -> Path:
    local_app = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    return Path(local_app) / "Programs" / APP_NAME


def _ps_single_quote(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def create_shortcut(
    shortcut_path: Path,
    target_exe: Path,
    work_dir: Path,
    description: str = "WarpRelayPanel 极简链式加速器",
) -> None:
    shortcut_path.parent.mkdir(parents=True, exist_ok=True)
    ps_script = (
        "$WshShell = New-Object -ComObject WScript.Shell; "
        f"$S = $WshShell.CreateShortcut({_ps_single_quote(str(shortcut_path))}); "
        f"$S.TargetPath = {_ps_single_quote(str(target_exe))}; "
        f"$S.WorkingDirectory = {_ps_single_quote(str(work_dir))}; "
        f"$S.IconLocation = {_ps_single_quote(str(target_exe) + ',0')}; "
        f"$S.Description = {_ps_single_quote(description)}; "
        "$S.Save()"
    )
    encoded = base64.b64encode(ps_script.encode("utf-16le")).decode("ascii")
    res = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            encoded,
        ],
        capture_output=True,
        text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        check=False,
    )
    if res.returncode != 0:
        raise RuntimeError(f"创建快捷方式失败：{res.stderr.strip() or res.stdout.strip()}")


def safe_extract_zip(
    zip_path: Path,
    target_dir: Path,
    progress_cb: Callable[[int, int, str], None] | None = None,
) -> Path:
    target_dir = target_dir.resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / "data").mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path, "r") as zf:
        members = [
            m for m in zf.infolist()
            if m.filename and not m.is_dir()
        ]
        total = max(len(members), 1)
        for idx, info in enumerate(members, start=1):
            norm = info.filename.replace("\\", "/").lstrip("/")
            if not norm or norm == "data" or norm.startswith("data/"):
                continue
            dest = (target_dir / norm).resolve()
            if not dest.is_relative_to(target_dir):
                raise ValueError(f"非法压缩路径：{info.filename}")
            dest.parent.mkdir(parents=True, exist_ok=True)
            import time as _time
            written = False
            for attempt in range(24):
                try:
                    with zf.open(info, "r") as src, dest.open("wb") as dst:
                        shutil.copyfileobj(src, dst, length=1024 * 128)
                    written = True
                    break
                except PermissionError as exc:
                    if attempt == 23:
                        raise RuntimeError(f"无法写入 {dest.name}，请先退出正在运行的 {APP_NAME}.exe 后重试。") from exc
                    _time.sleep(0.5)
            if not written:
                raise RuntimeError(f"无法写入 {dest.name}")
            if progress_cb:
                progress_cb(idx, total, norm)

    exe_path = target_dir / f"{APP_NAME}.exe"
    if not exe_path.exists():
        raise FileNotFoundError(f"安装完成但未找到主程序：{exe_path}")
    return exe_path


def write_uninstaller(install_dir: Path) -> Path:
    uninst_ps1 = install_dir / "uninstall.ps1"
    uninst_ps1.write_text(
        f"""$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Windows.Forms
$ans = [System.Windows.Forms.MessageBox]::Show("确定要卸载 {DISPLAY_NAME} 吗？", "卸载 {DISPLAY_NAME}", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
if ($ans -ne [System.Windows.Forms.DialogResult]::Yes) {{ exit 0 }}
Get-Process -Name "{APP_NAME}","mihomo","xray" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 400
Remove-Item (Join-Path $env:USERPROFILE "Desktop\\星桥 StarBridge.lnk") -Force
Remove-Item (Join-Path $env:APPDATA "Microsoft\\Windows\\Start Menu\\Programs\\星桥 StarBridge.lnk") -Force
Remove-Item "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{APP_NAME}" -Recurse -Force
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
Start-Process powershell -WindowStyle Hidden -ArgumentList "-NoProfile -Command Start-Sleep -Seconds 1; Remove-Item -LiteralPath '$dir' -Recurse -Force"
""",
        encoding="utf-8",
    )
    return uninst_ps1


def register_uninstall_entry(install_dir: Path, exe_path: Path, uninst_ps1: Path) -> None:
    if sys.platform != "win32":
        return
    import winreg

    key_path = rf"Software\Microsoft\Windows\CurrentVersion\Uninstall\{APP_NAME}"
    cmd = f'powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{uninst_ps1}"'
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
        winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, DISPLAY_NAME)
        winreg.SetValueEx(key, "DisplayIcon", 0, winreg.REG_SZ, str(exe_path))
        winreg.SetValueEx(key, "InstallLocation", 0, winreg.REG_SZ, str(install_dir))
        winreg.SetValueEx(key, "Publisher", 0, winreg.REG_SZ, "StarBridge")
        winreg.SetValueEx(key, "DisplayVersion", 0, winreg.REG_SZ, "2.2.5")
        winreg.SetValueEx(key, "UninstallString", 0, winreg.REG_SZ, cmd)
        winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)


def perform_install(
    install_dir: Path,
    create_desktop: bool = True,
    create_start_menu: bool = True,
    launch_after: bool = False,
    payload_path: Path | None = None,
    progress_cb: Callable[[int, int, str], None] | None = None,
    register_uninstall: bool = True,
) -> Path:
    zip_path = payload_path or resolve_payload_path()
    exe_path = safe_extract_zip(zip_path, install_dir, progress_cb=progress_cb)

    if register_uninstall:
        try:
            uninst = write_uninstaller(install_dir)
            register_uninstall_entry(install_dir, exe_path, uninst)
        except Exception:
            pass

    if create_start_menu:
        appdata = Path(os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming"))
        start_lnk = appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "星桥 StarBridge.lnk"
        create_shortcut(start_lnk, exe_path, install_dir, description=DISPLAY_NAME)

    if create_desktop:
        desktop_lnk = Path.home() / "Desktop" / "星桥 StarBridge.lnk"
        create_shortcut(desktop_lnk, exe_path, install_dir, description=DISPLAY_NAME)

    if launch_after:
        subprocess.Popen(
            [str(exe_path)],
            cwd=str(install_dir),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            creationflags=getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
    return exe_path


def run_gui() -> int:
    import ctypes
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

    root = tk.Tk()
    root.title(f"{DISPLAY_NAME} 安装向导")
    root.configure(bg="#0b1220")
    ico = resolve_icon_path()
    if ico:
        try:
            root.iconbitmap(str(ico))
        except Exception:
            pass

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass
    style.configure("Dark.Horizontal.TProgressbar", troughcolor="#162136", background="#2563eb", thickness=12)

    dir_var = tk.StringVar(value=str(default_install_dir()))
    desktop_var = tk.BooleanVar(value=True)
    startmenu_var = tk.BooleanVar(value=True)
    launch_var = tk.BooleanVar(value=True)
    status_var = tk.StringVar(value="准备就绪，选择安装目录后点击「开始安装」")

    header = tk.Frame(root, bg="#0b1220")
    header.pack(side="top", fill="x", padx=22, pady=(18, 8))
    tk.Label(
        header,
        text="星桥 (StarBridge) 安装程序",
        font=("Microsoft YaHei UI", 15, "bold"),
        fg="#f8fafc",
        bg="#0b1220",
        anchor="w",
    ).pack(fill="x")
    tk.Label(
        header,
        text="极简双核加速面板（已内置 mihomo + xray + GeoIP，安装即可使用）",
        font=("Microsoft YaHei UI", 9),
        fg="#94a3b8",
        bg="#0b1220",
        anchor="w",
    ).pack(fill="x", pady=(3, 0))

    # 先固定在底部，确保任何 DPI 缩放下“开始安装/取消”按钮都不会被挤压裁剪
    footer = tk.Frame(root, bg="#0b1220")
    footer.pack(side="bottom", fill="x", padx=22, pady=(6, 16))

    body = tk.Frame(root, bg="#111827", highlightbackground="#1f2937", highlightthickness=1)
    body.pack(fill="both", expand=True, padx=22, pady=(4, 10))

    tk.Label(
        body,
        text="安装位置：",
        font=("Microsoft YaHei UI", 9, "bold"),
        fg="#cbd5e1",
        bg="#111827",
        anchor="w",
    ).pack(fill="x", padx=14, pady=(12, 4))

    path_row = tk.Frame(body, bg="#111827")
    path_row.pack(fill="x", padx=14)
    path_entry = tk.Entry(
        path_row,
        textvariable=dir_var,
        font=("Consolas", 9),
        bg="#0b1220",
        fg="#e2e8f0",
        insertbackground="#e2e8f0",
        relief="flat",
        highlightthickness=1,
        highlightbackground="#334155",
    )
    path_entry.pack(side="left", fill="x", expand=True, ipady=5)

    def browse() -> None:
        chosen = filedialog.askdirectory(initialdir=dir_var.get() or str(Path.home()))
        if chosen:
            chosen_path = Path(chosen)
            if chosen_path.name.lower() != APP_NAME.lower():
                chosen_path = chosen_path / APP_NAME
            dir_var.set(str(chosen_path))

    browse_btn = tk.Button(
        path_row,
        text="浏览...",
        command=browse,
        font=("Microsoft YaHei UI", 9),
        bg="#1e293b",
        fg="#e2e8f0",
        activebackground="#334155",
        activeforeground="#ffffff",
        relief="flat",
        padx=12,
        pady=4,
    )
    browse_btn.pack(side="left", padx=(8, 0))

    opt_frame = tk.Frame(body, bg="#111827")
    opt_frame.pack(fill="x", padx=14, pady=(12, 6))
    for text, var in [
        ("创建桌面快捷方式", desktop_var),
        ("添加到开始菜单", startmenu_var),
        ("安装完成后立即启动", launch_var),
    ]:
        tk.Checkbutton(
            opt_frame,
            text=text,
            variable=var,
            font=("Microsoft YaHei UI", 9),
            fg="#cbd5e1",
            bg="#111827",
            selectcolor="#0b1220",
            activebackground="#111827",
            activeforeground="#ffffff",
        ).pack(anchor="w", pady=1)

    pbar = ttk.Progressbar(body, style="Dark.Horizontal.TProgressbar", maximum=100, mode="determinate")
    pbar.pack(fill="x", padx=14, pady=(8, 4))

    tk.Label(
        body,
        textvariable=status_var,
        font=("Microsoft YaHei UI", 8),
        fg="#94a3b8",
        bg="#111827",
        anchor="w",
    ).pack(fill="x", padx=14, pady=(0, 8))

    def start_install() -> None:
        target = Path(dir_var.get().strip())
        if not str(target):
            messagebox.showwarning("提示", "请选择有效的安装目录")
            return
        install_btn.config(state="disabled", text="正在安装...")
        browse_btn.config(state="disabled")
        cancel_btn.config(state="disabled")

        def worker() -> None:
            try:
                def on_prog(idx: int, total: int, fname: str) -> None:
                    pct = int(idx * 100 / max(total, 1))
                    root.after(
                        0,
                        lambda p=pct, n=fname: (pbar.configure(value=p), status_var.set(f"正在释放：{n}")),
                    )

                exe_path = perform_install(
                    install_dir=target,
                    create_desktop=desktop_var.get(),
                    create_start_menu=startmenu_var.get(),
                    launch_after=launch_var.get(),
                    progress_cb=on_prog,
                )

                def on_done() -> None:
                    pbar.configure(value=100)
                    status_var.set(f"安装完成：{exe_path}")
                    messagebox.showinfo("安装成功", f"{DISPLAY_NAME} 已安装到：\n{target}")
                    root.destroy()

                root.after(0, on_done)
            except Exception as exc:
                msg = str(exc)

                def on_err() -> None:
                    status_var.set(f"安装失败：{msg}")
                    install_btn.config(state="normal", text="重试安装")
                    browse_btn.config(state="normal")
                    cancel_btn.config(state="normal")
                    messagebox.showerror("安装失败", msg)

                root.after(0, on_err)

        threading.Thread(target=worker, daemon=True).start()

    install_btn = tk.Button(
        footer,
        text="开始安装",
        command=start_install,
        font=("Microsoft YaHei UI", 10, "bold"),
        bg="#2563eb",
        fg="#ffffff",
        activebackground="#1d4ed8",
        activeforeground="#ffffff",
        relief="flat",
        padx=18,
        pady=6,
    )
    install_btn.pack(side="right")

    cancel_btn = tk.Button(
        footer,
        text="取消",
        command=root.destroy,
        font=("Microsoft YaHei UI", 9),
        bg="#1e293b",
        fg="#cbd5e1",
        activebackground="#334155",
        activeforeground="#ffffff",
        relief="flat",
        padx=14,
        pady=6,
    )
    cancel_btn.pack(side="right", padx=(0, 8))

    root.update_idletasks()
    win_w = max(560, root.winfo_reqwidth() + 24)
    win_h = max(410, root.winfo_reqheight() + 16)
    pos_x = max(0, (root.winfo_screenwidth() - win_w) // 2)
    pos_y = max(0, (root.winfo_screenheight() - win_h) // 2)
    root.geometry(f"{win_w}x{win_h}+{pos_x}+{pos_y}")
    root.minsize(win_w, win_h)

    root.mainloop()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="WarpRelayPanel 安装程序")
    parser.add_argument("--silent", action="store_true", help="静默安装到指定目录")
    parser.add_argument("--dir", type=str, default="", help="安装目标目录")
    parser.add_argument("--no-desktop", action="store_true", help="不创建桌面快捷方式")
    parser.add_argument("--no-start-menu", action="store_true", help="不创建开始菜单快捷方式")
    parser.add_argument("--launch", action="store_true", help="安装后启动程序")
    args = parser.parse_args(argv)

    if args.silent:
        target = Path(args.dir) if args.dir else default_install_dir()
        exe_path = perform_install(
            install_dir=target,
            create_desktop=not args.no_desktop,
            create_start_menu=not args.no_start_menu,
            launch_after=args.launch,
        )
        print(str(exe_path))
        return 0
    return run_gui()


if __name__ == "__main__":
    raise SystemExit(main())
