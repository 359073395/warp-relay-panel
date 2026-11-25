import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from app import updater


class _FakeResp:
    def __init__(self, body: bytes, headers: dict[str, str] | None = None) -> None:
        self._buf = io.BytesIO(body)
        self.headers = headers or {"Content-Length": str(len(body))}

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class TestUpdater(unittest.TestCase):
    def test_version_parsing_and_comparison(self) -> None:
        self.assertEqual(updater.parse_version("v2.2.0"), (2, 2, 0))
        self.assertTrue(updater.is_newer_version("v2.3.0", "2.2.0"))
        self.assertFalse(updater.is_newer_version("v2.2.0", "2.2.0"))
        self.assertFalse(updater.is_newer_version("v2.1.9", "2.2.0"))

    def test_check_latest_release_and_download_setup(self) -> None:
        payload = json.dumps({
            "tag_name": "v2.5.0",
            "body": "Performance & update improvements",
            "html_url": "https://github.com/359073395/warp-relay-panel/releases/tag/v2.5.0",
            "assets": [
                {"name": "StarBridge-Setup.exe", "browser_download_url": "https://example.com/StarBridge-Setup.exe"},
                {"name": "StarBridge-android-arm64.apk", "browser_download_url": "https://example.com/StarBridge-android-arm64.apk"},
            ],
        }).encode("utf-8")

        with mock.patch("app.updater._open_url", return_value=_FakeResp(payload)):
            info = updater.check_latest_release(current_version="2.2.0")

        self.assertTrue(info["ok"])
        self.assertTrue(info["has_update"])
        self.assertEqual(info["latest_version"], "2.5.0")
        self.assertEqual(info["win_setup_url"], "https://example.com/StarBridge-Setup.exe")
        self.assertEqual(info["apk_url"], "https://example.com/StarBridge-android-arm64.apk")

        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "setup.exe"
            with mock.patch("app.updater._open_url", return_value=_FakeResp(b"MZ" + b"\x00" * 1024)):
                out = updater.download_setup_exe("https://example.com/StarBridge-Setup.exe", dest)
            self.assertTrue(out.exists())
            self.assertTrue(out.read_bytes().startswith(b"MZ"))

    def test_check_latest_release_falls_back_to_atom_when_api_fails(self) -> None:
        atom_xml = (
            b'<feed xmlns="http://www.w3.org/2005/Atom">'
            b'<entry><link rel="alternate" href="https://github.com/359073395/warp-relay-panel/releases/tag/v2.3.1"/></entry>'
            b'</feed>'
        )

        def fake_open(url: str, proxy_url: str | None = None, timeout: float = 10.0):
            if "api.github.com" in url:
                raise RuntimeError("rate limited")
            return _FakeResp(atom_xml)

        with mock.patch("app.updater._open_url", side_effect=fake_open):
            info = updater.check_latest_release(current_version="2.2.0")

        self.assertTrue(info["ok"])
        self.assertTrue(info["has_update"])
        self.assertEqual(info["latest_version"], "2.3.1")
        self.assertEqual(
            info["win_setup_url"],
            "https://github.com/359073395/warp-relay-panel/releases/download/v2.3.1/StarBridge-Setup.exe",
        )
        self.assertEqual(
            info["apk_url"],
            "https://github.com/359073395/warp-relay-panel/releases/download/v2.3.1/StarBridge-android-arm64.apk",
        )

    def test_launch_windows_silent_upgrade_uses_compatible_flags(self) -> None:
        import base64
        import subprocess

        with mock.patch.object(updater.sys, "platform", "win32"), \
             mock.patch.object(updater.subprocess, "Popen") as m_popen:
            updater.launch_windows_silent_upgrade(
                Path(r"C:\Temp\StarBridge-Setup-Update.exe"),
                Path(r"D:\StarBridge"),
                wait_pid=12345,
            )

        m_popen.assert_called_once()
        args, kwargs = m_popen.call_args
        cmd = args[0]
        self.assertEqual(cmd[0], "powershell.exe")
        self.assertIn("-EncodedCommand", cmd)
        encoded = cmd[cmd.index("-EncodedCommand") + 1]
        script = base64.b64decode(encoded).decode("utf-16le")
        self.assertIn("Wait-Process -Id 12345", script)
        self.assertIn("--silent", script)
        self.assertIn("--launch", script)

        flags = int(kwargs.get("creationflags", 0))
        create_no_window = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        detached = getattr(subprocess, "DETACHED_PROCESS", 0)
        new_group = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        if create_no_window:
            self.assertTrue(flags & create_no_window)
        if create_no_window and detached:
            self.assertFalse(bool(flags & detached))
        if new_group:
            self.assertTrue(flags & new_group)
        self.assertTrue(kwargs.get("close_fds"))


if __name__ == "__main__":
    unittest.main()
