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


if __name__ == "__main__":
    unittest.main()
