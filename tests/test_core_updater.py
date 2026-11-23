import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from app import core_updater, tray


class TestCoreUpdaterAndTray(unittest.TestCase):
    def test_download_core_assets_with_mocked_network(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("mihomo-windows-amd64-compatible.exe", b"MZ_FAKE_EXE" * 200)
        zip_bytes = buf.getvalue()
        geo_bytes = b"GEO_DATA" * 300

        release_json = json.dumps({
            "tag_name": "v1.19.0",
            "assets": [
                {
                    "name": "mihomo-windows-amd64-compatible-v1.19.0.zip",
                    "browser_download_url": "https://example.com/mihomo.zip",
                }
            ],
        }).encode("utf-8")

        def fake_open(url: str, proxy_url: str | None = None, timeout: float = 30.0) -> bytes:
            if url == core_updater.MIHOMO_LATEST_API:
                return release_json
            if "mihomo.zip" in url:
                return zip_bytes
            return geo_bytes

        with tempfile.TemporaryDirectory() as tmp:
            core_dir = Path(tmp) / "core"
            progress_events: list[tuple[str, int]] = []
            with mock.patch.object(core_updater, "_open_url", side_effect=fake_open):
                res = core_updater.download_core_assets(
                    core_dir,
                    progress_cb=lambda msg, pct: progress_events.append((msg, pct)),
                )

            self.assertTrue(res["ok"])
            self.assertEqual(res["version"], "v1.19.0")
            self.assertEqual(set(res["downloaded"]), {"mihomo.exe", "geosite.dat", "geoip.dat", "geoip.metadb"})
            self.assertTrue((core_dir / "mihomo.exe").exists())
            self.assertTrue(res["status"]["has_exe"])
            self.assertTrue(res["status"]["has_geo"])
            self.assertEqual(progress_events[-1][1], 100)

    def test_tray_icon_construct_and_stop(self) -> None:
        t = tray.TrayIcon(
            tooltip="TestTray",
            on_show=lambda: None,
            on_toggle=lambda: None,
            on_exit=lambda: None,
            is_connected_fn=lambda: False,
        )
        t.stop()

    def test_core_updater_mirrors_and_atom_fallback(self) -> None:
        self.assertNotIn("https://mirror.ghproxy.com/", core_updater.GH_MIRRORS)
        atom_xml = (
            b'<feed xmlns="http://www.w3.org/2005/Atom">'
            b'<entry><link href="https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.12"/></entry>'
            b'</feed>'
        )

        def fake_open(url: str, proxy_url: str | None = None, timeout: float = 30.0) -> bytes:
            if "api.github.com" in url:
                raise RuntimeError("api blocked")
            return atom_xml

        with mock.patch.object(core_updater, "_open_url", side_effect=fake_open):
            dl, tag = core_updater._resolve_mihomo_zip_url()
        self.assertEqual(tag, "v1.19.12")
        self.assertIn("mihomo-windows-amd64-compatible-v1.19.12.zip", dl)


if __name__ == "__main__":
    unittest.main()
