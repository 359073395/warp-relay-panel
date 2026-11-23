import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import installer


class TestInstaller(unittest.TestCase):
    def test_safe_extract_zip_preserves_existing_data_and_blocks_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            payload = tmp_path / "payload.zip"
            install_dir = tmp_path / "install"
            (install_dir / "data").mkdir(parents=True)
            (install_dir / "data" / "settings.json").write_text('{"keep": true}', encoding="utf-8")

            with zipfile.ZipFile(payload, "w") as zf:
                zf.writestr("StarBridge.exe", b"MZ_TEST")
                zf.writestr("core/mihomo.exe", b"MIHOMO")
                zf.writestr("data/settings.json", '{"keep": false}')

            with mock.patch("installer.create_shortcut") as m_lnk, \
                 mock.patch("installer.register_uninstall_entry") as m_reg:
                exe = installer.perform_install(
                    install_dir=install_dir,
                    create_desktop=True,
                    create_start_menu=True,
                    launch_after=False,
                    payload_path=payload,
                )

            self.assertEqual(exe, install_dir.resolve() / "StarBridge.exe")
            self.assertEqual(exe.read_bytes(), b"MZ_TEST")
            self.assertEqual((install_dir / "core" / "mihomo.exe").read_bytes(), b"MIHOMO")
            self.assertEqual((install_dir / "data" / "settings.json").read_text(encoding="utf-8"), '{"keep": true}')
            self.assertTrue((install_dir / "uninstall.ps1").exists())
            self.assertEqual(m_lnk.call_count, 2)
            m_reg.assert_called_once()

            bad_payload = tmp_path / "bad.zip"
            with zipfile.ZipFile(bad_payload, "w") as zf:
                zf.writestr("../escape.txt", "boom")
            with self.assertRaises(ValueError):
                installer.safe_extract_zip(bad_payload, install_dir)


if __name__ == "__main__":
    unittest.main()
