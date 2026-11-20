import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "android"))
import fetch_deps  # type: ignore  # noqa: E402


class TestAndroidProjectAndWorkflow(unittest.TestCase):
    def test_fetch_deps_asset_selectors(self) -> None:
        mihomo_assets = [
            {"name": "mihomo-android-arm64-v8-alpha-g123.gz", "browser_download_url": "https://x/alpha"},
            {"name": "mihomo-android-arm64-v8-v1.19.10.gz", "browser_download_url": "https://x/std"},
            {"name": "mihomo-android-arm64-v8-compatible-v1.19.10.gz", "browser_download_url": "https://x/compat"},
        ]
        chosen = fetch_deps.select_mihomo_android_asset(mihomo_assets)
        self.assertEqual(chosen["browser_download_url"], "https://x/compat")

        xray_assets = [{"name": "Xray-android-arm64-v8a.zip", "browser_download_url": "https://x/xray"}]
        self.assertEqual(fetch_deps.select_xray_android_asset(xray_assets)["name"], "Xray-android-arm64-v8a.zip")

        tproxy_assets = [{"name": "hev-socks5-tunnel.aar", "browser_download_url": "https://x/aar"}]
        self.assertEqual(fetch_deps.select_tproxy_aar_asset(tproxy_assets)["name"], "hev-socks5-tunnel.aar")

    def test_android_manifest_gradle_and_ci_yaml_valid(self) -> None:
        android_dir = ROOT / "android"
        manifest = (android_dir / "app" / "src" / "main" / "AndroidManifest.xml").read_text(encoding="utf-8")
        self.assertIn('android:extractNativeLibs="true"', manifest)
        self.assertIn("android.permission.BIND_VPN_SERVICE", manifest)
        self.assertIn("StarBridgeVpnService", manifest)

        gradle_app = (android_dir / "app" / "build.gradle.kts").read_text(encoding="utf-8")
        self.assertIn("useLegacyPackaging = true", gradle_app)
        self.assertIn("hev-socks5-tunnel.aar", gradle_app)

        ci_yaml = yaml.safe_load((ROOT / ".github" / "workflows" / "ci-build.yml").read_text(encoding="utf-8"))
        jobs = ci_yaml["jobs"]
        self.assertIn("build-windows", jobs)
        self.assertIn("build-android", jobs)
        self.assertIn("release", jobs)


if __name__ == "__main__":
    unittest.main()
