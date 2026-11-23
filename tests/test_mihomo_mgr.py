import tempfile
import unittest
from pathlib import Path

from app import mihomo_mgr


class TestMihomoManager(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.mgr = mihomo_mgr.MihomoManager(self.base)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_parse_custom_rules(self) -> None:
        raw = """
# comment
DOMAIN-SUFFIX,openai.com,EXIT
- DOMAIN-KEYWORD,anthropic,EXIT
MATCH,DIRECT
invalid_line
IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
"""
        rules = mihomo_mgr.parse_custom_rules(raw)
        self.assertEqual(
            rules,
            [
                "DOMAIN-SUFFIX,openai.com,EXIT",
                "DOMAIN-KEYWORD,anthropic,EXIT",
                "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            ],
        )

    def test_build_config_chaining_and_dedupe(self) -> None:
        underlays = [
            {"name": "EXIT", "type": "socks5", "server": "1.1.1.1", "port": 1080},
            {"name": "MyNode", "type": "socks5", "server": "2.2.2.2", "port": 1080},
            {"name": "MyNode", "type": "socks5", "server": "3.3.3.3", "port": 1080},
        ]
        exit_node = {"name": "US-Res", "type": "socks5", "server": "4.4.4.4", "port": 1080}
        # Put geo files so bypass_cn rules are generated
        self.mgr.core_dir.mkdir(parents=True, exist_ok=True)
        (self.mgr.core_dir / "geosite.dat").write_bytes(b"geo")
        (self.mgr.core_dir / "geoip.dat").write_bytes(b"geo")

        cfg = self.mgr.build_config(
            {
                "proxy_mode": "tun",
                "route_mode": "bypass_cn",
                "exit_mode": "residential",
                "allow_lan": True,
                "ipv6": True,
                "mixed_port": 18890,
                "custom_rules": "DOMAIN-SUFFIX,openai.com,EXIT",
            },
            underlays,
            exit_node,
        )

        self.assertEqual(cfg["mixed-port"], 18890)
        self.assertTrue(cfg["allow-lan"])
        self.assertTrue(cfg["ipv6"])
        self.assertTrue(cfg["tun"]["enable"])

        proxy_names = [p["name"] for p in cfg["proxies"]]
        self.assertIn("节点-EXIT", proxy_names)
        self.assertIn("MyNode", proxy_names)
        self.assertIn("MyNode #2", proxy_names)
        self.assertIn("落地-US-Res", proxy_names)

        exit_proxy = next(p for p in cfg["proxies"] if p["name"] == "落地-US-Res")
        self.assertEqual(exit_proxy["dialer-proxy"], "前置通道")

        # Custom rule precedes GEOSITE,cn
        self.assertEqual(
            cfg["rules"],
            [
                "GEOIP,private,DIRECT,no-resolve",
                "DOMAIN-SUFFIX,openai.com,EXIT",
                "GEOSITE,cn,DIRECT",
                "GEOIP,cn,DIRECT",
                "MATCH,EXIT",
            ],
        )

    def test_direct_hop1_and_diagnose_chain(self) -> None:
        exit_node = {"name": "DirectRes", "type": "socks5", "server": "4.4.4.4", "port": 1080}
        cfg = self.mgr.build_config(
            {
                "proxy_mode": "system",
                "route_mode": "global",
                "underlay_strategy": "direct",
                "exit_mode": "residential",
            },
            [],
            exit_node,
        )
        self.assertEqual(len(cfg["proxies"]), 1)
        self.assertNotIn("dialer-proxy", cfg["proxies"][0])
        self.assertEqual(cfg["proxy-groups"][0]["name"], "EXIT")
        self.assertEqual(cfg["proxy-groups"][0]["proxies"], ["落地-DirectRes"])

        # Mock diagnose_chain for fault_hop = underlay vs exit vs none
        from unittest import mock
        with mock.patch.object(self.mgr, "is_running", return_value=True), \
             mock.patch.object(self.mgr, "get_runtime_status", return_value={"current_underlay": "WARP-01", "current_exit": "落地-JP"}):
            with mock.patch.object(self.mgr, "test_node_delay", side_effect=[None]):
                d1 = self.mgr.diagnose_chain({"underlay_strategy": "auto_free", "use_exit_hop": True})
                self.assertEqual(d1["fault_hop"], "underlay")
                self.assertFalse(d1["underlay_ok"])

            with mock.patch.object(self.mgr, "test_node_delay", side_effect=[65, None]):
                d2 = self.mgr.diagnose_chain({"underlay_strategy": "auto_free", "use_exit_hop": True})
                self.assertEqual(d2["fault_hop"], "exit")
                self.assertTrue(d2["underlay_ok"])
                self.assertEqual(d2["underlay_ms"], 65)
                self.assertFalse(d2["exit_ok"])

            with mock.patch.object(self.mgr, "test_node_delay", side_effect=[55, 190]), \
                 mock.patch.object(self.mgr, "probe_exit_ip", return_value={"ok": True, "ip": "1.2.3.4"}):
                d3 = self.mgr.diagnose_chain({"underlay_strategy": "auto_free", "use_exit_hop": True})
                self.assertEqual(d3["fault_hop"], "none")
                self.assertEqual(d3["exit_ms"], 190)
                self.assertEqual(d3["probe"]["ip"], "1.2.3.4")

    def test_reload_config_and_cleanup_temp_artifacts(self) -> None:
        from unittest import mock

        self.mgr.core_dir.mkdir(parents=True, exist_ok=True)
        stale_yaml = self.mgr.core_dir / "temp_1234.yaml"
        stale_dir = self.mgr.core_dir / "probe_tmp_999"
        stale_dir.mkdir(parents=True, exist_ok=True)
        stale_yaml.write_text("x", encoding="utf-8")
        (stale_dir / "a.txt").write_text("y", encoding="utf-8")
        self.mgr._cleanup_temp_artifacts()
        self.assertFalse(stale_yaml.exists())
        self.assertFalse(stale_dir.exists())

        self.mgr.active_mode = "system"
        self.mgr.mixed_port = 17890
        underlays = [{"name": "W1", "type": "socks5", "server": "1.1.1.1", "port": 1080}]
        with mock.patch.object(self.mgr, "is_running", return_value=True), \
             mock.patch.object(self.mgr, "_api_request", return_value={}) as m_api, \
             mock.patch.object(self.mgr, "start") as m_start:
            res = self.mgr.reload_config(
                {"proxy_mode": "system", "route_mode": "global", "mixed_port": 17890},
                underlays,
                None,
            )
        self.assertTrue(res["reloaded"])
        m_start.assert_not_called()
        self.assertTrue(any("/configs?force=true" in str(c.args[0]) for c in m_api.call_args_list))


if __name__ == "__main__":
    unittest.main()
