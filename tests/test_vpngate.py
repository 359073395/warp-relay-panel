import unittest

from app import vpngate


class TestVpnGate(unittest.TestCase):
    def test_parse_ovpn_profile(self) -> None:
        sample = """
client
dev tun
proto tcp-client
remote 203.0.113.10 443
cipher AES-128-CBC
data-ciphers AES-256-GCM:AES-128-CBC
auth SHA1
tun-mtu 1500
<ca>
-----BEGIN CERTIFICATE-----
MOCKCA
-----END CERTIFICATE-----
</ca>
<cert>
MOCKCERT
</cert>
<key>
MOCKKEY
</key>
"""
        prof = vpngate.parse_ovpn_profile(sample)
        self.assertIsNotNone(prof)
        self.assertEqual(prof["server"], "203.0.113.10")
        self.assertEqual(prof["port"], 443)
        self.assertEqual(prof["proto"], "tcp")
        self.assertEqual(prof["cipher"], "AES-128-CBC")
        self.assertEqual(prof["data-ciphers"], ["AES-256-GCM", "AES-128-CBC"])
        self.assertIn("MOCKCA", prof["ca"])

    def test_classify_residential_vs_datacenter(self) -> None:
        cls1, _ = vpngate._classify_node("public-vpn-123.opengw.net", {"status": "success", "isp": "Some ISP"})
        self.assertEqual(cls1, "datacenter")

        cls2, _ = vpngate._classify_node("vpn123.opengw.net", {
            "status": "success",
            "isp": "Amazon Technologies Inc.",
            "org": "AWS",
            "as": "AS16509 Amazon.com",
            "hosting": True,
        })
        self.assertEqual(cls2, "datacenter")

        cls3, isp3 = vpngate._classify_node("res-user.opengw.net", {
            "status": "success",
            "isp": "Korea Telecom",
            "org": "KT Corporation",
            "as": "AS4766 Korea Telecom",
            "hosting": False,
        })
        self.assertEqual(cls3, "residential")
        self.assertEqual(isp3, "Korea Telecom")

    def test_build_mihomo_openvpn_outbound(self) -> None:
        node = {
            "name": "🇯🇵 JP 家宽 01",
            "profile": {
                "server": "198.51.100.5",
                "port": 1194,
                "proto": "udp",
                "mtu": 1500,
                "cipher": "AES-128-CBC",
                "ca": "CA_PEM",
            },
        }
        ob = vpngate.build_mihomo_openvpn_outbound(node)
        self.assertEqual(ob["type"], "openvpn")
        self.assertEqual(ob["mtu"], 1200)  # UDP MTU capped at 1200
        self.assertEqual(ob["server"], "198.51.100.5")

    def test_select_candidates_preserves_western_quota_and_tcp_priority(self) -> None:
        pool = [
            {"country_short": "JP", "proto": "udp", "score": 9000 - i, "speed_mbps": 50.0, "ip": f"1.1.1.{i}"}
            for i in range(15)
        ] + [
            {"country_short": "JP", "proto": "tcp", "score": 5000 - i, "speed_mbps": 20.0, "ip": f"1.1.2.{i}"}
            for i in range(5)
        ] + [
            {"country_short": "US", "proto": "udp", "score": 300, "speed_mbps": 5.0, "ip": "8.8.8.1"},
            {"country_short": "US", "proto": "tcp", "score": 200, "speed_mbps": 4.0, "ip": "8.8.8.2"},
            {"country_short": "DE", "proto": "tcp", "score": 150, "speed_mbps": 8.0, "ip": "9.9.9.1"},
        ]
        selected = vpngate._select_candidates(pool, max_nodes=10)
        self.assertEqual(len(selected), 10)
        ccs = [n["country_short"] for n in selected]
        self.assertEqual(ccs.count("US"), 2)
        self.assertEqual(ccs.count("DE"), 1)
        # TCP nodes should rank before UDP nodes of the same/lower priority tier
        tcp_indices = [i for i, n in enumerate(selected) if n["proto"] == "tcp"]
        udp_indices = [i for i, n in enumerate(selected) if n["proto"] == "udp"]
        self.assertTrue(max(tcp_indices) < min(udp_indices))

    def test_crosscheck_ipwho_downgrades_datacenter_ip(self) -> None:
        import io
        import json
        from unittest import mock

        class _Resp:
            def __init__(self, payload: dict) -> None:
                self._b = io.BytesIO(json.dumps(payload).encode("utf-8"))
            def read(self, n: int = -1) -> bytes:
                return self._b.read(n)
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False

        class _Opener:
            def open(self, req, timeout=5.0):
                url = req.full_url
                if url.endswith("203.0.113.10"):
                    return _Resp({"success": True, "connection": {"asn": 14061, "isp": "DigitalOcean LLC", "org": "DigitalOcean"}})
                return _Resp({"success": True, "connection": {"asn": 7922, "isp": "Comcast Cable", "org": "Comcast"}})

        hits = vpngate._crosscheck_ipwho(_Opener(), ["203.0.113.10", "73.1.2.3"], timeout=2.0, total_budget_sec=5.0)
        self.assertIn("203.0.113.10", hits)
        self.assertNotIn("73.1.2.3", hits)


if __name__ == "__main__":
    unittest.main()
