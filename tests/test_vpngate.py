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


if __name__ == "__main__":
    unittest.main()
