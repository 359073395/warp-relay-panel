import tempfile
import unittest
from pathlib import Path

from app import node_parser, xray_bridge


class TestXrayBridgeAndExtraProtocols(unittest.TestCase):
    def test_parse_xray_exclusive_and_extra_uris(self) -> None:
        kcp_node = node_parser.parse_proxy_uri(
            "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443"
            "?type=kcp&headerType=wechat-video&seed=myseed#KCPNode"
        )
        self.assertIsNotNone(kcp_node)
        self.assertEqual(kcp_node["network"], "kcp")
        self.assertEqual(kcp_node["kcp-opts"]["seed"], "myseed")
        self.assertEqual(kcp_node["kcp-opts"]["header-type"], "wechat-video")
        self.assertTrue(node_parser.is_xray_only_node(kcp_node))

        quic_node = node_parser.parse_proxy_uri(
            "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443"
            "?type=quic&quicSecurity=aes-128-gcm&key=qkey&headerType=utp#QUICNode"
        )
        self.assertIsNotNone(quic_node)
        self.assertTrue(node_parser.is_xray_only_node(quic_node))

        enc_node = node_parser.parse_proxy_uri(
            "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443"
            "?encryption=mlkem768x25519plus.native.0rtt&security=none#VlessEnc"
        )
        self.assertIsNotNone(enc_node)
        self.assertTrue(node_parser.is_xray_only_node(enc_node))

        tuic = node_parser.parse_proxy_uri(
            "tuic://11111111-1111-1111-1111-111111111111:pw@tuic.example.com:443"
            "?congestion_control=bbr&alpn=h3&allow_insecure=1#TUIC1"
        )
        self.assertIsNotNone(tuic)
        self.assertEqual(tuic["type"], "tuic")
        self.assertTrue(tuic["skip-cert-verify"])

        anytls = node_parser.parse_proxy_uri("anytls://pw123@any.example.com:443?sni=any.example.com&insecure=1#Any1")
        self.assertIsNotNone(anytls)
        self.assertEqual(anytls["type"], "anytls")
        self.assertTrue(anytls["skip-cert-verify"])

        wg = node_parser.parse_proxy_uri(
            "wireguard://PRIVKEY=@162.159.192.1:2408?publickey=PUBKEY&address=172.16.0.2/32&mtu=1280#WG1"
        )
        self.assertIsNotNone(wg)
        self.assertEqual(wg["type"], "wireguard")
        self.assertEqual(wg["peers"][0]["public-key"], "PUBKEY")

    def test_prepare_proxies_with_xray_bridge_config(self) -> None:
        kcp_node = node_parser.parse_proxy_uri(
            "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443"
            "?type=kcp&headerType=srtp&seed=s1#KCP"
        )
        normal_node = node_parser.parse_proxy_uri("socks5://5.5.5.5:1080#Normal")

        with tempfile.TemporaryDirectory() as tmp:
            out, bridge = xray_bridge.prepare_proxies_with_xray(
                Path(tmp),
                [kcp_node, normal_node],
                pick_port_fn=lambda p: p,
                base_port=18200,
            )
            self.assertIsNotNone(bridge)
            self.assertEqual(out[0]["type"], "socks5")
            self.assertEqual(out[0]["server"], "127.0.0.1")
            self.assertEqual(out[0]["port"], 18200)
            self.assertEqual(out[0]["name"], "KCP")
            self.assertEqual(out[1]["server"], "5.5.5.5")

            cfg = xray_bridge.build_xray_bridge_config(bridge.entries)
            self.assertEqual(cfg["inbounds"][0]["port"], 18200)
            self.assertEqual(cfg["outbounds"][0]["protocol"], "vless")
            self.assertEqual(cfg["outbounds"][0]["streamSettings"]["network"], "kcp")
            self.assertEqual(cfg["outbounds"][0]["streamSettings"]["kcpSettings"]["seed"], "s1")

    def test_reality_and_xhttp_bridge_when_xray_present(self) -> None:
        rel_node = node_parser.parse_proxy_uri(
            "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443"
            "?security=reality&sni=www.cloudflare.com&fp=chrome&pbk=PUB&sid=1234&spx=%2Fabc&type=tcp#Rel"
        )
        with tempfile.TemporaryDirectory() as tmp:
            core_dir = Path(tmp)
            # Without xray.exe, standard Reality stays native Mihomo
            self.assertFalse(xray_bridge.should_bridge_via_xray(core_dir, rel_node))
            # With xray.exe present, Reality is bridged via Xray-core for 100% compatibility
            (core_dir / "xray.exe").write_bytes(b"MZ")
            self.assertTrue(xray_bridge.should_bridge_via_xray(core_dir, rel_node))
            out, bridge = xray_bridge.prepare_proxies_with_xray(core_dir, [rel_node], lambda p: p, base_port=18400)
            self.assertIsNotNone(bridge)
            self.assertEqual(out[0]["type"], "socks5")
            cfg = xray_bridge.build_xray_bridge_config(bridge.entries)
            self.assertEqual(cfg["outbounds"][0]["streamSettings"]["security"], "reality")
            self.assertEqual(cfg["outbounds"][0]["streamSettings"]["realitySettings"]["spiderX"], "/abc")


if __name__ == "__main__":
    unittest.main()
