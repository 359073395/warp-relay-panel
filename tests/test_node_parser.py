import base64
import json
import unittest

from app import node_parser


class TestNodeParser(unittest.TestCase):
    def test_parse_residential_formats(self) -> None:
        n1 = node_parser.parse_residential_line("1.2.3.4:1080:user1:pass:with:colon", default_type="socks5", remark="US家宽")
        self.assertIsNotNone(n1)
        self.assertEqual(n1["type"], "socks5")
        self.assertEqual(n1["server"], "1.2.3.4")
        self.assertEqual(n1["port"], 1080)
        self.assertEqual(n1["username"], "user1")
        self.assertEqual(n1["password"], "pass:with:colon")
        self.assertEqual(n1["name"], "US家宽")

        n2 = node_parser.parse_residential_line("5.6.7.8:8080#HTTP出口", default_type="http")
        self.assertIsNotNone(n2)
        self.assertEqual(n2["type"], "http")
        self.assertEqual(n2["server"], "5.6.7.8")
        self.assertEqual(n2["port"], 8080)
        self.assertEqual(n2["name"], "HTTP出口")

        n3 = node_parser.parse_residential_line("[2001:db8::1]:9050:alice:secret", default_type="socks5")
        self.assertIsNotNone(n3)
        self.assertEqual(n3["server"], "2001:db8::1")
        self.assertEqual(n3["port"], 9050)
        self.assertEqual(n3["username"], "alice")
        self.assertEqual(n3["password"], "secret")

        n4 = node_parser.parse_residential_line("alice:bob@9.9.9.9:1080", default_type="socks5")
        self.assertIsNotNone(n4)
        self.assertEqual(n4["server"], "9.9.9.9")
        self.assertEqual(n4["username"], "alice")
        self.assertEqual(n4["password"], "bob")

    def test_parse_vless_reality_and_ws(self) -> None:
        uri = (
            "vless://11111111-1111-1111-1111-111111111111@example.com:443"
            "?security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUBKEY123&sid=abcd&flow=xtls-rprx-vision"
            "#RealityNode"
        )
        n = node_parser.parse_proxy_uri(uri)
        self.assertIsNotNone(n)
        self.assertEqual(n["type"], "vless")
        self.assertEqual(n["name"], "RealityNode")
        self.assertEqual(n["tls"], True)
        self.assertEqual(n["servername"], "www.microsoft.com")
        self.assertEqual(n["reality-opts"]["public-key"], "PUBKEY123")
        self.assertEqual(n["reality-opts"]["short-id"], "abcd")
        self.assertEqual(n["flow"], "xtls-rprx-vision")

    def test_parse_v2rayng_variants(self) -> None:
        # 1. VLESS Reality without fp + insecure=1
        v_rel = node_parser.parse_proxy_uri(
            "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443"
            "?security=reality&sni=apple.com&pbk=KEY&insecure=1#RelNoFp"
        )
        self.assertIsNotNone(v_rel)
        self.assertEqual(v_rel["client-fingerprint"], "chrome")
        self.assertTrue(v_rel["skip-cert-verify"])

        # 2. VLESS httpupgrade + host fallback as SNI
        v_hu = node_parser.parse_proxy_uri(
            "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443"
            "?type=httpupgrade&security=tls&host=cdn.example.com&path=/up#HU"
        )
        self.assertIsNotNone(v_hu)
        self.assertEqual(v_hu["network"], "ws")
        self.assertTrue(v_hu["ws-opts"]["v2ray-http-upgrade"])
        self.assertEqual(v_hu["servername"], "cdn.example.com")

        # 3. VLESS xhttp
        v_xh = node_parser.parse_proxy_uri(
            "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443"
            "?type=xhttp&security=tls&sni=x.example.com&path=/xh&mode=packet-up#XH"
        )
        self.assertIsNotNone(v_xh)
        self.assertEqual(v_xh["network"], "xhttp")
        self.assertEqual(v_xh["xhttp-opts"]["path"], "/xh")
        self.assertEqual(v_xh["xhttp-opts"]["mode"], "packet-up")

        # 4. SS with obfs plugin
        ss_cred = base64.b64encode(b"aes-256-gcm:pw").decode()
        ss_obfs = node_parser.parse_proxy_uri(
            f"ss://{ss_cred}@1.2.3.4:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com#SSObfs"
        )
        self.assertIsNotNone(ss_obfs)
        self.assertEqual(ss_obfs["plugin"], "obfs")
        self.assertEqual(ss_obfs["plugin-opts"]["mode"], "http")
        self.assertEqual(ss_obfs["plugin-opts"]["host"], "bing.com")

        # 5. Trojan with insecure=1 & alpn
        tr = node_parser.parse_proxy_uri("trojan://pw@tr.example.com:443?insecure=1&alpn=h2,http/1.1#TR")
        self.assertIsNotNone(tr)
        self.assertTrue(tr["skip-cert-verify"])
        self.assertEqual(tr["alpn"], ["h2", "http/1.1"])

    def test_parse_vmess_trojan_ss_hy2(self) -> None:
        vm_payload = base64.b64encode(json.dumps({
            "ps": "VMessWS",
            "add": "vm.example.com",
            "port": "443",
            "id": "uuid-1234",
            "aid": 0,
            "net": "ws",
            "host": "cdn.example.com",
            "path": "/ws",
            "tls": "tls",
        }).encode()).decode()
        vm = node_parser.parse_proxy_uri(f"vmess://{vm_payload}")
        self.assertIsNotNone(vm)
        self.assertEqual(vm["type"], "vmess")
        self.assertEqual(vm["network"], "ws")
        self.assertEqual(vm["ws-opts"]["headers"]["Host"], "cdn.example.com")

        tr = node_parser.parse_proxy_uri("trojan://secretpass@tr.example.com:443?sni=tr.example.com&allowInsecure=1#Trojan1")
        self.assertIsNotNone(tr)
        self.assertEqual(tr["type"], "trojan")
        self.assertEqual(tr["password"], "secretpass")
        self.assertTrue(tr["skip-cert-verify"])

        ss_cred = base64.b64encode(b"aes-256-gcm:pass123").decode()
        ss = node_parser.parse_proxy_uri(f"ss://{ss_cred}@ss.example.com:8388#SS1")
        self.assertIsNotNone(ss)
        self.assertEqual(ss["cipher"], "aes-256-gcm")
        self.assertEqual(ss["password"], "pass123")

        ss_legacy = base64.b64encode(b"chacha20-ietf-poly1305:pw@1.1.1.1:9000").decode()
        ss2 = node_parser.parse_proxy_uri(f"ss://{ss_legacy}#LegacySS")
        self.assertIsNotNone(ss2)
        self.assertEqual(ss2["server"], "1.1.1.1")
        self.assertEqual(ss2["port"], 9000)

        hy2 = node_parser.parse_proxy_uri("hy2://pw123@hy.example.com:8443?sni=hy.example.com&insecure=1&obfs=salamander&obfs-password=obfspw#HY2")
        self.assertIsNotNone(hy2)
        self.assertEqual(hy2["type"], "hysteria2")
        self.assertEqual(hy2["obfs"], "salamander")
        self.assertEqual(hy2["obfs-password"], "obfspw")

    def test_parse_subscription_yaml_and_base64(self) -> None:
        yaml_text = """
proxies:
  - name: NodeA
    type: socks5
    server: 10.0.0.1
    port: "1080"
  - name: InvalidNoPort
    type: socks5
    server: 10.0.0.2
"""
        nodes = node_parser.parse_subscription_content(yaml_text)
        self.assertEqual(len(nodes), 1)
        self.assertEqual(nodes[0]["port"], 1080)

        b64_sub = base64.b64encode(
            b"socks5://u:p@2.2.2.2:1080#S1\nhttp://3.3.3.3:8080#H1\n"
        ).decode()
        nodes2 = node_parser.parse_subscription_content(b64_sub)
        self.assertEqual(len(nodes2), 2)
        self.assertEqual(nodes2[0]["name"], "S1")
        self.assertEqual(nodes2[1]["type"], "http")


if __name__ == "__main__":
    unittest.main()
