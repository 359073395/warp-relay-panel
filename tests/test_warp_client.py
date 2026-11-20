import base64
import unittest

from app import warp_client


class TestWarpClient(unittest.TestCase):
    def test_x25519_rfc7748_vector(self) -> None:
        # RFC 7748 Section 6.1 test vector
        alice_priv = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        bob_pub = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        expected_shared = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        self.assertEqual(warp_client._x25519(alice_priv, bob_pub), expected_shared)

    def test_generate_wg_keypair(self) -> None:
        priv, pub = warp_client.generate_wg_keypair()
        self.assertEqual(len(base64.b64decode(priv)), 32)
        self.assertEqual(len(base64.b64decode(pub)), 32)
        self.assertNotEqual(priv, pub)

    def test_sample_and_normalize_endpoints(self) -> None:
        eps = warp_client.sample_warp_endpoints(12)
        self.assertEqual(len(eps), 12)
        self.assertEqual(len(set(eps)), 12)

        norm = warp_client.normalize_warp_endpoints([
            ["162.159.192.1", 2408],
            {"ip": "188.114.96.2", "port": 500, "delay_ms": 42, "speed_mbps": 18.5},
        ])
        self.assertEqual(norm[0], {"ip": "162.159.192.1", "port": 2408, "delay_ms": None, "speed_mbps": None})
        self.assertEqual(norm[1], {"ip": "188.114.96.2", "port": 500, "delay_ms": 42, "speed_mbps": 18.5})

    def test_build_warp_proxies(self) -> None:
        acct = {
            "private_key": "PRIV",
            "peer_public_key": "PUB",
            "ipv4": "172.16.0.2",
        }
        awg = warp_client.build_warp_proxies(acct, [("162.159.192.1", 2408)], use_awg=True)
        self.assertEqual(awg[0]["name"], "WARP-AWG-01")
        self.assertIn("amnezia-wg-option", awg[0])

        wg = warp_client.build_warp_proxies(acct, [("162.159.192.1", 2408)], use_awg=False)
        self.assertEqual(wg[0]["name"], "WARP-WG-01")
        self.assertNotIn("amnezia-wg-option", wg[0])


if __name__ == "__main__":
    unittest.main()
