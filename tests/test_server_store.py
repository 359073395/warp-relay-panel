import json
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from app import core_updater, server


class TestServerStoreAndHttp(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.base = Path(self._tmp.name)
        self.store = server.PanelStore(base_dir=self.base)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.create_handler(self.store))
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self._tmp.cleanup()

    def _req(self, path: str, body: dict | None = None) -> dict:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Content-Type": "application/json"} if body is not None else {}
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=data,
            headers=headers,
            method="POST" if body is not None else "GET",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def test_core_status_and_crud_endpoints(self) -> None:
        cs = core_updater.get_core_status(self.store.mgr.core_dir)
        self.assertFalse(cs["ready"])
        self.assertFalse(cs["has_exe"])

        # GET /api/state & /api/runtime
        st = self._req("/api/state")
        self.assertIn("core_status", st)
        self.assertIn("settings", st)
        rt = self._req("/api/runtime")
        self.assertTrue(rt["ok"])
        self.assertIn("runtime", rt)
        self.assertIn("smart_status", rt)

        # Add, edit, delete custom underlay
        r1 = self._req("/api/underlay/add", {"text": "socks5://u:p@1.2.3.4:1080#MyRelay"})
        self.assertEqual(r1["added"], 1)
        st = self._req("/api/state")
        uid = st["custom_underlays"][0]["id"]
        self.assertEqual(st["custom_underlays"][0]["name"], "MyRelay")

        self._req("/api/underlay/edit", {"id": uid, "name": "RenamedRelay"})
        st = self._req("/api/state")
        self.assertEqual(st["custom_underlays"][0]["name"], "RenamedRelay")

        self._req("/api/underlay/delete", {"id": uid})
        st = self._req("/api/state")
        self.assertEqual(len(st["custom_underlays"]), 0)

        # Add, edit, delete residential exit
        r2 = self._req("/api/exit/add", {"raw": "8.8.8.8:9000:user:pw", "remark": "HomeUS", "default_type": "socks5"})
        self.assertEqual(r2["added"], 1)
        eid = r2["selected_exit_id"]
        self._req("/api/exit/edit", {"id": eid, "name": "HomeUS-2"})
        st = self._req("/api/state")
        self.assertEqual(st["exits"][0]["name"], "HomeUS-2")
        self.assertEqual(st["settings"]["exit_mode"], "residential")

        self._req("/api/exit/delete", {"id": eid})
        st = self._req("/api/state")
        self.assertEqual(len(st["exits"]), 0)

        # Update settings including mixed_port, custom_rules, and hop toggles
        s_res = self._req("/api/settings", {
            "mixed_port": 18080,
            "allow_lan": True,
            "custom_rules": "DOMAIN-SUFFIX,openai.com,EXIT",
            "use_exit_hop": False,
            "auto_apply": False,
        })
        self.assertEqual(s_res["settings"]["mixed_port"], 18080)
        self.assertTrue(s_res["settings"]["allow_lan"])
        self.assertEqual(s_res["settings"]["exit_mode"], "direct_underlay")

        s_res2 = self._req("/api/settings", {
            "use_exit_hop": True,
            "exit_source": "vpngate",
            "auto_apply": False,
        })
        self.assertEqual(s_res2["settings"]["exit_mode"], "vpngate")

        # Select underlay node directly
        sel_res = self._req("/api/underlay/select", {"name": "CustomNodeA"})
        self.assertEqual(sel_res["settings"]["underlay_strategy"], "manual")
        self.assertEqual(sel_res["settings"]["selected_underlay"], "CustomNodeA")

    def test_hop1_pool_speed_and_delay_for_public_and_custom(self) -> None:
        from unittest import mock
        # Seed custom underlay, public backup, subscription, and warp endpoint
        self._req("/api/underlay/add", {"text": "socks5://1.1.1.1:1080#MyNode"})
        self.store._write_json(self.store.public_backup_file, [
            {
                "id": "pub-1",
                "name": "公益-HK",
                "proxy": {"name": "公益-HK", "type": "socks5", "server": "2.2.2.2", "port": 1080},
            }
        ])
        self.store._write_json(self.store.underlay_subs_file, [
            {
                "id": "sub-1",
                "name": "测试订阅",
                "url": "https://example.com/sub",
                "count": 1,
                "nodes": [{"name": "[测试订阅] SG", "type": "socks5", "server": "3.3.3.3", "port": 1080}],
                "updated_at": "2026-11-20 11:00",
            }
        ])
        self.store._write_json(self.store.warp_endpoints_file, [
            {"ip": "162.159.192.1", "port": 2408, "delay_ms": None, "speed_mbps": None}
        ])
        self.store._write_json(self.store.warp_account_file, {
            "private_key": "PRIV",
            "peer_public_key": "PUB",
            "ipv4": "172.16.0.2",
        })

        def fake_probe(_cfg, aliases, **_kwargs):
            return {
                alias: {"delay_ms": 40 + idx * 10, "speed_mbps": 12.5 + idx}
                for idx, alias in enumerate(aliases)
            }

        with mock.patch.object(self.store.mgr, "probe_proxies_speed_and_delay", side_effect=fake_probe):
            res = self._req("/api/underlay/test_all", {"kind": "all", "test_speed": True})

        self.assertEqual(res["tested"], 4)
        self.assertEqual(res["alive"], 4)

        st = self._req("/api/state")
        self.assertEqual(st["custom_underlays"][0]["delay_ms"], 40)
        self.assertEqual(st["custom_underlays"][0]["speed_mbps"], 12.5)
        self.assertEqual(st["sub_underlays"][0]["delay_ms"], 50)
        self.assertEqual(st["sub_underlays"][0]["speed_mbps"], 13.5)
        self.assertEqual(st["public_backups"][0]["delay_ms"], 60)
        self.assertEqual(st["public_backups"][0]["speed_mbps"], 14.5)
        self.assertEqual(st["warp"]["endpoints"][0]["delay_ms"], 70)
        self.assertEqual(st["warp"]["endpoints"][0]["speed_mbps"], 15.5)

        with mock.patch.object(self.store.mgr, "probe_proxies_speed_and_delay", side_effect=fake_probe):
            res_free = self._req("/api/underlay/test_all", {"kind": "free", "test_speed": False})
            res_user = self._req("/api/underlay/test_all", {"kind": "user", "test_speed": False})
        self.assertEqual(res_free["tested"], 2)
        self.assertEqual(res_user["tested"], 2)

    def test_pull_free_underlays_endpoint(self) -> None:
        from unittest import mock
        st0 = self._req("/api/state")
        self.assertFalse(st0["settings"]["use_exit_hop"])
        self.assertEqual(st0["settings"]["exit_mode"], "direct_underlay")

        self.store.mgr.core_dir.mkdir(parents=True, exist_ok=True)
        self.store.mgr.exe_path.write_bytes(b"MZ")
        with mock.patch.object(self.store, "ensure_warp_nodes", return_value=[{"name": "W1"}, {"name": "W2"}]), \
             mock.patch.object(self.store, "refresh_public_backups", return_value={"count": 5}), \
             mock.patch.object(self.store, "test_hop1_pool", return_value={
                 "tested": 7, "alive": 3, "best_name": "W1", "best_ms": 48, "best_mbps": 21.4,
             }):
            res_fast = self._req("/api/underlay/pull", {"auto_test": False})
            res = self._req("/api/underlay/pull", {"auto_test": True})
        self.assertTrue(res_fast["ok"])
        self.assertEqual(res_fast["tested"], 0)
        self.assertTrue(res["ok"])
        self.assertEqual(res["warp_count"], 2)
        self.assertEqual(res["public_count"], 5)
        self.assertEqual(res["alive"], 3)
        self.assertEqual(res["best_name"], "W1")
        self.assertEqual(res["best_ms"], 48)
        self.assertEqual(res["best_mbps"], 21.4)

    def test_hop1_ranking_sorts_by_speed_desc_and_alive_first(self) -> None:
        from unittest import mock
        self._req("/api/underlay/add", {"text": "socks5://1.1.1.1:1080#Slow\nsocks5://2.2.2.2:1080#Dead\nsocks5://3.3.3.3:1080#Fast"})

        def fake_probe(_cfg, aliases, **_kwargs):
            return {
                aliases[0]: {"delay_ms": 50, "speed_mbps": 5.0},
                aliases[1]: {"delay_ms": None, "speed_mbps": None},
                aliases[2]: {"delay_ms": 90, "speed_mbps": 30.0},
            }

        with mock.patch.object(self.store.mgr, "probe_proxies_speed_and_delay", side_effect=fake_probe):
            res = self._req("/api/underlay/test_all", {"kind": "custom", "test_speed": True})

        self.assertEqual(res["best_name"], "Fast")
        self.assertEqual(res["best_mbps"], 30.0)
        st = self._req("/api/state")
        names = [x["name"] for x in st["custom_underlays"]]
        self.assertEqual(names, ["Fast", "Slow", "Dead"])

    def test_smart_auto_select_and_connect_respects_toggle(self) -> None:
        from unittest import mock
        st0 = self._req("/api/state")
        self.assertFalse(st0["settings"]["smart_auto_select"])

        self.store.mgr.core_dir.mkdir(parents=True, exist_ok=True)
        self.store.mgr.exe_path.write_bytes(b"MZ")
        self._req("/api/underlay/add", {"text": "socks5://1.1.1.1:1080#Node1"})
        self._req("/api/settings", {"underlay_strategy": "custom_only", "auto_apply": False})

        with mock.patch.object(self.store, "smart_select_best") as m_smart, \
             mock.patch.object(self.store.mgr, "start", return_value={"ok": True, "mode": "system"}):
            self._req("/api/connect", {"smart_pick": True})
            m_smart.assert_not_called()

        self._req("/api/settings", {"smart_auto_select": True, "auto_apply": False})
        with mock.patch.object(self.store, "smart_select_best", return_value={"ok": True, "best_underlay": "Node1"}) as m_smart, \
             mock.patch.object(self.store.mgr, "start", return_value={"ok": True, "mode": "system"}), \
             mock.patch.object(self.store.mgr, "select_underlay") as m_sel:
            self._req("/api/connect", {"smart_pick": True})
            m_smart.assert_called_once()
            m_sel.assert_called_with("Node1")

        with mock.patch.object(self.store, "test_hop1_pool", return_value={
            "tested": 1, "alive": 1, "best_name": "Node1", "best_ms": 45, "best_mbps": 25.0,
        }), \
             mock.patch.object(self.store.mgr, "is_running", return_value=True), \
             mock.patch.object(self.store.mgr, "select_underlay") as m_sel:
            res = self._req("/api/smart_select", {})
            self.assertEqual(res["best_underlay"], "Node1")
            m_sel.assert_called_with("Node1")

        st1 = self._req("/api/state")
        self.assertIn("Node1", st1["smart_status"]["last_summary"])


if __name__ == "__main__":
    unittest.main()
