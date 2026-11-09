"""Offline ports regression tests."""
from pathlib import Path
from unittest import TestCase, mock
import check_unifi as mod
import os
import tempfile
import time
import unittest


class PortStatusTests(unittest.TestCase):
    def test_policies(self):
        for enabled, up, policy, expected in (
            (True, True, "up", 0),
            (True, False, "up", 2),
            (True, False, "admin", 0),
            (False, False, "down", 0),
            (False, False, "admin", 2),
            (True, True, "down", 2),
            (False, True, "up", 3),
        ):
            device = {"port_table": [{"port_idx": 2, "name": "Data",
                                       "enable": enabled, "up": up}]}
            self.assertEqual(mod.evaluate_port_state(device, 2, policy)[0], expected)

    def test_missing_status_is_unknown(self):
        with self.assertRaises(mod.APIError):
            mod.evaluate_port_state({"port_table": [{"port_idx": 2, "up": False}]}, 2, "down")

    def test_duplicate_port_is_unknown(self):
        p = {"port_idx": 2, "up": True, "enable": True}
        with self.assertRaises(mod.APIError):
            mod.evaluate_port_state({"port_table": [p, p]}, 2, "up")


class PortCacheTests(TestCase):
    def test_shared_inventory_and_expiry(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            data = {"meta": {"rc": "ok"}, "data": [{"name": "switch-office"}]}
            with mock.patch.object(mod, "fetch_legacy_inventory", return_value=data) as fetch:
                x = mod.cached_legacy_inventory("https://network.example", "default",
                    "/private/cred", 10, None, {"username": "monitoring-user"}, cache_dir=d)
                y = mod.cached_legacy_inventory("https://network.example", "default",
                    "/private/cred", 10, None, {"username": "monitoring-user"}, cache_dir=d)
                self.assertEqual(x, y)
                self.assertEqual(fetch.call_count, 1)
                cached = next(d.glob("*.json"))
                os.utime(cached, (time.time()-700, time.time()-700))
                mod.cached_legacy_inventory("https://network.example", "default",
                    "/private/cred", 10, None, {"username": "monitoring-user"}, cache_dir=d)
                self.assertEqual(fetch.call_count, 2)

    def test_429_is_not_retried_immediately(self):
        import urllib.error
        with tempfile.TemporaryDirectory() as tmp:
            error = urllib.error.HTTPError("https://x", 429, "rate limited",
                                           {"Retry-After": "30"}, None)
            with mock.patch.object(mod, "fetch_legacy_inventory", side_effect=error) as fetch:
                for _ in range(2):
                    with self.assertRaises(mod.APIError):
                        mod.cached_legacy_inventory("https://x", "default", "/private/cred",
                            10, None, {"username": "monitoring-user"}, cache_dir=Path(tmp))
                self.assertEqual(fetch.call_count, 1)

    def test_retry_after(self):
        self.assertEqual(mod.retry_after_seconds("23", 100), 23)
        self.assertEqual(mod.retry_after_seconds(None, 100), 600)

