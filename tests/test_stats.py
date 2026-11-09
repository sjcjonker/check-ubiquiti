"""Tests for UniFi statistics check."""
from check_unifi import APIError, evaluate_stats as evaluate, resolve_ids
from unittest.mock import patch
import datetime as dt
import unittest


NOW = dt.datetime(2026, 10, 24, 15, 13, tzinfo=dt.timezone.utc)


def sample(**changes):
    data = {"cpuUtilizationPct": 15.8, "memoryUtilizationPct": 37.8,
            "uptimeSec": 3184133, "lastHeartbeatAt": "2026-10-24T15:11:43Z",
            "uplink": {"txRateBps": 13137528, "rxRateBps": 13606296}}
    data.update(changes)
    return data


class StatsTests(unittest.TestCase):
    @patch("check_unifi.paginated")
    def test_resolve_names(self, pages):
        pages.side_effect = [
            [{"id": "site-id", "name": "Main"}],
            [{"id": "device-id", "name": "ap-office"}],
        ]
        self.assertEqual(
            resolve_ids("https://example.org", "key", 10, object(),
                        site="Main", device="ap-office"),
            ("site-id", "device-id"))

    @patch("check_unifi.paginated")
    def test_duplicate_device_name_rejected(self, pages):
        pages.return_value = [
            {"id": "a", "name": "ap-office"},
            {"id": "b", "name": "ap-office"},
        ]
        with self.assertRaisesRegex(APIError, "ambiguous"):
            resolve_ids("https://example.org", "key", 10, object(),
                        site_id="site-id", device="ap-office")

    @patch("check_unifi.paginated")
    def test_missing_device_rejected(self, pages):
        pages.return_value = []
        with self.assertRaisesRegex(APIError, "not found"):
            resolve_ids("https://example.org", "key", 10, object(),
                        site_id="site-id", device="missing")

    @patch("check_unifi.paginated")
    def test_uuid_compatibility_without_lookup(self, pages):
        self.assertEqual(
            resolve_ids("https://example.org", "key", 10, object(),
                        site_id="site-id", device_id="device-id"),
            ("site-id", "device-id"))
        pages.assert_not_called()

    def test_normal(self):
        level, msg = evaluate(sample(), NOW)
        self.assertEqual(level, 0)
        self.assertIn("uplink_rx_bps", msg)

    def test_cpu_warning(self):
        self.assertEqual(evaluate(sample(cpuUtilizationPct=85), NOW)[0], 1)

    def test_memory_critical(self):
        self.assertEqual(evaluate(sample(memoryUtilizationPct=97), NOW)[0], 2)

    def test_stale_heartbeat(self):
        later = NOW + dt.timedelta(minutes=10)
        self.assertEqual(evaluate(sample(), later)[0], 2)

    def test_future_heartbeat_is_unknown(self):
        with self.assertRaises(APIError):
            evaluate(sample(lastHeartbeatAt="2026-10-24T16:00:00Z"), NOW)

    def test_missing_metrics_rejected(self):
        with self.assertRaises(APIError):
            evaluate({"cpuUtilizationPct": 50}, NOW)

    def test_radio_retry_perfdata_does_not_alert(self):
        stats = sample(interfaces={"radios": [
            {"frequencyGHz": 2.4, "txRetriesPct": 21.5},
            {"frequencyGHz": 5, "txRetriesPct": 28.4},
        ]})
        level, message = evaluate(stats, NOW)
        self.assertEqual(level, 0)
        self.assertIn("'radio_2_4ghz_tx_retries_pct'=21.5%", message)
        self.assertIn("'radio_5ghz_tx_retries_pct'=28.4%", message)

    def test_flex_mini_memory_threshold_override(self):
        self.assertEqual(evaluate(sample(memoryUtilizationPct=80.5), NOW)[0], 1)
        self.assertEqual(evaluate(sample(memoryUtilizationPct=80.5), NOW,
                                  memory_warn=90, memory_crit=95)[0], 0)

    def test_no_uplink_is_valid(self):
        level, msg = evaluate(sample(uplink=None), NOW)
        self.assertEqual(level, 0)
        self.assertNotIn("uplink_tx_bps", msg)


if __name__ == "__main__":
    unittest.main()


