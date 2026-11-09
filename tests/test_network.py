"""Offline network regression tests."""
from check_unifi import APIError, DeviceOffline, controller_result, devices_main as main, firmware_result, load_devices, resolve_ids
from unittest import mock
from unittest.mock import patch
import check_unifi as module
import pathlib
import unittest


class EvaluationTests(unittest.TestCase):
    def test_legacy_ca_still_validates_certificates_and_hostname(self):
        context = module.tls_context(True)
        self.assertEqual(context.verify_mode, module.ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertFalse(context.verify_flags & module.ssl.VERIFY_X509_STRICT)


    def test_api_key_rejects_symlinks_and_insecure_modes(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / "key"
            path.write_text("secret")
            path.chmod(0o600)
            self.assertEqual(module.read_key(path), "secret")
            link = pathlib.Path(temp) / "link"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                module.read_key(link)
            path.chmod(0o640)
            with self.assertRaises(module.APIError):
                module.read_key(path)

    def test_api_key_rejects_nonregular_files(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(module.APIError):
                module.read_key(temp)

    def test_direct_https_disables_environment_proxy(self):
        request = module.urllib.request.Request("https://example.invalid")
        context = module.tls_context()
        with mock.patch.object(module.urllib.request, "build_opener") as builder:
            module.https_open(request, 5, context)
        self.assertIsInstance(builder.call_args.args[0], module.urllib.request.ProxyHandler)
        self.assertEqual(builder.call_args.args[0].proxies, {})

    def test_all_online(self):
        self.assertEqual(module.evaluate_devices([{"name": "ap", "state": "ONLINE", "firmwareUpdatable": False}])[0], 0)

    def test_firmware_warning(self):
        self.assertEqual(module.evaluate_devices([{"name": "sw", "state": "ONLINE", "firmwareUpdatable": True}])[0], 1)

    def test_firmware_can_be_suppressed(self):
        self.assertEqual(module.evaluate_devices([{"name": "sw", "state": "ONLINE", "firmwareUpdatable": True}], False)[0], 0)

    def test_offline_precedes_updates(self):
        self.assertEqual(module.evaluate_devices([{"name": "sw", "state": "OFFLINE"}, {"name": "ap", "state": "ONLINE", "firmwareUpdatable": True}])[0], 2)

    def test_empty_is_unknown(self):
        self.assertEqual(module.evaluate_devices([])[0], 3)

    def test_missing_state_is_unknown(self):
        self.assertEqual(module.evaluate_devices([{"name": "sw"}])[0], 3)

    @mock.patch.object(module, "fetch")
    def test_multiple_pages(self, get):
        get.side_effect = [
            {"data": [{"state": "ONLINE"}] * 100, "totalCount": 101},
            {"data": [{"state": "ONLINE"}], "totalCount": 101},
        ]
        self.assertEqual(len(module.paginated("https://example.org", "/sites/s/devices", "key", 5, module.tls_context())), 101)

    @mock.patch.object(module, "fetch")
    def test_incomplete_page_rejected(self, get):
        get.return_value = {"data": [{"state": "ONLINE"}], "totalCount": 10}
        with self.assertRaises(module.APIError):
            module.paginated("https://example.org", "/sites/s/devices", "key", 5, module.tls_context())


class DeviceFilterTests(unittest.TestCase):
    def check(self,devices):
        with patch('check_unifi.read_key',return_value='secret'),patch('check_unifi.tls_context'),patch('check_unifi.paginated',side_effect=[[{'id':'site1'}],devices]):
            return main(['--url','https://example.org','--key-file','unused','--device','AP Office','--no-firmware-warning'])

    def test_online_offline_missing_duplicate(self):
        for states,expected in [(['ONLINE'],0),(['OFFLINE'],2),([],3),(['ONLINE','ONLINE'],3)]:
            self.assertEqual(self.check([{'name':'AP Office','state':s} for s in states]),expected)

    def test_stats_reject_offline_before_latest_request(self):
        with patch('check_unifi.paginated',return_value=[{'id':'d','name':'AP Office','state':'OFFLINE'}]):
            with self.assertRaises(DeviceOffline):resolve_ids('https://example.org','secret',3,object(),site_id='site1',device='AP Office')


class StatusTests(unittest.TestCase):
    def test_controller_version(self):
        self.assertEqual(controller_result({"applicationVersion": "10.6.109"})[0], 0)

    def test_controller_missing_version(self):
        with self.assertRaises(APIError):
            controller_result({})

    def test_firmware_ok(self):
        self.assertEqual(firmware_result([{"name": "ap", "firmwareUpdatable": False}])[0], 0)

    def test_firmware_warning(self):
        status, message = firmware_result([{"name": "sw", "firmwareUpdatable": True}])
        self.assertEqual(status, 1)
        self.assertIn("sw", message)

    def test_firmware_missing_unknown(self):
        with self.assertRaises(APIError):
            firmware_result([{"name": "sw"}])

    def test_empty_firmware_unknown(self):
        with self.assertRaises(APIError):
            firmware_result([])

    @patch("check_unifi.paginated")
    def test_firmware_site_selection(self, page):
        page.side_effect = [
            [{"id": "a", "name": "Main"}, {"id": "b", "name": "Other"}],
            [{"name": "sw", "firmwareUpdatable": False}],
        ]
        self.assertEqual(len(load_devices("https://example.org", "key", 5, object(), "Main")), 1)
        self.assertEqual(page.call_count, 2)

    @patch("check_unifi.paginated")
    def test_missing_site_is_unknown(self, page):
        page.return_value = [{"id": "a", "name": "Main"}]
        with self.assertRaises(APIError):
            load_devices("https://example.org", "key", 5, object(), "Missing")

