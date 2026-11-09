"""Offline protect regression tests."""
from check_unifi import APIError, evaluate_cameras as evaluate
from unittest import mock
import check_unifi as cameras
import contextlib
import io
import json
import unittest


class ProtectCameraTests(unittest.TestCase):
    def test_connected(self):
        status, output = evaluate([{"id": "1", "name": "Door", "state": "CONNECTED"},
                                   {"id": "2", "name": "Hall", "state": "CONNECTED"}])
        self.assertEqual(status, 0)
        self.assertIn("'cameras_connected'=2", output)

    def test_disconnected(self):
        status, output = evaluate([{"id": "1", "name": "Door", "state": "CONNECTED"},
                                   {"id": "2", "name": "Hall", "state": "DISCONNECTED"}])
        self.assertEqual(status, 2)
        self.assertIn("Hall (DISCONNECTED)", output)

    def test_missing_state(self):
        with self.assertRaises(APIError):
            evaluate([{"id": "1", "name": "Door"}])

    def test_empty(self):
        with self.assertRaises(APIError):
            evaluate([])

    def test_wrapped(self):
        self.assertEqual(evaluate({"data": [{"id": "1", "state": "CONNECTED"}]})[0], 0)

    def test_duplicate(self):
        with self.assertRaises(APIError):
            evaluate([{"name": "Door", "state": "CONNECTED"}, {"name": "Door", "state": "CONNECTED"}])

    def test_one_offline_allowed_and_perfdata_preserved(self):
        data = [{"name": "Door", "state": "CONNECTED"},
                {"name": "Bedroom", "state": "DISCONNECTED"}]
        status, output = evaluate(data, allow_offline=1)
        self.assertEqual(status, 0)
        self.assertIn("Bedroom (DISCONNECTED)", output)
        self.assertIn("allowed offline: 1", output)
        self.assertEqual(output.split(" | ")[1], evaluate(data)[1].split(" | ")[1])

    def test_both_offline_still_critical(self):
        data = [{"name": "Door", "state": "DISCONNECTED"},
                {"name": "Bedroom", "state": "DISCONNECTED"}]
        self.assertEqual(evaluate(data, allow_offline=1)[0], 2)

    def test_all_offline_never_ok_even_with_large_allowance(self):
        self.assertEqual(evaluate([{"name": "Only", "state": "DISCONNECTED"}],
                                 allow_offline=1)[0], 2)

    def test_allowance_does_not_hide_invalid_inventory(self):
        for data in ([], [{"name": "Broken"}]):
            with self.assertRaises(APIError):
                evaluate(data, allow_offline=1)

    def test_negative_allowance(self):
        with self.assertRaises(APIError):
            evaluate([{"name": "Door", "state": "CONNECTED"}], allow_offline=-1)


class ForwardedProtectTests(unittest.TestCase):
    def test_camera_api_routes_with_ca_and_hostname_verification(self):
        body=json.dumps([{'name': 'Camera', 'state': 'CONNECTED'}]).encode()
        response=mock.MagicMock()
        response.__enter__.return_value=io.BytesIO(body)
        with mock.patch.object(cameras, 'read_key', return_value='SECRET'), mock.patch.object(cameras, 'tls_context', return_value='TLS') as tls, mock.patch.object(cameras, 'https_open', return_value=response) as opened, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(cameras.cameras_main(['--url', 'https://unifi.local:8444', '--key-file', '/private/key', '--ca-file', '/cert.pem', '--connect-ip', '192.0.2.10', '--allow-legacy-ca']), 0)
        tls.assert_called_once_with(True, '/cert.pem')
        request, timeout, context, address=opened.call_args.args
        self.assertEqual(request.full_url, 'https://unifi.local:8444/proxy/protect/integration/v1/cameras')
        self.assertEqual((context, address), ('TLS', '192.0.2.10'))
        self.assertNotIn('SECRET', output.getvalue())

    def test_camera_api_default_tls_path_is_preserved(self):
        response=mock.MagicMock()
        response.__enter__.return_value=io.BytesIO(b'[{"name":"Camera","state":"CONNECTED"}]')
        with mock.patch.object(cameras, 'read_key', return_value='SECRET'), mock.patch.object(cameras, 'tls_context', return_value='TLS') as tls, mock.patch.object(cameras, 'https_open', return_value=response) as opened, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cameras.cameras_main(['--url', 'https://protect.example', '--key-file', '/private/key']), 0)
        tls.assert_called_once_with(False, None)
        self.assertIsNone(opened.call_args.args[3])

