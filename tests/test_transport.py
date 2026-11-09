"""Offline transport regression tests."""
from check_unifi import APIError, https_open, tls_context
from unittest.mock import patch
import check_unifi as api
import contextlib
import email.message
import export_ubiquiti as exporter
import io
import json
import ssl
import unittest
import urllib.request
import urllib.response


def response(code=200, location=None):
    headers = email.message.Message()
    if location:
        headers['Location'] = location
    result = urllib.response.addinfourl(io.BytesIO(b'{}'), headers,
                                       'https://console.local/api', code)
    result.msg = 'Found' if code != 200 else 'OK'
    return result


class SecurityTests(unittest.TestCase):
    hostile = 'Door|fake=99\r\n\x00\x1b\x85\u2028\u2029'

    def safe(self, text):
        self.assertNotIn('|', text)
        self.assertTrue(all(c.isprintable() for c in text))

    def test_origin_and_timeout_validation(self):
        for bad_url in ("http://console.local", "https://user:pass@console.local",
                        "https://console.local/path", "https://console.local/?key=x",
                        "https://console.local:99999", "https://console.local:0"):
            with self.subTest(url=bad_url), self.assertRaises(api.APIError):
                api.validate_api_origin(bad_url, 10)
        for timeout in (float("nan"), float("inf"), -1, 0, 61):
            with self.subTest(timeout=timeout), self.assertRaises(api.APIError):
                api.validate_api_origin("https://console.local", timeout)
        api.validate_api_origin("https://console.local:8443", 10)

    def test_redirects_never_send_a_second_request(self):
        for route in (None, '192.0.2.1'):
            for code in (301, 302, 303, 307, 308):
                for target in ('https://other.local/key', 'http://other.local/key',
                               'http://console.local/plain', '/same-origin'):
                    with self.subTest(route=route, code=code, target=target):
                        req = urllib.request.Request('https://console.local/api',
                                                     headers={'X-API-Key': 'SECRET'})
                        with patch.object(urllib.request.AbstractHTTPHandler, 'do_open',
                                          return_value=response(code, target)) as opened:
                            with self.assertRaisesRegex(api.APIError, '^API redirects are not allowed$'):
                                api.https_open(req, 3, ssl.create_default_context(), route)
                        self.assertEqual(opened.call_count, 1)

    def test_successful_responses_remain_supported(self):
        for route in (None, '192.0.2.1'):
            req = urllib.request.Request('https://console.local/api')
            context = ssl.create_default_context()
            with patch.object(urllib.request.AbstractHTTPHandler, 'do_open',
                              return_value=response()) as opened:
                with api.https_open(req, 3, context, route) as stream:
                    self.assertEqual(json.load(stream), {})
            self.assertEqual(opened.call_count, 1)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(context.check_hostname)

    def test_protect_export_rejects_redirects_through_shared_transport(self):
        with patch.object(urllib.request.AbstractHTTPHandler, 'do_open',
                          return_value=response(302, 'http://other.local/key')) as opened:
            with self.assertRaisesRegex(api.APIError, '^Protect meta/info: request failed$'):
                exporter.collect_protect('https://console.local', 'SECRET', 3,
                                         ssl.create_default_context())
        self.assertEqual(opened.call_count, 1)

    def test_all_modes_render_errors_safely_and_redirects_unknown(self):
        for mode in ('controller', 'devices', 'firmware', 'stats', 'cameras'):
            extra = ['--site-id', 's', '--device-id', 'd'] if mode == 'stats' else []
            for error in (self.hostile, 'API redirects are not allowed'):
                with patch.object(api, 'read_key', return_value='SECRET'), \
                     patch.object(api, 'https_open', side_effect=api.APIError(error)), \
                     contextlib.redirect_stdout(io.StringIO()) as output:
                    code = api.main(['--check', mode, '--url', 'https://console.local',
                                     '--key-file', 'unused', *extra])
                self.assertEqual(code, 3)
                self.assertIn('UNKNOWN', output.getvalue())
                self.assertNotIn('SECRET', output.getvalue())
                self.assertEqual(output.getvalue().count('\n'), 1)
                self.safe(output.getvalue().rstrip('\n'))

    def test_display_normalization_and_field_bound(self):
        self.safe(api.display_text(self.hostile))
        self.assertEqual(api.display_text('AP Office – café'), 'AP Office – café')
        self.assertEqual(len(api.display_text('x' * 1000)), 200)

    def test_devices_and_firmware_keep_status(self):
        for state, expected in (('ONLINE', 1), (self.hostile, 2)):
            code, text = api.evaluate_devices([{'name': self.hostile, 'state': state,
                                               'firmwareUpdatable': True}])
            self.assertEqual(code, expected)
            self.safe(text)
        code, text = api.firmware_result([{'name': self.hostile, 'firmwareUpdatable': True}])
        self.assertEqual(code, 1)
        self.safe(text)

    def test_camera_metrics_and_identity_are_preserved(self):
        code, text = api.evaluate_cameras([{'name': self.hostile, 'state': self.hostile}])
        self.assertEqual(code, 2)
        text, metrics = text.split(' | ')
        self.safe(text)
        self.assertEqual(metrics, "'cameras_total'=1 'cameras_connected'=0 'cameras_not_connected'=1")
        self.assertEqual(api.evaluate_cameras([{'name': 'Door|', 'state': 'CONNECTED'},
                                              {'name': 'Door ', 'state': 'CONNECTED'}])[0], 0)

    def test_stats_offline_error_is_safe(self):
        with patch.object(api, 'read_key', return_value='SECRET'), \
             patch.object(api, 'resolve_ids', side_effect=api.DeviceOffline(self.hostile)), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            code = api.main(['--check', 'stats', '--url', 'https://console.local',
                             '--key-file', 'unused', '--site-id', 's', '--device-id', 'd'])
        self.assertEqual(code, 2)
        self.safe(output.getvalue().rstrip('\n'))


class RoutedTLSOptionsTests(unittest.TestCase):
    def test_default_trust(self):
        self.assertEqual(tls_context().verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(tls_context().check_hostname)

    def test_bad_ip_fails_closed(self):
        request = __import__("urllib.request", fromlist=["Request"]).Request("https://unifi.local:8443/")
        with self.assertRaises(ValueError):
            https_open(request, 3, tls_context(), "not-an-ip")

    def test_ipv6_is_explicitly_rejected(self):
        request = __import__("urllib.request", fromlist=["Request"]).Request("https://unifi.local:8443/")
        with self.assertRaises(APIError):
            https_open(request, 3, tls_context(), "::1")

