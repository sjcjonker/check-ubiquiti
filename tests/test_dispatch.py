"""Exercise the public API entrypoint, including its actual request paths."""
from unittest.mock import MagicMock, patch
import check_unifi as api
import contextlib
import datetime as dt
import io
import json
import unittest



class DispatchTests(unittest.TestCase):
    def run_mode(self, mode, body, extra=()):
        response = MagicMock()
        response.__enter__.return_value = io.BytesIO(json.dumps(body).encode())
        output = io.StringIO()
        with patch.object(api, 'read_key', return_value='SECRET'), \
             patch.object(api, 'tls_context', return_value='TLS'), \
             patch.object(api, 'https_open', return_value=response) as opened, \
             contextlib.redirect_stdout(output):
            result = api.main(['--check', mode, '--url', 'https://unifi.local:8444',
                               '--key-file', '/private/key', '--ca-file', '/ca.pem',
                               '--connect-ip', '192.0.2.1', *extra])
        self.assertNotIn('SECRET', output.getvalue())
        return result, output.getvalue(), opened

    def test_controller(self):
        code, text, opened = self.run_mode('controller', {'applicationVersion': '10.6.109'})
        self.assertEqual((code, text), (0, 'UniFi Controller OK - Network API available; application version 10.6.109\n'))
        self.assertEqual(opened.call_args.args[0].full_url,
                         'https://unifi.local:8444/proxy/network/integration/v1/info')
        self.assertEqual(opened.call_args.args[2:], ('TLS', '192.0.2.1'))

    def test_devices_and_firmware_use_existing_counts(self):
        rows = [{'name': 'AP', 'state': 'ONLINE', 'firmwareUpdatable': True}]
        with patch.object(api, 'paginated', side_effect=[[{'id': 'site'}], rows]):
            code, text, _ = self.run_mode('devices', {}, ['--no-firmware-warning'])
        self.assertEqual((code, text), (0, 'UNIFI NETWORK OK - 1 devices online; 1 firmware updates available | devices=1\n'))
        with patch.object(api, 'paginated', side_effect=[[{'id': 'site'}], rows]):
            code, text, _ = self.run_mode('firmware', {})
        self.assertEqual((code, text), (1, 'UniFi Firmware WARNING - 1/1 firmware updates available: AP | devices=1 updates=1\n'))

    def test_stats_preserve_path_and_perfdata(self):
        body = {'cpuUtilizationPct': 10, 'memoryUtilizationPct': 20,
                'uptimeSec': 123, 'lastHeartbeatAt': dt.datetime.now(dt.timezone.utc).isoformat()}
        code, text, opened = self.run_mode('stats', body, ['--site-id', 'site', '--device-id', 'device'])
        self.assertEqual(code, 0)
        self.assertIn("'cpu_pct'=10.0%;80;95;0;100 'memory_pct'=20.0%;80;95;0;100 'uptime_sec'=123s 'heartbeat_age_sec'=0s;180;300;0;", text)
        self.assertTrue(opened.call_args.args[0].full_url.endswith('/sites/site/devices/device/statistics/latest'))

    def test_cameras_keep_privacy_margin(self):
        body = [{'name': 'Door', 'state': 'CONNECTED'}, {'name': 'Bedroom', 'state': 'DISCONNECTED'}]
        code, text, opened = self.run_mode('cameras', body, ['--allow-offline', '1'])
        self.assertEqual((code, text), (0, "UniFi Protect Cameras OK - 1/2 cameras not connected: Bedroom (DISCONNECTED) (allowed offline: 1) | 'cameras_total'=2 'cameras_connected'=1 'cameras_not_connected'=1\n"))
        self.assertTrue(opened.call_args.args[0].full_url.endswith('/proxy/protect/integration/v1/cameras'))

    def test_mode_specific_arguments_cannot_be_silently_ignored(self):
        with patch.object(api, 'read_key') as read, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                api.main(['--check', 'devices', '--url', 'https://console',
                          '--key-file', '/private/key', '--allow-offline', '1'])
        read.assert_not_called()

    def test_invalid_response_is_unknown(self):
        for mode, body in [('controller', {}), ('cameras', [])]:
            code, text, _ = self.run_mode(mode, body)
            self.assertEqual(code, 3)
            self.assertIn('UNKNOWN', text)

    def test_general_help(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(api.main(['--help']), 0)
        self.assertIn('controller,devices,firmware,stats,cameras', output.getvalue())

