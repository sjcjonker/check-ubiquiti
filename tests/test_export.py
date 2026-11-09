"""Offline export regression tests."""
from check_unifi import APIError
from export_ubiquiti import collect_network, collect_protect, main, write_private_gzip
from pathlib import Path
from unittest.mock import patch
import contextlib
import gzip
import io
import json
import ssl
import tempfile
import unittest
import urllib.error


class ExportTests(unittest.TestCase):
    def test_private_gzip_and_exclusive_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "out.json.gz"
            write_private_gzip(path, {"devices": [1]})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with gzip.open(path, "rt", encoding="utf-8") as stream:
                self.assertEqual(json.load(stream), {"devices": [1]})
            with self.assertRaises(FileExistsError):
                write_private_gzip(path, {"devices": [2]})

    @patch("export_ubiquiti.fetch")
    @patch("export_ubiquiti.paginated")
    def test_collection(self, pages, fetch):
        pages.side_effect = [
            [{"id": "site1", "name": "Main"}],
            [{"id": "device1", "name": "sw1", "model": "switch"}],
        ]
        fetch.side_effect = [{"applicationVersion": "10.6.109"},
                             {"id": "device1", "interfaces": {"ports": []}},
                             {"cpuUtilizationPct": 12}]
        report = collect_network("https://example.org", "key", 10, object())
        self.assertEqual(len(report["sites"][0]["devices"]), 1)
        self.assertEqual(report["sites"][0]["devices"][0]["statistics"]["cpuUtilizationPct"], 12)

    @patch("export_ubiquiti.fetch")
    @patch("export_ubiquiti.paginated")
    def test_device_request_failure_is_recorded(self, pages, fetch):
        from check_unifi import APIError
        pages.side_effect = [[{"id": "site1"}], [{"id": "dev"}]]
        fetch.side_effect = [{"applicationVersion": "10"}, APIError("secret shouldn't be serialized"),
                             {"uptimeSec": 42}]
        report = collect_network("https://example.org", "key", 10, object())
        row = report["sites"][0]["devices"][0]
        self.assertEqual(row["details"], None)
        self.assertEqual(row["errors"][0]["error"], "request failed")
        self.assertNotIn("secret", json.dumps(report))


class ProtectExportTests(unittest.TestCase):
    def test_tls_and_connection_diagnostics_hide_private_details(self):
        legacy = ssl.SSLCertVerificationError('private SECRET')
        legacy.verify_code = 85
        untrusted = ssl.SSLCertVerificationError('private SECRET')
        untrusted.verify_code = 20
        for reason, expected, hint in (
            (legacy, 'TLS certificate verification failed', True),
            (untrusted, 'TLS certificate verification failed', False),
            (TimeoutError('private SECRET'), 'connection timed out', False),
            (ConnectionRefusedError('private SECRET'), 'connection refused', False),
        ):
            for error in (reason, urllib.error.URLError(reason)):
                with self.subTest(error=type(error).__name__, expected=expected):
                    with patch('export_ubiquiti.https_open', side_effect=error):
                        with self.assertRaises(APIError) as caught:
                            collect_protect('https://console.local', 'SECRET', 10, None)
                    message = str(caught.exception)
                    self.assertIn(expected, message)
                    self.assertEqual('--allow-legacy-ca' in message, hint)
                    self.assertNotIn('SECRET', message)
                    self.assertNotIn('private', message)

    def collect(self, payloads):
        streams = [io.StringIO(json.dumps(data)) for data in payloads]
        with patch('export_ubiquiti.https_open', side_effect=streams) as opened:
            result = collect_protect('https://console.local', 'SECRET', 10, None)
        self.assertEqual([call.args[0].full_url for call in opened.call_args_list], [
            'https://console.local/proxy/protect/integration/v1/' + endpoint
            for endpoint in ('meta/info', 'nvrs', 'cameras')])
        self.assertTrue(all(call.args[0].get_header('X-api-key') == 'SECRET'
                            for call in opened.call_args_list))
        return result

    def test_preserves_raw_metadata_and_empty_inventory(self):
        for cameras in ([], [{'id': 'cam1', 'name': 'Door'}], {'data': [{'id': 'cam1'}]}):
            with self.subTest(cameras=cameras):
                report = self.collect([{'applicationVersion': '6'}, {'storage': {'size': 123}}, cameras])
                self.assertEqual(report['type'], 'protect')
                self.assertEqual(report['nvrs']['storage']['size'], 123)
                self.assertEqual(report['cameras'], cameras)
                self.assertEqual(report['errors'], [])

    def test_missing_nvr_endpoint_is_explicit(self):
        for status in (404, 405):
            responses = [io.StringIO('{"applicationVersion":"6"}'),
                         urllib.error.HTTPError('private', status, 'private', {}, None),
                         io.StringIO('[]')]
            with patch('export_ubiquiti.https_open', side_effect=responses):
                report = collect_protect('https://console.local', 'SECRET', 10, None)
            self.assertIsNone(report['nvrs'])
            self.assertEqual(report['errors'][0]['status'], status)
            self.assertNotIn('private', json.dumps(report))

    def test_other_nvr_failures_abort(self):
        for status in (401, 403, 500):
            with patch('export_ubiquiti.https_open', side_effect=[
                io.StringIO('{"applicationVersion":"6"}'),
                urllib.error.HTTPError('private', status, 'private', {}, None)]):
                with self.assertRaisesRegex(APIError, f'HTTP {status}'):
                    collect_protect('https://console.local', 'SECRET', 10, None)

    def test_malformed_responses_rejected(self):
        for payloads in ([[]], [{'applicationVersion': '6'}, 1],
                         [{'applicationVersion': '6'}, {}, {'data': ['bad']} ]):
            with patch('export_ubiquiti.https_open', side_effect=[
                io.StringIO(json.dumps(data)) for data in payloads]):
                with self.assertRaisesRegex(APIError, 'unexpected response shape'):
                    collect_protect('https://console.local', 'SECRET', 10, None)

    def test_cli_writes_private_archive_and_failure_writes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'protect.json.gz'
            argv = ['--type', 'protect', '--site', 'main', '--url', 'https://console.local',
                    '--key-file', 'unused', '--output', str(path)]
            with patch('export_ubiquiti.read_key', return_value='SECRET'), \
                 patch('export_ubiquiti.https_open', side_effect=APIError('private SECRET')):
                self.assertEqual(main(argv), 1)
            self.assertFalse(path.exists())
            with patch('export_ubiquiti.read_key', return_value='SECRET'), \
                 patch('export_ubiquiti.https_open', side_effect=[
                     io.StringIO('{"applicationVersion":"6"}'), io.StringIO('{}'), io.StringIO('[]')]):
                self.assertEqual(main(argv), 0)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


class StdoutTests(unittest.TestCase):
    def test_json_only_for_both_export_types(self):
        for kind, data in [('protect', {'cameras': [], 'errors': []}),
                           ('network', {'sites': []})]:
            out, err = io.StringIO(), io.StringIO()
            with patch('export_ubiquiti.read_key', return_value='key'), \
                 patch('export_ubiquiti.collect_' + kind, return_value=data), \
                 patch('export_ubiquiti.write_private_gzip') as writer, \
                 contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(['--type', kind, '--site', 'main', '--url',
                             'https://console.local', '--key-file', 'unused'])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out.getvalue())['installation'], 'main')
            self.assertIn('\n  \"installation\": \"main\"', out.getvalue())
            self.assertIn('written to stdout', err.getvalue())
            writer.assert_not_called()

    def test_failure_leaves_stdout_empty(self):
        out, err = io.StringIO(), io.StringIO()
        with patch('export_ubiquiti.read_key', return_value='key'), \
             patch('export_ubiquiti.collect_protect', side_effect=APIError('request failed')), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(['--type', 'protect', '--site', 'main', '--url',
                         'https://console.local', '--key-file', 'unused'])
        self.assertEqual(code, 1)
        self.assertEqual(out.getvalue(), '')
        self.assertIn('ERROR', err.getvalue())

