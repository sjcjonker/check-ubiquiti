"""Regression coverage for release-readiness input and cache failures."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_unifi as api
import export_ubiquiti as exporter


class InputSafetyTests(unittest.TestCase):
    def test_json_limit_accepts_boundary_and_rejects_larger_document(self):
        with patch.object(api, 'MAX_JSON_BYTES', 32):
            self.assertEqual(api.read_json(io.BytesIO(b'{}' + b' ' * 30)), {})
            with self.assertRaisesRegex(api.APIError, 'exceeds 16 MiB'):
                api.read_json(io.BytesIO(b'{}' + b' ' * 31))

    def test_invalid_json_and_encoding_are_rejected(self):
        for data in (b'{', b'\xff'):
            with self.subTest(size=len(data)), self.assertRaisesRegex(api.APIError, 'invalid JSON'):
                api.read_json(io.BytesIO(data))

    def test_network_malformed_collection_returns_unknown(self):
        with patch.object(api, 'read_key', return_value='fixture'), \
             patch.object(api, 'fetch', return_value={'data': [None]}), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            code = api.main(['--check', 'devices', '--url', 'https://network.example',
                             '--key-file', 'unused'])
        self.assertEqual(code, 3)
        self.assertIn('invalid record', output.getvalue())

    def test_oversized_api_response_returns_unknown(self):
        with patch.object(api, 'read_key', return_value='fixture'), \
             patch.object(api, 'MAX_JSON_BYTES', 32), \
             patch.object(api, 'https_open', return_value=io.BytesIO(b' ' * 33)), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            code = api.main(['--check', 'controller', '--url', 'https://network.example',
                             '--key-file', 'unused'])
        self.assertEqual(code, 3)
        self.assertIn('exceeds', output.getvalue())

    def test_bad_legacy_meta_or_records_are_never_cached(self):
        for response in ({'meta': None, 'data': []},
                         {'meta': {'rc': 'ok'}, 'data': [None]}):
            with self.subTest(response=response), tempfile.TemporaryDirectory() as directory:
                with patch.object(api, 'fetch_legacy_inventory', return_value=response):
                    with self.assertRaisesRegex(api.APIError, 'invalid legacy'):
                        api.cached_legacy_inventory('https://network.example', 'default',
                            '/private/key', 10, None, {'username': 'fixture'}, cache_dir=Path(directory))
                self.assertEqual(list(Path(directory).glob('*.json')), [])

    def test_corrupt_cached_inventory_is_refetched(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            good = {'meta': {'rc': 'ok'}, 'data': []}
            with patch.object(api, 'fetch_legacy_inventory', return_value=good) as fetch:
                args = ('https://network.example', 'default', '/private/key', 10,
                        None, {'username': 'fixture'})
                api.cached_legacy_inventory(*args, cache_dir=cache)
                next(cache.glob('*.json')).write_text(json.dumps({'meta': None, 'data': []}))
                self.assertEqual(api.cached_legacy_inventory(*args, cache_dir=cache), good)
                self.assertEqual(fetch.call_count, 2)

    def test_export_rejects_malformed_site_and_device(self):
        for pages in ([[None]], [[{'id': 'site'}], [None]]):
            with patch('export_ubiquiti.paginated', side_effect=pages), \
                 patch('export_ubiquiti.fetch', return_value={'applicationVersion': '1.0'}):
                with self.assertRaisesRegex(api.APIError, 'invalid .*identifier'):
                    exporter.collect_network('https://network.example', 'fixture', 10, None)

    def test_protect_export_uses_the_json_limit(self):
        with patch.object(api, 'MAX_JSON_BYTES', 32), \
             patch('export_ubiquiti.https_open', return_value=io.BytesIO(b' ' * 33)):
            with self.assertRaises(api.APIError):
                exporter.collect_protect('https://protect.example', 'fixture', 10, None)

    def test_tmpfiles_and_runtime_use_the_same_cache_path(self):
        example = Path(__file__).resolve().parents[1] / 'config/tmpfiles.conf.example'
        records = [line.split() for line in example.read_text().splitlines()
                   if line and not line.startswith('#')]
        self.assertIn(['d', str(api.PORT_CACHE_DIR), '0700', 'nagios', 'nagios', '-'], records)
