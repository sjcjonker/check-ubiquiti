#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Stijn Jonker
"""Read-only UniFi Network and Protect diagnostic export.

Author: Stijn Jonker (sjcjonker) | https://github.com/sjcjonker
Usage: python3 export_ubiquiti.py --type network|protect --site LABEL
         --url https://console.example --key-file /private/api.key
         [--output report.json.gz] [--allow-legacy-ca]
Default: pretty-printed JSON on stdout; --output creates a private gzip file.
Exports contain unredacted metadata. Run --help for all options.
"""
import argparse
import datetime as dt
import gzip
import json
import os
import ssl
from pathlib import Path
import sys
import urllib.parse
import urllib.error
import urllib.request

from check_unifi import APIError, display_text, fetch, paginated, read_key, tls_context, validate_api_origin, https_open, read_json


def collect_network(base, key, timeout, context):
    sites = paginated(base, "/sites", key, timeout, context)
    output = {
        "schemaVersion": 1,
        "type": "network",
        "collectedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "controller": fetch(base, "/info", key, timeout, context),
        "sites": [],
    }
    for site in sites:
        sid = site.get("id") if isinstance(site, dict) else None
        if not isinstance(sid, str) or not sid:
            raise APIError("invalid site identifier")
        prefix = "/sites/" + urllib.parse.quote(sid, safe="") + "/devices"
        devices = paginated(base, prefix, key, timeout, context)
        site_data = {"site": site, "devices": []}
        for device in devices:
            did = device.get("id") if isinstance(device, dict) else None
            if not isinstance(did, str) or not did:
                raise APIError("invalid device identifier")
            path = prefix + "/" + urllib.parse.quote(did, safe="")
            row = {"name": device.get("name"), "model": device.get("model"),
                   "details": None, "statistics": None, "errors": []}
            for field, endpoint in (
                ("details", path), ("statistics", path + "/statistics/latest")
            ):
                try:
                    row[field] = fetch(base, endpoint, key, timeout, context)
                except APIError:
                    # Do not serialize exception text; URLs/proxies could embed credentials.
                    row["errors"].append({"endpoint": field, "error": "request failed"})
            site_data["devices"].append(row)
        output["sites"].append(site_data)
    return output


def collect_protect(base, key, timeout, context):
    """Export official integration metadata and inventory; never fetch media."""
    output = {
        "schemaVersion": 1,
        "type": "protect",
        "collectedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "controller": None,
        "nvrs": None,
        "cameras": None,
        "errors": [],
    }
    for field, endpoint in (("controller", "meta/info"), ("nvrs", "nvrs"),
                            ("cameras", "cameras")):
        req = urllib.request.Request(
            base.rstrip("/") + "/proxy/protect/integration/v1/" + endpoint,
            headers={"X-API-Key": key, "Accept": "application/json"},
            method="GET")
        try:
            with https_open(req, timeout, context) as response:
                data = read_json(response)
        except urllib.error.HTTPError as exc:
            # Some console versions do not expose NVR inventory. Preserve this
            # omission explicitly, but never hide authentication/server errors.
            if field == "nvrs" and exc.code in (404, 405):
                output["errors"].append({"endpoint": endpoint, "status": exc.code,
                                         "error": "endpoint unavailable"})
                continue
            raise APIError(f"Protect {endpoint}: HTTP {exc.code}") from exc
        except (urllib.error.URLError, OSError, ValueError, APIError) as exc:
            # Classify locally without printing URLs, response bodies or secrets.
            reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
            if isinstance(reason, ssl.SSLCertVerificationError):
                detail = "TLS certificate verification failed; check CA trust, hostname and validity"
                if getattr(reason, "verify_code", None) in (85, 86):
                    detail += "; for a trusted legacy CA, try --allow-legacy-ca"
            elif isinstance(reason, ssl.SSLError):
                detail = "TLS handshake failed"
            elif isinstance(reason, TimeoutError):
                detail = "connection timed out"
            elif isinstance(reason, ConnectionRefusedError):
                detail = "connection refused"
            elif isinstance(exc, ValueError):
                detail = "invalid JSON response"
            else:
                detail = "request failed"
            raise APIError(f"Protect {endpoint}: {detail}") from exc
        if field == "controller":
            valid = isinstance(data, dict) and isinstance(data.get("applicationVersion"), str)
        elif field == "cameras":
            records = data.get("data") if isinstance(data, dict) else data
            valid = isinstance(records, list) and all(isinstance(row, dict) for row in records)
        else:
            valid = isinstance(data, dict) or (isinstance(data, list) and
                                              all(isinstance(row, dict) for row in data))
        if not valid:
            raise APIError(f"Protect {endpoint}: unexpected response shape")
        output[field] = data
    return output


def write_private_gzip(path, data):
    """Create only a new file, never replace an existing report or follow a symlink."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as raw:
            with gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=9, mtime=0) as gz:
                gz.write(json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8"))
                gz.write(b"\n")
    except BaseException:
        Path(path).unlink(missing_ok=True)
        raise


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--type", choices=("network", "protect"), required=True)
    p.add_argument("--site", required=True, help="Safe installation label, e.g. main")
    p.add_argument("--url", required=True)
    p.add_argument("--key-file", required=True)
    p.add_argument("--output", help="New .json.gz path (never overwrite); default: pretty JSON on stdout")
    p.add_argument("--timeout", type=float, default=10)
    p.add_argument("--allow-legacy-ca", action="store_true")
    args = p.parse_args(argv)
    try:
        validate_api_origin(args.url, args.timeout)
        if not args.site.replace("-", "").isalnum() or len(args.site) > 32:
            raise APIError("invalid site label")
        if args.output is not None and not args.output.endswith(".json.gz"):
            raise APIError("output file must end in .json.gz")
        collector = collect_protect if args.type == "protect" else collect_network
        output = collector(args.url, read_key(args.key_file), args.timeout,
                                 tls_context(args.allow_legacy_ca))
        output["installation"] = args.site
        if args.output is None:
            json.dump(output, sys.stdout, indent=2, ensure_ascii=False)
            sys.stdout.write("\n")
        else:
            write_private_gzip(args.output, output)
        if args.type == "network":
            count = sum(len(site["devices"]) for site in output["sites"])
            summary = f"{count} devices, {len(output['sites'])} site(s)"
        else:
            cameras = output["cameras"]
            count = len(cameras["data"] if isinstance(cameras, dict) else cameras)
            summary = f"{count} cameras; {len(output['errors'])} unavailable endpoint(s)"
        destination = "written to stdout" if args.output is None else f"saved to {args.output}"
        print(f"UniFi Export OK - {summary}; {destination}",
              file=sys.stderr if args.output is None else sys.stdout)
        return 0
    except (APIError, OSError) as exc:
        print("UniFi Export ERROR - " + display_text(exc, 300), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())



