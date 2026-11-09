#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Stijn Jonker
"""Read-only UniFi Network and Protect monitoring for Nagios.

Author: Stijn Jonker (sjcjonker) | https://github.com/sjcjonker
Usage: python3 check_unifi.py --check MODE --url https://console.example
         --key-file /private/api.key [mode-specific options]
Modes: controller, devices, firmware, stats, cameras; port (legacy API).
Help: --help or --check MODE --help. Requires Python 3; no extra packages.
Exit codes: 0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN.
"""
import argparse
import datetime as dt
import http.client
import http.cookiejar
import fcntl
import hashlib
import pathlib
import tempfile
import time
import email.utils

import ipaddress
import json
import math
import os
import re
import socket
import stat
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request


def api_parser(description):
    parser = argparse.ArgumentParser(description=description,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", required=True, help="HTTPS console origin")
    parser.add_argument("--key-file", required=True, help="API key file (0600)")
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--ca-file", help="PEM certificate/CA for this console")
    parser.add_argument("--connect-ip", help="Connect to this IPv4 while verifying the URL hostname")
    parser.add_argument("--allow-legacy-ca", action="store_true",
                        help="Relax X509_STRICT only; retain trust and hostname verification")
    return parser


API = "/proxy/network/integration/v1"
MAX_JSON_BYTES = 16 * 1024 * 1024


def validate_api_origin(url, timeout):
    """Reject URL components that could redirect API keys or alter request paths."""
    try:
        parts = urllib.parse.urlsplit(url)
        # Force evaluation of the port: urllib defers errors for malformed ports.
        port = parts.port
    except ValueError as exc:
        raise APIError("invalid HTTPS origin") from exc
    if (parts.scheme != "https" or not parts.hostname or parts.username or
            parts.password or parts.path not in ("", "/") or parts.query or
            parts.fragment or (port is not None and port == 0)):
        raise APIError("URL must be an HTTPS origin without credentials, path or query")
    if not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise APIError("timeout must be between 0 and 60 seconds")



STATUS = ("OK", "WARNING", "CRITICAL", "UNKNOWN")


class APIError(Exception):
    pass


def read_key(filename):
    # Verify the opened inode, not a path that could change between stat and open.
    fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise APIError("API key must be a regular file")
        if st.st_mode & 0o077:
            raise APIError("API key file must not be accessible by group or others (mode 0600)")
        with os.fdopen(fd, encoding="utf-8") as stream:
            fd = -1
            key = stream.read(65537)
            if len(key) > 65536:
                raise APIError("API key file is too large")
            key = key.strip()
    finally:
        if fd >= 0:
            os.close(fd)
    if not key:
        raise APIError("API key file is empty")
    return key


def tls_context(allow_legacy_ca=False, ca_file=None):
    context = ssl.create_default_context(cafile=ca_file)
    if allow_legacy_ca:
        context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return context


class NoAPIRedirect(urllib.request.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        fp.close()
        raise APIError("API redirects are not allowed")

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


def display_text(value, limit=200):
    """Keep remote display data out of Nagios syntax and terminal controls."""
    return "".join(char if char.isprintable() and char != "|" else " "
                   for char in str(value)[:limit])


def https_open(req, timeout, context, connect_ip=None):
    if not connect_ip:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context), NoAPIRedirect())
        return opener.open(req, timeout=timeout)
    address = str(ipaddress.ip_address(connect_ip))
    if ":" in address:
        raise APIError("only IPv4 --connect-ip is currently supported")

    class RoutedHTTPSConnection(http.client.HTTPSConnection):
        def connect(self):
            raw = socket.create_connection((address, self.port), timeout=self.timeout,
                                           source_address=self.source_address)
            try:
                self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
            except BaseException:
                raw.close()
                raise

    class RoutedHTTPSHandler(urllib.request.HTTPSHandler):
        def https_open(self, request):
            return self.do_open(lambda host, **kw: RoutedHTTPSConnection(host, context=context, **kw),
                                request)

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         RoutedHTTPSHandler(), NoAPIRedirect())
    return opener.open(req, timeout=timeout)


def read_json(stream):
    """Bound each API/cache JSON document before decoding it."""
    payload = stream.read(MAX_JSON_BYTES + 1)
    if len(payload) > MAX_JSON_BYTES:
        raise APIError("JSON response exceeds 16 MiB")
    try:
        return json.loads(payload)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise APIError("invalid JSON response") from exc


def validate_legacy_inventory(data):
    if (not isinstance(data, dict) or not isinstance(data.get("meta"), dict)
            or data["meta"].get("rc") != "ok"
            or not isinstance(data.get("data"), list)
            or any(not isinstance(row, dict) for row in data["data"])):
        raise APIError("invalid legacy device inventory")
    return data


def fetch(base, path, key, timeout, context, connect_ip=None):
    req = urllib.request.Request(
        base.rstrip("/") + API + path,
        headers={"X-API-Key": key, "Accept": "application/json"},
        method="GET",
    )
    try:
        with https_open(req, timeout, context, connect_ip) as resp:
            data = read_json(resp)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise APIError("API request failed: " + str(exc)) from exc
    if not isinstance(data, dict):
        raise APIError("unexpected API response type")
    return data


def paginated(base, path, key, timeout, context, connect_ip=None):
    rows = []
    offset = 0
    limit = 100
    for _ in range(100):
        sep = "&" if "?" in path else "?"
        data = fetch(base, f"{path}{sep}offset={offset}&limit={limit}", key, timeout, context, connect_ip)
        page = data.get("data")
        if not isinstance(page, list):
            raise APIError("response missing data array")
        if any(not isinstance(row, dict) for row in page):
            raise APIError("invalid record in paginated response")
        rows.extend(page)
        total = data.get("totalCount")
        if isinstance(total, int) and len(rows) >= total:
            return rows
        if len(page) < limit:
            if isinstance(total, int) and len(rows) < total:
                raise APIError("incomplete paginated response")
            return rows
        offset += len(page)
    raise APIError("pagination exceeded 100 pages")


def evaluate_devices(devices, firmware_warning=True):
    if not devices:
        return 3, "no adopted devices returned"
    failures, updates = [], []
    for device in devices:
        if not isinstance(device, dict):
            return 3, "invalid device record"
        name = display_text(device.get("name") or device.get("macAddress") or device.get("id") or "unnamed")
        state = device.get("state")
        if state is None:
            return 3, "missing state for " + name
        if state != "ONLINE":
            failures.append(f"{name} ({display_text(state)})")
        if device.get("firmwareUpdatable") is True:
            updates.append(display_text(name))
    if failures:
        return 2, "not online: " + ", ".join(failures[:12]) + (f" (+{len(failures)-12} more)" if len(failures) > 12 else "")
    if firmware_warning and updates:
        return 1, "firmware available: " + ", ".join(updates[:12]) + (f" (+{len(updates)-12} more)" if len(updates) > 12 else "")
    return 0, f"{len(devices)} devices online" + (f"; {len(updates)} firmware updates available" if updates else "")


def devices_main(argv=None):
    parser = api_parser(__doc__)
    parser.add_argument("--device", help="Monitor one exact device name; reject missing/duplicate names")
    parser.add_argument("--site-id", help="official site UUID; omit to monitor all sites")
    parser.add_argument("--no-firmware-warning", action="store_true")
    args = parser.parse_args(argv)
    try:
        validate_api_origin(args.url, args.timeout)
        key = read_key(args.key_file)
        context = tls_context(args.allow_legacy_ca, args.ca_file)
        sites = [{"id": args.site_id}] if args.site_id else paginated(args.url, "/sites", key, args.timeout, context, args.connect_ip)
        if not sites:
            raise APIError("no sites returned")
        devices = []
        for site in sites:
            ident = site.get("id")
            if not isinstance(ident, str) or not ident:
                raise APIError("invalid site identifier")
            devices.extend(paginated(args.url, "/sites/" + urllib.parse.quote(ident, safe="") + "/devices", key, args.timeout, context, args.connect_ip))
        if args.device is not None:
            devices = [d for d in devices if isinstance(d, dict) and d.get("name") == args.device]
            if len(devices) != 1:
                raise APIError("device name missing or ambiguous")
        status, message = evaluate_devices(devices, not args.no_firmware_warning)
        print(f"UNIFI NETWORK {STATUS[status]} - {message} | devices={len(devices)}")
        return status
    except (APIError, OSError) as exc:
        print("UNIFI NETWORK UNKNOWN - " + display_text(exc, 400))
        return 3


VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9_.-]+)?$")


def controller_result(info):
    version = info.get("applicationVersion") if isinstance(info, dict) else None
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise APIError("controller response missing valid applicationVersion")
    return 0, f"Network API available; application version {version}"


def firmware_result(devices):
    if not devices:
        raise APIError("no adopted devices returned")
    updates = []
    unknown = []
    for device in devices:
        if not isinstance(device, dict):
            raise APIError("invalid device record")
        name = device.get("name") or device.get("macAddress") or device.get("id")
        if not isinstance(name, str) or not name:
            raise APIError("device has no identifier")
        value = device.get("firmwareUpdatable")
        if type(value) is not bool:
            unknown.append(name)
        elif value:
            updates.append(display_text(name))
    if unknown:
        raise APIError(f"firmwareUpdatable missing/invalid for {len(unknown)} devices")
    if updates:
        names = ", ".join(updates[:10])
        extra = f" (+{len(updates)-10} more)" if len(updates) > 10 else ""
        return 1, f"{len(updates)}/{len(devices)} firmware updates available: {names}{extra}"
    return 0, f"no firmware updates for {len(devices)} devices"


def load_devices(base, key, timeout, context, site_name=None, connect_ip=None):
    sites = paginated(base, "/sites", key, timeout, context, connect_ip)
    if site_name:
        sites = [s for s in sites if isinstance(s, dict) and s.get("name") == site_name]
        if len(sites) != 1:
            raise APIError("site name not found or ambiguous")
    if not sites:
        raise APIError("no sites returned")
    devices = []
    for site in sites:
        ident = site.get("id") if isinstance(site, dict) else None
        if not isinstance(ident, str) or not ident:
            raise APIError("invalid site identifier")
        devices.extend(paginated(base, "/sites/" + urllib.parse.quote(ident, safe="") + "/devices", key, timeout, context, connect_ip))
    return devices


def status_main(argv=None):
    p = api_parser(__doc__)
    p.add_argument("--check", required=True, choices=("controller", "firmware"))
    p.add_argument("--site", help="Exact Network site name; firmware only")
    args = p.parse_args(argv)
    try:
        validate_api_origin(args.url, args.timeout)
        if args.check == "controller" and args.site:
            raise APIError("--site is only supported for firmware")
        key = read_key(args.key_file)
        context = tls_context(args.allow_legacy_ca, args.ca_file)
        if args.check == "controller":
            state, message = controller_result(fetch(args.url, "/info", key, args.timeout, context, args.connect_ip))
            print(f"UniFi Controller OK - {message}")
        else:
            devices = load_devices(args.url, key, args.timeout, context, args.site, args.connect_ip)
            state, message = firmware_result(devices)
            print(f"UniFi Firmware {'WARNING' if state else 'OK'} - {message} | devices={len(devices)} updates={sum(d['firmwareUpdatable'] for d in devices)}")
        return state
    except (APIError, OSError) as exc:
        label = "Controller" if args.check == "controller" else "Firmware"
        print(f"UniFi {label} UNKNOWN - {display_text(exc, 300)}")
        return 3


class DeviceOffline(APIError):
    """Known device is offline; do not consume stale statistics."""


def parse_time(value):
    if not isinstance(value, str):
        raise APIError("missing heartbeat timestamp")
    try:
        stamp = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError("missing timezone")
        return stamp
    except ValueError as exc:
        raise APIError("invalid heartbeat timestamp") from exc


def numeric(data, key):
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise APIError("missing or invalid " + key)
    return float(value)


def evaluate_stats(data, now, cpu_warn=80, cpu_crit=95, memory_warn=80,
             memory_crit=95, heartbeat_warn=180, heartbeat_crit=300):
    if not isinstance(data, dict):
        raise APIError("unexpected device statistics response")
    cpu = numeric(data, "cpuUtilizationPct")
    mem = numeric(data, "memoryUtilizationPct")
    uptime = numeric(data, "uptimeSec")
    for name, n in (("CPU", cpu), ("memory", mem)):
        if not 0 <= n <= 100:
            raise APIError(name + " outside 0-100")
    if uptime < 0:
        raise APIError("negative uptime")
    age = (now - parse_time(data.get("lastHeartbeatAt"))).total_seconds()
    if age < -120:
        raise APIError("heartbeat in future: verify controller/monitoring-host clocks")
    age = max(0, age)
    level = 0
    if cpu >= cpu_crit or mem >= memory_crit or age >= heartbeat_crit:
        level = 2
    elif cpu >= cpu_warn or mem >= memory_warn or age >= heartbeat_warn:
        level = 1
    perf = [f"'cpu_pct'={cpu:.1f}%;{cpu_warn};{cpu_crit};0;100",
            f"'memory_pct'={mem:.1f}%;{memory_warn};{memory_crit};0;100",
            f"'uptime_sec'={uptime:.0f}s",
            f"'heartbeat_age_sec'={age:.0f}s;{heartbeat_warn};{heartbeat_crit};0;"]
    uplink = data.get("uplink")
    if isinstance(uplink, dict):
        for field, label in (("txRateBps", "uplink_tx_bps"), ("rxRateBps", "uplink_rx_bps")):
            val = uplink.get(field)
            if isinstance(val, (int, float)) and not isinstance(val, bool) and math.isfinite(val) and val >= 0:
                perf.append(f"'{label}'={val:.0f}")
    # Radio retries are useful trends, but a single sample does not warrant an alarm.
    radio_summary = []
    radios = (data.get("interfaces") or {}).get("radios") if isinstance(data.get("interfaces"), dict) else None
    if isinstance(radios, list):
        for radio in radios:
            if not isinstance(radio, dict):
                continue
            frequency = radio.get("frequencyGHz")
            retries = radio.get("txRetriesPct")
            if (isinstance(frequency, (int, float)) and not isinstance(frequency, bool)
                    and math.isfinite(frequency) and frequency in (2.4, 5, 6)
                    and isinstance(retries, (int, float)) and not isinstance(retries, bool)
                    and math.isfinite(retries) and 0 <= retries <= 100):
                label = str(frequency).replace(".", "_")
                perf.append(f"'radio_{label}ghz_tx_retries_pct'={retries:.1f}%;;;0;100")
                radio_summary.append(f"{frequency:g}GHz retries {retries:.1f}%")
    message = f"CPU {cpu:.1f}%, memory {mem:.1f}%, heartbeat {age:.0f}s ago, uptime {uptime:.0f}s"
    if radio_summary:
        message += "; " + ", ".join(radio_summary)
    return level, message + " | " + " ".join(perf)


def unique_match(items, field, wanted, category):
    matches = [item for item in items if isinstance(item, dict) and item.get(field) == wanted]
    if not matches:
        raise APIError(f"{category} {wanted!r} not found")
    if len(matches) != 1:
        raise APIError(f"{category} {wanted!r} is ambiguous ({len(matches)} matches)")
    identifier = matches[0].get("id")
    if not isinstance(identifier, str) or not identifier:
        raise APIError(f"{category} {wanted!r} has no valid id")
    return identifier


def resolve_ids(base, key, timeout, context, site_id=None, site=None,
                device_id=None, device=None, connect_ip=None):
    if site_id is None:
        sites = paginated(base, "/sites", key, timeout, context, connect_ip)
        site_id = unique_match(sites, "name", site, "site")
    if device_id is None:
        path = "/sites/" + urllib.parse.quote(site_id, safe="") + "/devices"
        devices = paginated(base, path, key, timeout, context, connect_ip)
        device_id = unique_match(devices, "name", device, "device")
        selected = next(d for d in devices if isinstance(d, dict) and d.get("id") == device_id)
        state = selected.get("state")
        if state is not None and state != "ONLINE":
            raise DeviceOffline(f"{device}: {state}")
    return site_id, device_id


def stats_main(argv=None):
    p = api_parser(__doc__)
    site_selection = p.add_mutually_exclusive_group(required=True)
    site_selection.add_argument("--site", help="Exact UniFi site name, e.g. Main")
    site_selection.add_argument("--site-id", help="UniFi site UUID")
    device_selection = p.add_mutually_exclusive_group(required=True)
    device_selection.add_argument("--device", help="Exact adopted device name")
    device_selection.add_argument("--device-id", help="UniFi device UUID")
    p.add_argument("--cpu-warning", type=float, default=80)
    p.add_argument("--cpu-critical", type=float, default=95)
    p.add_argument("--memory-warning", type=float, default=80)
    p.add_argument("--memory-critical", type=float, default=95)
    p.add_argument("--heartbeat-warning", type=float, default=180)
    p.add_argument("--heartbeat-critical", type=float, default=300)
    args = p.parse_args(argv)
    try:
        validate_api_origin(args.url, args.timeout)
        for prefix in ("cpu", "memory", "heartbeat"):
            warning = getattr(args, prefix + "_warning")
            critical = getattr(args, prefix + "_critical")
            ceiling = 100 if prefix != "heartbeat" else 86400
            if not 0 < warning < critical <= ceiling:
                raise APIError(prefix + " thresholds must be positive, warning < critical")
        key = read_key(args.key_file)
        context = tls_context(args.allow_legacy_ca, args.ca_file)
        site_id, device_id = resolve_ids(
            args.url, key, args.timeout, context,
            site_id=args.site_id, site=args.site,
            device_id=args.device_id, device=args.device, connect_ip=args.connect_ip)
        path = ("/sites/" + urllib.parse.quote(site_id, safe="") + "/devices/" +
                urllib.parse.quote(device_id, safe="") + "/statistics/latest")
        response = fetch(args.url, path, key, args.timeout, context, args.connect_ip)
        # GET detail/statistics returns an object directly, not the collection wrapper.
        status, message = evaluate_stats(
            response, dt.datetime.now(dt.timezone.utc),
            args.cpu_warning, args.cpu_critical, args.memory_warning,
            args.memory_critical, args.heartbeat_warning, args.heartbeat_critical)
        print(f"UniFi Stats {STATUS[status]} - {message}")
        return status
    except DeviceOffline as exc:
        print("UniFi Stats CRITICAL - " + display_text(exc, 300))
        return 2
    except (APIError, OSError) as exc:
        print("UniFi Stats UNKNOWN - " + display_text(exc, 300))
        return 3


CAMERAS_PATH = "/proxy/protect/integration/v1/cameras"


def evaluate_cameras(data, allow_offline=0):
    if not isinstance(allow_offline, int) or allow_offline < 0:
        raise APIError("allow-offline must be a nonnegative integer")
    cameras = data if isinstance(data, list) else data.get("data") if isinstance(data, dict) else None
    if not isinstance(cameras, list) or not cameras:
        raise APIError("missing or empty camera inventory")
    failed = []
    names = set()
    for camera in cameras:
        if not isinstance(camera, dict):
            raise APIError("invalid camera entry")
        name = camera.get("name") or camera.get("id")
        if not isinstance(name, str) or not name:
            raise APIError("camera entry missing name and id")
        if name in names:
            raise APIError("duplicate camera name/id: " + name)
        names.add(name)
        state = camera.get("state")
        if not isinstance(state, str) or not state:
            raise APIError("missing camera state for " + name)
        if state != "CONNECTED":
            failed.append((display_text(name), display_text(state)))
    count = len(cameras)
    offline = len(failed)
    perf = f"'cameras_total'={count} 'cameras_connected'={count-offline} 'cameras_not_connected'={offline}"
    if offline:
        descriptions = ", ".join(f"{name} ({state})" for name, state in failed[:10])
        if offline > 10:
            descriptions += f" (+{offline-10} more)"
        level = 2 if offline > allow_offline or offline == count else 0
        allowance = f" (allowed offline: {allow_offline})" if allow_offline else ""
        return level, f"{offline}/{count} cameras not connected: {descriptions}{allowance} | {perf}"
    return 0, f"{count}/{count} cameras connected | {perf}"


def cameras_main(argv=None):
    p = api_parser(__doc__)
    p.add_argument("--allow-offline", type=int, default=0,
                   help="allowed disconnected cameras; at least one must remain connected")
    args = p.parse_args(argv)
    try:
        if args.allow_offline < 0:
            raise APIError("allow-offline must be a nonnegative integer")
        validate_api_origin(args.url, args.timeout)
        if args.connect_ip and ipaddress.ip_address(args.connect_ip).version != 4:
            raise APIError("only IPv4 --connect-ip is currently supported")
        key = read_key(args.key_file)
        req = urllib.request.Request(
            args.url.rstrip("/") + CAMERAS_PATH,
            headers={"X-API-Key": key, "Accept": "application/json"}, method="GET")
        try:
            with https_open(req, args.timeout,
                            tls_context(args.allow_legacy_ca, args.ca_file), args.connect_ip) as resp:
                data = read_json(resp)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise APIError("Protect request failed: " + str(exc)) from exc
        level, output = evaluate_cameras(data, args.allow_offline)
        print(f"UniFi Protect Cameras {STATUS[level]} - {output}")
        return level
    except (APIError, OSError, ValueError) as exc:
        print("UniFi Protect Cameras UNKNOWN - " + display_text(exc, 350))
        return 3



def evaluate_port_state(device, port_number, policy):
    """Map independent administrative and operational states to Nagios."""
    ports = device.get("port_table")
    if not isinstance(ports, list):
        raise APIError("device has no port_table")
    matches = [p for p in ports if isinstance(p, dict) and type(p.get("port_idx")) is int
               and p["port_idx"] == port_number]
    if len(matches) != 1:
        raise APIError(f"port {port_number} not uniquely available")
    port = matches[0]
    enabled, up = port.get("enable"), port.get("up")
    if type(enabled) is not bool or type(up) is not bool:
        raise APIError("port admin/oper status unavailable")
    name = display_text(port.get("name") or f"Port {port_number}", 80)
    if not enabled and up:
        return 3, f"Port {port_number} ({name}): inconsistent admin DOWN, oper UP"
    if policy == "up":
        state = 0 if enabled and up else 2
    elif policy == "admin":
        state = 0 if enabled else 2
    elif policy == "down":
        state = 0 if not enabled and not up else 2
    else:
        raise APIError("invalid port policy")
    return state, (f"Port {port_number} ({name}): admin="
                   f"{'UP' if enabled else 'DOWN'}, oper={'UP' if up else 'DOWN'}"
                   f" | 'admin_up'={int(enabled)} 'oper_up'={int(up)}")



PORT_CACHE_DIR = pathlib.Path("/run/nagios4/unifi-ports")
PORT_CACHE_TTL = 600
PORT_RATE_LIMIT_FALLBACK = 600


def fetch_legacy_inventory(origin, site, timeout, context, credentials,
                           api_key=None, connect_ip=None):
    if api_key is not None:
        req = urllib.request.Request(
            origin.rstrip("/") + "/proxy/network/api/s/" + site + "/stat/device",
            headers={"X-API-Key": api_key, "Accept": "application/json"},
            method="GET")
        with https_open(req, timeout, context, connect_ip) as response:
            return read_json(response)
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=context),
        NoAPIRedirect())
    try:
        req = urllib.request.Request(origin.rstrip("/") + "/api/auth/login",
            data=json.dumps({"username": credentials["username"],
                             "password": credentials["password"],
                             "remember": False}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with opener.open(req, timeout=timeout):
            pass
        req = urllib.request.Request(
            origin.rstrip("/") + "/proxy/network/api/s/" + site + "/stat/device",
            headers={"Accept": "application/json"}, method="GET")
        with opener.open(req, timeout=timeout) as response:
            return read_json(response)
    finally:
        jar.clear()


def retry_after_seconds(value, now):
    if value:
        try:
            return max(1, min(3600, int(value)))
        except (TypeError, ValueError):
            try:
                stamp = email.utils.parsedate_to_datetime(value)
                return max(1, min(3600, int(stamp.timestamp() - now)))
            except (TypeError, ValueError, OverflowError):
                pass
    return PORT_RATE_LIMIT_FALLBACK


def cached_legacy_inventory(origin, site, credentials_path, timeout, context,
                            credentials, cache_dir=PORT_CACHE_DIR, now=None,
                            api_key=None, connect_ip=None):
    """Coalesce port checks with flock; expired data is never returned."""
    if not cache_dir.is_dir() or cache_dir.is_symlink():
        raise APIError("private UniFi port cache directory is missing")
    stat = cache_dir.stat()
    if stat.st_mode & 0o077 or stat.st_uid != os.geteuid():
        raise APIError("UniFi port cache directory must be owned by the check user, mode 0700")
    identity = json.dumps(
        [origin.rstrip("/"), site, os.path.realpath(credentials_path),
         "api-key" if api_key is not None else credentials["username"]],
        separators=(",", ":"))
    key = hashlib.sha256(identity.encode()).hexdigest()
    cache_path = cache_dir / (key + ".json")
    cooldown_path = cache_dir / (key + ".retry")
    lock_path = cache_dir / (key + ".lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        # Recheck freshness after the lock so concurrent Nagios services share one fetch.
        now = time.time() if now is None else now
        try:
            if now - cache_path.stat().st_mtime < PORT_CACHE_TTL:
                with cache_path.open("rb") as stream:
                    return validate_legacy_inventory(read_json(stream))
        except (FileNotFoundError, ValueError, APIError):
            pass
        try:
            next_allowed = float(cooldown_path.read_text(encoding="ascii"))
        except (FileNotFoundError, ValueError):
            next_allowed = 0
        if now < next_allowed:
            raise APIError("UniFi port API rate limited; retry after cooldown")
        try:
            response = fetch_legacy_inventory(
                origin, site, timeout, context, credentials,
                api_key=api_key, connect_ip=connect_ip)
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                delay = retry_after_seconds(exc.headers.get("Retry-After"), now)
                atomic_private_write(cooldown_path, str(now + delay))
                raise APIError(f"UniFi port API rate limited (HTTP 429); retry in {delay}s") from None
            raise
        validate_legacy_inventory(response)
        atomic_private_write(cache_path, json.dumps(response))
        cooldown_path.unlink(missing_ok=True)
        return response
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def atomic_private_write(path, content):
    fd, temp = tempfile.mkstemp(dir=path.parent, prefix=".unifi-", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
        os.replace(temp, path)
    finally:
        pathlib.Path(temp).unlink(missing_ok=True)


def legacy_port_main(argv=None):
    p = argparse.ArgumentParser(description="UniFi legacy API physical port check")
    p.add_argument("--url", required=True)
    auth = p.add_mutually_exclusive_group(required=True)
    auth.add_argument("--credentials-file",
                      help="Legacy private JSON credentials (deprecated)")
    auth.add_argument("--key-file", help="Existing UniFi Network Integration API key")
    p.add_argument("--device", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--policy", required=True, choices=("up", "admin", "down"))
    p.add_argument("--timeout", type=float, default=10)
    p.add_argument("--site", default="default", help="Legacy UniFi site slug")
    p.add_argument("--ca-file")
    p.add_argument("--connect-ip", help="IPv4 destination with URL hostname TLS verification")
    p.add_argument("--allow-legacy-ca", action="store_true")
    args = p.parse_args(argv)
    try:
        validate_api_origin(args.url, args.timeout)
        if not 0 < args.port <= 1024:
            raise APIError("invalid port")
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", args.site):
            raise APIError("invalid site slug")
        if args.connect_ip and ipaddress.ip_address(args.connect_ip).version != 4:
            raise APIError("only IPv4 --connect-ip supported")
        credentials = None
        api_key = None
        auth_path = args.key_file or args.credentials_file
        if args.key_file:
            api_key = read_key(args.key_file)
        else:
            credentials = json.loads(read_key(args.credentials_file))
            if (not isinstance(credentials, dict)
                    or not isinstance(credentials.get("username"), str)
                    or not isinstance(credentials.get("password"), str)
                    or not credentials["username"] or not credentials["password"]):
                raise APIError("invalid credentials file")
        data = cached_legacy_inventory(
            args.url, args.site, auth_path, args.timeout,
            tls_context(args.allow_legacy_ca, args.ca_file), credentials,
            api_key=api_key, connect_ip=args.connect_ip)
        validate_legacy_inventory(data)
        matches = [d for d in data["data"] if isinstance(d, dict) and d.get("name") == args.device]
        if len(matches) != 1:
            raise APIError(f"device {args.device!r} not uniquely found")
        state, message = evaluate_port_state(matches[0], args.port, args.policy)
        print(f"UniFi Port {STATUS[state]} - {message}")
        return state
    except (APIError, OSError, ValueError, TypeError, urllib.error.URLError) as exc:
        print("UniFi Port UNKNOWN - " + display_text(exc, 300))
        return 3


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(description=__doc__, add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Use --check MODE --help for mode-specific options.")
    parser.add_argument("--check", required=True,
                        choices=("controller", "devices", "firmware", "stats", "cameras", "port"))
    if argv in (["--help"], ["-h"]):
        parser.print_help()
        return 0
    # Leave mode-specific validation and help to the existing check parsers.
    args, remaining = parser.parse_known_args(argv)
    if args.check == "port":
        return legacy_port_main(remaining)
    if args.check in ("controller", "firmware"):
        return status_main(["--check", args.check, *remaining])
    return {"devices": devices_main, "stats": stats_main,
            "cameras": cameras_main}[args.check](remaining)


if __name__ == "__main__":
    sys.exit(main())



