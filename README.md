# check-ubiquiti

Read-only Nagios monitoring and diagnostic exports through the official local UniFi Network and Protect HTTPS APIs. Python 3.9+ on Linux; standard library only.

Author: [Stijn Jonker (sjcjonker)](https://github.com/sjcjonker).

## Monitoring

`check_unifi.py --check MODE` is the monitoring entry point. Use `--help` for an overview or `--check MODE --help` for mode-specific options.

| Mode | Purpose |
| --- | --- |
| `controller` | Network API availability and application version |
| `devices` | Adopted device connectivity; optionally one exact device name |
| `firmware` | Available firmware updates from the adopted inventory |
| `stats` | Device CPU, memory, uptime, heartbeat and available uplink/radio metrics |
| `cameras` | Protect camera connectivity |
| `port` | Physical port state through the separate legacy Network API |

```sh
python3 check_unifi.py --check controller \
  --url https://network.example --key-file /private/network.key

python3 check_unifi.py --check devices \
  --url https://network.example --key-file /private/network.key \
  --no-firmware-warning

python3 check_unifi.py --check stats \
  --url https://network.example --key-file /private/network.key \
  --site Main --device ap-office

python3 check_unifi.py --check cameras \
  --url https://protect.example --key-file /private/protect.key
```

Exit codes: 0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN. Output includes Nagios performance data where available.

`--site` and `--device` use exact, case-sensitive names and reject ambiguous matches. Stats also supports `--site-id` and `--device-id`; supplying both IDs avoids discovery requests. Devices accepts `--device` and `--site-id`.

`--allow-offline N` permits N disconnected cameras, but always requires at least one connected camera. Empty or invalid inventory remains UNKNOWN. This accepts a monitoring gap and does not inspect Home Assistant privacy state. Connectivity does not prove recording or storage health.

## Diagnostic export

`export_ubiquiti.py` collects metadata for troubleshooting. Without `--output`, it prints indented JSON directly to stdout; status and errors go to stderr. No external formatter is required.

```sh
# Pretty-print Protect metadata to the terminal.
python3 export_ubiquiti.py --type protect --site main \
  --url https://protect.example --key-file /private/protect.key

# Save a private, compressed Network export.
python3 export_ubiquiti.py --type network --site main \
  --url https://network.example --key-file /private/network.key \
  --output main-network.json.gz
```

Both types support either output destination. `--output` requires a new `.json.gz` file, creates it with mode 0600 and never overwrites an existing file. Stdout is plain JSON; shell redirection uses your shell's permissions instead. All exports are unredacted: review before sharing and never commit them. `--site` is an installation label, not a site filter.

Network exports collect controller info, sites, device details and latest statistics. Device detail/statistics failures are recorded in the archive. Protect exports preserve responses from `meta/info`, `nvrs` and `cameras`; they do not fetch recordings or snapshots. NVR HTTP 404/405 is recorded in `errors` with `nvrs: null`; other request failures abort before producing output. Available fields depend on the console version.

## Credentials and TLS

Use a local integration API key with the minimum necessary permissions. Keep it outside Git in an owner-only file readable by the monitoring account. A Site Manager key is not automatically valid for local integration endpoints.

Both scripts verify certificate trust and hostname and disable proxies and redirects. Configure the final HTTPS console origin. `--allow-legacy-ca` relaxes OpenSSL X509_STRICT for a trusted legacy CA while retaining trust and hostname checks; prefer reissuing the CA correctly. Protect exports distinguish certificate, handshake, timeout and connection-refused failures without displaying underlying private error details.

The monitoring script additionally supports `--ca-file` for a trusted CA and `--connect-ip` for routing to a specific IPv4 while verifying the URL hostname.

Network uses `/proxy/network/integration/v1`; Protect uses `/proxy/protect/integration/v1`. Consult the console's local integration documentation.

Legacy port checks require a private cache directory. Install
`config/tmpfiles.conf.example` under `/etc/tmpfiles.d/` and apply it with
`systemd-tmpfiles --create`. It creates `/run/nagios4/unifi-ports` owned by
`nagios:nagios` with mode 0700. Adapt the account/group in the example for your
installation. Runtime and tmpfiles paths must match.

Each API or cached JSON document is limited to 16 MiB. Malformed JSON and
invalid collection records are rejected rather than used for monitoring.

## Validation and deployment

```sh
python3 -m compileall -q .
python3 -m unittest discover -s tests -v
```

CI runs a single Python syntax check on code PRs to `main` or manual dispatch.
The full offline suite remains the local code-change and pre-release check.

Tests run offline and cover dispatch, Network, Protect, statistics, transport/security, legacy ports/cache and exports. No controller credentials are needed.

Deploy `check_unifi.py` for monitoring. Keep `export_ubiquiti.py` beside it or beside a checkout copy of `check_unifi.py`, which supplies shared API functions. Both files must be readable by the executing account; keys remain owner-only.

## Scope

SNMP, disk, RAID and SMART monitoring are outside this project's scope; use generic system checks and native storage alerts for those functions.

API-derived monitoring text is normalized for Nagios output. Restrict the legacy port-cache directory to the monitoring account (0700). The legacy port API and username/password fallback are separate from the official integration API; retire them when equivalent port states become available there. Polling cannot capture every brief STP or loop event; use native alerts or separate event monitoring.


## License

Copyright (C) 2026 Stijn Jonker. Licensed under GPL-3.0-or-later; see [LICENSE](LICENSE).
