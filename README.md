# Brave Diagnostics for macOS

Two independent Python scripts (Python 3.9+, standard library only):

- [`brave_extension_scan.py`](https://github.com/eferbarn/brave-proxy-crash-diagnostics/blob/main/brave_extension_scan.py): read-only offline Brave multi-profile extension inventory, static WebSocket URL scan, rankings and progress bar.
- [`brave_crash_monitor.py`](https://github.com/eferbarn/brave-proxy-crash-diagnostics/blob/main/brave_crash_monitor.py): crash-report watcher; optionally launches Brave with Chromium NetLog to correlate WebSocket domains with proxy HTTP 407. **Does not rely on the scanner or its output files.**

## 1. Scanner

Open Terminal in the folder containing these scripts, then:

```bash
python3 brave_extension_scan.py
```

By default, output is written to the **current working directory** (`pwd`), not hard-coded to the home directory and not necessarily the script directory:

| File | Contents |
|---|---|
| `brave_extensions_inventory.json` | Full per-profile inventory including extensions without WebSocket literals; ID, display name, version, settings state (best effort), detected `ws://` and `wss://` hosts, source filenames, service-worker literal hints. |
| `brave_extensions_shared.json` | All unique extension IDs sorted by **descending number of profiles**; those shared by 2+ profiles; those present in every scanned profile; ranked WebSocket domains across profiles. |
| `brave_extensions_shared.md` | Quick human-readable summary/table with rankings. |
| `brave_scan.log` | Timestamped profile and extension scan logs (appends across runs). |

For a custom output directory:

```bash
python3 brave_extension_scan.py --out ./scan_results
```

Use `python3 brave_extension_scan.py --help` for options. The scanner displays a terminal progress bar and scans Brave's `Default` and `Profile N` folders, including profiles with zero extensions when they have Preferences/Local State. It does not require the browser to be closed.

**Scope:** static scanning of extension source files only. A URL appearing in code does *not* show a live WebSocket, nor prove that a service worker opened one. Dynamic URLs may be missed. Disabled extensions are also inventoried. The `literal_in_service_worker_file` signal means a literal URL was present in that file, not that it was used. Some extension names rely on translations not present locally.

**Data safety:** no browser files are written, deleted, modified or executed. The script never uploads information. It overwrites the three generated report files with the same names in the output folder and appends to `brave_scan.log`. Review domain, extension and profile names before sharing the reports.

## 2. Crash monitor (independent)

**Recommended diagnostic mode**: quit *all* Brave windows/processes with Cmd+Q first, and then run:

```bash
python3 brave_crash_monitor.py --launch
```

This starts the Brave application binary with these standard Chromium flags:

```
--log-net-log=<current-folder>/brave_monitor_logs/session_<timestamp>/netlog.json
--net-log-capture-mode=Default
--net-log-max-size-mb=100
```

You can verify the flags at `brave://version` while Brave is open. The monitor then watches for new macOS crash reports (`~/Library/Logs/DiagnosticReports/Brave Browser*.ips` or `.crash`) and Brave Crashpad minidumps (`~/Library/Application Support/BraveSoftware/Brave-Browser/Crashpad/completed/*.dmp`). It ignores reports that were already present when monitoring started. The monitor waits up to 20 seconds after Brave exits for delayed reports. This script does **not** force-quit Brave. If you interrupt the monitor with Ctrl+C, it stops watching but does not close Brave. This is a **foreground per-session tool**, not a persistent startup daemon.

Each monitor run makes a private directory under `./brave_monitor_logs/session_...`, containing:

| File | Contents |
|---|---|
| `monitor_events.jsonl` | Timestamped append-only session and new-crash-artifact events. |
| `crash_artifact_001.json`, etc. | Parsed crash details and best-effort NetLog correlation; native crash trigger is marked unknown unless evidence exists. |
| `netlog.json` | Chromium network log, potentially incomplete after a sudden crash. Only created in `--launch` mode. |

### Watch without relaunching Brave

If Brave is already running, use:

```bash
python3 brave_crash_monitor.py
```

This captures **new crash reports only**; it does not attach a NetLog to an existing Brave process.

If you are manually saving NetLog from `brave://net-export` (start the capture before reproducing the crash), you can provide a file path:

```bash
python3 brave_crash_monitor.py --netlog /path/to/netlog.json
```

For a bounded test:

```bash
python3 brave_crash_monitor.py --duration 300
```

### What monitor correlation really means

- Looks for a literal `ws://` / `wss://` URL in NetLog events, `407` or `Proxy Authentication Required` responses, and `chrome-extension://<ID>` initiator strings if exposed.
- Relates WebSocket requests and 407 events on the same NetLog `source.id` or via explicit `source_dependency` links (maximum 3 hops).
- Records domain names and possible extension IDs, not sensitive full URLs/headers in the generated **crash-summary JSON**.
- A source match is **investigative evidence, not proof** that the associated extension caused the native Brave crash. NetLog is not guaranteed to contain an extension initiator. If attribution is ambiguous, the script says `possible_trigger_extension: null`. Exact attribution generally requires NetLog + symbolicated crash dump and/or controlled reproduction with extensions selectively disabled.
- macOS `.ips` and Brave `.dmp` may record the **same incident twice**. The monitor counts artifacts, not deduplicated incidents.
- An abrupt browser crash can leave a truncated NetLog. The parser tries to salvage complete event objects but may not find every request.

**Privacy:** Raw `netlog.json` can contain browsing hosts, timestamps, IP addresses, and potentially other sensitive metadata, *even with the `Default` (redacted) capture mode*. Keep this file private; don't publish it on GitHub or send it unreviewed. The generated summary JSON is safer but still contains domain names and local file paths. No script uploads any data.

## Important bug context

The Brave issue [#60118](https://github.com/brave/brave-browser/issues/60118) contains technical reproduction of a Service Worker WebSocket + authenticated proxy `407` crash around `BraveProxyingWebSocket::OnAuthRequired`. This package is intended to collect evidence for or against **that specific scenario**. It cannot guarantee the same root cause on every machine.
