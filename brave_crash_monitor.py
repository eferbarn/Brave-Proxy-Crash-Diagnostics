#!/usr/bin/env python3
"""macOS Brave crash monitor with optional startup NetLog capture.

Python 3.9+; standard library only. It does not inject code into Brave, inspect
private browser profile content, or send network requests. A crash's offending
extension cannot always be identified from macOS diagnostics / NetLog.
"""
import argparse
from collections import defaultdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.parse import urlsplit

BRAVE_BINARY = Path('/Applications/Brave Browser.app/Contents/MacOS/Brave Browser')
DIAG_DIR = Path.home() / 'Library/Logs/DiagnosticReports'
CRASHPAD = Path.home() / 'Library/Application Support/BraveSoftware/Brave-Browser/Crashpad/completed'
HOST_URL = re.compile(r'\b(wss?://[^\s\x00"<>\\]+)', re.I)
EXT_URL = re.compile(r'chrome-extension://([a-p]{32})', re.I)
HTTP_407 = re.compile(r'HTTP/[0-9.]+\s+407\b|[\"\'](?:response_code|status_code|http_status_code)[\"\']\s*:\s*407\b|Proxy Authentication Required', re.I)


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def event_print(message):
    print(f'[{datetime.now().astimezone().strftime("%H:%M:%S")}] {message}', flush=True)


def save_json(path, obj):
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


def app_running():
    """Check main Brave process without terminating or modifying anything."""
    try:
        result = subprocess.run(['ps', '-A', '-o', 'comm='], capture_output=True, text=True, timeout=5, check=True)
        for line in result.stdout.splitlines():
            command = line.strip()
            if command == 'Brave Browser' or command.endswith('/MacOS/Brave Browser'):
                return True
    except (OSError, subprocess.SubprocessError):
        pass
    return False


def report_paths():
    if DIAG_DIR.is_dir():
        try:
            for p in DIAG_DIR.iterdir():
                if p.is_file() and p.suffix.lower() in ('.ips', '.crash'):
                    if p.name.startswith('Brave Browser') and not p.name.startswith('Brave Browser Helper'):
                        yield p
        except OSError:
            pass
    if CRASHPAD.is_dir():
        try:
            for p in CRASHPAD.iterdir():
                if p.is_file() and p.suffix.lower() == '.dmp':
                    yield p
        except OSError:
            pass


def fingerprint(path):
    try:
        s = path.stat()
        return (s.st_mtime_ns, s.st_size)
    except OSError:
        return None


def parse_macos_report(path):
    result = {'file': str(path), 'report_type': 'macos_diagnostic', 'parsed': False}
    try:
        raw = path.read_text(encoding='utf-8', errors='replace')[:4_000_000]
    except OSError as exc:
        return {**result, 'error': str(exc)}

    # Current .ips may consist of one JSON metadata line followed by JSON body.
    parts = []
    try:
        parts = [json.loads(raw)]
    except json.JSONDecodeError:
        first, sep, rest = raw.partition('\n')
        if sep:
            for candidate in (first, rest):
                try:
                    parts.append(json.loads(candidate))
                except json.JSONDecodeError:
                    pass
    if parts:
        head = parts[0] if isinstance(parts[0], dict) else {}
        body = parts[-1] if isinstance(parts[-1], dict) else {}
        if body.get('threads') or body.get('exception'):
            result.update({
                'parsed': True, 'process': body.get('procName', head.get('procName')),
                'time': body.get('captureTime', head.get('timestamp')),
                'version': body.get('bundleInfo', {}).get('CFBundleShortVersionString') if isinstance(body.get('bundleInfo'), dict) else None,
                'exception': body.get('exception', {}),
                'termination': body.get('termination', {}),
                'faulting_thread': body.get('faultingThread'),
            })
            threads = body.get('threads', [])
            ti = body.get('faultingThread')
            if isinstance(ti, int) and 0 <= ti < len(threads):
                frames = threads[ti].get('frames', [])[:10]
                result['top_crash_frames'] = [{k: f.get(k) for k in ('symbol', 'imageOffset', 'imageIndex') if k in f} for f in frames]
            return result
    # Text-style translated macOS report.
    fields = {
        'process': r'^Process:\s*(.+)$',
        'time': r'^Date/Time:\s*(.+)$',
        'version': r'^Version:\s*(.+)$',
        'exception_type': r'^Exception Type:\s*(.+)$',
        'exception_subtype': r'^Exception Subtype:\s*(.+)$',
        'triggered_thread': r'^Triggered by Thread:\s*(.+)$',
        'termination_reason': r'^Termination Reason:\s*(.+)$',
    }
    for name, pattern in fields.items():
        m = re.search(pattern, raw, flags=re.M)
        if m:
            result[name] = m.group(1).strip()
            result['parsed'] = True
    crashed = re.search(r'^Thread \d+ Crashed::?[^\n]*\n((?:[^\n]*\n){0,12})', raw, flags=re.M)
    if crashed:
        result['top_crash_frames'] = [s.strip()[:300] for s in crashed.group(1).splitlines()[:10] if s.strip()]
    return result


def parse_crash_artifact(path):
    if path.suffix.lower() == '.dmp':
        return {'file': str(path), 'report_type': 'brave_crashpad_minidump',
                'parsed': False, 'note': 'Binary .dmp is preserved at original path; requires Crashpad tooling and Brave debug symbols to symbolicate.'}
    return parse_macos_report(path)


def normalize_domain(url):
    try:
        host = urlsplit(url.strip(' ,;\"\'}]')).hostname
        if host:
            return host.lower()
    except ValueError:
        pass
    return None


def partial_or_full_events(raw):
    """Try a complete NetLog JSON; fall back to parsing completed event objects
    in a truncated file, which is common when a browser crashes mid-write.
    """
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return data.get('events', []), data.get('constants', {}), False
    except (ValueError, TypeError):
        pass
    pos = raw.find('"events"')
    if pos < 0:
        return [], {}, True
    pos = raw.find('[', pos)
    if pos < 0:
        return [], {}, True
    pos += 1
    decoder = json.JSONDecoder()
    results = []
    length = len(raw)
    while pos < length:
        while pos < length and raw[pos] in ' \n\r\t,':
            pos += 1
        if pos >= length or raw[pos] == ']':
            break
        try:
            evt, end = decoder.raw_decode(raw, pos)
        except json.JSONDecodeError:
            break
        if isinstance(evt, dict):
            results.append(evt)
        pos = end
    # Event-type mapping generally lives in constants, before or after events.
    # If netlog is truncated, event.type may remain numeric; keep it as-is.
    constants = {}
    try:
        const_start = raw.find('"constants"')
        if const_start >= 0 and const_start < raw.find('"events"'):
            brace = raw.find('{', const_start)
            const_obj, _ = decoder.raw_decode(raw, brace)
            if isinstance(const_obj, dict):
                constants = const_obj
    except (ValueError, TypeError):
        pass
    return results, constants, True


def netlog_summary(netlog_path):
    result = {
        'available': False,
        'note': 'NetLog offers correlation, not guaranteed attribution to an extension.',
        'matched_websocket_sources_with_407': [],
        'explicit_extension_ids_on_correlated_sources': [],
    }
    if not netlog_path:
        result['note'] = 'No NetLog supplied. Run monitor with --launch (Brave fully quit first), or provide --netlog PATH.'
        return result
    path = Path(netlog_path)
    if not path.is_file():
        result['note'] = 'NetLog file has not been created yet.'
        return result
    try:
        size = path.stat().st_size
        # Bound disk/memory use, even with a user-supplied capture.
        if size > 120 * 1024 * 1024:
            result['note'] = 'NetLog exceeds safe parser limit (120 MiB). Analyze separately.'
            result['file'] = str(path)
            return result
        raw = path.read_text(encoding='utf-8', errors='replace')
    except OSError as exc:
        result['note'] = f'Could not read NetLog: {exc}'
        return result
    events, constants, partial = partial_or_full_events(raw)
    types = constants.get('logEventTypes', {})
    type_by_id = {str(v): k for k, v in types.items()} if isinstance(types, dict) else {}
    per_source = defaultdict(lambda: {'ws_hosts': set(), 'extensions': set(), 'saw_407': False, 'types': set()})
    links = defaultdict(set)
    ws_all = set()
    n407 = 0
    network_change_events = 0
    for e in events:
        if not isinstance(e, dict):
            continue
        sid = str(e.get('source', {}).get('id', 'unknown')) if isinstance(e.get('source'), dict) else 'unknown'
        etype = str(e.get('type', '?'))
        readable_type = type_by_id.get(etype, etype)
        if any(marker in readable_type.upper() for marker in ('NETWORK_CHANGED', 'IP_ADDRESSES_CHANGED', 'PROXY_CONFIG_CHANGED')):
            network_change_events += 1
        params = e.get('params', {})
        try:
            ptext = json.dumps(params, ensure_ascii=False, separators=(',', ':'))
        except (ValueError, TypeError):
            continue
        # Link NetLog source objects explicitly connected by source_dependency.
        # A CONNECT handshake and its WebSocket are often DIFFERENT source IDs.
        def find_dependencies(value):
            if isinstance(value, dict):
                dependency = value.get('source_dependency')
                if isinstance(dependency, dict) and 'id' in dependency:
                    other = str(dependency['id'])
                    links[sid].add(other)
                    links[other].add(sid)
                for nested in value.values():
                    if isinstance(nested, (dict, list)):
                        find_dependencies(nested)
            elif isinstance(value, list):
                for nested in value:
                    if isinstance(nested, (dict, list)):
                        find_dependencies(nested)
        find_dependencies(params)
        is_407 = bool(HTTP_407.search(ptext))
        wss_hosts = {host for u in HOST_URL.findall(ptext) if (host := normalize_domain(u))}
        ext_ids = set(EXT_URL.findall(ptext))
        if not (is_407 or wss_hosts or ext_ids):
            continue
        record = per_source[sid]
        record['ws_hosts'].update(wss_hosts)
        record['extensions'].update(ext_ids)
        record['saw_407'] |= is_407
        record['types'].add(readable_type)
        ws_all.update(wss_hosts)
        if is_407:
            n407 += 1
    # Correlate 407 with WebSocket source IDs directly, or through explicit
    # NetLog source_dependency links (never by arbitrary temporal proximity).
    correlation = []
    for sid, info in per_source.items():
        if not info['ws_hosts']:
            continue
        linked_ids = {sid}
        frontier = {sid}
        for _ in range(3):
            frontier = set().union(*(links.get(x, set()) for x in frontier)) - linked_ids
            if not frontier:
                break
            linked_ids.update(frontier)
        hit_407 = [other for other in linked_ids if per_source[other]['saw_407']]
        if not hit_407:
            continue
        exts = set().union(*(per_source[x]['extensions'] for x in linked_ids))
        typelist = set().union(*(per_source[x]['types'] for x in linked_ids))
        correlation.append({
            'netlog_websocket_source_id': sid,
            'http_407_source_ids': sorted(hit_407),
            'correlation_kind': 'same_source' if sid in hit_407 else 'explicit_source_dependency',
            'websocket_domains': sorted(info['ws_hosts']),
            'explicit_extension_ids': sorted(exts),
            'event_types': sorted(typelist)[:20],
        })
    result.update({
        'available': True, 'file': str(path), 'file_complete_json': not partial,
        'events_parsed': len(events), 'events_matching_http_407': n407,
        'network_change_or_proxy_change_events': network_change_events,
        'websocket_domains_seen': sorted(ws_all)[:200],
        'matched_websocket_sources_with_407': correlation[:50],
        'explicit_extension_ids_on_correlated_sources': sorted({x for c in correlation for x in c['explicit_extension_ids']}),
        'note': ('Correlated means HTTP 407 and a WebSocket URL occur on the same NetLog source or on '
                 'sources explicitly connected through source_dependency. This is not proof that an extension caused '
                 'the native Brave bug. No match does not rule out the bug. Full URLs and headers are excluded.'),
    })
    return result


def append_event(path, item):
    with path.open('a', encoding='utf-8') as f:
        f.write(json.dumps(item, ensure_ascii=False) + '\n')


def main():
    parser = argparse.ArgumentParser(description='Watch Brave crashes on macOS, optionally launch with a bounded NetLog.')
    parser.add_argument('--launch', action='store_true', help='Launch Brave with NetLog after fully quitting all Brave windows.')
    parser.add_argument('--netlog', type=Path, help='Existing NetLog file to analyze after a crash (for watch-only mode).')
    parser.add_argument('--out', type=Path, default=Path.cwd() / 'brave_monitor_logs', help='Session storage parent (default: ./brave_monitor_logs).')
    parser.add_argument('--interval', type=float, default=2.0, help='Crash report polling interval (default: 2 seconds).')
    parser.add_argument('--duration', type=float, default=0, help='Stop after N seconds (default: run until Ctrl+C / Brave exits).')
    args = parser.parse_args()
    if args.interval < 0.5:
        parser.error('interval must be >= 0.5 seconds')
    if args.launch and args.netlog:
        parser.error('Use --launch OR --netlog, not both.')
    if args.launch and sys.platform != 'darwin':
        parser.error('--launch is only supported on macOS.')
    if args.launch and not BRAVE_BINARY.is_file():
        parser.error(f'Brave binary not found: {BRAVE_BINARY}')
    if args.launch and app_running():
        parser.error('Brave is already running. Quit ALL Brave instances with Cmd+Q and retry. No processes were changed.')

    # Outputs contain network/domain metadata. Restrict newly-created files to the current user.
    os.umask(0o077)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    session = args.out.expanduser().resolve() / f'session_{timestamp}_{os.getpid()}'
    session.mkdir(parents=True, exist_ok=False, mode=0o700)
    event_file = session / 'monitor_events.jsonl'
    netlog_path = (session / 'netlog.json') if args.launch else args.netlog
    start_time = time.monotonic()
    seen = {p: fingerprint(p) for p in report_paths()}
    done = set()
    brave = None
    if args.launch:
        command = [str(BRAVE_BINARY), f'--log-net-log={netlog_path}',
                   '--net-log-capture-mode=Default', '--net-log-max-size-mb=100']
        try:
            brave = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        except OSError as exc:
            parser.error(f'Could not launch Brave: {exc}')
        event_print(f'Launched Brave PID {brave.pid} with NetLog (default privacy mode; <=100 MB).')
    else:
        event_print('Watch-only mode: observing macOS and Crashpad reports; no network capture started.')
    event_print('Session output: ' + str(session))
    event_print('Monitoring Brave crashes. Press Ctrl+C to stop. Existing old crash reports are ignored.')
    if netlog_path:
        event_print('NetLog: ' + str(netlog_path))
    append_event(event_file, {'event': 'monitor_started', 'at_utc': utcnow(), 'mode': 'launch' if args.launch else 'watch'})

    crash_count = 0
    stopped_at = None
    try:
        while True:
            time.sleep(args.interval)
            for path in report_paths():
                fp = fingerprint(path)
                if fp is None or path in done:
                    continue
                if path in seen and seen[path] == fp:
                    continue
                # Wait for a stable file; macOS may still be writing a report.
                if (time.time_ns() - fp[0]) / 1e9 < 1.5:
                    continue
                seen[path] = fp
                done.add(path)
                crash_count += 1
                report = parse_crash_artifact(path)
                network = netlog_summary(netlog_path)
                matched = network.get('matched_websocket_sources_with_407', [])
                candidate_ids = network.get('explicit_extension_ids_on_correlated_sources', [])
                candidate = ({'extension_id': candidate_ids[0], 'evidence': 'explicit chrome-extension:// ID on a correlated NetLog source',
                              'status': 'candidate_only_not_proven'} if len(candidate_ids) == 1 else None)
                incident = {
                    'incident_index': crash_count,
                    'observed_at_utc': utcnow(),
                    'crash_artifact': report,
                    'network_evidence': network,
                    'possible_trigger_extension': candidate,
                    'assessment': ('WebSocket + HTTP 407 correlated through NetLog source ID(s). Investigate the listed domain(s).'
                                   if matched else 'No linked-source WebSocket+407 match available; trigger remains unknown.'),
                    'limitations': [
                        'A native browser crash cannot be conclusively assigned to one extension by observing processes alone.',
                        'Crashpad and macOS reports may represent the same crash; artifacts are not deduplicated.',
                        'NetLog may be incomplete after a sudden crash and service-worker initiators may not be recorded.',
                    ],
                }
                incident_file = session / f'crash_artifact_{crash_count:03d}.json'
                save_json(incident_file, incident)
                append_event(event_file, {
                    'event': 'new_crash_artifact', 'at_utc': utcnow(),
                    'artifact_file': str(path), 'incident_json': str(incident_file),
                    'network_407_events': network.get('events_matching_http_407'),
                    'ws_407_correlations': len(matched),
                })
                event_print(f'CRASH ARTIFACT detected: {path.name} -> {incident_file.name}')
                if matched:
                    for item in matched[:5]:
                        event_print('  WebSocket/407 correlation: ' + ', '.join(item['websocket_domains']))
                else:
                    event_print('  Extension attribution: unknown (see JSON for evidence).')
            if args.duration and time.monotonic() - start_time >= args.duration:
                event_print('Configured monitoring duration ended.')
                break
            if brave is not None and brave.poll() is not None:
                if stopped_at is None:
                    stopped_at = time.monotonic()
                    event_print(f'Brave process exited (code {brave.returncode}); allowing 20 seconds for delayed crash reports.')
                    append_event(event_file, {'event': 'brave_exited', 'at_utc': utcnow(), 'exit_code': brave.returncode})
                elif time.monotonic() - stopped_at > 20:
                    break
    except KeyboardInterrupt:
        event_print('Monitoring stopped by user. Brave was NOT terminated.')
    finally:
        append_event(event_file, {'event': 'monitor_stopped', 'at_utc': utcnow(), 'crash_artifacts': crash_count})
        event_print(f'Finished. Recorded {crash_count} new crash artifact(s). Output: {session}')


if __name__ == '__main__':
    main()
