#!/usr/bin/env python3
"""Read-only multi-profile Brave extension inventory and static WebSocket URL scan.

Python 3.9+; standard library only. Does not execute extension JavaScript.
"""
import argparse
from collections import defaultdict
from datetime import datetime, timezone
import json
import re
import sys
from pathlib import Path

DEFAULT_ROOT = Path.home() / 'Library/Application Support/BraveSoftware/Brave-Browser'
EXT_ID = re.compile(r'[a-p]{32}\Z')
WS_URL = re.compile(rb'\bwss?://([a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?\.[a-zA-Z]{2,63})(?=[/:?#\s\x00-\x1f"\'\\]|$)', re.I)
SEARCH_SUFFIXES = {'.js', '.mjs', '.cjs', '.html', '.htm', '.json'}
CHUNK_SIZE = 1024 * 1024
LOGFILE = None


def log(message):
    print(message, flush=True)
    if LOGFILE is not None:
        with LOGFILE.open('a', encoding='utf-8') as log_file:
            log_file.write(f'[{datetime.now().astimezone().isoformat(timespec="seconds")}] {message}\n')


def read_json(path):
    try:
        with path.open('r', encoding='utf-8') as f:
            return json.load(f)
    except (OSError, UnicodeError, ValueError):
        return {}


def real_name(manifest, version_dir):
    name = str(manifest.get('name', '(unnamed)'))
    match = re.fullmatch(r'__MSG_(.*?)__', name, flags=re.I)
    if not match:
        return name
    for locale in dict.fromkeys(filter(None, [manifest.get('default_locale'), 'en', 'en_US', 'en_GB'])):
        messages = read_json(version_dir / '_locales' / locale / 'messages.json')
        for key, val in messages.items():
            if key.lower() == match.group(1).lower() and isinstance(val, dict):
                return str(val.get('message') or name)
    return name


def extension_dirs(profile):
    base = profile / 'Extensions'
    if not base.is_dir():
        return []
    try:
        return sorted(p for p in base.iterdir() if p.is_dir() and not p.is_symlink() and EXT_ID.fullmatch(p.name))
    except OSError:
        return []


def latest_manifest(ext_dir):
    try:
        options = [p for p in ext_dir.iterdir() if p.is_dir() and not p.is_symlink() and (p / 'manifest.json').is_file()]
        return max(options, key=lambda p: p.stat().st_mtime) if options else None
    except OSError:
        return None


def scan_urls(folder, progress=None):
    hosts = defaultdict(set)
    unreadable = 0
    scanned_files = 0
    files = [file for file in folder.rglob('*')
             if not file.is_symlink() and file.is_file() and file.suffix.lower() in SEARCH_SUFFIXES]
    for file in files:
        scanned_files += 1
        try:
            relative = file.relative_to(folder).as_posix()
            with file.open('rb') as f:
                overlap = b''
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    blob = overlap + chunk
                    for match in WS_URL.finditer(blob):
                        domain = match.group(1).decode('ascii', errors='ignore').lower().rstrip('.')
                        if domain and '..' not in domain:
                            hosts[domain].add(relative)
                    overlap = blob[-512:]
        except (OSError, ValueError):
            unreadable += 1
        if progress and (scanned_files == len(files) or scanned_files % 20 == 0):
            progress(scanned_files, len(files))
    return hosts, scanned_files, unreadable


def print_progress(done, total, profile_name, ext_name):
    width = 28
    fraction = done / total if total else 1
    filled = round(width * fraction)
    bar = '#' * filled + '-' * (width - filled)
    msg = f'[{bar}] {done:>3}/{total:<3} {fraction:>5.0%}  {profile_name} | {ext_name[:34]}'
    if sys.stdout.isatty():
        print('\r\033[2K' + msg, end='', flush=True)
    else:
        print(msg, flush=True)


def write_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def main():
    ap = argparse.ArgumentParser(description='Scan Brave profiles and rank shared extensions / static WebSocket domains.')
    ap.add_argument('--root', type=Path, default=DEFAULT_ROOT, help='Brave user data root (macOS default).')
    ap.add_argument('--out', type=Path, default=Path.cwd(), help='Output folder; default: current working directory.')
    args = ap.parse_args()
    root = args.root.expanduser()
    out = args.out.expanduser().resolve()
    if not root.is_dir():
        ap.error(f'Brave profile directory does not exist: {root}')
    out.mkdir(parents=True, exist_ok=True)
    global LOGFILE
    LOGFILE = out / 'brave_scan.log'
    log('[START] New read-only static scan')
    state = read_json(root / 'Local State')
    info_cache = state.get('profile', {}).get('info_cache', {})
    if not isinstance(info_cache, dict):
        info_cache = {}

    profiles = []
    known = set(info_cache)
    for path in sorted(root.iterdir()):
        if not path.is_dir() or path.is_symlink():
            continue
        is_profile = path.name in known or path.name == 'Default' or bool(re.fullmatch(r'Profile \d+', path.name))
        if is_profile and ((path / 'Preferences').is_file() or (path / 'Extensions').is_dir()):
            profiles.append((path, extension_dirs(path)))
    total = sum(len(dirs) for _, dirs in profiles)
    if not profiles:
        ap.error('No Brave profiles were found.')
    if not total:
        log('[WARN] Profiles found but no installed extension directories were present.')

    log(f'[INFO] Found {len(profiles)} profiles containing extensions; {total} installed extension directories.')
    entries = []
    count = 0
    bad_files = 0
    for index, (profile, dirs) in enumerate(profiles, 1):
        label = str(info_cache.get(profile.name, {}).get('name') or profile.name)
        log(f'\n[PROFILE {index}/{len(profiles)}] {label} ({profile.name}) - {len(dirs)} extensions')
        pref = read_json(profile / 'Preferences')
        settings = pref.get('extensions', {}).get('settings', {})
        if not isinstance(settings, dict):
            settings = {}
        for ext in dirs:
            version_dir = latest_manifest(ext)
            count += 1
            if version_dir is None:
                print_progress(count, total, profile.name, 'no manifest; skipped')
                continue
            manifest = read_json(version_dir / 'manifest.json')
            worker = manifest.get('background', {}).get('service_worker') if isinstance(manifest.get('background'), dict) else None
            def inner_progress(done_files, total_files):
                if sys.stdout.isatty():
                    print(f'\r\033[2K[FILES {done_files}/{total_files}] {profile.name} | {ext.name[:12]}', end='', flush=True)
            hosts, files_count, unreadable = scan_urls(version_dir, inner_progress)
            bad_files += unreadable
            state_value = settings.get(ext.name, {}).get('state') if isinstance(settings.get(ext.name), dict) else None
            enabled = (state_value == 1) if state_value in (0, 1) else None
            entry = {
                'profile_directory': profile.name,
                'profile_name': label,
                'name': real_name(manifest, version_dir),
                'id': ext.name,
                'version': manifest.get('version'),
                'enabled_in_preferences': enabled,
                'manifest_version': manifest.get('manifest_version'),
                'service_worker': worker,
                'scanned_source_files': files_count,
                'unreadable_source_files': unreadable,
                'has_static_websocket_urls': bool(hosts),
                'websocket_domains': [
                    {
                        'domain': domain,
                        'source_files': sorted(files),
                        'literal_in_service_worker_file': bool(worker and worker.lstrip('./') in files),
                    }
                    for domain, files in sorted(hosts.items())
                ],
            }
            entries.append(entry)
            log(f"[EXT] {profile.name} | {entry['name']} [{ext.name}] | source files: {files_count} | WebSocket domains: {len(hosts)} | read errors: {unreadable}")
            print_progress(count, total, profile.name, entry['name'])
        if sys.stdout.isatty():
            print()

    profile_items = []
    for profile, dirs in profiles:
        label = str(info_cache.get(profile.name, {}).get('name') or profile.name)
        mine = sorted([e for e in entries if e['profile_directory'] == profile.name], key=lambda e: (e['name'].casefold(), e['id']))
        profile_items.append({
            'directory': profile.name, 'name': label,
            'extensions_scanned': len(mine),
            'extensions_with_websocket_urls': sum(e['has_static_websocket_urls'] for e in mine),
            'extensions': mine,
        })

    grouped = defaultdict(list)
    for entry in entries:
        grouped[entry['id']].append(entry)
    ranked = []
    for eid, group in grouped.items():
        names = [x['name'] for x in group]
        ws_domains = sorted({h['domain'] for g in group for h in g['websocket_domains']})
        profile_names = sorted({g['profile_directory'] for g in group})
        ranked.append({
            'rank': None,
            'name': max(set(names), key=lambda n: (names.count(n), n)),
            'id': eid,
            'profile_count': len(profile_names),
            'coverage_percent': round(100 * len(profile_names) / len(profiles), 1),
            'profiles': [{'directory': g['profile_directory'], 'name': g['profile_name'],
                          'version': g['version'], 'enabled_in_preferences': g['enabled_in_preferences'],
                          'has_static_websocket_urls': g['has_static_websocket_urls']}
                         for g in sorted(group, key=lambda item: item['profile_directory'])],
            'has_static_websocket_urls': bool(ws_domains),
            'websocket_domains': ws_domains,
        })
    ranked.sort(key=lambda e: (-e['profile_count'], -len(e['websocket_domains']), e['name'].casefold(), e['id']))
    for idx, item in enumerate(ranked, 1):
        item['rank'] = idx

    domains = defaultdict(lambda: {'profiles': set(), 'extensions': set()})
    for item in entries:
        for h in item['websocket_domains']:
            domains[h['domain']]['profiles'].add(item['profile_directory'])
            domains[h['domain']]['extensions'].add(item['id'])
    domain_ranking = sorted([
        {'domain': d, 'profile_count': len(data['profiles']), 'profiles': sorted(data['profiles']),
         'extension_count': len(data['extensions']), 'extension_ids': sorted(data['extensions'])}
        for d, data in domains.items()
    ], key=lambda e: (-e['profile_count'], -e['extension_count'], e['domain']))

    metadata = {'generated_at_utc': datetime.now(timezone.utc).isoformat(), 'platform': 'macOS',
                'scan_type': 'read_only_static_source_scan', 'profile_count': len(profiles),
                'installed_extension_instances': len(entries), 'unique_extension_ids': len(ranked),
                'extensions_in_multiple_profiles': sum(x['profile_count'] >= 2 for x in ranked),
                'unreadable_source_files': bad_files}
    inventory = {'metadata': metadata, 'profiles': profile_items}
    overlap = {
        'metadata': metadata,
        'all_extensions_ranked_by_profile_coverage': ranked,
        'shared_across_at_least_two_profiles': [x for x in ranked if x['profile_count'] >= 2],
        'present_in_every_scanned_profile': [x for x in ranked if x['profile_count'] == len(profiles)],
        'websocket_domains_ranked_by_profile_coverage': domain_ranking,
        'notes': [
            'wss/ws domains are extracted from literal source strings, not observed network activity.',
            'A domain appearing in a service-worker file does not prove a connection was opened.',
            'A disabled extension can still have source files; enabled_in_preferences is best-effort.',
            'A VPN allowlist excludes network traffic from VPN protection; do not allowlist all detected domains.',
        ],
    }
    write_json(out / 'brave_extensions_inventory.json', inventory)
    write_json(out / 'brave_extensions_shared.json', overlap)

    lines = [
        '# Brave extension overlap and WebSocket report', '',
        f"Generated: {metadata['generated_at_utc']}",
        f"Profiles: {len(profiles)} | Installed instances: {len(entries)} | Unique extensions: {len(ranked)}",
        f"Shared in 2+ profiles: {metadata['extensions_in_multiple_profiles']} | Unreadable source files: {bad_files}", '',
        '## All extensions sorted by profile coverage', '',
        '| # | Extension | Profiles | WebSocket URLs in source | Domains |',
        '|---:|---|---:|---|---|',
    ]
    for x in ranked:
        safe_name = x['name'].replace('|', '\\|').replace('\n', ' ')
        dom_str = ', '.join('`' + d + '`' for d in x['websocket_domains'][:5])
        if len(x['websocket_domains']) > 5:
            dom_str += f" (+{len(x['websocket_domains'])-5} more)"
        lines.append(f"| {x['rank']} | {safe_name} (`{x['id']}`) | {x['profile_count']}/{len(profiles)} | {'Yes' if x['has_static_websocket_urls'] else 'No'} | {dom_str or '-'} |")
    lines.extend(['', '## Shared extensions with literal WebSocket URLs', ''])
    shared_ws = [x for x in ranked if x['profile_count'] >= 2 and x['has_static_websocket_urls']]
    if not shared_ws:
        lines.append('None identified by static source scanning.')
    for x in shared_ws:
        lines.extend([f"### {x['name']} ({x['profile_count']} profiles)",
                      f"- Profiles: {', '.join(p['directory'] for p in x['profiles'])}",
                      f"- Domains: {', '.join(x['websocket_domains'])}", ''])
    lines += ['', '## Interpretation', '',
              '- Finding a literal URL does not mean the extension uses it while Brave is crashing.',
              '- Only consider VPN bypass rules after a NetLog identifies a relevant WebSocket and HTTP 407.',
              '- A bypassed domain will no longer be protected by the Windscribe browser proxy.', '']
    (out / 'brave_extensions_shared.md').write_text('\n'.join(lines), encoding='utf-8')
    log('\n[DONE] Saved reports in: ' + str(out))
    for filename in ('brave_extensions_inventory.json', 'brave_extensions_shared.json', 'brave_extensions_shared.md', 'brave_scan.log'):
        log('  - ' + filename)
    log(f"[SUMMARY] {len(ranked)} unique extensions; {metadata['extensions_in_multiple_profiles']} shared in 2+ profiles; {len(domain_ranking)} unique literal WebSocket domains.")


if __name__ == '__main__':
    main()
