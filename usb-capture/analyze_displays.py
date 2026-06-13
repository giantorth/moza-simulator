#!/usr/bin/env python3
"""Display-negotiation inventory + analysis across all MOZA USB captures.

Walks every `.pcapng` under `usb-capture/`, extracts MOZA protocol frames,
categorises traffic, and emits a markdown report detailing which captures
contain PitHouse↔wheel display negotiation (Phase 1/2). For captures that
do contain it, dumps a time-ordered cascade timeline (Phase 3) and diffs
host-side probes against the current sim's identity tables (Phase 4).

Usage:
    python3 usb-capture/analyze_displays.py [--out display-negotiation-inventory.md]
"""

import argparse
import json
import os
import subprocess
import sys
import zlib
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_here = Path(__file__).parent
_root = _here.parent
sys.path.insert(0, str(_root / 'sim'))

from wheel_sim import (  # noqa: E402
    WHEEL_MODELS, _build_identity_tables, frame_payload, verify, swap_nibbles,
)


def extract_frames(path: Path) -> Tuple[List[Tuple[int, str, bytes]], Dict[str, str]]:
    """Return (frames, descriptor_info).

    frames: list of (frame_no, direction, wire_bytes) where direction is
    'host' (host→device) or 'device' (device→host).
    descriptor_info: {idVendor, idProduct, bcdDevice} (first USB DEVICE descriptor).
    """
    # Get device descriptor
    desc = {}
    try:
        out = subprocess.check_output(
            ['tshark', '-r', str(path), '-Y', 'usb.bDescriptorType == 1',
             '-T', 'fields', '-e', 'usb.idVendor', '-e', 'usb.idProduct',
             '-e', 'usb.bcdDevice'],
            stderr=subprocess.DEVNULL, timeout=120).decode()
        for line in out.splitlines():
            parts = line.split('\t')
            if len(parts) >= 3 and parts[0].startswith('0x346e'):
                desc = {'idVendor': parts[0], 'idProduct': parts[1], 'bcdDevice': parts[2]}
                break
    except Exception:
        pass

    # Get payloads
    frames: List[Tuple[int, str, bytes]] = []
    try:
        out = subprocess.check_output(
            ['tshark', '-r', str(path), '-Y', 'usbcom', '-T', 'fields',
             '-e', 'frame.number', '-e', 'usbcom.data.in_payload',
             '-e', 'usbcom.data.out_payload'],
            stderr=subprocess.DEVNULL, timeout=600).decode()
    except Exception as e:
        print(f'  [warn] tshark failed on {path.name}: {e}', file=sys.stderr)
        return frames, desc

    for line in out.splitlines():
        parts = line.split('\t')
        if len(parts) < 2: continue
        try:
            fn = int(parts[0])
        except ValueError:
            continue
        in_p = parts[1].replace(':', '') if len(parts) >= 2 else ''
        out_p = parts[2].replace(':', '') if len(parts) >= 3 else ''
        for hx, dir_ in ((in_p, 'device'), (out_p, 'host')):
            if not hx: continue
            try:
                raw = bytes.fromhex(hx)
            except ValueError:
                continue
            i = 0
            while i < len(raw) - 3:
                if raw[i] == 0x7e:
                    ln = raw[i+1]
                    if 0 < ln <= 200 and i + 2 + ln + 1 <= len(raw):
                        frames.append((fn, dir_, raw[i:i+3+ln]))
                        i += 3 + ln
                        continue
                i += 1
    return frames, desc


def frame_key(f: bytes) -> Tuple[int, int, int, int]:
    """(grp, dev, cmd, sub) where sub = second payload byte or 0."""
    grp, dev = f[2], f[3]
    pl = frame_payload(f)
    cmd = pl[0] if len(pl) >= 1 else 0
    sub = pl[1] if len(pl) >= 2 else 0
    return (grp, dev, cmd, sub)


def is_session_frame(f: bytes) -> bool:
    pl = frame_payload(f)
    return len(pl) >= 2 and pl[0] == 0x7c and pl[1] == 0x00


def session_info(f: bytes) -> Optional[dict]:
    """Parse a 7c:00 session frame. Returns dict or None."""
    pl = frame_payload(f)
    if len(pl) < 5 or pl[0] != 0x7c or pl[1] != 0x00:
        return None
    return {
        'sess': pl[2],
        'type': pl[3],       # 0x81 open, 0x01 data, 0x00 end
        'data': bytes(pl[4:]),
    }


def is_display_cascade(f: bytes) -> bool:
    """Host→wheel probe matching display-identity cascade (grp 0x43, dev 0x17,
    cmd in {02,04,05,06,07,08,09,0a,0b,0f,10,11})."""
    if f[2] != 0x43 or f[3] != 0x17:
        return False
    pl = frame_payload(f)
    if not pl: return False
    return pl[0] in (0x02, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0f, 0x10, 0x11)


def analyze(path: Path) -> dict:
    frames, desc = extract_frames(path)
    host_frames = [(fn, f) for fn, d, f in frames if d == 'host']
    dev_frames = [(fn, f) for fn, d, f in frames if d == 'device']

    # Session activity
    sessions_host_open: Dict[int, int] = Counter()
    sessions_dev_open: Dict[int, int] = Counter()
    sessions_host_data: Dict[int, int] = Counter()
    sessions_dev_data: Dict[int, int] = Counter()
    sessions_ends: Dict[int, int] = Counter()

    # Display cascade probes
    display_short: Counter = Counter()      # (cmd,) short-form (no sub-byte)
    display_sub: Counter = Counter()         # (cmd, sub) long-form

    # Large payload blobs (candidate uploads on specific sessions)
    session_blobs: Dict[int, List[int]] = defaultdict(list)  # session → list of blob sizes
    total_session_data_bytes: Dict[int, int] = Counter()

    # mcUid candidates: dev→host responses of 12 bytes random-looking
    mcuid_candidates: List[Tuple[int, int, int, str]] = []  # (frame, grp, dev, hex)

    # All unique host probes (for sim-diff)
    host_probes: Dict[Tuple[int, int, bytes], int] = Counter()

    for fn, f in host_frames:
        grp, dev = f[2], f[3]
        pl = frame_payload(f)
        host_probes[(grp, dev, bytes(pl))] += 1

        si = session_info(f)
        if si:
            sess = si['sess']
            if si['type'] == 0x81:
                sessions_host_open[sess] += 1
            elif si['type'] == 0x01:
                sessions_host_data[sess] += 1
                # Track payload length after sess,type,seq prefix
                if len(si['data']) > 4:
                    body_len = len(si['data']) - 4  # minus seq bytes
                    total_session_data_bytes[sess] += body_len
                    if body_len > 40:
                        session_blobs[sess].append(body_len)
            elif si['type'] == 0x00:
                sessions_ends[sess] += 1
        elif is_display_cascade(f):
            if len(pl) == 1:
                display_short[pl[0]] += 1
            else:
                display_sub[(pl[0], pl[1])] += 1

    for fn, f in dev_frames:
        si = session_info(f)
        if si:
            sess = si['sess']
            if si['type'] == 0x81:
                sessions_dev_open[sess] += 1
            elif si['type'] == 0x01:
                sessions_dev_data[sess] += 1
                if len(si['data']) > 4:
                    body_len = len(si['data']) - 4
                    total_session_data_bytes[sess] += body_len
                    if body_len > 40:
                        session_blobs[sess].append(body_len)
            elif si['type'] == 0x00:
                sessions_ends[sess] += 1
        else:
            pl = frame_payload(f)
            if len(pl) >= 13 and f[2] in (0x80, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x8e, 0x8f, 0x90, 0x91) \
                    and f[3] in (0x21, 0x31):
                # Responses from hub (0x21=swap(0x12)) or base (0x31=swap(0x13)) with ≥12B data
                non_zero = sum(1 for b in pl[1:13] if b)
                ascii_n = sum(1 for b in pl[1:13] if 32 <= b < 127)
                if non_zero >= 8 and ascii_n < 8:
                    mcuid_candidates.append((fn, f[2], f[3], pl.hex()))

    # Identity strings
    identities: List[str] = []
    all_hex = b''.join(f for _, _, f in frames).hex().encode()
    import re
    for m in re.finditer(rb'RS21-[A-Z0-9\-]{4,}', bytes.fromhex(all_hex.decode())):
        s = m.group().decode()
        if s not in identities:
            identities.append(s)

    # Classify
    has_display_cascade = bool(display_short or display_sub)
    has_session_opens = bool(sessions_host_open)
    # configJson state push on session 0x09
    has_configjson = any(s == 0x09 for s in session_blobs)
    # tier def on session 0x02
    has_tier_def = 0x02 in session_blobs
    # Categorisation
    if has_session_opens and has_display_cascade and has_configjson:
        category = 'full_handshake_with_display'
    elif has_session_opens and has_display_cascade:
        category = 'handshake_display_no_configjson'
    elif has_session_opens:
        category = 'full_handshake_no_display_cascade'
    elif has_tier_def or total_session_data_bytes.get(0x02, 0) > 1000:
        category = 'mid_session_telemetry'
    else:
        category = 'specialty'

    # Software: assume PitHouse unless filename marks it as SimHub. User
    # convention: every capture is PitHouse-against-wheel except those
    # explicitly containing 'simhub' in the name. SimHub-tagged captures are
    # from an OLDER plugin build missing many later protocol features —
    # treat as historical baseline only.
    software = 'simhub_old_build' if 'simhub' in path.name.lower() else 'pithouse'

    return {
        'path': str(path.relative_to(_root)),
        'size': path.stat().st_size,
        'desc': desc,
        'frame_count': len(frames),
        'identities': identities,
        'sessions_host_open': dict(sessions_host_open),
        'sessions_dev_open': dict(sessions_dev_open),
        'sessions_host_data': dict(sessions_host_data),
        'sessions_dev_data': dict(sessions_dev_data),
        'sessions_ends': dict(sessions_ends),
        'session_blob_counts': {s: len(b) for s, b in session_blobs.items()},
        'session_data_bytes': dict(total_session_data_bytes),
        'display_short': {f'{c:02x}': n for c, n in display_short.items()},
        'display_sub': {f'{c:02x}{s:02x}': n for (c, s), n in display_sub.items()},
        'mcuid_candidate_count': len(mcuid_candidates),
        'mcuid_samples': [
            f'f{fn} grp={g:02x} dev={d:02x}: {hx[:48]}'
            for fn, g, d, hx in mcuid_candidates[:5]
        ],
        'category': category,
        'software': software,
        'unique_host_probe_count': len(host_probes),
        'host_probes': host_probes,  # kept for sim-diff phase
    }


def sim_diff_probes(host_probes: Dict[Tuple[int, int, bytes], int], model_name: str) -> dict:
    """Classify host probes by whether sim's current identity tables answer them."""
    model = WHEEL_MODELS[model_name]
    plugin_rsp, pithouse_rsp = _build_identity_tables(model)
    handled_plugin = 0
    handled_pithouse = 0
    unhandled: List[Tuple[int, int, bytes]] = []
    for (grp, dev, pl), cnt in host_probes.items():
        if (grp, dev, pl) in plugin_rsp:
            handled_plugin += cnt
            continue
        if dev == 0x17 and (grp, pl) in pithouse_rsp:
            handled_pithouse += cnt
            continue
        unhandled.append((grp, dev, pl))
    # Group unhandled by (grp, dev) for summary
    by_dev = defaultdict(list)
    for grp, dev, pl in unhandled:
        by_dev[(grp, dev)].append(pl)
    return {
        'handled_plugin': handled_plugin,
        'handled_pithouse': handled_pithouse,
        'unhandled_unique': len(unhandled),
        'unhandled_by_dev': {
            f'grp={g:02x}_dev={d:02x}': len(pls) for (g, d), pls in by_dev.items()
        },
    }


def write_report(results: List[dict], out_path: Path) -> None:
    lines: List[str] = []
    lines.append('# Display-negotiation capture inventory\n')
    lines.append('Auto-generated by `usb-capture/analyze_displays.py`. '
                 'Classifies each `.pcapng` by whether it contains the '
                 'PitHouse↔wheel display-identity negotiation sequence and '
                 'quantifies session/blob/probe traffic.\n')
    lines.append(f'Captures scanned: **{len(results)}**  '
                 f'Full display handshakes: **'
                 f'{sum(1 for r in results if r["category"] == "full_handshake_with_display")}**\n')

    # Summary table
    lines.append('## Summary table\n')
    lines.append('| Capture | Size | Category | Software | Identities | '
                 'Sess opens (host/dev) | Display short/sub | Blobs (s=count) |')
    lines.append('|---------|------|----------|----------|------------|----------------------|'
                 '-------------------|-----------------|')
    for r in sorted(results, key=lambda x: x['category'] + x['path']):
        ids = ', '.join(r['identities'][:3]) + ('…' if len(r['identities']) > 3 else '')
        open_str = (f'{sum(r["sessions_host_open"].values())}'
                    f'/{sum(r["sessions_dev_open"].values())}')
        short_n = sum(r['display_short'].values())
        sub_n = sum(r['display_sub'].values())
        blob_str = ', '.join(f'0x{s:02x}={c}' for s, c in sorted(r['session_blob_counts'].items()))
        lines.append(f'| `{r["path"]}` | {r["size"]//1024}KB | {r["category"]} | '
                     f'{r["software"]} | {ids or "—"} | {open_str} | '
                     f'{short_n}/{sub_n} | {blob_str or "—"} |')
    lines.append('')

    # Per-capture detail for display-negotiation captures
    negotiation_caps = [r for r in results
                        if r['category'] in ('full_handshake_with_display',
                                             'handshake_display_no_configjson')]
    if negotiation_caps:
        lines.append('## Display-negotiation captures (detail)\n')
        for r in negotiation_caps:
            lines.append(f'### `{r["path"]}`\n')
            lines.append(f'- **Size**: {r["size"]//1024} KB  |  **Frames**: {r["frame_count"]}')
            lines.append(f'- **Category**: `{r["category"]}`  |  **Software**: {r["software"]}')
            lines.append(f'- **USB descriptor**: {r["desc"] or "(not captured)"}')
            lines.append(f'- **Identity strings**: {", ".join(r["identities"]) or "—"}')
            lines.append(f'- **Sessions — host opens**: '
                         f'{ {hex(s): c for s, c in r["sessions_host_open"].items()} }')
            lines.append(f'- **Sessions — device opens**: '
                         f'{ {hex(s): c for s, c in r["sessions_dev_open"].items()} }')
            lines.append(f'- **Session data bytes**: '
                         f'{ {hex(s): c for s, c in r["session_data_bytes"].items()} }')
            lines.append(f'- **Session blobs**: '
                         f'{ {hex(s): c for s, c in r["session_blob_counts"].items()} }')
            lines.append(f'- **Display cascade — short form**: {r["display_short"] or "(none)"}')
            lines.append(f'- **Display cascade — sub-byte form**: {r["display_sub"] or "(none)"}')
            lines.append(f'- **mcUid candidate responses (≥12B random from hub/base)**: '
                         f'{r["mcuid_candidate_count"]}')
            if r['mcuid_samples']:
                lines.append('  ```')
                for s in r['mcuid_samples']:
                    lines.append(f'  {s}')
                lines.append('  ```')
            # Sim diff — use VGS identity tables (broadest coverage of identity probes)
            diff = sim_diff_probes(r['host_probes'], 'vgs')
            lines.append(f'- **Sim vs capture (VGS identity tables)**: '
                         f'{diff["handled_plugin"]} plugin + {diff["handled_pithouse"]} '
                         f'pithouse = {diff["handled_plugin"] + diff["handled_pithouse"]} handled, '
                         f'**{diff["unhandled_unique"]} unhandled** unique probes')
            if diff['unhandled_by_dev']:
                lines.append('  Unhandled breakdown:')
                for k, v in sorted(diff['unhandled_by_dev'].items()):
                    lines.append(f'  - {k}: {v}')
            lines.append('')

    # Cross-capture display-cascade aggregate
    lines.append('## Cross-capture display-cascade aggregate\n')
    agg_short: Counter = Counter()
    agg_sub: Counter = Counter()
    for r in results:
        for k, v in r['display_short'].items():
            agg_short[k] += v
        for k, v in r['display_sub'].items():
            agg_sub[k] += v
    lines.append(f'- **Short-form probes** (43:17:cmd, 1 byte payload):')
    for k, v in sorted(agg_short.items()):
        lines.append(f'  - `{k}`: {v} occurrences')
    lines.append(f'- **Sub-byte probes** (43:17:cmd:sub):')
    for k, v in sorted(agg_sub.items()):
        lines.append(f'  - `{k}`: {v} occurrences')
    lines.append('')

    with open(out_path, 'w') as f:
        f.write('\n'.join(lines))
    print(f'[write] {out_path} ({len(lines)} lines, '
          f'{sum(len(l) for l in lines)} bytes)')


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', default='usb-capture/display-negotiation-inventory.md')
    ap.add_argument('--pattern', default='*.pcapng',
                    help='Glob pattern (default *.pcapng)')
    ap.add_argument('--limit', type=int, default=0,
                    help='Analyze at most N captures (0 = all)')
    args = ap.parse_args()

    capture_dir = _root / 'usb-capture'
    paths = sorted(capture_dir.rglob(args.pattern))
    if args.limit:
        paths = paths[:args.limit]

    print(f'Analyzing {len(paths)} captures…')
    results: List[dict] = []
    for i, p in enumerate(paths, 1):
        print(f'  [{i}/{len(paths)}] {p.relative_to(_root)} '
              f'({p.stat().st_size // 1024} KB)')
        try:
            results.append(analyze(p))
        except Exception as e:
            print(f'    [error] {e}', file=sys.stderr)

    out_path = _root / args.out
    write_report(results, out_path)
    return 0


if __name__ == '__main__':
    sys.exit(main())
