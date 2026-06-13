#!/usr/bin/env python3
"""Diff sim's session 0x09 configJson state push against a real-wheel capture.

Builds the state body the sim would emit RIGHT NOW (using current FS,
factory_state_file, displayVersion/resetVersion, image manifest), then
loads the real-wheel reference blob from a pcapng, and walks every JSON
field reporting per-field diffs.

Usage:
    python3 usb-capture/diff_state_push.py <real_capture.pcapng> [--model vgs|csp|ks]

Reference capture suggestions:
    - Real VGS, working steady state:
      usb-capture/latestcaps/automobilista2-wheel-connect-dash-change.pcapng
    - Real KS-Pro:
      usb-capture/latestcaps/pithouse-switch-list-delete-upload-reupload.pcapng

Exits non-zero if any field differs (suitable for CI / scripts).
"""
import argparse
import json
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / 'sim'))

import wheel_sim  # noqa: E402


def build_sim_state(model_name: str) -> dict:
    """Build sim state push body for the given model profile."""
    if model_name not in wheel_sim.WHEEL_MODELS:
        raise SystemExit(f'unknown model {model_name!r}; '
                         f'choose from {sorted(wheel_sim.WHEEL_MODELS)}')
    model = wheel_sim.WHEEL_MODELS[model_name]
    factory_file = model.get('factory_state_file')
    sim = wheel_sim.WheelSimulator(db={}, factory_state_file=factory_file)
    img_ref, img_path = sim.fs.image_manifest()
    state_bytes = wheel_sim.build_configjson_state(
        sim.fs.dashboards(),
        display_version=sim._display_version,
        reset_version=sim._reset_version,
        factory_file=factory_file,
        image_ref_map=img_ref,
        image_path=img_path,
    )
    comp_size = int.from_bytes(state_bytes[1:5], 'little')
    decoded = zlib.decompress(state_bytes[9:9 + comp_size])
    return json.loads(decoded)


def load_real_state(capture: Path) -> dict:
    """Extract first session 0x09 device→host blob from a pcapng."""
    out_dir = Path(tempfile.mkdtemp(prefix='sess09_'))
    subprocess.run(
        ['python3', str(REPO / 'usb-capture' / 'analyze_session09.py'),
         str(out_dir), str(capture)],
        check=True, capture_output=True,
    )
    blobs = sorted(out_dir.glob('*__dev_blob*.json'))
    if not blobs:
        raise SystemExit(f'no device blob extracted from {capture}')
    return json.loads(blobs[0].read_text())


def diff_lists(name: str, sim_v: list, real_v: list, indent: str = '') -> int:
    """Diff two lists. Returns count of differences."""
    diffs = 0
    if len(sim_v) != len(real_v):
        print(f'{indent}{name}: LEN sim={len(sim_v)} real={len(real_v)}')
        diffs += 1
    common = min(len(sim_v), len(real_v))
    for i in range(common):
        sv, rv = sim_v[i], real_v[i]
        if isinstance(sv, dict) and isinstance(rv, dict):
            d = diff_dicts(f'{name}[{i}]', sv, rv, indent + '  ')
            diffs += d
        elif sv != rv:
            print(f'{indent}{name}[{i}]: sim={sv!r} real={rv!r}')
            diffs += 1
    for i in range(common, len(sim_v)):
        print(f'{indent}{name}[{i}] only in sim: {sim_v[i]!r}')
        diffs += 1
    for i in range(common, len(real_v)):
        print(f'{indent}{name}[{i}] only in real: {real_v[i]!r}')
        diffs += 1
    return diffs


def diff_dicts(name: str, sim_v: dict, real_v: dict, indent: str = '') -> int:
    """Diff two dicts. Returns count of differences."""
    diffs = 0
    sim_keys = set(sim_v.keys())
    real_keys = set(real_v.keys())
    only_sim = sim_keys - real_keys
    only_real = real_keys - sim_keys
    for k in sorted(only_sim):
        print(f'{indent}{name}.{k}: only in sim ({sim_v[k]!r})')
        diffs += 1
    for k in sorted(only_real):
        print(f'{indent}{name}.{k}: only in real ({real_v[k]!r})')
        diffs += 1
    for k in sorted(sim_keys & real_keys):
        sv, rv = sim_v[k], real_v[k]
        if isinstance(sv, dict) and isinstance(rv, dict):
            diffs += diff_dicts(f'{name}.{k}', sv, rv, indent + '  ')
        elif isinstance(sv, list) and isinstance(rv, list):
            diffs += diff_lists(f'{name}.{k}', sv, rv, indent + '  ')
        elif sv != rv:
            print(f'{indent}{name}.{k}: sim={sv!r} real={rv!r}')
            diffs += 1
    return diffs


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('capture', type=Path)
    p.add_argument('--model', default='vgs',
                   choices=sorted(wheel_sim.WHEEL_MODELS),
                   help='wheel model profile to build sim state from')
    p.add_argument('--summary-only', action='store_true',
                   help='print only top-level summary, skip per-entry diff')
    args = p.parse_args()
    if not args.capture.exists():
        raise SystemExit(f'capture not found: {args.capture}')

    sim_state = build_sim_state(args.model)
    real_state = load_real_state(args.capture)

    print(f'== sim ({args.model}) vs real ({args.capture.name}) ==')
    print(f'  sim top keys: {sorted(sim_state.keys())}')
    print(f'  real top keys: {sorted(real_state.keys())}')
    print()
    print(f'  sim     real    field')
    for k in sorted(set(sim_state) | set(real_state)):
        if k not in sim_state:
            print(f'  ----    {len(real_state[k]) if isinstance(real_state[k],(list,dict)) else real_state[k]:<7} {k} (only real)')
            continue
        if k not in real_state:
            print(f'  {len(sim_state[k]) if isinstance(sim_state[k],(list,dict)) else sim_state[k]:<7} ----    {k} (only sim)')
            continue
        sv = sim_state[k]; rv = real_state[k]
        if isinstance(sv, list):
            print(f'  {len(sv):<7} {len(rv):<7} {k}')
        elif isinstance(sv, dict):
            print(f'  {len(sv):<7} {len(rv):<7} {k} (keys)')
        else:
            mark = ' ' if sv == rv else '!'
            print(f'  {sv!r:<7} {rv!r:<7} {k} {mark}')
    print()

    if args.summary_only:
        return

    print('== detailed diff ==')
    diffs = diff_dicts('state', sim_state, real_state)
    print(f'\n== total field diffs: {diffs} ==')
    sys.exit(0 if diffs == 0 else 1)


if __name__ == '__main__':
    main()
