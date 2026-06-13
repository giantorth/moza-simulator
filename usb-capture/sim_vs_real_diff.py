#!/usr/bin/env python3
"""For each host→wheel frame in a real capture, compare the real wheel's
response against what sim would produce for the same request. Lists the
first N divergences so we can see where sim's behavior diverges from real
HW during the display-negotiation / connect phase.

Usage:
    python3 usb-capture/sim_vs_real_diff.py <capture.pcapng> [--model vgs|csp|kspro]
                                            [--limit 50]
"""

import argparse
import subprocess
import sys
from pathlib import Path

_root = Path(__file__).parent.parent
sys.path.insert(0, str(_root / 'sim'))

from wheel_sim import (  # noqa: E402
    WHEEL_MODELS, _build_identity_tables, frame_payload, swap_nibbles,
    build_frame, GRP_WHEEL, DEV_WHEEL_RSP, _PROBE_SYNTH,
)


def extract(path):
    out = subprocess.check_output(
        ['tshark', '-r', path, '-Y', 'usbcom', '-T', 'fields',
         '-e', 'frame.number', '-e', 'usbcom.data.in_payload',
         '-e', 'usbcom.data.out_payload'],
        stderr=subprocess.DEVNULL, timeout=600).decode()
    frames = []
    for line in out.splitlines():
        parts = line.split('\t')
        if len(parts) < 2: continue
        try: fn = int(parts[0])
        except: continue
        for hx, dir_ in ((parts[1].replace(':', '') if len(parts)>=2 else '', 'device'),
                         (parts[2].replace(':', '') if len(parts)>=3 else '', 'host')):
            if not hx: continue
            try: raw = bytes.fromhex(hx)
            except: continue
            i = 0
            while i < len(raw) - 3:
                if raw[i] == 0x7e:
                    ln = raw[i+1]
                    if 0 < ln <= 200 and i+2+ln+1 <= len(raw):
                        frames.append((fn, dir_, raw[i:i+3+ln]))
                        i += 3 + ln
                        continue
                i += 1
    return frames


def sim_would_respond(frame, plugin_rsp, pithouse_rsp, device_rsp=None):
    """Mimic the first-match portion of sim's _handle_core dispatch.
    Returns a list of response frames sim would produce for this probe,
    or None if sim falls through (no response / silent)."""
    group, device = frame[2], frame[3]
    payload = bytes(frame_payload(frame))

    # Skip session 7c:00 management frames — not a simple req/rsp
    if len(payload) >= 2 and payload[0] == 0x7c and payload[1] == 0x00:
        return None  # sim handles via stateful path; complex

    # Skip fc:00 ack frames — sim now consumes silently
    if len(payload) >= 2 and payload[0] == 0xfc and payload[1] == 0x00:
        return []

    # Plugin probe rsp — longest prefix match (4,3,2,1)
    for _plen in (4, 3, 2, 1):
        if len(payload) >= _plen:
            rsp = plugin_rsp.get((group, device, payload[:_plen]))
            if rsp is not None:
                return [build_frame(group | 0x80, swap_nibbles(device), rsp)]

    # _PROBE_SYNTH
    synth = _PROBE_SYNTH.get((group, device))
    if synth is not None:
        rsp_group, rsp_dev = synth
        return [build_frame(rsp_group, rsp_dev, payload)]

    # PitHouse identity probes (only for wheel dev 0x17)
    if device == 0x17:
        rsp = pithouse_rsp.get((group, payload))
        if rsp is not None:
            return [build_frame(group | 0x80, swap_nibbles(device), rsp)]

    # Per-device identity (hub 0x12, base 0x13, pedal 0x19)
    if device_rsp is not None:
        rsp = device_rsp.get((device, group, payload))
        if rsp is not None:
            return [build_frame(group | 0x80, swap_nibbles(device), rsp)]

    # group 0x0e fw_debug — silent drop
    if group == 0x0e:
        return []

    # Heartbeat (group 0x00, empty payload)
    if group == 0x00 and len(payload) == 0 and device in (0x12, 0x13, 0x17):
        return [build_frame(0x80, swap_nibbles(device), b'')]

    return None  # sim has no response — falls through to replay table


def pair_host_with_response(frames):
    """Pair each host→wheel frame with the NEXT device→host frame whose
    grp = host_grp | 0x80 and dev = swap_nibbles(host_dev). Skip acks.
    Returns list of (host_frame_no, host_frame, real_response_frame or None)."""
    pairs = []
    for i, (fn, d, f) in enumerate(frames):
        if d != 'host' or len(f) < 4: continue
        exp_grp = f[2] | 0x80
        exp_dev = swap_nibbles(f[3])
        real_rsp = None
        for j in range(i+1, min(i+10, len(frames))):
            fn2, d2, f2 = frames[j]
            if d2 != 'device': continue
            if f2[2] == exp_grp and f2[3] == exp_dev:
                real_rsp = f2
                break
        pairs.append((fn, f, real_rsp))
    return pairs


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('capture')
    ap.add_argument('--model', default='vgs')
    ap.add_argument('--limit', type=int, default=50)
    ap.add_argument('--start-frame', type=int, default=0,
                    help='Skip frames before this number')
    args = ap.parse_args()

    model = WHEEL_MODELS[args.model]
    plugin_rsp, pithouse_rsp, device_rsp = _build_identity_tables(model)
    print(f'[model={args.model}] plugin_rsp={len(plugin_rsp)}, '
          f'pithouse_rsp={len(pithouse_rsp)}, device_rsp={len(device_rsp)}')

    frames = extract(args.capture)
    print(f'[{args.capture}] {len(frames)} frames')

    pairs = pair_host_with_response(frames)
    print(f'paired {len(pairs)} host→response')

    divergences = []
    handled_match = 0
    sim_silent_real_silent = 0
    sim_silent_real_replies = 0  # sim has no handler but real wheel replies
    sim_replies_real_silent = 0
    mismatch = 0

    for fn, hf, real_rsp in pairs:
        if fn < args.start_frame:
            continue
        sim_rsp = sim_would_respond(hf, plugin_rsp, pithouse_rsp, device_rsp)

        if sim_rsp is None:  # sim has no handler (would fall through)
            if real_rsp is None:
                sim_silent_real_silent += 1
            else:
                sim_silent_real_replies += 1
                divergences.append(('no_handler', fn, hf, real_rsp))
        elif not sim_rsp:  # sim explicitly returns empty (fc:00 ack, fw_debug, etc)
            if real_rsp is None:
                sim_silent_real_silent += 1
            else:
                sim_silent_real_replies += 1
                divergences.append(('sim_silent_real_speaks', fn, hf, real_rsp))
        else:  # sim has a handler with a response
            if real_rsp is None:
                sim_replies_real_silent += 1
                divergences.append(('extra_reply', fn, hf, sim_rsp))
            else:
                sim_bytes = sim_rsp[0]
                real_bytes = real_rsp
                sim_stripped = sim_bytes[:-1] if sim_bytes else b''
                real_stripped = real_bytes[:-1] if real_bytes else b''
                if sim_stripped == real_stripped:
                    handled_match += 1
                else:
                    mismatch += 1
                    divergences.append(('mismatch', fn, hf, (sim_rsp[0], real_rsp)))

    print(f'\n=== summary ===')
    print(f'  match             : {handled_match}')
    print(f'  silent/silent     : {sim_silent_real_silent}')
    print(f'  no_handler (gap)  : {sim_silent_real_replies}')
    print(f'  extra_reply       : {sim_replies_real_silent}')
    print(f'  mismatch          : {mismatch}')

    print(f'\n=== first {args.limit} divergences ===')
    for kind, fn, hf, data in divergences[:args.limit]:
        hf_hex = hf.hex()
        if kind == 'no_handler':
            real_rsp = data
            print(f'  f{fn} [NO_HANDLER] host={hf_hex}')
            print(f'             real={real_rsp.hex()}')
        elif kind == 'extra_reply':
            sim_rsp = data
            sim_hex = sim_rsp[0].hex() if sim_rsp else '(none)'
            print(f'  f{fn} [EXTRA_REPLY] host={hf_hex}')
            print(f'             sim={sim_hex} (real: silent)')
        elif kind == 'sim_silent_real_speaks':
            real_rsp = data
            print(f'  f{fn} [SIM_SILENT_REAL_SPEAKS] host={hf_hex}')
            print(f'             real={real_rsp.hex()}')
        else:
            sim_rsp, real_rsp = data
            print(f'  f{fn} [MISMATCH] host={hf_hex}')
            print(f'             sim={sim_rsp.hex()}')
            print(f'            real={real_rsp.hex()}')


if __name__ == '__main__':
    sys.exit(main() or 0)
