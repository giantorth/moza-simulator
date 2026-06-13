#!/usr/bin/env python3
"""Find the upload completion signal in a MOZA pcapng.

For each session that carries a file upload (host pushes type=0x02 metadata
+ type=0x03 content sub-msgs), prints:
  - Per-chunk: time, dir, type, body size, counter, last 16 bytes (look for
    terminator pattern), final 4 bytes of chunk body
  - Wheel→host replies near the upload tail (look for type=0x11 final ack)
  - The exact host frame immediately before the wheel's first type=0x11 reply

Usage:
    python3 usb-capture/analyze_upload_end.py <capture.pcapng> [--session 0xNN]
"""
import argparse
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / 'sim'))
from wheel_sim import parse_frames, frame_payload  # noqa: E402


def get_payloads(path):
    out = subprocess.check_output(
        ['tshark', '-r', str(path), '-Y', 'usbcom', '-T', 'fields',
         '-e', 'frame.number', '-e', 'frame.time_relative',
         '-e', 'usbcom.data.in_payload', '-e', 'usbcom.data.out_payload'],
        stderr=subprocess.DEVNULL, timeout=600).decode()
    rows = []
    for line in out.splitlines():
        parts = line.split('\t')
        if len(parts) < 3:
            continue
        try:
            fn = int(parts[0])
            t = float(parts[1])
        except ValueError:
            continue
        in_hex = parts[2].replace(':', '') if len(parts) >= 3 else ''
        out_hex = parts[3].replace(':', '') if len(parts) >= 4 else ''
        if in_hex:
            rows.append((fn, t, 'device', bytes.fromhex(in_hex)))
        if out_hex:
            rows.append((fn, t, 'host', bytes.fromhex(out_hex)))
    return rows


def collect_per_session(rows):
    """Return {(sess, dir): [(fn, t, ttype, seq, body)]} for type=0x01 chunks
    only (the actual data sub-msg type at the session-mux layer)."""
    by_key = defaultdict(list)
    for fn, t, d, raw in rows:
        for fr in parse_frames(raw):
            pl = frame_payload(fr)
            if len(pl) < 6 or pl[0] != 0x7c or pl[1] != 0x00:
                continue
            sess = pl[2]
            mtype = pl[3]
            if mtype != 0x01:
                continue
            seq = pl[4] | (pl[5] << 8)
            body = bytes(pl[6:])
            by_key[(sess, d)].append((fn, t, mtype, seq, body))
    return by_key


def walk_submsgs(buf):
    """Walk a reassembled session buffer, yielding (offset, type, size,
    counter, body_slice) for every type-prefixed sub-msg with a 6-byte
    header [type:1][size_LE:2][pad:3=00 00 00]."""
    pos = 0
    while pos < len(buf) - 6:
        t = buf[pos]
        if buf[pos+3:pos+6] != b'\x00\x00\x00':
            pos += 1
            continue
        sz = int.from_bytes(buf[pos+1:pos+3], 'little')
        if not (10 < sz < 80000) or pos + 6 + sz > len(buf):
            pos += 1
            continue
        body = buf[pos+6:pos+6+sz]
        ctr = int.from_bytes(body[281:284], 'little') if len(body) >= 284 else None
        yield (pos, t, sz, ctr, body)
        pos += 6 + sz


def reassemble(chunks, strip_crc=True):
    """Dedup by seq (prefer larger), concat in seq order."""
    by_seq = {}
    for fn, t, mtype, seq, body in chunks:
        prev = by_seq.get(seq)
        if prev is None or len(body) > len(prev[2]):
            by_seq[seq] = (fn, t, body)
    seqs = sorted(by_seq.keys())
    data = bytearray()
    seq_offsets = []
    for s in seqs:
        fn, t, body = by_seq[s]
        net = body[:-4] if strip_crc and len(body) > 4 else body
        seq_offsets.append((s, len(data), fn, t))
        data.extend(net)
    return bytes(data), seq_offsets


def is_upload_session(host_chunks, dev_chunks):
    """Detect file-transfer session: host buffer has many type=0x03 sub-msgs."""
    host_buf, _ = reassemble(host_chunks)
    n03 = sum(1 for off, t, sz, ctr, body in walk_submsgs(host_buf) if t == 0x03)
    return n03 >= 3


def analyze_one(cap, target_session=None):
    print(f'== {cap.name} ==')
    rows = get_payloads(cap)
    by_key = collect_per_session(rows)
    sessions = sorted({s for s, _ in by_key})
    if target_session is not None:
        sessions = [s for s in sessions if s == target_session]
    for sess in sessions:
        host = by_key.get((sess, 'host'), [])
        dev = by_key.get((sess, 'device'), [])
        if not host or not dev:
            continue
        if not is_upload_session(host, dev):
            continue
        host_buf, host_offs = reassemble(host)
        dev_buf, dev_offs = reassemble(dev)
        print(f'\n  --- session 0x{sess:02x} (likely upload) ---')
        print(f'    host: {len(host)} chunks, {len(host_buf)} net bytes')
        print(f'    dev : {len(dev)} chunks, {len(dev_buf)} net bytes')

        # Walk host sub-msgs in time order.
        host_msgs = list(walk_submsgs(host_buf))
        type_counts = defaultdict(int)
        for off, t, sz, ctr, body in host_msgs:
            type_counts[t] += 1
        print(f'    host sub-msg types: {dict(type_counts)}')

        # Last few host content sub-msgs.
        type03 = [m for m in host_msgs if m[1] == 0x03]
        print(f'    host type=0x03 chunks: {len(type03)}')
        if type03:
            print(f'    last 3 type=0x03 chunks:')
            for off, t, sz, ctr, body in type03[-3:]:
                tail = body[-32:].hex() if len(body) >= 32 else body.hex()
                head = body[:8].hex()
                print(f'      off=0x{off:06x} sz={sz} ctr={ctr} '
                      f'head={head} ... tail={tail}')

        # Walk wheel device sub-msgs to find ack pattern.
        dev_msgs = list(walk_submsgs(dev_buf))
        dev_type_counts = defaultdict(int)
        for off, t, sz, ctr, body in dev_msgs:
            dev_type_counts[t] += 1
        print(f'    dev  sub-msg types: {dict(dev_type_counts)}')

        # Find type=0x11 wheel final ack frames if present.
        type11 = [m for m in dev_msgs if m[1] == 0x11]
        type01 = [m for m in dev_msgs if m[1] == 0x01]
        print(f'    dev type=0x01 acks: {len(type01)}, type=0x11 acks: {len(type11)}')
        if type11:
            print(f'    type=0x11 details (first 2):')
            for off, t, sz, ctr, body in type11[:2]:
                tail = body[-24:].hex() if len(body) >= 24 else body.hex()
                head = body[:24].hex()
                print(f'      off=0x{off:06x} sz={sz} head={head} tail={tail}')

        # Find the host frame immediately before the wheel's first 0x11 ack.
        if type11:
            first_11 = type11[0]
            # Find seq+fn of first 0x11
            cum = 0
            ack_fn = None
            for s, o, fn, t in dev_offs:
                if o + (54 if cum > 0 else 0) > first_11[0]:
                    ack_fn = fn
                    break
                cum = o
            if ack_fn:
                # Find host chunks just before ack_fn
                host_before = [c for c in host if c[0] < ack_fn]
                print(f'    host chunks just before first dev 0x11 (fn={ack_fn}):')
                for fn, t, mtype, seq, body in host_before[-3:]:
                    last_bytes = body[-24:].hex()
                    print(f'      fn={fn} t={t:.3f}s seq=0x{seq:04x} '
                          f'len={len(body)} last={last_bytes}')


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('captures', nargs='+')
    ap.add_argument('--session', type=lambda x: int(x, 0), default=None)
    args = ap.parse_args()
    for cp in args.captures:
        cap = Path(cp)
        if not cap.exists():
            print(f'!! missing: {cap}', file=sys.stderr)
            continue
        analyze_one(cap, target_session=args.session)


if __name__ == '__main__':
    sys.exit(main() or 0)
