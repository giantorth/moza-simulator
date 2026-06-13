#!/usr/bin/env python3
"""Reassemble and decode session-multiplexed data from a MOZA pcapng capture.

MOZA wheels use sessions 0x01-0x0a as independent byte-oriented streams
framed via `7c:00 [sess] [type] [seq] [data]` sub-headers carried in group
0x43/0xc3 frames. This tool pulls all session data for one direction (or
both) and dumps:

  - per-session byte totals + chunk counts
  - reassembled stream (dir=host and dir=device)
  - envelope detection: zlib (`0x78 0x9C` magic), UTF-16LE text runs,
    MOZA TLV (leading `0xFF <type> <size_le>`), JSON, raw hex

Usage:
    python3 usb-capture/decode_session.py <capture.pcapng> --session 1
    python3 usb-capture/decode_session.py <capture.pcapng> --session 9 --save out.bin
    python3 usb-capture/decode_session.py <capture.pcapng> --session 2 --direction host
"""

import argparse
import json
import re
import subprocess
import sys
import zlib
from pathlib import Path
from typing import Dict, List, Tuple

_root = Path(__file__).parent.parent
sys.path.insert(0, str(_root / 'sim'))
from wheel_sim import frame_payload, verify  # noqa: E402


def extract(path: Path):
    """Extract (frame_no, direction, frame_bytes) list via tshark."""
    out = subprocess.check_output(
        ['tshark', '-r', str(path), '-Y', 'usbcom', '-T', 'fields',
         '-e', 'frame.number', '-e', 'usbcom.data.in_payload',
         '-e', 'usbcom.data.out_payload'],
        stderr=subprocess.DEVNULL, timeout=600).decode()
    frames = []
    for line in out.splitlines():
        parts = line.split('\t')
        if len(parts) < 2: continue
        try: fn = int(parts[0])
        except ValueError: continue
        for hx, dir_ in ((parts[1].replace(':', '') if len(parts)>=2 else '', 'device'),
                         (parts[2].replace(':', '') if len(parts)>=3 else '', 'host')):
            if not hx: continue
            try: raw = bytes.fromhex(hx)
            except ValueError: continue
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


def reassemble(frames, session: int, direction: str) -> Tuple[bytes, List[Tuple[int, int, bytes]]]:
    """Return (concatenated_bytes, [(frame_no, seq, chunk)])."""
    chunks: List[Tuple[int, int, bytes]] = []
    for fn, d, f in frames:
        if d != direction: continue
        pl = frame_payload(f)
        if len(pl) < 7: continue
        if pl[0] != 0x7c or pl[1] != 0x00: continue
        if pl[2] != session: continue
        if pl[3] != 0x01: continue   # data only (not open/end)
        seq = pl[4] | (pl[5] << 8)
        # Chunk body after the 6-byte session header
        body = bytes(pl[6:])
        chunks.append((fn, seq, body))
    chunks.sort(key=lambda c: c[1])   # order by seq
    concat = b''.join(c[2] for c in chunks)
    return concat, chunks


def try_zlib(buf: bytes) -> List[Tuple[int, int, bytes]]:
    """Scan for 0x78 0x9c zlib streams. Return (offset, uncomp_size, data)."""
    results = []
    i = 0
    while i < len(buf) - 1:
        if buf[i] == 0x78 and buf[i+1] in (0x01, 0x5e, 0x9c, 0xda):
            try:
                d = zlib.decompressobj()
                out = d.decompress(buf[i:])
                results.append((i, len(out), out))
                i += (len(buf[i:]) - len(d.unused_data))
                continue
            except Exception:
                pass
        i += 1
    return results


def describe_zlib_out(data: bytes) -> str:
    """Describe decompressed zlib output (JSON? UTF-16? binary?)."""
    # Try JSON
    try:
        txt = data.decode('utf-8')
        obj = json.loads(txt)
        return f'JSON keys={sorted(obj.keys())[:8]}  sample={json.dumps(obj)[:200]}'
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
    # UTF-16LE?
    try:
        s = data.decode('utf-16-le', errors='strict')
        if sum(1 for c in s if c.isprintable()) / max(1, len(s)) > 0.6:
            return f'UTF-16LE text ({len(s)} chars): {s[:200]!r}'
    except UnicodeDecodeError:
        pass
    # Hex preview + printable ASCII density
    asc = sum(1 for b in data if 32 <= b < 127) / max(1, len(data))
    return f'binary ({len(data)}B, ASCII density={asc:.1%}): {data[:60].hex()}...'


def find_utf16_runs(buf: bytes, min_len: int = 8) -> List[Tuple[int, str]]:
    """Heuristic: consecutive bytes where every second byte is 0x00 (UTF-16LE ASCII)."""
    runs = []
    i = 0
    while i < len(buf) - 1:
        j = i
        while (j + 1 < len(buf) and buf[j+1] == 0x00
               and 32 <= buf[j] < 127):
            j += 2
        if j - i >= min_len * 2:
            runs.append((i, buf[i:j].decode('utf-16-le')))
            i = j
        else:
            i += 1
    return runs


def find_moza_tlv(buf: bytes) -> List[Tuple[int, int, int]]:
    """Look for MOZA-style TLV blocks: 0xFF [type] [size_le_4B] [payload]."""
    results = []
    i = 0
    while i < len(buf) - 6:
        if buf[i] == 0xff:
            t = buf[i+1]
            sz = int.from_bytes(buf[i+2:i+6], 'little')
            if 0 < sz < min(len(buf) - i - 6, 65536):
                results.append((i, t, sz))
                i += 6 + sz
                continue
        i += 1
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('capture')
    ap.add_argument('--session', type=lambda x: int(x, 0), required=True,
                    help='Session byte (e.g. 1, 2, 9, 0x0a)')
    ap.add_argument('--direction', choices=['host', 'device', 'both'], default='both')
    ap.add_argument('--save', help='Write reassembled bytes to this path')
    ap.add_argument('--limit', type=int, default=10, help='Max chunks to print')
    args = ap.parse_args()

    path = Path(args.capture)
    if not path.exists():
        print(f'error: {path} not found', file=sys.stderr)
        return 1

    print(f'[extract] {path}...')
    frames = extract(path)
    print(f'  total frames: {len(frames)}')

    dirs = ['host', 'device'] if args.direction == 'both' else [args.direction]
    for d in dirs:
        concat, chunks = reassemble(frames, args.session, d)
        print(f'\n── session 0x{args.session:02x} {d:6s}: '
              f'{len(chunks)} chunks, {len(concat)} bytes')
        if not chunks:
            continue
        if args.save and d == args.direction:
            with open(args.save, 'wb') as f:
                f.write(concat)
            print(f'  saved to {args.save}')
        # Print first few chunk previews
        print(f'  first chunks (seq, size, hex[:40]):')
        for fn, seq, body in chunks[:args.limit]:
            print(f'    f{fn} seq=0x{seq:04x} len={len(body)}: {body[:40].hex()}')
        if len(chunks) > args.limit:
            print(f'    … ({len(chunks) - args.limit} more)')

        # Envelope detection
        zs = try_zlib(concat)
        if zs:
            print(f'  zlib streams: {len(zs)}')
            for off, usz, out in zs[:5]:
                print(f'    @{off}: uncomp={usz}B — {describe_zlib_out(out)}')
            if len(zs) > 5:
                print(f'    … ({len(zs) - 5} more)')

        tlv = find_moza_tlv(concat)
        if tlv:
            print(f'  MOZA TLV-like blocks (0xFF type size_LE): {len(tlv)}')
            for off, t, sz in tlv[:5]:
                print(f'    @{off}: type=0x{t:02x} size={sz}')

        runs = find_utf16_runs(concat, min_len=6)
        if runs:
            print(f'  UTF-16LE ASCII runs ≥12B: {len(runs)}')
            for off, s in runs[:10]:
                print(f'    @{off}: {s!r}')
            if len(runs) > 10:
                print(f'    … ({len(runs) - 10} more)')

    return 0


if __name__ == '__main__':
    sys.exit(main())
