#!/usr/bin/env python3
"""Parse reassembled session streams into semantic messages. For each session
direction (host/wheel), strip per-chunk 3-byte CRC trailers, concatenate, then
walk the continuous byte stream identifying:

- `07 01 ...` : device description TLV (identity envelope)
- `ff [type] [size_LE4] [payload]` : MOZA message envelope (field 0 marker)
- `03 04 00 00 00 [n] 00 00 00` : field-count marker (field 0 = n)
- `04 [size_LE4] [idx] [url]` : channel entry (catalog)
- `06 04 00 00 00 [count_LE4]` : total-channel-count marker
- `00 [comp_LE4] [uncomp_LE4] [zlib]` : zlib-compressed blob envelope
- `01 64 00 00 00` / `05 00` / `06 00` : small per-port TLV markers

Writes one structured report per capture per session+direction.

Usage:
    python3 usb-capture/message_content_decoder.py <capture.pcapng> [--session N]
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
from wheel_sim import frame_payload  # noqa: E402


def extract_session_stream(path: Path, session: int, direction: str) -> bytes:
    """Reassemble a session's data chunks into one byte stream (3B CRC stripped)."""
    field = 'usbcom.data.out_payload' if direction == 'host' else 'usbcom.data.in_payload'
    out = subprocess.check_output(
        ['tshark', '-r', str(path), '-Y', 'usbcom', '-T', 'fields',
         '-e', 'frame.number', '-e', field],
        stderr=subprocess.DEVNULL, timeout=600).decode()
    chunks: List[Tuple[int, bytes]] = []
    for line in out.splitlines():
        parts = line.split('\t')
        if len(parts) < 2 or not parts[1]:
            continue
        raw = bytes.fromhex(parts[1].replace(':', ''))
        i = 0
        while i < len(raw) - 3:
            if raw[i] == 0x7e:
                ln = raw[i+1]
                if 0 < ln <= 200 and i + 5 + ln <= len(raw):
                    f = raw[i:i + 5 + ln]
                    pl = bytes(frame_payload(f))
                    i += 5 + ln
                    if len(pl) >= 7 and pl[0] == 0x7c and pl[1] == 0x00:
                        if pl[2] != session or pl[3] != 0x01:
                            continue
                        seq = pl[4] | (pl[5] << 8)
                        body = pl[6:]
                        if len(body) >= 3:
                            chunks.append((seq, body[:-3]))  # strip 3B CRC
                    continue
                i += 1
            else:
                i += 1
    chunks.sort(key=lambda c: c[0])
    return b''.join(c[1] for c in chunks)


def parse_stream(stream: bytes) -> List[dict]:
    """Walk a reassembled session stream, emit semantic messages."""
    results = []
    i = 0
    while i < len(stream):
        b = stream[i]
        # Device description TLV: `07 01 ...`
        if b == 0x07 and i + 1 < len(stream) and stream[i+1] == 0x01:
            # Try to determine desc length
            end = i + 30  # soft cap
            results.append({
                'type': 'device_desc',
                'offset': i,
                'bytes': stream[i:min(end, len(stream))].hex(),
                'ascii': ''.join(chr(c) if 32<=c<127 else '.' for c in stream[i:min(end, len(stream))]),
            })
            i = end
            continue
        # Multi-chunk preamble `ff 00 00 00`
        if b == 0xff and i + 3 < len(stream) and stream[i+1:i+4] == b'\x00\x00\x00':
            results.append({'type': 'session_start_marker', 'offset': i, 'bytes': 'ff000000'})
            i += 4
            continue
        # Field-0 marker `03 04 00 00 00 [n] 00 00 00`
        if b == 0x03 and i + 8 < len(stream) and stream[i+1:i+5] == b'\x04\x00\x00\x00':
            field_value = stream[i+5]
            results.append({
                'type': 'field0_marker',
                'offset': i,
                'field0_value': field_value,
                'bytes': stream[i:i+9].hex(),
            })
            i += 9
            continue
        # Total count `06 04 00 00 00 [count_LE4]`
        if b == 0x06 and i + 8 < len(stream) and stream[i+1:i+5] == b'\x04\x00\x00\x00':
            count = int.from_bytes(stream[i+5:i+9], 'little')
            results.append({'type': 'channel_count', 'offset': i, 'count': count})
            i += 9
            continue
        # Channel entry `04 [size_LE4] [idx] [url]`
        if b == 0x04 and i + 5 < len(stream):
            size = int.from_bytes(stream[i+1:i+5], 'little')
            if 2 <= size <= 200 and i + 5 + size <= len(stream):
                idx = stream[i+5]
                url_bytes = stream[i+6:i+5+size]
                try:
                    url = url_bytes.decode('ascii')
                    if url.startswith('v') or '/' in url:
                        results.append({
                            'type': 'channel_entry',
                            'offset': i, 'idx': idx, 'url': url,
                        })
                        i += 5 + size
                        continue
                except UnicodeDecodeError:
                    pass
        # Small TLV `01 64 00 00 00` (5B)
        if b == 0x01 and i + 4 < len(stream) and stream[i+1:i+5] == b'\x64\x00\x00\x00':
            results.append({'type': 'tlv_01_64', 'offset': i, 'bytes': '0164000000'})
            i += 5
            continue
        if b == 0x05 and i + 1 < len(stream) and stream[i+1] == 0x00:
            results.append({'type': 'tlv_05_00', 'offset': i})
            i += 2
            continue
        if b == 0x06 and i + 1 < len(stream) and stream[i+1] == 0x00:
            results.append({'type': 'tlv_06_00', 'offset': i})
            i += 2
            continue
        # Zlib stream detection `0x78 <flag>`
        if b == 0x78 and i + 1 < len(stream) and stream[i+1] in (0x01, 0x5e, 0x9c, 0xda):
            try:
                d = zlib.decompressobj()
                out_bytes = d.decompress(stream[i:])
                if len(out_bytes) > 20:
                    consumed = len(stream) - i - len(d.unused_data)
                    desc = describe_decompressed(out_bytes)
                    results.append({
                        'type': 'zlib_stream',
                        'offset': i,
                        'compressed_len': consumed,
                        'uncompressed_len': len(out_bytes),
                        'decoded': desc,
                    })
                    i += consumed
                    continue
            except Exception:
                pass
        # ff-prefix envelope: `ff [type] [size LE4] [payload]`
        if b == 0xff and i + 5 < len(stream):
            t = stream[i+1]
            sz = int.from_bytes(stream[i+2:i+6], 'little')
            if 0 < sz < 32768 and i + 6 + sz <= len(stream):
                payload = stream[i+6:i+6+sz]
                # Try zlib
                desc = f'{sz}B binary'
                if len(payload) >= 2 and payload[0] == 0x78 and payload[1] in (0x01, 0x5e, 0x9c, 0xda):
                    try:
                        uncomp = zlib.decompress(payload)
                        desc = f'{sz}B → {len(uncomp)}B zlib ({describe_decompressed(uncomp)[:80]})'
                    except Exception:
                        pass
                results.append({
                    'type': f'ff_envelope_type_{t:02x}',
                    'offset': i,
                    'size': sz,
                    'summary': desc,
                })
                i += 6 + sz
                continue
        # Fallback: unknown byte
        results.append({'type': 'unknown_byte', 'offset': i, 'value': f'{b:02x}'})
        i += 1
    return results


def describe_decompressed(data: bytes) -> str:
    """Classify decompressed output — JSON, UTF-16LE text, or binary."""
    try:
        s = data.decode('utf-8')
        try:
            obj = json.loads(s)
            return f'JSON keys={sorted(obj.keys())[:6]}'
        except Exception:
            printable = sum(1 for c in s if c.isprintable() or c in '\n\r\t')
            if printable / max(1, len(s)) > 0.8:
                return f'UTF-8 text: {s[:60]!r}'
    except UnicodeDecodeError:
        pass
    try:
        s16 = data.decode('utf-16-le')
        printable = sum(1 for c in s16 if c.isprintable() or c in '\0\n\r\t')
        if printable / max(1, len(s16)) > 0.5:
            # Extract first few non-null substrings
            parts = [p for p in s16.split('\0') if len(p) >= 3 and p.isprintable()]
            return f'UTF-16LE, samples: {parts[:5]}'
    except UnicodeDecodeError:
        pass
    ascii_density = sum(1 for b in data if 32 <= b < 127) / max(1, len(data))
    return f'binary ({len(data)}B, ASCII density {ascii_density:.0%})'


def summarize(results: List[dict]) -> str:
    """Produce a short summary string."""
    from collections import Counter
    types = Counter(r['type'] for r in results)
    return ', '.join(f'{t}={n}' for t, n in types.most_common())


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('capture')
    ap.add_argument('--session', type=lambda x: int(x, 0), default=None,
                    help='Decode one specific session')
    ap.add_argument('--max-messages', type=int, default=40,
                    help='Cap detailed entry printing per stream')
    args = ap.parse_args()

    path = Path(args.capture)
    sessions = [args.session] if args.session is not None else [1, 2, 3, 4, 9, 0xa]
    print(f'[capture] {path}')

    for sess in sessions:
        for dir_ in ('host', 'device'):
            stream = extract_session_stream(path, sess, dir_)
            if not stream:
                continue
            results = parse_stream(stream)
            print(f'\n── session 0x{sess:02x} {dir_} ({len(stream)}B, {len(results)} msgs) ──')
            print(f'   summary: {summarize(results)}')
            for r in results[:args.max_messages]:
                t = r['type']
                off = r['offset']
                extra = ''
                if t == 'channel_entry':
                    extra = f' idx={r["idx"]} url={r["url"]!r}'
                elif t == 'channel_count':
                    extra = f' count={r["count"]}'
                elif t == 'field0_marker':
                    extra = f' field0={r["field0_value"]}'
                elif t.startswith('ff_envelope'):
                    extra = f' size={r["size"]} ({r["summary"]})'
                elif t == 'zlib_stream':
                    extra = f' comp={r["compressed_len"]} uncomp={r["uncompressed_len"]} ({r["decoded"]})'
                elif t == 'device_desc':
                    extra = f' hex={r["bytes"]}'
                elif t == 'unknown_byte':
                    extra = f' value=0x{r["value"]}'
                print(f'  @{off}: {t}{extra}')
            if len(results) > args.max_messages:
                print(f'  … ({len(results) - args.max_messages} more messages)')

    return 0


if __name__ == '__main__':
    sys.exit(main() or 0)
