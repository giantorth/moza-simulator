#!/usr/bin/env python3
"""Strip 0xff TLV headers from reassembled session stream and decompress
embedded zlib chunks. Session 0x01 host→wheel traffic carries multiple
zlib streams fragmented across inner TLV boundaries; this tool walks the
TLV framing, concatenates chunks of the same type/stream, and decompresses.

Usage:
    python3 usb-capture/strip_tlv_decode.py <sess01_host.bin>

Each 0xff block has layout `ff [type:1B] [size:3B LE + 1B pad? OR 4B LE] [payload]`.
"""

import argparse
import json
import sys
import zlib
from collections import defaultdict
from pathlib import Path


def walk_tlvs(buf: bytes, verbose: bool = False):
    """Yield (offset, type, size, payload) tuples by walking 0xff-prefixed
    TLV blocks. Treats the 4 bytes after the type as LE u32 size."""
    i = 0
    out = []
    while i < len(buf):
        if buf[i] != 0xff:
            # Skip one byte to keep going (shouldn't happen if stream aligned)
            if verbose:
                print(f'  [align] non-ff at {i}: 0x{buf[i]:02x}, skipping 1')
            i += 1
            continue
        if i + 6 > len(buf):
            break
        t = buf[i+1]
        sz = int.from_bytes(buf[i+2:i+6], 'little')
        if sz == 0 or sz > len(buf) - i - 6:
            # Try 3-byte size
            sz3 = int.from_bytes(buf[i+2:i+5], 'little')
            if 0 < sz3 < len(buf) - i - 5:
                sz = sz3
                payload = buf[i+5:i+5+sz]
                out.append((i, t, sz, payload))
                i += 5 + sz
                continue
            if verbose:
                print(f'  [tlv?] @{i}: ff {t:02x} sz={sz} — size invalid')
            i += 1
            continue
        payload = buf[i+6:i+6+sz]
        out.append((i, t, sz, payload))
        i += 6 + sz
    return out


def try_decompress_concat(chunks, label=''):
    """Concat all chunks and try zlib decompress."""
    concat = b''.join(chunks)
    try:
        d = zlib.decompressobj()
        out = d.decompress(concat)
        rest = concat[len(concat) - len(d.unused_data):]
        return out, rest
    except Exception as e:
        # Try starting at each 78 xx magic in concat
        for off in range(len(concat)):
            if concat[off] == 0x78 and concat[off+1] in (0x01, 0x5e, 0x9c, 0xda):
                try:
                    out = zlib.decompress(concat[off:])
                    return out, concat[off:]
                except Exception:
                    pass
        return None, str(e)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('input')
    ap.add_argument('--verbose', action='store_true')
    args = ap.parse_args()

    buf = Path(args.input).read_bytes()
    print(f'[input] {args.input}: {len(buf)} bytes')

    tlvs = walk_tlvs(buf, verbose=args.verbose)
    print(f'[tlvs] {len(tlvs)} TLV blocks detected\n')

    # Group by type
    by_type = defaultdict(list)
    for off, t, sz, payload in tlvs:
        by_type[t].append((off, sz, payload))

    print('=== TLV type summary ===')
    for t, entries in sorted(by_type.items()):
        total_sz = sum(sz for _, sz, _ in entries)
        offs = [off for off, _, _ in entries[:4]]
        print(f'  type=0x{t:02x}: {len(entries)} blocks, {total_sz} bytes total, first offsets={offs}')

    # Try decompressing each type's concatenation
    print('\n=== Decompression attempts ===')
    for t, entries in sorted(by_type.items()):
        chunks = [p for _, _, p in entries]
        total_sz = sum(len(c) for c in chunks)
        if total_sz < 16:
            continue
        result, rest = try_decompress_concat(chunks, label=f'type=0x{t:02x}')
        if result is None:
            print(f'  type=0x{t:02x} ({total_sz}B): decomp FAIL ({rest[:80]})')
            continue
        # Describe decomp output
        try:
            txt = result.decode('utf-8')
            try:
                obj = json.loads(txt)
                keys = sorted(obj.keys())[:8]
                print(f'  type=0x{t:02x} ({total_sz}B → {len(result)}B JSON): keys={keys}')
                preview = json.dumps(obj, separators=(',', ':'))[:300]
                print(f'     {preview}')
                continue
            except json.JSONDecodeError:
                printable = sum(1 for c in txt if c.isprintable() or c in '\n\r\t')
                if printable / len(txt) > 0.8:
                    print(f'  type=0x{t:02x} ({total_sz}B → {len(result)}B UTF-8 text): {txt[:200]!r}')
                    continue
        except UnicodeDecodeError:
            pass
        try:
            s16 = result.decode('utf-16-le')
            printable = sum(1 for c in s16 if c.isprintable())
            if printable / max(1, len(s16)) > 0.5:
                print(f'  type=0x{t:02x} ({total_sz}B → {len(result)}B UTF-16LE): {s16[:200]!r}')
                continue
        except UnicodeDecodeError:
            pass
        # Binary
        asc = sum(1 for b in result if 32<=b<127)
        print(f'  type=0x{t:02x} ({total_sz}B → {len(result)}B binary, asc={asc/len(result):.1%}): '
              f'{result[:48].hex()}...')


if __name__ == '__main__':
    sys.exit(main() or 0)
