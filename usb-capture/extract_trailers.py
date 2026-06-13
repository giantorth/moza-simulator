#!/usr/bin/env python3
"""Scan pcapng captures for type=0x01/0x11 wheel->host file-transfer replies.
Extract (md5, bytes_written, total_size, trailer) triples to feed trailer
algorithm reversing.

Reply body layout (from moza-protocol.md §2026-04-24):
    [type:1] [size_LE:u32] [00 00 00]                    8B header
    [0x8c 0x00] [UTF-16LE path] [00 00]                  LOCAL path TLV
    [0x70 0x00] [UTF-16LE path] [00 00]                  REMOTE path TLV
    10                                                    flag byte
    [md5:16]
    [bytes_written:u32 BE]
    [total_size:u32 BE]
    ff ff ff ff                                          sentinel
    [trailer:4]                                          unknown
"""
import argparse
import subprocess
import sys
from pathlib import Path

_root = Path(__file__).parent.parent
sys.path.insert(0, str(_root / 'sim'))
from wheel_sim import frame_payload  # noqa: E402


def extract_frames(path: Path):
    out = subprocess.check_output(
        ['tshark', '-r', str(path), '-Y', 'usbcom', '-T', 'fields',
         '-e', 'frame.number', '-e', 'usbcom.data.in_payload',
         '-e', 'usbcom.data.out_payload'],
        stderr=subprocess.DEVNULL, timeout=600).decode()
    frames = []
    for line in out.splitlines():
        parts = line.split('\t')
        if len(parts) < 2:
            continue
        try:
            fn = int(parts[0])
        except ValueError:
            continue
        for hx, dir_ in ((parts[1].replace(':', '') if len(parts) >= 2 else '', 'device'),
                         (parts[2].replace(':', '') if len(parts) >= 3 else '', 'host')):
            if not hx:
                continue
            try:
                raw = bytes.fromhex(hx)
            except ValueError:
                continue
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


def get_chunks(frames, session, direction):
    """Ordered list of (frame_no, seq, payload_no_crc) in capture order.
    Don't sort by seq because counters reset across upload transactions."""
    chunks = []
    for fn, d, f in frames:
        if d != direction:
            continue
        pl = frame_payload(f)
        if len(pl) < 7:
            continue
        if pl[0] != 0x7c or pl[1] != 0x00:
            continue
        if pl[2] != session:
            continue
        if pl[3] != 0x01:
            continue
        seq = pl[4] | (pl[5] << 8)
        body = bytes(pl[6:])
        # NOTE: earlier doc claim of per-chunk 4B CRC32 trailer does not match
        # 2025-11 captures — real wheel sends chunks as raw payload fragments,
        # frame-level 7e checksum is the only integrity byte. Do not strip.
        chunks.append((fn, seq, body))
    return chunks


def extract_replies_from_chunks(chunks):
    """Walk chunks in order. When a chunk begins with 0x01/0x11 followed by a
    plausible LE size field and 3 zero pad bytes, treat as message start; collect
    until message length reached, parse, continue.
    Returns list of parsed dicts."""
    replies = []
    i = 0
    n = len(chunks)
    while i < n:
        body = chunks[i][2]
        if not body:
            i += 1
            continue
        if body[0] in (0x01, 0x11) and len(body) >= 8:
            size = int.from_bytes(body[1:5], 'little')
            pad = body[5:8]
            if 0 < size < 4096 and pad == b'\x00\x00\x00':
                total = 8 + size
                acc = body[:]
                j = i + 1
                while len(acc) < total and j < n:
                    acc += chunks[j][2]
                    j += 1
                if len(acc) >= total:
                    parsed = parse_reply(acc, 0)
                    if parsed and parsed['sentinel'] == 'ffffffff':
                        replies.append(parsed)
                    i = j
                    continue
        i += 1
    return replies


def parse_reply(body: bytes, offset: int):
    """Parse a type=0x01 or 0x11 reply starting at `offset` in body.
    Returns dict or None if malformed."""
    if offset + 8 > len(body):
        return None
    t = body[offset]
    if t not in (0x01, 0x11):
        return None
    size = int.from_bytes(body[offset+1:offset+5], 'little')
    # size is body length excluding 8B header
    total = 8 + size
    if offset + total > len(body):
        return None
    reply = body[offset:offset + total]
    # Walk TLVs
    p = 8
    paths = []
    for _ in range(2):
        if p + 2 > len(reply):
            return None
        marker = reply[p:p+2]
        p += 2
        # find UTF-16LE path terminated by 00 00 aligned
        end = p
        while end + 1 < len(reply):
            if reply[end] == 0x00 and reply[end+1] == 0x00:
                break
            end += 2
        if end + 1 >= len(reply):
            return None
        try:
            path_str = reply[p:end].decode('utf-16-le')
        except UnicodeDecodeError:
            path_str = reply[p:end].hex()
        paths.append((marker.hex(), path_str))
        p = end + 2
    # flag byte
    if p >= len(reply):
        return None
    flag = reply[p]
    p += 1
    if p + 16 > len(reply):
        return None
    md5 = reply[p:p+16]
    p += 16
    if p + 8 > len(reply):
        return None
    bytes_written = int.from_bytes(reply[p:p+4], 'big')
    total_size = int.from_bytes(reply[p+4:p+8], 'big')
    p += 8
    if p + 8 > len(reply):
        return None
    sentinel = reply[p:p+4]
    trailer = reply[p+4:p+8]
    return {
        'type': t,
        'reply_bytes': reply,
        'body_size_field': size,
        'paths': paths,
        'flag': flag,
        'md5': md5.hex(),
        'bytes_written': bytes_written,
        'total_size': total_size,
        'sentinel': sentinel.hex(),
        'trailer': trailer.hex(),
        'offset': offset,
    }


def scan_replies(buf: bytes):
    """Scan reassembled stream for type=0x01/0x11 replies."""
    found = []
    i = 0
    while i < len(buf):
        if buf[i] in (0x01, 0x11):
            parsed = parse_reply(buf, i)
            if parsed and parsed['sentinel'] == 'ffffffff':
                # Only report if sentinel matches — real reply, not noise
                found.append(parsed)
                i = parsed['offset'] + len(parsed['reply_bytes'])
                continue
        i += 1
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('captures', nargs='+', help='pcapng files')
    ap.add_argument('--sessions', default='4,5,6',
                    help='comma-separated session bytes to scan (default 4,5,6)')
    args = ap.parse_args()

    sessions = [int(s, 0) for s in args.sessions.split(',')]

    all_trailers = []
    for cap in args.captures:
        path = Path(cap)
        if not path.exists():
            print(f'skip {cap}: missing', file=sys.stderr)
            continue
        print(f'\n== {path.name} ==')
        frames = extract_frames(path)
        for sess in sessions:
            chunks = get_chunks(frames, sess, 'device')
            if not chunks:
                continue
            replies = extract_replies_from_chunks(chunks)
            total = sum(len(c[2]) for c in chunks)
            if not replies:
                print(f'  session 0x{sess:02x}: {len(chunks)} chunks, {total}B, no replies')
                continue
            print(f'  session 0x{sess:02x}: {len(chunks)} chunks, {total}B, {len(replies)} reply(ies)')
            for r in replies:
                tag = 'ready ' if r['type'] == 0x01 else 'done  '
                print(f'    {tag} md5={r["md5"]} '
                      f'bw={r["bytes_written"]:>8} sz={r["total_size"]:>8} '
                      f'trailer={r["trailer"]}')
                print(f'      paths: {r["paths"]}')
                all_trailers.append({
                    'capture': path.name,
                    'session': sess,
                    'type': r['type'],
                    'md5': r['md5'],
                    'bytes_written': r['bytes_written'],
                    'total_size': r['total_size'],
                    'trailer': r['trailer'],
                    'reply_hex': r['reply_bytes'].hex(),
                })

    print(f'\nTotal trailers: {len(all_trailers)}')
    uniq = {(t['md5'], t['total_size'], t['type'], t['trailer'])
            for t in all_trailers}
    print(f'Unique (md5, size, type, trailer) tuples: {len(uniq)}')
    for m, s, t, tr in sorted(uniq):
        ttag = '0x01' if t == 0x01 else '0x11'
        print(f'  {ttag}  md5={m}  size={s:>8}  trailer={tr}')


if __name__ == '__main__':
    sys.exit(main() or 0)
