#!/usr/bin/env python3
"""Extract ALL file-transfer message trailers from a capture.
Strips 3B truncated CRC from each chunk then parses type=0x01/0x02/0x03/0x11
messages, grabbing trailing 4B past the ff*4 sentinel.
"""
import argparse
import subprocess
import sys
import zlib
from pathlib import Path

_root = Path(__file__).parent.parent
sys.path.insert(0, str(_root / 'sim'))
from wheel_sim import frame_payload  # noqa: E402


def extract_frames(path):
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
        for hx, dir_ in ((parts[1].replace(':', '') if len(parts) >= 2 else '', 'device'),
                         (parts[2].replace(':', '') if len(parts) >= 3 else '', 'host')):
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


def strip_chunk_crc(body):
    """Strip 3B truncated CRC32-LE trailer from chunk. Falls back to 4B
    strip when 3B CRC doesn't match (pathological capture corruption)."""
    if len(body) < 4:
        return body, False
    # Try 3B truncated CRC: CRC32(body[:-3]) & 0xFFFFFF == last 3B LE
    payload = body[:-3]
    crc = zlib.crc32(payload).to_bytes(4, 'little')
    if crc[:3] == body[-3:]:
        return payload, True
    return body, False


def get_chunks(frames, session, direction):
    chunks = []
    for fn, d, f in frames:
        if d != direction: continue
        pl = frame_payload(f)
        if len(pl) < 7: continue
        if pl[0] != 0x7c or pl[1] != 0x00: continue
        if pl[2] != session: continue
        if pl[3] != 0x01: continue
        seq = pl[4] | (pl[5]<<8)
        body = bytes(pl[6:])
        stripped, crc_ok = strip_chunk_crc(body)
        chunks.append((fn, seq, stripped, crc_ok, len(body)))
    return chunks


def parse_message(buf, off):
    """Parse a message at offset `off` in reassembled `buf`.
    Returns dict or None."""
    if off + 8 > len(buf): return None
    t = buf[off]
    if t not in (0x01, 0x02, 0x03, 0x08, 0x0a, 0x11): return None
    size = int.from_bytes(buf[off+1:off+5], 'little')
    pad = buf[off+5:off+8]
    if pad != b'\x00\x00\x00': return None
    if size < 10 or size > 4096: return None
    if off + 8 + size > len(buf): return None
    msg = buf[off:off+8+size]
    # Look for ffffffff sentinel followed by 4B trailer at end
    # For types 0x01/0x11/0x02, the structure ends with sentinel+trailer
    # For type 0x03 (content) and 0x08 (probe) structure differs
    end = msg[-8:]
    sentinel = end[:4]
    trailer = end[4:]
    # Extract md5 if present — look for preceding 0x10 flag + 16B md5
    md5 = None
    bw = None
    sz = None
    # md5 is 24 bytes before end: [md5:16][bw:4][sz:4][ff*4][trailer:4]
    if len(msg) >= 32:
        md5_start = len(msg) - 8 - 4 - 4 - 16
        md5 = msg[md5_start:md5_start+16]
        bw = int.from_bytes(msg[md5_start+16:md5_start+20], 'big')
        sz = int.from_bytes(msg[md5_start+20:md5_start+24], 'big')
    return {
        'type': t, 'size': size, 'msg_len': len(msg),
        'sentinel': sentinel, 'trailer': trailer,
        'md5': md5, 'bytes_written': bw, 'total_size': sz,
        'msg_bytes': msg,
    }


def scan_messages(chunks):
    """Reassemble by accumulating chunks per message start."""
    results = []
    buf = bytearray()
    pending_start = None
    for fn, seq, body, crc_ok, raw_len in chunks:
        buf.extend(body)
        # Try to parse from any position
        while True:
            if len(buf) < 8: break
            # Look for plausible message header at buf[0]
            t = buf[0]
            if t in (0x01, 0x02, 0x03, 0x08, 0x0a, 0x11):
                size = int.from_bytes(bytes(buf[1:5]), 'little')
                pad = bytes(buf[5:8])
                if pad == b'\x00\x00\x00' and 10 < size < 4096 and len(buf) >= 8 + size:
                    parsed = parse_message(bytes(buf), 0)
                    if parsed:
                        results.append(parsed)
                        del buf[:8 + size]
                        continue
            # Not a message start; drop leading byte
            del buf[0]
            if len(buf) < 8: break
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('captures', nargs='+')
    ap.add_argument('--sessions', default='1,4,5,6',
                    help='comma-separated session bytes')
    args = ap.parse_args()
    sessions = [int(s, 0) for s in args.sessions.split(',')]

    for cap in args.captures:
        path = Path(cap)
        if not path.exists():
            print(f'skip {cap}: missing', file=sys.stderr); continue
        print(f'\n== {path.name} ==')
        frames = extract_frames(path)
        for sess in sessions:
            for dir_ in ('host', 'device'):
                chunks = get_chunks(frames, sess, dir_)
                if not chunks: continue
                msgs = scan_messages(chunks)
                if not msgs: continue
                ok = sum(1 for c in chunks if c[3])
                print(f'  sess 0x{sess:02x} {dir_:6s}: chunks={len(chunks)} crc_ok={ok}/{len(chunks)} msgs={len(msgs)}')
                for m in msgs:
                    ttag = {0x01:'ready', 0x02:'meta ', 0x03:'cont ',
                            0x08:'probe', 0x0a:'list ', 0x11:'done '}.get(m['type'], hex(m['type']))
                    sentinel_tag = 'OK' if m['sentinel'] == b'\xff\xff\xff\xff' else m['sentinel'].hex()
                    md5_hex = m['md5'].hex() if m['md5'] else 'N/A'
                    print(f'    {ttag} size={m["size"]:>5} md5={md5_hex} '
                          f'bw={m["bytes_written"]:>6} sz={m["total_size"]:>6} '
                          f'sent={sentinel_tag} trail={m["trailer"].hex()}')


if __name__ == '__main__':
    sys.exit(main() or 0)
