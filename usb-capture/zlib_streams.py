#!/usr/bin/env python3
"""Walk every session in a MOZA pcapng, reassemble per (session, direction),
strip per-chunk CRC trailers, and aggressively scan for zlib streams. Each
stream that decompresses cleanly is written to disk along with a manifest
recording its source coordinates.

Output (under <out_dir>/<capture_stem>/):
  - manifest.tsv  — (dir, session, offset, comp_len, uncomp_len, fn_at_offset,
                     env_kind, save_path, decoded_kind)
  - <dir>_sess0xXX_off<NN>_sz<NN>.{json,bin,utf16,b64}

Envelope kinds detected (just for annotation; we still rely on raw zlib magic
scanning, so unknown envelopes don't drop blobs):
  - "9b"   — `00 [comp+4 LE u32] [uncomp LE u32] zlib...` (session 0x09 / 0x0a)
  - "12b"  — `FF 01 00 [comp+4 LE u32] FF 00 [uncomp BE u24] zlib...` (session 0x03 tile-server)
  - "raw"  — bare zlib magic with no recognised envelope

Usage:
    python3 usb-capture/zlib_streams.py <out_dir> <capture.pcapng>...
"""
import argparse
import json
import struct
import subprocess
import sys
import zlib
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / 'sim'))
from wheel_sim import parse_frames, frame_payload  # noqa: E402

ZLIB_MAGIC_2ND = (0x01, 0x5e, 0x9c, 0xda)


def get_payloads(path):
    out = subprocess.check_output(
        ['tshark', '-r', str(path), '-Y', 'usbcom', '-T', 'fields',
         '-e', 'frame.number', '-e', 'usbcom.data.in_payload',
         '-e', 'usbcom.data.out_payload'],
        stderr=subprocess.DEVNULL, timeout=600).decode()
    rows = []
    for line in out.splitlines():
        parts = line.split('\t')
        if len(parts) < 2:
            continue
        try:
            fn = int(parts[0])
        except ValueError:
            continue
        in_hex = parts[1].replace(':', '') if len(parts) >= 2 else ''
        out_hex = parts[2].replace(':', '') if len(parts) >= 3 else ''
        if in_hex:
            rows.append((fn, 'device', bytes.fromhex(in_hex)))
        if out_hex:
            rows.append((fn, 'host', bytes.fromhex(out_hex)))
    return rows


def collect_session_chunks(rows):
    """Return {(session, dir): [(fn, ttype, seq, body)]} for type=0x01 only."""
    by_key = defaultdict(list)
    for fn, d, raw in rows:
        for fr in parse_frames(raw):
            pl = frame_payload(fr)
            if len(pl) < 6 or pl[0] != 0x7c or pl[1] != 0x00:
                continue
            sess = pl[2]
            ttype = pl[3]
            seq = pl[4] | (pl[5] << 8)
            body = bytes(pl[6:])
            if ttype != 0x01:
                continue
            by_key[(sess, d)].append((fn, seq, body))
    return by_key


def split_bursts(chunks, fn_gap=5000):
    """Split (fn, seq, body) chunks into bursts. New burst when:
      - frame-number gap > fn_gap (idle period), OR
      - seq decreases (counter reset = new session lifetime)
    Chunks are processed in fn (capture-time) order."""
    chunks = sorted(chunks, key=lambda c: c[0])
    bursts = []
    cur = []
    last_fn = None
    last_seq = None
    for fn, seq, body in chunks:
        if cur and (fn - last_fn > fn_gap or seq < last_seq):
            bursts.append(cur)
            cur = []
        cur.append((fn, seq, body))
        last_fn = fn
        last_seq = seq
    if cur:
        bursts.append(cur)
    return bursts


def reassemble(chunks, strip_crc=True):
    """Single burst: dedupe by seq (prefer LARGER chunk over keepalive), strip
    4B CRC trailer, sort by seq, concat. Returns (data, [(seq, offset, fn)])."""
    by_seq = {}
    for fn, seq, body in chunks:
        prev = by_seq.get(seq)
        if prev is None or len(body) > len(prev[1]):
            by_seq[seq] = (fn, body)
    seqs = sorted(by_seq.keys())
    data = bytearray()
    seq_offsets = []
    for s in seqs:
        fn, body = by_seq[s]
        net = body[:-4] if strip_crc and len(body) > 4 else body
        seq_offsets.append((s, len(data), fn))
        data.extend(net)
    return bytes(data), seq_offsets


def fn_at(seq_offsets, off):
    last = None
    for s, o, fn in seq_offsets:
        if o <= off:
            last = fn
        else:
            break
    return last


def detect_envelope(data, zlib_off):
    """Look at bytes immediately preceding the zlib magic to classify the
    envelope. Return (kind, env_start, comp_len_field, uncomp_len_field).
    All three values may be None if envelope unrecognised."""
    # 9-byte envelope: 9 bytes back from magic
    if zlib_off >= 9:
        e = data[zlib_off - 9:zlib_off]
        if e[0] == 0x00:
            comp = struct.unpack('<I', e[1:5])[0]
            uncomp = struct.unpack('<I', e[5:9])[0]
            if 0 < comp < (1 << 22) and 0 < uncomp < (1 << 22):
                return ('9b', zlib_off - 9, comp, uncomp)
    # 12-byte envelope: 12 bytes back
    if zlib_off >= 12:
        e = data[zlib_off - 12:zlib_off]
        if e[0] == 0xff and e[1] == 0x01 and e[2] == 0x00 and e[7] == 0xff and e[8] == 0x00:
            comp = struct.unpack('<I', e[3:7])[0]
            uncomp = (e[9] << 16) | (e[10] << 8) | e[11]
            if 0 < comp < (1 << 22) and 0 < uncomp < (1 << 22):
                return ('12b', zlib_off - 12, comp, uncomp)
    return ('raw', zlib_off, None, None)


def describe(decoded):
    """Best-effort describe decoded blob; returns (kind, preview)."""
    try:
        s = decoded.decode('utf-8')
        try:
            obj = json.loads(s)
            return 'json', obj
        except json.JSONDecodeError:
            if sum(1 for c in s if c.isprintable() or c.isspace()) / max(1, len(s)) > 0.95:
                return 'utf8', s
    except UnicodeDecodeError:
        pass
    try:
        s = decoded.decode('utf-16-le')
        if sum(1 for c in s if c.isprintable() or c.isspace()) / max(1, len(s)) > 0.9:
            return 'utf16', s
    except UnicodeDecodeError:
        pass
    return 'binary', decoded


def scan(data):
    """Find every zlib stream in `data`. Returns list of dicts."""
    found = []
    i = 0
    while i + 2 <= len(data):
        if data[i] == 0x78 and data[i+1] in ZLIB_MAGIC_2ND:
            try:
                d = zlib.decompressobj()
                out = d.decompress(data[i:])
                consumed = len(data[i:]) - len(d.unused_data)
                env_kind, env_start, env_comp, env_uncomp = detect_envelope(data, i)
                found.append({
                    'zlib_offset': i,
                    'consumed': consumed,
                    'uncomp_size': len(out),
                    'decoded': out,
                    'env_kind': env_kind,
                    'env_start': env_start,
                    'env_comp_field': env_comp,
                    'env_uncomp_field': env_uncomp,
                })
                i += max(1, consumed)
                continue
            except zlib.error:
                pass
        i += 1
    return found


def dump_blob(out_root, cap_stem, dir_, sess, blob_idx, blob, seq_offsets):
    out_dir = out_root / cap_stem
    out_dir.mkdir(parents=True, exist_ok=True)
    z_off = blob['zlib_offset']
    fn = fn_at(seq_offsets, z_off)
    base = f'{dir_}_sess0x{sess:02x}_b{blob_idx:02d}_off{z_off:06x}_sz{blob["uncomp_size"]}'
    decoded = blob['decoded']
    kind, body = describe(decoded)
    path = None
    if kind == 'json':
        path = out_dir / f'{base}.json'
        path.write_text(json.dumps(body, indent=2, sort_keys=True))
    elif kind == 'utf8':
        path = out_dir / f'{base}.txt'
        path.write_text(body)
    elif kind == 'utf16':
        path = out_dir / f'{base}.utf16.txt'
        path.write_text(body)
    else:
        path = out_dir / f'{base}.bin'
        path.write_bytes(decoded)
    return {
        'dir': dir_,
        'session': f'0x{sess:02x}',
        'offset': f'0x{z_off:06x}',
        'comp_len': blob['consumed'],
        'uncomp_len': blob['uncomp_size'],
        'fn_at_offset': fn,
        'env_kind': blob['env_kind'],
        'env_comp_field': blob['env_comp_field'],
        'env_uncomp_field': blob['env_uncomp_field'],
        'decoded_kind': kind,
        'save_path': path.name,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('out_dir')
    ap.add_argument('captures', nargs='+')
    args = ap.parse_args()
    out_root = Path(args.out_dir)
    out_root.mkdir(parents=True, exist_ok=True)

    for cap_path in args.captures:
        cap = Path(cap_path)
        if not cap.exists():
            print(f'!! missing: {cap}', file=sys.stderr)
            continue
        print(f'-- {cap.name} --')
        rows = get_payloads(cap)
        chunks = collect_session_chunks(rows)
        manifest_rows = ['\t'.join([
            'dir', 'session', 'offset', 'comp_len', 'uncomp_len',
            'fn_at_offset', 'burst', 'env_kind',
            'env_comp_field', 'env_uncomp_field',
            'decoded_kind', 'save_path',
        ])]
        total_blobs = 0
        for (sess, d), evs in sorted(chunks.items()):
            bursts = split_bursts(evs)
            for bi, burst in enumerate(bursts):
                data, seq_offsets = reassemble(burst)
                blobs = scan(data)
                if not blobs:
                    continue
                for idx, b in enumerate(blobs):
                    row = dump_blob(out_root, cap.stem, d, sess,
                                    idx + 100 * bi, b, seq_offsets)
                    manifest_rows.append('\t'.join([
                        row['dir'], row['session'], row['offset'],
                        str(row['comp_len']), str(row['uncomp_len']),
                        str(row['fn_at_offset']), str(bi), row['env_kind'],
                        str(row['env_comp_field']), str(row['env_uncomp_field']),
                        row['decoded_kind'], row['save_path'],
                    ]))
                    total_blobs += 1
                print(f'  sess 0x{sess:02x} {d} burst{bi} '
                      f'(fn={burst[0][0]}-{burst[-1][0]}): {len(blobs)} blob(s)')
        manifest = out_root / cap.stem / 'manifest.tsv'
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text('\n'.join(manifest_rows) + '\n')
        print(f'  total blobs: {total_blobs} → {manifest}')

    return 0


if __name__ == '__main__':
    sys.exit(main())
