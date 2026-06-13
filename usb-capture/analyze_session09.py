#!/usr/bin/env python3
"""Walk a pcapng capture and extract every session 0x09 device→host configJson
state blob, then decompress and dump as JSON.

Output:
  - One JSON file per blob: <out_dir>/<cap_stem>__blob<NN>__fn<frame>.json
  - Index TSV: <out_dir>/INDEX.tsv with (capture, blob#, first_fn, comp_size,
    uncomp_size, TitleId, sortTag, n_enable, n_disable, cjl_count,
    img_ref_top, img_ref_dis, img_path_n)

Reassembly handles:
  - 0x7E byte stuffing (via wheel_sim.parse_frames)
  - 4-byte CRC32 trailer per chunk (stripped before reassembly)
  - Multiple back-to-back blobs in the same session (walks 9-byte envelope
    [flag=0x00][comp_size LE u32][uncomp_size LE u32][zlib stream])
  - seq counter resets / out-of-order chunks within a session lifetime

Usage:
    python3 usb-capture/analyze_session09.py <out_dir> <capture.pcapng>...
"""
import sys
import json
import struct
import subprocess
import zlib
from pathlib import Path

_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_root / 'sim'))
from wheel_sim import parse_frames, frame_payload  # noqa: E402


def get_payloads(path: Path):
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


def collect_session_events(rows, sess: int):
    """Return per-direction lists of (fn, ttype, seq, body)."""
    by_dir = {'host': [], 'device': []}
    for fn, d, raw in rows:
        for fr in parse_frames(raw):
            pl = frame_payload(fr)
            if len(pl) < 6:
                continue
            if pl[0] != 0x7c or pl[1] != 0x00:
                continue
            if pl[2] != sess:
                continue
            ttype = pl[3]
            seq = pl[4] | (pl[5] << 8)
            body = bytes(pl[6:])
            by_dir[d].append((fn, ttype, seq, body))
    for d in by_dir:
        by_dir[d].sort()
    return by_dir


def split_blobs_by_lifecycle(events):
    """Group DATA chunks into bursts: each burst = consecutive DATA frames
    bracketed by OPEN (0x81) or END (0x00) markers in either direction.
    Returns list-of-lists of (fn, seq, body)."""
    bursts = []
    cur = []
    for fn, ttype, seq, body in events:
        if ttype == 0x81:
            if cur:
                bursts.append(cur)
                cur = []
        elif ttype == 0x00:
            if cur:
                bursts.append(cur)
                cur = []
        elif ttype == 0x01:
            cur.append((fn, seq, body))
    if cur:
        bursts.append(cur)
    return bursts


def split_bursts_by_fn_gap(chunks, gap=2000):
    """Split (fn, seq, body) chunks into bursts where consecutive chunks have
    frame-number gap > `gap`. Within each burst, also split if seq decreases
    (seq counter reset = new push)."""
    if not chunks:
        return []
    chunks = sorted(chunks)  # by (fn, seq)
    bursts = []
    cur = []
    last_fn = None
    last_seq = None
    for fn, seq, body in chunks:
        if cur and last_fn is not None and (fn - last_fn > gap or seq < last_seq):
            bursts.append(cur)
            cur = []
        cur.append((fn, seq, body))
        last_fn = fn
        last_seq = seq
    if cur:
        bursts.append(cur)
    return bursts


def _reassemble_one_burst(chunks):
    """Single burst: dedupe by seq (keep first), strip 4B CRC, sort by seq,
    concat, walk 9B envelopes."""
    if not chunks:
        return []
    by_seq = {}
    for fn, seq, body in chunks:
        if seq not in by_seq:
            by_seq[seq] = (fn, body)
    seqs = sorted(by_seq.keys())
    fn_for_seq = {s: by_seq[s][0] for s in seqs}
    data = b''
    seq_offsets = []
    for s in seqs:
        body = by_seq[s][1]
        net = body[:-4] if len(body) > 4 else body
        seq_offsets.append((s, len(data)))
        data += net

    def fn_at_offset(off):
        last = None
        for s, o in seq_offsets:
            if o <= off:
                last = fn_for_seq[s]
            else:
                break
        return last

    blobs = []
    i = 0
    while i + 9 <= len(data):
        flag = data[i]
        comp = struct.unpack('<I', data[i+1:i+5])[0]
        uncomp = struct.unpack('<I', data[i+5:i+9])[0]
        if flag != 0 or comp == 0 or comp > (1 << 22) or uncomp == 0:
            i += 1
            continue
        end = i + 9 + comp
        if end > len(data):
            blobs.append({
                'start_fn': fn_at_offset(i), 'offset': i,
                'comp_size': comp, 'uncomp_size': uncomp,
                'status': 'incomplete',
                'avail': len(data) - i - 9,
            })
            break
        zb = data[i+9:end]
        try:
            dec = zlib.decompress(zb)
            try:
                obj = json.loads(dec)
                blobs.append({
                    'start_fn': fn_at_offset(i), 'offset': i,
                    'comp_size': comp, 'uncomp_size': uncomp,
                    'status': 'ok', 'json': obj,
                })
            except json.JSONDecodeError as e:
                blobs.append({
                    'start_fn': fn_at_offset(i), 'offset': i,
                    'comp_size': comp, 'uncomp_size': uncomp,
                    'status': f'json-err: {e}',
                })
        except zlib.error as e:
            blobs.append({
                'start_fn': fn_at_offset(i), 'offset': i,
                'comp_size': comp, 'uncomp_size': uncomp,
                'status': f'zlib-err: {e}',
            })
            i += 1
            continue
        i = end
    return blobs


def reassemble_blobs(chunks):
    """chunks: list of (fn, seq, body). Three reassembly strategies tried in
    order; first one yielding ≥1 successful blob wins:

      1. Whole-stream dedup by seq (first-occurrence) — handles single-blob
         captures with retransmissions.
      2. Whole-stream dedup by seq (LAST occurrence) — handles seq counter
         re-use where the second push is the complete one.
      3. Per-burst dedup (split by frame-number gap) — handles multi-blob
         captures.

    Strategy 1+2 are zlib-validated: only successful zlib decompressions
    count as wins. If all strategies decode no blobs the function returns
    the strategy-1 attempt list (with error markers) for diagnostics.
    """
    if not chunks:
        return []

    def all_unique(by_seq):
        seqs = sorted(by_seq.keys())
        fn_for_seq = {s: by_seq[s][0] for s in seqs}
        data = b''
        seq_offsets = []
        for s in seqs:
            body = by_seq[s][1]
            net = body[:-4] if len(body) > 4 else body
            seq_offsets.append((s, len(data)))
            data += net

        def fn_at_offset(off):
            last = None
            for s, o in seq_offsets:
                if o <= off:
                    last = fn_for_seq[s]
                else:
                    break
            return last

        blobs = []
        i = 0
        while i + 9 <= len(data):
            flag = data[i]
            comp = struct.unpack('<I', data[i+1:i+5])[0]
            uncomp = struct.unpack('<I', data[i+5:i+9])[0]
            # Validate header: only proceed if zlib magic appears at i+9
            zb_start = i + 9
            magic_ok = (zb_start + 2 <= len(data)
                        and data[zb_start] == 0x78
                        and data[zb_start+1] in (0x01, 0x5e, 0x9c, 0xda))
            if (flag != 0 or comp == 0 or comp > (1 << 22)
                    or uncomp == 0 or not magic_ok):
                i += 1
                continue
            end = i + 9 + comp
            if end > len(data):
                blobs.append({
                    'start_fn': fn_at_offset(i), 'offset': i,
                    'comp_size': comp, 'uncomp_size': uncomp,
                    'status': 'incomplete',
                    'avail': len(data) - i - 9,
                })
                break
            zb = data[i+9:end]
            try:
                dec = zlib.decompress(zb)
                try:
                    obj = json.loads(dec)
                    blobs.append({
                        'start_fn': fn_at_offset(i), 'offset': i,
                        'comp_size': comp, 'uncomp_size': uncomp,
                        'status': 'ok', 'json': obj,
                    })
                    i = end
                    continue
                except json.JSONDecodeError as e:
                    blobs.append({
                        'start_fn': fn_at_offset(i), 'offset': i,
                        'comp_size': comp, 'uncomp_size': uncomp,
                        'status': f'json-err: {e}',
                    })
                    i = end
                    continue
            except zlib.error as e:
                blobs.append({
                    'start_fn': fn_at_offset(i), 'offset': i,
                    'comp_size': comp, 'uncomp_size': uncomp,
                    'status': f'zlib-err: {e}',
                })
                i += 1
        return blobs

    chunks = sorted(chunks)
    by_seq_first = {}
    by_seq_last = {}
    for fn, seq, body in chunks:
        if seq not in by_seq_first:
            by_seq_first[seq] = (fn, body)
        by_seq_last[seq] = (fn, body)

    def n_ok(blobs):
        return sum(1 for b in blobs if b.get('status') == 'ok')

    s1 = all_unique(by_seq_first)
    s2 = all_unique(by_seq_last)
    s3 = []
    for burst in split_bursts_by_fn_gap(chunks):
        bs = {}
        for fn, seq, body in burst:
            if seq not in bs:
                bs[seq] = (fn, body)
        s3.extend(all_unique(bs))

    candidates = [(s1, 'first'), (s2, 'last'), (s3, 'burst')]
    best = max(candidates, key=lambda c: n_ok(c[0]))
    return best[0]


def summarize_state(obj):
    if not isinstance(obj, dict):
        return {}
    en = obj.get('enableManager', {})
    dis = obj.get('disableManager', {})
    return {
        'TitleId': obj.get('TitleId'),
        'sortTag': obj.get('sortTag'),
        'displayVersion': obj.get('displayVersion'),
        'resetVersion': obj.get('resetVersion'),
        'rootDirPath': obj.get('rootDirPath'),
        'cjl_count': len(obj.get('configJsonList', []) or []),
        'cjl': obj.get('configJsonList', []),
        'n_enable': len(en.get('dashboards', []) or []),
        'enable_dirNames': [d.get('dirName') for d in (en.get('dashboards') or [])],
        'enable_titles': [d.get('title') for d in (en.get('dashboards') or [])],
        'enable_ids': [d.get('id') for d in (en.get('dashboards') or [])],
        'n_disable': len(dis.get('dashboards', []) or []),
        'disable_dirNames': [d.get('dirName') for d in (dis.get('dashboards') or [])],
        'img_ref_top': len(obj.get('imageRefMap', {}) or {}),
        'img_ref_en': len(en.get('imageRefMap', {}) or {}),
        'img_ref_dis': len(dis.get('imageRefMap', {}) or {}),
        'img_path_n': len(obj.get('imagePath', []) or []),
        'rootPath_en': en.get('rootPath'),
        'rootPath_dis': dis.get('rootPath'),
    }


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    out_dir = Path(sys.argv[1])
    out_dir.mkdir(parents=True, exist_ok=True)
    captures = [Path(p) for p in sys.argv[2:]]

    index_rows = []
    index_rows.append('\t'.join([
        'capture', 'blob', 'start_fn', 'comp', 'uncomp', 'TitleId', 'sortTag',
        'n_enable', 'n_disable', 'cjl_count', 'img_ref_top', 'img_ref_dis',
        'img_path_n', 'rootDirPath', 'titles']))

    for cap in captures:
        if not cap.exists():
            print(f'!! missing: {cap}', file=sys.stderr)
            continue
        print(f'== {cap.name}')
        rows = get_payloads(cap)
        events = collect_session_events(rows, 0x09)
        dev_chunks = [(fn, seq, body) for fn, t, seq, body in events['device'] if t == 0x01]
        host_chunks = [(fn, seq, body) for fn, t, seq, body in events['host'] if t == 0x01]
        print(f'  device DATA chunks: {len(dev_chunks)}, host DATA chunks: {len(host_chunks)}')

        # Try reassembly: dedupe by seq + walk envelopes
        blobs = reassemble_blobs(dev_chunks)
        print(f'  blobs decoded: {len(blobs)}')
        for i, b in enumerate(blobs):
            stem = f'{cap.stem}__dev_blob{i:02d}__fn{b.get("start_fn")}'
            if b.get('status') == 'ok':
                summ = summarize_state(b['json'])
                index_rows.append('\t'.join([
                    cap.name, str(i), str(b['start_fn']),
                    str(b['comp_size']), str(b['uncomp_size']),
                    str(summ['TitleId']), str(summ['sortTag']),
                    str(summ['n_enable']), str(summ['n_disable']),
                    str(summ['cjl_count']), str(summ['img_ref_top']),
                    str(summ['img_ref_dis']), str(summ['img_path_n']),
                    str(summ['rootDirPath']),
                    ','.join(t or '?' for t in summ['enable_titles']),
                ]))
                (out_dir / f'{stem}.json').write_text(
                    json.dumps(b['json'], indent=2, sort_keys=True))
                print(f'  blob{i:02d}: TitleId={summ["TitleId"]} '
                      f'sortTag={summ["sortTag"]} '
                      f'enable={summ["n_enable"]} disable={summ["n_disable"]} '
                      f'cjl={summ["cjl_count"]} '
                      f'img_ref_top={summ["img_ref_top"]} '
                      f'rootDirPath={summ["rootDirPath"]}')
            else:
                print(f'  blob{i:02d}: {b["status"]}')

        # Same for host blobs (reply pushes — `configJson()` lib list)
        host_blobs = reassemble_blobs(host_chunks)
        for i, b in enumerate(host_blobs):
            stem = f'{cap.stem}__host_blob{i:02d}__fn{b.get("start_fn")}'
            if b.get('status') == 'ok':
                (out_dir / f'{stem}.json').write_text(
                    json.dumps(b['json'], indent=2, sort_keys=True))

    (out_dir / 'INDEX.tsv').write_text('\n'.join(index_rows) + '\n')
    print(f'\nwrote index: {out_dir / "INDEX.tsv"}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
