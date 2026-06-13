#!/usr/bin/env python3
"""Exhaustive per-(session, direction, type) + per-bare-cmd inventory of a
MOZA pcapng capture. Goal: classify every 7E frame so nothing slips through
unnamed.

Outputs (under <out_dir>):
  - <stem>_session_mux.tsv   — (session, dir, type, count, total_bytes,
                                 first_seq, last_seq, first_fn, last_fn)
  - <stem>_session_ack.tsv   — (session, dir, count, total_bytes, distinct_ack,
                                 first_fn, last_fn)
  - <stem>_bare_cmd.tsv      — (group, device, plen, hex_prefix, count,
                                 first_fn, last_fn)
  - <stem>_unmatched.tsv     — anything that wasn't 7c:00 / fc:00 (mirror of
                                 bare_cmd, but only for cmd bytes outside the
                                 documented set)

Usage:
    python3 usb-capture/inventory_pcap.py <out_dir> <capture.pcapng>...
"""
import argparse
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / 'sim'))
from wheel_sim import parse_frames, frame_payload  # noqa: E402

# Cmd bytes already routed by the sim or otherwise documented. Anything outside
# this set is surfaced in the unmatched TSV so we can hunt for new behaviours.
DOCUMENTED_CMD = {
    0x00, 0x0e, 0x40, 0x43, 0x3f, 0x7c, 0x7d, 0xc3,
    # ack/session
    0xfc,
    # display family responses
    0x80, 0x82, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8f, 0x90, 0x91,
}

# Common groups (docs/moza-protocol.md): host writes have bit7 clear, wheel
# replies have bit7 set. We only filter on the "raw" group (no bit7) here so
# the inventory keeps both directions visible.


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


def classify(payload):
    """Return ('session_mux', sess, ttype, seq, body_bytes)
    or ('session_ack', sess, ack)
    or ('bare', group_or_first, payload_prefix)
    based on payload (frame_payload bytes — i.e. cmd + data, no group/dev)."""
    if len(payload) >= 6 and payload[0] == 0x7c and payload[1] == 0x00:
        sess = payload[2]
        ttype = payload[3]
        seq = payload[4] | (payload[5] << 8)
        body = bytes(payload[6:])
        return ('session_mux', sess, ttype, seq, body)
    if len(payload) >= 4 and payload[0] == 0xfc and payload[1] == 0x00:
        sess = payload[2]
        ack = payload[3] | ((payload[4] << 8) if len(payload) >= 5 else 0)
        return ('session_ack', sess, ack)
    return ('bare', None, bytes(payload))


def inventory(rows):
    """Return dict of aggregations."""
    sess_mux = defaultdict(lambda: {
        'count': 0, 'total_bytes': 0,
        'first_seq': None, 'last_seq': None,
        'first_fn': None, 'last_fn': None,
        'seqs': [],
    })
    sess_ack = defaultdict(lambda: {
        'count': 0, 'total_bytes': 0,
        'acks': set(),
        'first_fn': None, 'last_fn': None,
    })
    bare = defaultdict(lambda: {
        'count': 0,
        'first_fn': None, 'last_fn': None,
    })
    n_total_frames = 0
    n_classified_session_mux = 0
    n_classified_session_ack = 0
    n_classified_bare = 0

    for fn, d, raw in rows:
        for fr in parse_frames(raw):
            n_total_frames += 1
            if len(fr) < 5:
                continue
            group = fr[2]
            device = fr[3]
            pl = frame_payload(fr)
            kind = classify(pl)
            if kind[0] == 'session_mux':
                _, sess, ttype, seq, body = kind
                key = (sess, d, ttype)
                rec = sess_mux[key]
                rec['count'] += 1
                rec['total_bytes'] += len(body)
                if rec['first_fn'] is None:
                    rec['first_fn'] = fn
                rec['last_fn'] = fn
                if rec['first_seq'] is None:
                    rec['first_seq'] = seq
                rec['last_seq'] = seq
                rec['seqs'].append(seq)
                n_classified_session_mux += 1
            elif kind[0] == 'session_ack':
                _, sess, ack = kind
                key = (sess, d)
                rec = sess_ack[key]
                rec['count'] += 1
                rec['total_bytes'] += len(pl)
                rec['acks'].add(ack)
                if rec['first_fn'] is None:
                    rec['first_fn'] = fn
                rec['last_fn'] = fn
                n_classified_session_ack += 1
            else:
                # bare cmd — key on (group, device, payload[:4])
                prefix = bytes(pl[:4])
                key = (group, device, d, len(pl), prefix)
                rec = bare[key]
                rec['count'] += 1
                if rec['first_fn'] is None:
                    rec['first_fn'] = fn
                rec['last_fn'] = fn
                n_classified_bare += 1

    return {
        'sess_mux': sess_mux,
        'sess_ack': sess_ack,
        'bare': bare,
        'totals': {
            'frames': n_total_frames,
            'session_mux': n_classified_session_mux,
            'session_ack': n_classified_session_ack,
            'bare': n_classified_bare,
        },
    }


def write_session_mux_tsv(path, sess_mux):
    rows = ['\t'.join([
        'session', 'dir', 'type', 'count', 'total_bytes',
        'first_seq', 'last_seq', 'min_seq', 'max_seq',
        'first_fn', 'last_fn',
    ])]
    for (sess, d, ttype), rec in sorted(sess_mux.items()):
        seqs = rec['seqs']
        rows.append('\t'.join([
            f'0x{sess:02x}', d, f'0x{ttype:02x}',
            str(rec['count']), str(rec['total_bytes']),
            f'0x{rec["first_seq"]:04x}' if rec['first_seq'] is not None else '-',
            f'0x{rec["last_seq"]:04x}' if rec['last_seq'] is not None else '-',
            f'0x{min(seqs):04x}' if seqs else '-',
            f'0x{max(seqs):04x}' if seqs else '-',
            str(rec['first_fn']), str(rec['last_fn']),
        ]))
    path.write_text('\n'.join(rows) + '\n')


def write_session_ack_tsv(path, sess_ack):
    rows = ['\t'.join([
        'session', 'dir', 'count', 'total_bytes',
        'distinct_acks', 'sample_acks', 'first_fn', 'last_fn',
    ])]
    for (sess, d), rec in sorted(sess_ack.items()):
        acks = sorted(rec['acks'])
        rows.append('\t'.join([
            f'0x{sess:02x}', d, str(rec['count']), str(rec['total_bytes']),
            str(len(acks)),
            ','.join(f'0x{a:04x}' for a in acks[:8]),
            str(rec['first_fn']), str(rec['last_fn']),
        ]))
    path.write_text('\n'.join(rows) + '\n')


def write_bare_cmd_tsv(path, bare, only_unmatched=False):
    rows = ['\t'.join([
        'group', 'device', 'dir', 'payload_len',
        'prefix_hex', 'count', 'first_fn', 'last_fn',
    ])]
    keys = sorted(bare.keys())
    for (group, device, d, plen, prefix) in keys:
        if only_unmatched and group in DOCUMENTED_CMD:
            continue
        rec = bare[(group, device, d, plen, prefix)]
        rows.append('\t'.join([
            f'0x{group:02x}', f'0x{device:02x}', d, str(plen),
            prefix.hex(), str(rec['count']),
            str(rec['first_fn']), str(rec['last_fn']),
        ]))
    path.write_text('\n'.join(rows) + '\n')


def print_summary(name, inv):
    t = inv['totals']
    print(f'== {name} ==')
    print(f'  frames: {t["frames"]}  session_mux: {t["session_mux"]}  '
          f'session_ack: {t["session_ack"]}  bare: {t["bare"]}')
    print(f'  sessions seen ({len(set(s for s, _, _ in inv["sess_mux"]))}): '
          + ' '.join(f'0x{s:02x}' for s in sorted(set(s for s, _, _ in inv["sess_mux"]))))
    print(f'  ack sessions ({len(set(s for s, _ in inv["sess_ack"]))}): '
          + ' '.join(f'0x{s:02x}' for s in sorted(set(s for s, _ in inv["sess_ack"]))))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('out_dir')
    ap.add_argument('captures', nargs='+')
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    for cap_path in args.captures:
        cap = Path(cap_path)
        if not cap.exists():
            print(f'!! missing: {cap}', file=sys.stderr)
            continue
        print(f'-- {cap.name} --')
        rows = get_payloads(cap)
        inv = inventory(rows)
        print_summary(cap.name, inv)

        stem = cap.stem
        write_session_mux_tsv(out_dir / f'{stem}_session_mux.tsv', inv['sess_mux'])
        write_session_ack_tsv(out_dir / f'{stem}_session_ack.tsv', inv['sess_ack'])
        write_bare_cmd_tsv(out_dir / f'{stem}_bare_cmd.tsv', inv['bare'])
        write_bare_cmd_tsv(out_dir / f'{stem}_unmatched.tsv', inv['bare'],
                           only_unmatched=True)
        print(f'  wrote {stem}_session_mux.tsv / _session_ack.tsv / '
              f'_bare_cmd.tsv / _unmatched.tsv')

    return 0


if __name__ == '__main__':
    sys.exit(main())
