#!/usr/bin/env python3
"""Extract moza-protocol frames (0x7e ...) from a USBPcap pcapng without
relying on a custom Wireshark dissector. Walks USBPcap pseudo-header to find
bulk-transfer payloads, then scans for 0x7e-framed sub-frames.

Usage:
    python3 usb-capture/extract_moza_frames.py <capture.pcapng>
        [--filter-group 0x29] [--filter-dev 0x13] [--filter-payload-prefix 1c]
        [--show-context 4] [--limit 50]
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path
from typing import Iterator, Tuple

PCAPNG_BLOCK_EPB = 0x00000006
PCAPNG_BLOCK_SHB = 0x0a0d0d0a
PCAPNG_BLOCK_IDB = 0x00000001
PCAPNG_BLOCK_SPB = 0x00000003


def iter_pcapng_blocks(data: bytes) -> Iterator[Tuple[int, bytes]]:
    off = 0
    while off + 8 <= len(data):
        block_type = struct.unpack_from('<I', data, off)[0]
        block_len = struct.unpack_from('<I', data, off + 4)[0]
        if block_len < 12 or off + block_len > len(data):
            return
        body = data[off + 8 : off + block_len - 4]
        yield block_type, body
        off += block_len


def epb_packet_data(body: bytes) -> bytes:
    # Enhanced Packet Block body: interface_id u32, ts_high u32, ts_low u32,
    # captured_len u32, packet_len u32, packet_data..., padding to 4B, options.
    cap_len = struct.unpack_from('<I', body, 12)[0]
    return body[20 : 20 + cap_len]


def parse_usbpcap_payload(pkt: bytes) -> Tuple[int, int, int, bytes]:
    """Return (transfer_type, endpoint, data_length, payload_bytes)."""
    if len(pkt) < 27:
        return 0, 0, 0, b''
    # USBPcap pseudo-header layout (little-endian):
    #   u16 header_length
    #   u64 irp_id
    #   u32 usbd_status
    #   u16 urb_function
    #   u8  irp_info
    #   u16 bus
    #   u16 device
    #   u8  endpoint
    #   u8  transfer
    #   u32 data_length
    hdr_len = struct.unpack_from('<H', pkt, 0)[0]
    if hdr_len < 27 or hdr_len > len(pkt):
        return 0, 0, 0, b''
    endpoint = pkt[21]
    transfer = pkt[22]
    data_length = struct.unpack_from('<I', pkt, 23)[0]
    payload = pkt[hdr_len:]
    if len(payload) > data_length:
        payload = payload[:data_length]
    return transfer, endpoint, data_length, payload


def scan_moza_frames(buf: bytes) -> Iterator[bytes]:
    """Yield well-formed moza frames `7E N CMD DEV [N-bytes payload] CSUM`."""
    i = 0
    n = len(buf)
    while i < n:
        if buf[i] != 0x7E:
            i += 1
            continue
        if i + 4 > n:
            break
        ln = buf[i + 1]
        # full frame size = 4 + ln (start, len, cmd, dev, payload..., csum) but
        # csum is the last byte AFTER the ln payload bytes. So frame size = 5+ln-1 = ln+4? Let's check:
        # 7e 00 09 12 a6 → ln=0, frame=5 bytes (start, len, cmd, dev, csum)
        # 7e 04 04 12 00 00 00 00 a5 → ln=4, frame=9 bytes
        # frame_size = ln + 5
        frame_size = ln + 5
        if i + frame_size > n:
            i += 1
            continue
        yield buf[i : i + frame_size]
        i += frame_size


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('capture', type=Path)
    ap.add_argument('--filter-group', type=lambda s: int(s, 0))
    ap.add_argument('--filter-dev', type=lambda s: int(s, 0))
    ap.add_argument('--filter-payload-prefix',
                    help='hex bytes to match at start of moza payload, e.g. "1c00"')
    ap.add_argument('--limit', type=int, default=200)
    ap.add_argument('--with-context', type=int, default=0,
                    help='also print N moza frames before/after each match')
    args = ap.parse_args()

    raw = args.capture.read_bytes()
    pfx = bytes.fromhex(args.filter_payload_prefix) if args.filter_payload_prefix else None

    matches_emitted = 0
    moza_seq: list[Tuple[int, str, bytes]] = []  # (frame_no, dir, frame_bytes)

    pcap_frame_no = 0
    for btype, body in iter_pcapng_blocks(raw):
        if btype != PCAPNG_BLOCK_EPB:
            continue
        pcap_frame_no += 1
        pkt = epb_packet_data(body)
        transfer, endpoint, _, payload = parse_usbpcap_payload(pkt)
        if transfer != 0x03:
            continue
        if not payload:
            continue
        # endpoint bit 7 set = IN (device→host); else OUT (host→device)
        direction = 'in' if (endpoint & 0x80) else 'out'
        for frame in scan_moza_frames(payload):
            moza_seq.append((pcap_frame_no, direction, frame))

    # filter pass
    print(f'parsed {len(moza_seq)} moza frames from {pcap_frame_no} bulk packets')
    indices_match = []
    for idx, (_pno, _dir, fb) in enumerate(moza_seq):
        if len(fb) < 4:
            continue
        ln = fb[1]
        cmd = fb[2]
        dev = fb[3]
        pl = fb[4 : 4 + ln]
        if args.filter_group is not None and cmd != args.filter_group:
            continue
        if args.filter_dev is not None and dev != args.filter_dev:
            continue
        if pfx is not None and not pl.startswith(pfx):
            continue
        indices_match.append(idx)

    print(f'matched {len(indices_match)} frames')
    seen = set()
    for idx in indices_match[: args.limit]:
        win_lo = max(0, idx - args.with_context)
        win_hi = min(len(moza_seq), idx + args.with_context + 1)
        for k in range(win_lo, win_hi):
            if k in seen:
                continue
            seen.add(k)
            pno, dir_, fb = moza_seq[k]
            marker = '<<' if k == idx else '  '
            print(f'  {marker} pno={pno:7d} {dir_:3s}  {fb.hex(" ")}')
        if args.with_context:
            print('  ----')


if __name__ == '__main__':
    main()
