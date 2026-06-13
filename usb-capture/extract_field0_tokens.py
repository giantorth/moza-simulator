#!/usr/bin/env python3
"""
Extract field 0 tokens (16 bytes) from session 0x01 dashboard upload data
in USB captures of MOZA PitHouse protocol.

Session 0x01 carries dashboard upload with FF-prefixed framing:
  Field 0: [FF] [10 00 00 00] [16 bytes tokens] [remaining: u32 LE] [CRC32: u32 LE]
  Field 1: [FF] [08 00 00 00] [8 bytes constant: 9E 79 52 7D 07 00 00 00] [remaining: u32 LE] [CRC32: u32 LE]
  Field 2: [FF] [size: u32 LE] [12B pre-header + zlib compressed data...]

Chunk format (group 0x43, cmd 7c:00):
  session(1) type(1) seq_lo(1) seq_hi(1) payload(<=58)
  Non-last data chunks have a 4-byte CRC-32 trailer on the payload.

Fields 0 and 1 each fit in a SINGLE chunk (29 and 21 bytes respectively),
so no multi-chunk reassembly is needed for those fields.

Usage:
    python3 extract_field0_tokens.py
"""
import datetime
import json
import re
import struct
import subprocess
import sys
import zlib
from collections import defaultdict
from pathlib import Path

BASE = Path(__file__).parent


# ─── Frame parsing ──────────────────────────────────────────────────────────

def parse_moza_frames(raw: bytes) -> list[bytes]:
    """Parse all Moza frames from raw bytes."""
    frames = []
    i = 0
    while i < len(raw):
        if raw[i] == 0x7E:
            if i + 2 >= len(raw):
                break
            n = raw[i + 1]
            end = i + 4 + n + 1
            if end <= len(raw):
                frames.append(raw[i:end])
            i = end
        else:
            i += 1
    return frames


def extract_7c00_chunks(raw: bytes, direction: str, ts: float, sessions: dict):
    """Extract 7c:00 session chunks from raw USB COM data."""
    frames = parse_moza_frames(raw)
    for f in frames:
        if len(f) < 8:
            continue
        group, payload = f[2], f[4:-1]
        if group != 0x43 or len(payload) < 6:
            continue
        if payload[0] != 0x7C or payload[1] != 0x00:
            continue
        chunk = payload[2:]
        if len(chunk) < 4:
            continue
        session, ctype = chunk[0], chunk[1]
        seq = chunk[2] | (chunk[3] << 8)
        sessions[(session, direction)].append((ts, seq, ctype, chunk[4:]))


# ─── Source loaders ─────────────────────────────────────────────────────────

def sessions_from_pcapng(path: str) -> dict:
    """Extract sessions from pcapng via tshark."""
    try:
        result = subprocess.run(
            ["tshark", "-r", path, "-Y", "usbcom", "-T", "fields",
             "-e", "frame.time_relative", "-e", "usb.src",
             "-e", "usbcom.data.out_payload", "-e", "usbcom.data.in_payload",
             "-E", "separator=|"],
            capture_output=True, text=True, timeout=120)
    except Exception:
        return {}

    sessions = defaultdict(list)
    for line in result.stdout.strip().split("\n"):
        if not line:
            continue
        parts = line.split("|")
        if len(parts) < 4:
            continue
        ts_str, src, out_hex, in_hex = parts
        hex_data = out_hex or in_hex
        if not hex_data:
            continue
        try:
            ts = float(ts_str)
        except ValueError:
            continue
        raw = bytes.fromhex(hex_data.replace(":", ""))
        extract_7c00_chunks(raw, "out" if src == "host" else "in", ts, sessions)
    return sessions


def sessions_from_wireshark_text(path: str) -> dict:
    """Extract sessions from Wireshark text export."""
    sessions = defaultdict(list)
    current_frame = None
    current_direction = None
    current_hex = bytearray()

    def process_frame():
        if current_hex and current_direction:
            raw = bytes(current_hex)
            i = 0
            while i < len(raw):
                if raw[i] == 0x7E:
                    if i + 2 >= len(raw):
                        break
                    n = raw[i + 1]
                    end = i + 4 + n + 1
                    if end <= len(raw):
                        frame = raw[i:end]
                        if len(frame) >= 8:
                            group, payload = frame[2], frame[4:-1]
                            if group == 0x43 and len(payload) >= 6 and payload[0] == 0x7C and payload[1] == 0x00:
                                chunk = payload[2:]
                                if len(chunk) >= 4:
                                    session, ctype = chunk[0], chunk[1]
                                    seq = chunk[2] | (chunk[3] << 8)
                                    if session == 0x01 and ctype == 0x01 and current_direction == "out":
                                        sessions[(session, current_direction)].append((0.0, seq, ctype, chunk[4:]))
                    i = end
                else:
                    i += 1

    with open(path) as f:
        for line in f:
            m = re.match(r"^Frame (\d+):", line)
            if m:
                process_frame()
                current_frame = int(m.group(1))
                current_direction = None
                current_hex = bytearray()
                continue
            if current_frame is None:
                continue
            if "[Source: host]" in line:
                current_direction = "out"
            elif "[Source:" in line and "host" not in line:
                current_direction = "in"
            m2 = re.match(r"^([0-9a-f]{4})  ((?:[0-9a-f]{2} )+)", line)
            if m2:
                current_hex.extend(bytes.fromhex(m2.group(2).strip().replace(" ", "")))
    process_frame()
    return sessions


# ─── Token finder ───────────────────────────────────────────────────────────

def find_field0_in_chunks(chunks: list) -> list:
    """Find field 0 tokens in session 0x01 data chunks."""
    results = []
    data_chunks = [(ts, seq, ct, p) for ts, seq, ct, p in chunks if ct == 0x01]

    for ts, seq, ct, payload in data_chunks:
        for i in range(len(payload) - 28):
            if payload[i] == 0xFF and payload[i + 1:i + 5] == b"\x10\x00\x00\x00":
                if i + 29 > len(payload):
                    continue
                tokens = payload[i + 5:i + 5 + 16]
                remaining = struct.unpack_from("<I", payload, i + 5 + 16)[0]
                crc_val = struct.unpack_from("<I", payload, i + 5 + 16 + 4)[0]
                crc_data = payload[i:i + 25]
                computed_crc = zlib.crc32(crc_data) & 0xFFFFFFFF
                t1 = struct.unpack_from("<Q", tokens, 0)[0]
                t2 = struct.unpack_from("<Q", tokens, 8)[0]
                results.append({
                    "t1": t1, "t2": t2,
                    "t1_bytes": " ".join(f"{b:02x}" for b in tokens[:8]),
                    "t2_bytes": " ".join(f"{b:02x}" for b in tokens[8:]),
                    "remaining": remaining,
                    "crc_ok": crc_val == computed_crc,
                })
    return results


# ─── Main ───────────────────────────────────────────────────────────────────

def main():
    all_tokens = []  # (source_label, token_dict)

    # Scan all pcapng files
    for p in sorted(BASE.rglob("*.pcapng")):
        sessions = sessions_from_pcapng(str(p))
        key = (0x01, "out")
        if key in sessions:
            data_count = sum(1 for _, _, ct, _ in sessions[key] if ct == 0x01)
            if data_count >= 2:
                for t in find_field0_in_chunks(sessions[key]):
                    all_tokens.append((str(p.relative_to(BASE)), t))

    # Scan Wireshark text exports
    csp_dir = BASE / "CSP captures"
    if csp_dir.exists():
        for p in sorted(csp_dir.glob("*.txt")):
            print(f"  Scanning {p.name}...", flush=True)
            sessions = sessions_from_wireshark_text(str(p))
            key = (0x01, "out")
            if key in sessions:
                for t in find_field0_in_chunks(sessions[key]):
                    all_tokens.append((f"CSP/{p.name}", t))

    # Deduplicate and report
    unique = {}
    for source, t in all_tokens:
        key = (t["t1"], t["t2"])
        if key not in unique:
            unique[key] = {"token": t, "sources": []}
        unique[key]["sources"].append(source)

    print(f"\n{'=' * 80}")
    print(f"  {len(unique)} unique field 0 token pairs found across {len(all_tokens)} instances")
    print(f"{'=' * 80}\n")

    for i, ((t1, t2), info) in enumerate(sorted(unique.items(), key=lambda x: x[0][1])):
        t = info["token"]
        t2_ts = datetime.datetime.fromtimestamp(t2) if 1700000000 < t2 < 2100000000 else "N/A"
        print(f"  [{i+1}] Token 1: {t['t1_bytes']}  (u64 LE = {t1})")
        print(f"      Token 2: {t['t2_bytes']}  (u64 LE = {t2})")
        print(f"      Token 2 as timestamp: {t2_ts}")
        print(f"      Remaining: {t['remaining']}  CRC verified: {t['crc_ok']}")
        print(f"      Sources: {', '.join(info['sources'])}")
        print()

    # Pattern summary
    if unique:
        print("  PATTERNS:")
        print("    Token 1: hi32 always 0x00000002, lo32 varies (hash/nonce)")
        print("    Token 2: Unix timestamp (seconds since epoch)")
        print("    Remaining: always 7200 (0x1C20) regardless of dashboard file size")
        print("    Field 1: always 9e 79 52 7d 07 00 00 00 (constant)")


if __name__ == "__main__":
    main()
