#!/usr/bin/env python3
"""
Analyze Moza USB captures (tshark JSON exports) to understand
the group 0x43 / 0xC3 telemetry frame structure.

Usage:
    python3 analyze_telemetry.py [file1.json file2.json ...]

Defaults to the three 09-04-29 captures if no files are given.

Frame format (docs/moza-protocol.md):
    7E [N] [group] [device] [id_bytes + data_bytes, N total] [checksum]

Moza protocol data lives in the `usbcom` layer of tshark JSON exports
(device 1.1.2, bulk endpoints 0x02/0x82), NOT in the HID layer.
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

DEFAULT_FILES = [
    "09-04-29/dash-upload.json",
    "09-04-29/0-6thgear-0-simple-rpm-dash.json",
    "09-04-29/0-100redline-0-simple-rpm-dash.json",
]

# ──────────────────────────────────────────────────────────────────────────────
# Frame parsing
# ──────────────────────────────────────────────────────────────────────────────

def parse_moza_frames(hex_str: str) -> list[bytes]:
    """Parse all Moza frames from a colon-separated hex string."""
    raw = bytes([int(x, 16) for x in hex_str.split(":")])
    frames = []
    i = 0
    while i < len(raw):
        if raw[i] == 0x7E:
            if i + 2 >= len(raw):
                break
            n = raw[i + 1]
            end = i + 4 + n + 1  # 7E + N + group + device + payload(N) + checksum
            if end <= len(raw):
                frames.append(raw[i:end])
            i = end
        else:
            i += 1
    return frames


def decode_frame(f: bytes):
    """Return (group, device, payload) or None if too short."""
    if len(f) < 4:
        return None
    # payload = everything between device byte and checksum
    return f[2], f[3], f[4:-1]


# ──────────────────────────────────────────────────────────────────────────────
# Packet loading
# ──────────────────────────────────────────────────────────────────────────────

def load_capture(path: str) -> list[tuple]:
    """
    Load tshark JSON export and return a list of
        (pkt_index, time_relative, direction, [moza_frame, ...])
    for every packet that has usbcom data with Moza frames.
    """
    print(f"Loading {path} ...", flush=True)
    with open(path) as fh:
        data = json.load(fh)
    print(f"  {len(data):,} raw packets", flush=True)

    result = []
    for i, p in enumerate(data):
        layers = p["_source"].get("layers", {})
        uc = layers.get("usbcom", {})
        usb = layers.get("usb", {})

        payload = uc.get("usbcom.data.out_payload") or uc.get("usbcom.data.in_payload", "")
        if not payload:
            continue

        src = usb.get("usb.src", "")
        direction = "host->dev" if src == "host" else "dev->host"
        ts = float(layers.get("frame", {}).get("frame.time_relative", 0))

        try:
            frames = parse_moza_frames(payload)
        except Exception:
            continue

        if frames:
            result.append((i, ts, direction, frames))

    print(f"  {len(result):,} packets with Moza frames", flush=True)
    return result


# ──────────────────────────────────────────────────────────────────────────────
# Per-capture analysis
# ──────────────────────────────────────────────────────────────────────────────

def show_frame_set(label: str, frames: list[tuple], dominant_len: int | None = None):
    """Print summary and byte table for a list of (pkt_i, ts, payload) frames."""
    if not frames:
        print(f"  {label}: (none)")
        return

    lengths = defaultdict(int)
    for _, _, p in frames:
        lengths[len(p)] += 1
    print(f"\n  {label}: {len(frames)} frames")
    print(f"  Payload lengths: {dict(lengths)}")

    if dominant_len is None:
        dominant_len = max(lengths, key=lengths.__getitem__)

    main = [(i, ts, p) for i, ts, p in frames if len(p) == dominant_len]
    if not main:
        return

    dur = max(main[-1][1], 0.001)
    print(f"  Dominant length: {dominant_len} bytes "
          f"({len(main)} frames, {dur:.1f}s, ~{len(main)/dur:.1f} Hz)")

    print("  First 5 samples:")
    for pkt_i, ts, p in main[:5]:
        print(f"    t={ts:8.3f}s pkt={pkt_i:6d}: {p.hex()}")
    mid = len(main) // 2
    print(f"  Middle 5 samples (t≈{main[mid][1]:.1f}s):")
    for pkt_i, ts, p in main[mid:mid+5]:
        print(f"    t={ts:8.3f}s pkt={pkt_i:6d}: {p.hex()}")
    print("  Last 5 samples:")
    for pkt_i, ts, p in main[-5:]:
        print(f"    t={ts:8.3f}s pkt={pkt_i:6d}: {p.hex()}")

    print(f"\n  Byte-by-byte variance (all {len(main)} frames):")
    print(f"  {'Byte':>4}  {'Min':>5}  {'Max':>5}  {'Unique':>6}  {'Const?':>6}  "
          f"Sample (first 12 values)")
    for bi in range(dominant_len):
        vals = [p[bi] for _, _, p in main if len(p) > bi]
        unique = set(vals)
        mn, mx = min(vals), max(vals)
        const = "YES" if len(unique) == 1 else ""
        sample = " ".join(f"{v:02X}" for v in vals[:12])
        print(f"  [{bi:2d}]  {mn:5d}  {mx:5d}  {len(unique):6d}  {const:>6}  {sample}")

    return main, dominant_len


def analyze_capture(path: str, label: str) -> dict:
    """
    Analyze a single capture and print results.
    Returns dict with extracted data for cross-capture comparison.

    NOTE: group 0x43 carries telemetry as WRITES host→device.
    The host sends live telemetry data; device sends back 0xC3 as an ACK/echo.
    We analyze both directions to confirm the frame structure.
    """
    packets = load_capture(path)

    print(f"\n{'='*70}")
    print(f"CAPTURE: {label}")
    print(f"{'='*70}")

    # ── Group 0x40: telemetry config / keep-alive ──
    print("\n[Group 0x40 — telemetry config sent host→device]")
    g40_unique = {}
    for pkt_i, ts, direction, frames in packets:
        if direction != "host->dev":
            continue
        for f in frames:
            d = decode_frame(f)
            if d and d[0] == 0x40:
                sig = f[4:-1].hex()  # payload only
                if sig not in g40_unique:
                    g40_unique[sig] = (ts, pkt_i, d[2])
    if g40_unique:
        for sig, (ts, pkt_i, payload) in g40_unique.items():
            print(f"  payload={payload.hex()}  (first seen t={ts:.3f}s pkt={pkt_i})")
    else:
        print("  (none found)")

    # ── Group 0x43: telemetry WRITES (host→device) — this is the actual live data ──
    g43_frames = []
    g43_by_cmd = defaultdict(list)
    for pkt_i, ts, direction, frames in packets:
        if direction != "host->dev":
            continue
        for f in frames:
            d = decode_frame(f)
            if d and d[0] == 0x43:
                payload = d[2]
                cmd_key = payload[:2].hex() if len(payload) >= 2 else payload.hex()
                g43_by_cmd[cmd_key].append((pkt_i, ts, payload))
                g43_frames.append((pkt_i, ts, payload))

    print(f"\n[Group 0x43 — telemetry WRITES host→device: {len(g43_frames)} total]")
    print(f"  Sub-commands seen: { {k: len(v) for k, v in g43_by_cmd.items()} }")

    # Focus on the main telemetry sub-command (cmd 7D 23)
    main_cmd = "7d23"
    main_g43 = g43_by_cmd.get(main_cmd, [])
    result = show_frame_set(f"cmd 0x7D23 main telemetry (host→device)", main_g43)
    main_frames_g43 = result[0] if result else []
    dominant_len_g43 = result[1] if result else None

    # Show all other sub-commands briefly
    for cmd, cmd_frames in sorted(g43_by_cmd.items()):
        if cmd == main_cmd:
            continue
        lengths = defaultdict(int)
        for _, _, p in cmd_frames:
            lengths[len(p)] += 1
        sample_payload = cmd_frames[0][2].hex() if cmd_frames else ""
        print(f"\n  cmd 0x{cmd.upper()} — {len(cmd_frames)} frames, "
              f"lengths={dict(lengths)}, sample: {sample_payload}")

    # ── Group 0xC3: telemetry responses (device→host, ACKs) ──
    c3_frames = []
    for pkt_i, ts, direction, frames in packets:
        for f in frames:
            d = decode_frame(f)
            if d and d[0] == 0xC3:
                c3_frames.append((pkt_i, ts, d[2]))

    print(f"\n[Group 0xC3 — device responses (ACK/echo): {len(c3_frames)} received]")
    c3_by_cmd = defaultdict(list)
    for pkt_i, ts, p in c3_frames:
        cmd_key = p[:2].hex() if len(p) >= 2 else p.hex()
        c3_by_cmd[cmd_key].append((pkt_i, ts, p))
    print(f"  Sub-commands: { {k: len(v) for k, v in c3_by_cmd.items()} }")

    return {
        "g43_main": main_frames_g43,
        "dominant_len": dominant_len_g43,
        "g43_by_cmd": g43_by_cmd,
        "g40": g40_unique,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Cross-capture comparison
# ──────────────────────────────────────────────────────────────────────────────

def compare_captures(label_a: str, data_a: dict, label_b: str, data_b: dict):
    """Print side-by-side byte variance comparison between two captures."""
    print(f"\n{'='*70}")
    print(f"COMPARISON: {label_a}  vs  {label_b}")
    print(f"{'='*70}")

    frames_a = data_a.get("g43_main", [])
    frames_b = data_b.get("g43_main", [])

    if not frames_a or not frames_b:
        print("  One or both captures have no dominant-length telemetry frames.")
        return

    len_a = data_a.get("dominant_len") or 0
    len_b = data_b.get("dominant_len") or 0
    max_len = max(len_a, len_b)

    print(f"\n  A: {len(frames_a)} frames, payload len={len_a}")
    print(f"  B: {len(frames_b)} frames, payload len={len_b}")

    if len_a != len_b:
        print(f"\n  *** Payload lengths differ ({len_a} vs {len_b}) — "
              f"layout may be dashboard-specific! ***\n")
    else:
        print(f"\n  Payload lengths match ({len_a} bytes)\n")

    print(f"  {'Byte':>4}  {'A range':>12}  {'A uniq':>6}  "
          f"{'B range':>12}  {'B uniq':>6}  Notes")
    for bi in range(min(max_len, 40)):
        vals_a = [p[bi] for _, _, p in frames_a if len(p) > bi]
        vals_b = [p[bi] for _, _, p in frames_b if len(p) > bi]

        if not vals_a and not vals_b:
            continue

        def fmt_range(vals):
            if not vals:
                return "N/A", 0
            return f"[{min(vals):3d}..{max(vals):3d}]", len(set(vals))

        r_a, u_a = fmt_range(vals_a)
        r_b, u_b = fmt_range(vals_b)

        notes = []
        if vals_a and vals_b:
            ua = set(vals_a)
            ub = set(vals_b)
            if len(ua) == 1 and len(ub) == 1:
                if list(ua)[0] == list(ub)[0]:
                    notes.append("CONST_SAME")
                else:
                    notes.append(f"CONST_DIFF A=0x{list(ua)[0]:02X} B=0x{list(ub)[0]:02X}")
            elif len(ua) == 1:
                notes.append(f"CONST_A=0x{list(ua)[0]:02X}")
            elif len(ub) == 1:
                notes.append(f"CONST_B=0x{list(ub)[0]:02X}")

            # Flag dramatically different variance
            if u_a > 5 and u_b == 1:
                notes.append("VARIES_A_only")
            elif u_b > 5 and u_a == 1:
                notes.append("VARIES_B_only")
            elif u_a > 5 and u_b > 5:
                notes.append("varies_both")

        print(f"  [{bi:2d}]  {r_a:12s}  {u_a:6d}  {r_b:12s}  {u_b:6d}  {', '.join(notes)}")


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    script_dir = Path(__file__).parent
    if len(sys.argv) > 1:
        paths = sys.argv[1:]
        labels = [Path(p).stem for p in paths]
    else:
        paths = [str(script_dir / f) for f in DEFAULT_FILES]
        labels = [Path(f).stem for f in DEFAULT_FILES]

    results = {}
    for path, label in zip(paths, labels):
        results[label] = analyze_capture(path, label)

    label_list = list(results.keys())
    if len(label_list) >= 2:
        compare_captures(label_list[0], results[label_list[0]],
                         label_list[1], results[label_list[1]])
    if len(label_list) >= 3:
        compare_captures(label_list[1], results[label_list[1]],
                         label_list[2], results[label_list[2]])
    if len(label_list) >= 3:
        compare_captures(label_list[0], results[label_list[0]],
                         label_list[2], results[label_list[2]])


if __name__ == "__main__":
    main()
