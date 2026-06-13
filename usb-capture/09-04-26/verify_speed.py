#!/usr/bin/env python3
"""Verify speed encoding and investigate flag byte changes."""
import json, struct


def load_all_0x43(path):
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line.startswith('{'):
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if r.get('group') != '0x43' or r.get('cmd') != '7d:23' or r.get('direction') != 'out':
                continue
            live = r.get('live', '')
            if not live:
                continue
            bts = [int(b, 16) for b in live.split(':')]
            rows.append((float(r['ts']), r.get('flag', ''), bts))
    return rows


BASE = 'usb-capture/09-04-29'


def check_flag_vs_data():
    """Check if data layout changes when flag byte changes."""
    print("=" * 70)
    print("  FLAG BYTE CHANGES vs DATA LAYOUT")
    print("=" * 70)

    for fname in ['0-100redline-0-main-dash', '0-6thgear-0-main-dash', 'burn-tyres']:
        data = load_all_0x43(f'{BASE}/{fname}.ndjson')
        if not data:
            continue
        print(f"\n--- {fname} ---")

        # Group by flag
        by_flag = {}
        for ts, flag, bts in data:
            by_flag.setdefault(flag, []).append((ts, bts))

        for flag, rows in sorted(by_flag.items()):
            print(f"  Flag {flag}: {len(rows)} packets, live_len={len(rows[0][1])}")
            # Show a sample
            if rows:
                ts, bts = rows[0]
                print(f"    First: t={ts:.3f} bytes={':'.join(f'{b:02x}' for b in bts)}")
                ts, bts = rows[-1]
                print(f"    Last:  t={ts:.3f} bytes={':'.join(f'{b:02x}' for b in bts)}")


def verify_speed_all_packets():
    """Check speed = (byte[13]<<4 | byte[12]>>4) / 10 for majority flag packets only."""
    print("\n" + "=" * 70)
    print("  SPEED VERIFICATION (majority flag only)")
    print("=" * 70)

    data = load_all_0x43(f'{BASE}/0-100redline-0-main-dash.ndjson')
    # Find majority flag
    from collections import Counter
    flags = Counter(f for _, f, _ in data)
    majority_flag = flags.most_common(1)[0][0]
    print(f"  Majority flag: {majority_flag} ({flags[majority_flag]}/{len(data)} packets)")

    filtered = [(ts, bts) for ts, flag, bts in data if flag == majority_flag and len(bts) >= 16]
    print(f"  Filtered to {len(filtered)} packets")

    # Speed time series
    speeds = [(ts, (bts[13] << 4 | bts[12] >> 4) / 10) for ts, bts in filtered]
    print(f"\n  Speed range: {min(s for _, s in speeds):.1f} - {max(s for _, s in speeds):.1f} km/h")
    print(f"  Speed at start: {speeds[0][1]:.1f} km/h")
    print(f"  Speed at end: {speeds[-1][1]:.1f} km/h")
    peak_idx = max(range(len(speeds)), key=lambda i: speeds[i][1])
    print(f"  Peak speed: {speeds[peak_idx][1]:.1f} km/h at t={speeds[peak_idx][0]:.3f}s")

    # Check that byte[12] & 0x0f is consistent
    lo_nibs = set(bts[12] & 0x0f for _, bts in filtered)
    print(f"  byte[12] low nibble values: {sorted(lo_nibs)}")

    # Separate by low nibble value
    for nib in sorted(lo_nibs):
        subset = [(ts, bts) for ts, bts in filtered if (bts[12] & 0x0f) == nib]
        if subset:
            t_range = f"t={subset[0][0]:.1f}-{subset[-1][0]:.1f}"
            print(f"    nibble={nib}: {len(subset)} packets, {t_range}")


def verify_speed_6thgear():
    """Verify speed encoding for 6th gear capture."""
    print("\n" + "=" * 70)
    print("  SPEED IN 6TH GEAR CAPTURE")
    print("=" * 70)

    data = load_all_0x43(f'{BASE}/0-6thgear-0-main-dash.ndjson')
    from collections import Counter
    flags = Counter(f for _, f, _ in data)
    majority_flag = flags.most_common(1)[0][0]
    filtered = [(ts, bts) for ts, flag, bts in data if flag == majority_flag and len(bts) >= 16]
    print(f"  {len(filtered)} packets with flag {majority_flag}")

    speeds = [(ts, (bts[13] << 4 | bts[12] >> 4) / 10) for ts, bts in filtered]
    print(f"  Speed range: {min(s for _, s in speeds):.1f} - {max(s for _, s in speeds):.1f} km/h")
    peak_idx = max(range(len(speeds)), key=lambda i: speeds[i][1])
    print(f"  Peak speed: {speeds[peak_idx][1]:.1f} km/h at t={speeds[peak_idx][0]:.3f}s")

    # byte[12] low nibble values — should show gears 1-6
    lo_nibs = Counter(bts[12] & 0x0f for _, bts in filtered)
    print(f"  byte[12] low nibble values: {dict(lo_nibs)}")

    # Show speed vs low nibble over time
    print(f"\n  {'t':>8s}  {'spd':>6s}  {'nib':>3s}  bytes[10:16]")
    for i in range(0, len(filtered), max(1, len(filtered) // 30)):
        ts, bts = filtered[i]
        spd = (bts[13] << 4 | bts[12] >> 4) / 10
        nib = bts[12] & 0x0f
        hex_tail = ':'.join(f'{b:02x}' for b in bts[10:16])
        print(f"  {ts:8.3f}  {spd:6.1f}  {nib:3d}  {hex_tail}")


def try_all_channels_dashboard_order():
    """Try to match all 16 channels using dashboard order with various bit widths."""
    print("\n" + "=" * 70)
    print("  BIT BUDGET ANALYSIS")
    print("  Total: 128 bits for 16 channels")
    print("=" * 70)

    # Known compression types and their probable bit widths
    # Let's compute total for various assumptions
    channels = [
        ("SpeedKmh", "float_6000_1"),
        ("Throttle", "float_001"),
        ("Brake", "float_001"),
        ("Gear", "int30"),
        ("Rpm", "uint16_t"),
        ("CurrentLapTime", "float"),
        ("LastLapTime", "float"),
        ("BestLapTime", "float"),
        ("GAP", "float"),
        ("FuelRemainder", "percent_1"),
        ("ErsState", "uint3"),
        ("TyreWearFL", "percent_1"),
        ("TyreWearFR", "percent_1"),
        ("TyreWearRL", "percent_1"),
        ("TyreWearRR", "percent_1"),
        ("DrsState", "bool"),
    ]

    # Try to find bit widths that sum to 128
    # Known: uint16_t=16, bool=1, uint3=3
    # Confirmed from data: SpeedKmh uses ~16 bits (12-bit value in bytes 12-13)

    scenarios = [
        {"float": 8, "float_6000_1": 16, "float_001": 10, "int30": 5, "percent_1": 7},
        {"float": 10, "float_6000_1": 16, "float_001": 10, "int30": 4, "percent_1": 7},
        {"float": 12, "float_6000_1": 16, "float_001": 8, "int30": 4, "percent_1": 7},
        {"float": 16, "float_6000_1": 16, "float_001": 10, "int30": 4, "percent_1": 7},
        {"float": 8, "float_6000_1": 12, "float_001": 10, "int30": 5, "percent_1": 7},
        {"float": 10, "float_6000_1": 12, "float_001": 10, "int30": 4, "percent_1": 7},
        {"float": 8, "float_6000_1": 16, "float_001": 7, "int30": 4, "percent_1": 7},
        {"float": 8, "float_6000_1": 16, "float_001": 10, "int30": 4, "percent_1": 7},
        {"float": 10, "float_6000_1": 16, "float_001": 7, "int30": 5, "percent_1": 7},
        {"float": 10, "float_6000_1": 12, "float_001": 7, "int30": 5, "percent_1": 7},
    ]

    fixed = {"uint16_t": 16, "bool": 1, "uint3": 3}

    for scenario in scenarios:
        total = 0
        for name, comp in channels:
            if comp in fixed:
                bits = fixed[comp]
            elif comp in scenario:
                bits = scenario[comp]
            else:
                bits = 0
            total += bits
        if total == 128:
            print(f"\n  *** MATCH: {scenario} (total=128) ***")
            cum = 0
            for name, comp in channels:
                bits = fixed.get(comp, scenario.get(comp, 0))
                start_byte = cum // 8
                start_bit = cum % 8
                print(f"    {name:20s} ({comp:15s}): {bits:3d} bits, starts at byte {start_byte:2d} bit {start_bit}")
                cum += bits
        elif abs(total - 128) <= 2:
            print(f"  Close: {scenario} → total={total}")


if __name__ == '__main__':
    check_flag_vs_data()
    verify_speed_all_packets()
    verify_speed_6thgear()
    try_all_channels_dashboard_order()
