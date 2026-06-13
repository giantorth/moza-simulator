#!/usr/bin/env python3
"""Deep analysis of telemetry byte meanings across captures."""
import json, sys, os
from collections import Counter


def load_telem(path, group='0x43', cmd='7d:23', direction='out'):
    """Load 0x43/7d:23 telemetry packets, return list of (ts, live_bytes)."""
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
            if r.get('group') != group or r.get('cmd') != cmd or r.get('direction') != direction:
                continue
            live = r.get('live', '')
            if not live:
                continue
            live_bytes = [int(b, 16) for b in live.split(':')]
            rows.append((float(r['ts']), live_bytes, r.get('flag', '')))
    return rows


def load_rpm_led(path):
    """Load 0x3f RPM LED packets."""
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
            if r.get('group') != '0x3f' or r.get('direction') != 'out':
                continue
            data = r.get('data', '')
            if not data:
                continue
            data_bytes = [int(b, 16) for b in data.split(':')]
            if len(data_bytes) >= 8:
                # cmd is first 2 bytes, then 8 data bytes = 4 x 16-bit LE
                vals = []
                for i in range(0, min(8, len(data_bytes)), 2):
                    val = data_bytes[i] | (data_bytes[i+1] << 8)
                    vals.append(val)
                rows.append((float(r['ts']), r.get('cmd', ''), vals))
    return rows


BASE = 'usb-capture/09-04-29'


def compare_rpm_simple_vs_main():
    """Compare RPM from simple-rpm dash (2-byte LE) with main dash bytes."""
    print("\n" + "="*70)
    print("  COMPARISON: 0-100 redline — simple-rpm (2B) vs main-dash (16B)")
    print("="*70)

    simple = load_telem(f'{BASE}/0-100redline-0-simple-rpm-dash.ndjson')
    main = load_telem(f'{BASE}/0-100redline-0-main-dash.ndjson')

    print(f"\n  Simple RPM: {len(simple)} packets, {simple[0][0]:.3f}s - {simple[-1][0]:.3f}s")
    print(f"  Main dash:  {len(main)} packets, {main[0][0]:.3f}s - {main[-1][0]:.3f}s")

    # Show simple RPM values (LE uint16)
    print("\n  Simple RPM dash — raw 2-byte LE uint16 RPM over time:")
    for i in range(0, len(simple), max(1, len(simple)//20)):
        ts, bts, flag = simple[i]
        rpm = bts[0] | (bts[1] << 8)
        print(f"    t={ts:8.3f}s  raw=[0x{bts[0]:02x} 0x{bts[1]:02x}]  RPM={rpm:5d}")

    # For each byte in main dash, compute correlation with RPM from time-matched simple
    print("\n  Main dash — per-byte time series (sampled):")
    print(f"  {'t':>8s}", end="")
    for bi in range(16):
        print(f"  [{bi:2d}]", end="")
    print()
    for i in range(0, len(main), max(1, len(main)//25)):
        ts, bts, flag = main[i]
        print(f"  {ts:8.3f}", end="")
        for b in bts:
            print(f"  0x{b:02x}", end="")
        print()


def compare_6thgear_simple_vs_main():
    """Compare RPM from simple-rpm dash (2-byte LE) with main dash bytes for 6th gear."""
    print("\n" + "="*70)
    print("  COMPARISON: 0-6th gear — simple-rpm (2B) vs main-dash (16B)")
    print("="*70)

    simple = load_telem(f'{BASE}/0-6thgear-0-simple-rpm-dash.ndjson')
    main = load_telem(f'{BASE}/0-6thgear-0-main-dash.ndjson')

    print(f"\n  Simple RPM: {len(simple)} packets, {simple[0][0]:.3f}s - {simple[-1][0]:.3f}s")
    print(f"  Main dash:  {len(main)} packets, {main[0][0]:.3f}s - {main[-1][0]:.3f}s")

    print("\n  Simple RPM dash — sampled RPM:")
    for i in range(0, len(simple), max(1, len(simple)//20)):
        ts, bts, flag = simple[i]
        rpm = bts[0] | (bts[1] << 8)
        print(f"    t={ts:8.3f}s  RPM={rpm:5d}")

    print("\n  Main dash — sampled bytes:")
    print(f"  {'t':>8s}", end="")
    for bi in range(16):
        print(f"  [{bi:2d}]", end="")
    print()
    for i in range(0, len(main), max(1, len(main)//25)):
        ts, bts, flag = main[i]
        print(f"  {ts:8.3f}", end="")
        for b in bts:
            print(f"  0x{b:02x}", end="")
        print()


def analyze_burn_tyres():
    """Analyze burn-tyres capture for changing tyre wear values."""
    print("\n" + "="*70)
    print("  BURN-TYRES (LMU, main dash) — looking for tyre wear changes")
    print("="*70)

    data = load_telem(f'{BASE}/burn-tyres.ndjson')
    print(f"\n  {len(data)} telemetry packets, {data[0][0]:.3f}s - {data[-1][0]:.3f}s")

    # Show full time series sampled
    print("\n  Sampled bytes over time:")
    print(f"  {'t':>8s}", end="")
    for bi in range(16):
        print(f"  [{bi:2d}]", end="")
    print("  flag")
    for i in range(0, len(data), max(1, len(data)//40)):
        ts, bts, flag = data[i]
        print(f"  {ts:8.3f}", end="")
        for b in bts:
            print(f"  0x{b:02x}", end="")
        print(f"  {flag}")

    # Per-byte analysis: check which bytes show long-term trends (tyre wear should decrease)
    print("\n  Per-byte trend analysis (first 10% vs last 10%):")
    n = len(data)
    first_10 = data[:n//10]
    last_10 = data[9*n//10:]

    for bi in range(16):
        first_vals = [d[1][bi] for d in first_10]
        last_vals = [d[1][bi] for d in last_10]
        first_avg = sum(first_vals) / len(first_vals)
        last_avg = sum(last_vals) / len(last_vals)
        delta = last_avg - first_avg
        if abs(delta) > 2:
            print(f"    Byte [{bi:2d}]: first_avg={first_avg:6.1f} last_avg={last_avg:6.1f} delta={delta:+.1f}")


def analyze_other_dash():
    """Analyze the 'other' default dash (6 bytes)."""
    print("\n" + "="*70)
    print("  OTHER DASH (6 bytes) — 0-100 redline")
    print("="*70)

    data = load_telem(f'{BASE}/0-100redline-0-other-dash.ndjson')
    print(f"\n  {len(data)} telemetry packets, {data[0][0]:.3f}s - {data[-1][0]:.3f}s")
    print(f"  Flag: {Counter(d[2] for d in data)}")

    print("\n  Sampled bytes:")
    print(f"  {'t':>8s}  [ 0]  [ 1]  [ 2]  [ 3]  [ 4]  [ 5]")
    for i in range(0, len(data), max(1, len(data)//30)):
        ts, bts, flag = data[i]
        print(f"  {ts:8.3f}", end="")
        for b in bts:
            print(f"  0x{b:02x}", end="")
        print()


def analyze_rpm_led_all():
    """Compare RPM LED values across captures."""
    print("\n" + "="*70)
    print("  RPM LED (0x3f) — cross-capture comparison")
    print("="*70)

    for fname in ['0-100redline-0-main-dash', '0-100redline-0-simple-rpm-dash',
                   '0-6thgear-0-main-dash', '0-6thgear-0-simple-rpm-dash', 'burn-tyres']:
        led = load_rpm_led(f'{BASE}/{fname}.ndjson')
        if not led:
            print(f"\n  {fname}: no RPM LED data")
            continue
        # Only show cmd=1a:00 (the one with RPM position)
        rpm_1a00 = [(ts, cmd, vals) for ts, cmd, vals in led if cmd == '1a:00']
        print(f"\n  {fname}: {len(rpm_1a00)} RPM LED (1a:00) packets")
        for i in range(0, len(rpm_1a00), max(1, len(rpm_1a00)//10)):
            ts, cmd, vals = rpm_1a00[i]
            print(f"    t={ts:8.3f}s  pos={vals[0]:4d}/1023 ({vals[0]/10.23:.1f}%)  vals={vals}")


def analyze_flag_byte():
    """Investigate what the flag byte means across captures."""
    print("\n" + "="*70)
    print("  FLAG BYTE analysis across all captures")
    print("="*70)

    for fname in ['0-100redline-0-main-dash', '0-100redline-0-other-dash',
                   '0-100redline-0-simple-rpm-dash',
                   '0-6thgear-0-main-dash', '0-6thgear-0-simple-rpm-dash',
                   'burn-tyres']:
        data = load_telem(f'{BASE}/{fname}.ndjson')
        if not data:
            continue
        flags = Counter(d[2] for d in data)
        nbytes = len(data[0][1]) if data else 0
        print(f"  {fname}: {nbytes}B live, flags={dict(flags)}")


if __name__ == '__main__':
    analyze_flag_byte()
    compare_rpm_simple_vs_main()
    compare_6thgear_simple_vs_main()
    analyze_other_dash()
    analyze_burn_tyres()
    analyze_rpm_led_all()
