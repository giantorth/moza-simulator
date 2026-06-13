#!/usr/bin/env python3
"""Analyze extracted moza ndjson files to compare telemetry across captures."""
import json, sys, os
from collections import Counter, defaultdict


def load_ndjson(path):
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line.startswith('{'):
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass  # skip corrupted lines
    return rows


def summarize_groups(rows, label):
    """Show which groups/cmds appear and how often."""
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"  {len(rows)} total moza packets")
    print(f"{'='*60}")

    by_group_cmd = Counter()
    for r in rows:
        key = f"{r['group']} cmd={r.get('cmd','')} dir={r['direction']}"
        by_group_cmd[key] += 1

    for key, cnt in sorted(by_group_cmd.items()):
        print(f"  {key:50s} x{cnt}")


def analyze_telem_0x43(rows, label):
    """Analyze group 0x43, cmd 7d:23 telemetry packets."""
    telem = [r for r in rows if r.get('group') == '0x43' and r.get('cmd') == '7d:23' and r['direction'] == 'out']
    if not telem:
        print(f"\n  [{label}] No 0x43/7d:23 outbound telemetry found")
        return

    print(f"\n--- {label}: 0x43/7d:23 telemetry ({len(telem)} packets) ---")

    # Check flag and const values
    flags = Counter(r.get('flag', '') for r in telem)
    const4s = Counter(r.get('const4', '') for r in telem)
    const20s = Counter(r.get('const20', '') for r in telem)
    print(f"  flag values: {dict(flags)}")
    print(f"  const4 values: {dict(const4s)}")
    print(f"  const20 values: {dict(const20s)}")

    # Parse live bytes
    live_data = []
    for r in telem:
        live_hex = r.get('live', '')
        if not live_hex:
            continue
        live_bytes = [int(b, 16) for b in live_hex.split(':')]
        live_data.append((float(r['ts']), live_bytes))

    if not live_data:
        print("  No live data bytes found")
        return

    num_bytes = len(live_data[0][1])
    print(f"  Live data: {num_bytes} bytes per packet")
    print(f"  Time span: {live_data[0][0]:.3f}s - {live_data[-1][0]:.3f}s")

    # Per-byte analysis
    print(f"\n  {'Byte':>4} | {'Min':>3} {'Max':>3} {'Unique':>6} | {'First':>5} {'Last':>5} | Sample values (first, 25%, 50%, 75%, last)")
    print(f"  {'-'*4}-+-{'-'*3}-{'-'*3}-{'-'*6}-+-{'-'*5}-{'-'*5}-+-{'-'*50}")

    for bi in range(num_bytes):
        vals = [d[1][bi] for d in live_data if bi < len(d[1])]
        if not vals:
            continue
        uniq = len(set(vals))
        q1 = vals[len(vals)//4]
        q2 = vals[len(vals)//2]
        q3 = vals[3*len(vals)//4]
        print(f"  [{bi:2d}] | {min(vals):3d} {max(vals):3d} {uniq:6d} | 0x{vals[0]:02x}  0x{vals[-1]:02x}  | 0x{vals[0]:02x} 0x{q1:02x} 0x{q2:02x} 0x{q3:02x} 0x{vals[-1]:02x}")


def analyze_telem_rpm_led(rows, label):
    """Analyze group 0x3f RPM LED telemetry."""
    rpm_led = [r for r in rows if r.get('group') == '0x3f' and r['direction'] == 'out']
    if not rpm_led:
        return

    print(f"\n--- {label}: 0x3f RPM LED ({len(rpm_led)} packets) ---")
    for r in rpm_led[:5]:
        data_hex = r.get('data', '')
        if data_hex:
            data_bytes = [int(b, 16) for b in data_hex.split(':')]
            # 8 bytes = 4 x 16-bit LE values
            if len(data_bytes) >= 8:
                vals = []
                for i in range(0, 8, 2):
                    val = data_bytes[i] | (data_bytes[i+1] << 8)
                    vals.append(val)
                print(f"  t={float(r['ts']):8.3f}s  RPM LED: {vals}")


def main():
    base = 'usb-capture/09-04-29'
    files = sorted(f for f in os.listdir(base) if f.endswith('.ndjson'))

    for fname in files:
        path = os.path.join(base, fname)
        rows = load_ndjson(path)
        label = fname.replace('.ndjson', '')
        summarize_groups(rows, label)
        analyze_telem_0x43(rows, label)
        analyze_telem_rpm_led(rows, label)


if __name__ == '__main__':
    main()
