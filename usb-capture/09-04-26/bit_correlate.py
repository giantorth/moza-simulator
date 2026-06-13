#!/usr/bin/env python3
"""
Bit-level correlation analysis.
For each of the 128 bits in the 16-byte telemetry, compute correlation with:
1. RPM LED percentage (known ground truth from same capture)
2. Monotonic time (to find counter/time channels)
3. Constant detection (bits that never change)
"""
import json, math
from collections import Counter


def load_telem_with_flag(path, majority_flag_only=True):
    rows = []
    flag_counts = Counter()
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
            flag = r.get('flag', '')
            flag_counts[flag] += 1
            rows.append((float(r['ts']), flag, bts))

    if majority_flag_only:
        maj = flag_counts.most_common(1)[0][0]
        rows = [(ts, f, bts) for ts, f, bts in rows if f == maj and len(bts) >= 16]

    return rows


def load_rpm_led(path):
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
            if r.get('group') != '0x3f' or r.get('cmd') != '1a:00' or r.get('direction') != 'out':
                continue
            payload = r.get('payload', '')
            if not payload:
                continue
            parts = [int(b, 16) for b in payload.split(':')]
            data = parts[6:-1]
            if len(data) >= 6:
                pos = data[0] | (data[1] << 8)
                mx = data[4] | (data[5] << 8)
                pct = pos / max(mx, 1) * 100
                rows.append((float(r['ts']), pct))
    return rows


def get_bit(byte_array, bit_index):
    """Get bit at position bit_index (0 = LSB of byte 0)."""
    byte_idx = bit_index // 8
    bit_pos = bit_index % 8
    return (byte_array[byte_idx] >> bit_pos) & 1


def extract_bits(byte_array, start_bit, num_bits):
    """Extract num_bits starting from start_bit (LSB-first)."""
    val = 0
    for i in range(num_bits):
        val |= get_bit(byte_array, start_bit + i) << i
    return val


def correlate(x, y):
    """Pearson correlation coefficient."""
    n = len(x)
    if n < 3:
        return 0
    mx = sum(x) / n
    my = sum(y) / n
    sx = math.sqrt(sum((xi - mx) ** 2 for xi in x) / n)
    sy = math.sqrt(sum((yi - my) ** 2 for yi in y) / n)
    if sx == 0 or sy == 0:
        return 0
    return sum((xi - mx) * (yi - my) for xi, yi in zip(x, y)) / (n * sx * sy)


BASE = 'usb-capture/09-04-29'


def find_rpm_bits():
    """Find which bit ranges correlate with RPM LED."""
    print("=" * 70)
    print("  BIT-LEVEL RPM CORRELATION (0-100 main dash)")
    print("=" * 70)

    telem = load_telem_with_flag(f'{BASE}/0-100redline-0-main-dash.ndjson')
    rpm_led = load_rpm_led(f'{BASE}/0-100redline-0-main-dash.ndjson')

    if not rpm_led:
        print("  No RPM LED data!")
        return

    # For each telem packet, find nearest RPM LED value
    rpm_at_telem = []
    ri = 0
    for ts, _, bts in telem:
        while ri < len(rpm_led) - 1 and abs(rpm_led[ri + 1][0] - ts) < abs(rpm_led[ri][0] - ts):
            ri += 1
        rpm_at_telem.append(rpm_led[ri][1])

    # Try various bit ranges (sliding window of different widths)
    print("\n  Testing all possible N-bit unsigned values (N=8,10,12,16) at each bit offset:")
    print(f"  {'bits':>12s}  {'corr':>6s}  {'range':>20s}  interpretation")

    best_results = []
    for width in [8, 10, 12, 16]:
        for start in range(128 - width + 1):
            vals = [extract_bits(bts, start, width) for _, _, bts in telem]
            c = correlate(vals, rpm_at_telem)
            if abs(c) > 0.7:
                mn, mx = min(vals), max(vals)
                best_results.append((abs(c), c, start, width, mn, mx))

    best_results.sort(reverse=True)
    for _, c, start, width, mn, mx in best_results[:20]:
        byte_s = start // 8
        bit_s = start % 8
        print(f"  bits[{start:3d}:{start + width:3d}]  {c:+.3f}  {mn:6d}-{mx:6d}  (byte[{byte_s}].{bit_s}..byte[{(start + width - 1) // 8}])")


def find_speed_bits():
    """Find which bit ranges encode speed using 6th gear capture."""
    print("\n" + "=" * 70)
    print("  BIT-LEVEL SPEED CORRELATION (6th gear)")
    print("  Using time-proxy: speed should increase then decrease")
    print("=" * 70)

    telem = load_telem_with_flag(f'{BASE}/0-6thgear-0-main-dash.ndjson')

    # Speed proxy: rises from 0 to max around t=30, then drops back to 0
    # Use a triangle wave
    times = [ts for ts, _, _ in telem]
    max_time = max(times)
    # Peak at ~60% of capture (roughly where max speed is)
    speed_proxy = [t / (0.65 * max_time) if t < 0.65 * max_time else (max_time - t) / (0.35 * max_time) for t in times]
    speed_proxy = [max(0, s) for s in speed_proxy]

    print(f"\n  Testing all N-bit values for speed correlation:")
    print(f"  {'bits':>12s}  {'corr':>6s}  {'range':>20s}")

    best = []
    for width in [12, 16]:
        for start in range(128 - width + 1):
            vals = [extract_bits(bts, start, width) for _, _, bts in telem]
            c = correlate(vals, speed_proxy)
            if abs(c) > 0.8:
                mn, mx = min(vals), max(vals)
                best.append((abs(c), c, start, width, mn, mx))

    best.sort(reverse=True)
    for _, c, start, width, mn, mx in best[:15]:
        byte_s = start // 8
        print(f"  bits[{start:3d}:{start + width:3d}]  {c:+.3f}  {mn:6d}-{mx:6d}  (byte[{byte_s}]..byte[{(start + width - 1) // 8}])")


def find_counter_bits():
    """Find bit ranges that form a monotonic counter (= CurrentLapTime)."""
    print("\n" + "=" * 70)
    print("  MONOTONIC COUNTER / LAPTIME DETECTION (0-100 main dash)")
    print("=" * 70)

    telem = load_telem_with_flag(f'{BASE}/0-100redline-0-main-dash.ndjson')
    times = [ts for ts, _, _ in telem]

    print(f"\n  {'bits':>12s}  {'corr':>6s}  {'range':>20s}  {'monotonic%':>10s}")

    best = []
    for width in [8, 10, 12, 16, 24, 32]:
        for start in range(128 - width + 1):
            vals = [extract_bits(bts, start, width) for _, _, bts in telem]
            c = correlate(vals, times)
            if c > 0.9:
                # Check monotonicity
                mono = sum(1 for i in range(1, len(vals)) if vals[i] >= vals[i - 1]) / (len(vals) - 1) * 100
                mn, mx = min(vals), max(vals)
                best.append((c, start, width, mn, mx, mono))

    best.sort(reverse=True)
    for c, start, width, mn, mx, mono in best[:15]:
        byte_s = start // 8
        print(f"  bits[{start:3d}:{start + width:3d}]  {c:+.3f}  {mn:6d}-{mx:6d}  {mono:8.1f}%  (byte[{byte_s}]..byte[{(start + width - 1) // 8}])")


def find_constant_bits():
    """Find bits that are constant across all packets."""
    print("\n" + "=" * 70)
    print("  CONSTANT BIT DETECTION (0-100 main dash, majority flag)")
    print("=" * 70)

    telem = load_telem_with_flag(f'{BASE}/0-100redline-0-main-dash.ndjson')

    const_bits = []
    for bit in range(128):
        vals = set(get_bit(bts, bit) for _, _, bts in telem)
        if len(vals) == 1:
            const_bits.append((bit, vals.pop()))

    # Group into ranges
    if const_bits:
        print(f"\n  {len(const_bits)} constant bits out of 128:")
        ranges = []
        start = const_bits[0][0]
        prev = start
        val = const_bits[0][1]
        for bit, v in const_bits[1:]:
            if bit == prev + 1 and v == val:
                prev = bit
            else:
                ranges.append((start, prev, val))
                start = bit
                prev = bit
                val = v
        ranges.append((start, prev, val))

        for s, e, v in ranges:
            byte_s = s // 8
            byte_e = e // 8
            print(f"    bits [{s:3d}:{e + 1:3d}] = {v} ({e - s + 1:2d} bits, byte[{byte_s}]-byte[{byte_e}])")


def find_tyre_wear_bits():
    """Find bits that show long-term decreasing trend in burn-tyres capture."""
    print("\n" + "=" * 70)
    print("  TYRE WEAR DETECTION (burn-tyres, looking for decreasing trends)")
    print("=" * 70)

    telem = load_telem_with_flag(f'{BASE}/burn-tyres.ndjson')
    times = [ts for ts, _, _ in telem]

    # For tyre wear: expect 4 channels that decrease over time
    # Correlate negatively with time
    print(f"\n  {'bits':>12s}  {'corr':>6s}  {'range':>20s}  notes")

    results = []
    for width in [7, 8, 10]:
        for start in range(128 - width + 1):
            vals = [extract_bits(bts, start, width) for _, _, bts in telem]
            c = correlate(vals, times)
            if c < -0.5:  # negatively correlated = decreasing
                mn, mx = min(vals), max(vals)
                results.append((c, start, width, mn, mx))

    results.sort()  # most negative first
    for c, start, width, mn, mx in results[:20]:
        byte_s = start // 8
        print(f"  bits[{start:3d}:{start + width:3d}]  {c:+.3f}  {mn:6d}-{mx:6d}  (byte[{byte_s}]..byte[{(start + width - 1) // 8}])")


if __name__ == '__main__':
    find_constant_bits()
    find_counter_bits()
    find_rpm_bits()
    find_speed_bits()
    find_tyre_wear_bits()
