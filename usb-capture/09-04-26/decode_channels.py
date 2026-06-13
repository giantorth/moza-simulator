#!/usr/bin/env python3
"""
Test 12-bit nibble packing hypothesis on main-dash telemetry.
For each byte pair [2i, 2i+1]:
  12-bit value = byte[2i+1] << 4 | byte[2i] >> 4
  4-bit value  = byte[2i] & 0x0f
Cross-reference with RPM LED within the same capture.
"""
import json, struct


def load_telem(path, group='0x43', cmd='7d:23', direction='out'):
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
            bts = [int(b, 16) for b in live.split(':')]
            rows.append((float(r['ts']), bts))
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
                rpm_pos = data[0] | (data[1] << 8)
                rpm_max = data[4] | (data[5] << 8)
                rows.append((float(r['ts']), rpm_pos, rpm_max))
    return rows


def decode_12bit(lo_byte, hi_byte):
    """12-bit value from a byte pair."""
    return (hi_byte << 4) | (lo_byte >> 4)


def decode_4bit(lo_byte):
    """4-bit secondary value from low nibble."""
    return lo_byte & 0x0f


BASE = 'usb-capture/09-04-29'


def verify_speed_encoding():
    """Verify speed = (byte[13]<<4 | byte[12]>>4) / 10 km/h in all captures."""
    print("=" * 70)
    print("  SPEED VERIFICATION: v6 = decode_12bit(byte[12], byte[13]) / 10 km/h")
    print("  User said: redline at 107-108 km/h in 1st gear")
    print("=" * 70)

    for fname in ['0-100redline-0-main-dash', '0-6thgear-0-main-dash', 'burn-tyres']:
        data = load_telem(f'{BASE}/{fname}.ndjson')
        if not data or len(data[0][1]) < 16:
            continue

        # Get min/max/peak of v6
        v6_vals = [decode_12bit(d[1][12], d[1][13]) for d in data]
        v6_max_idx = v6_vals.index(max(v6_vals))
        v6_max_ts = data[v6_max_idx][0]
        print(f"\n  {fname}:")
        print(f"    v6 range: {min(v6_vals)} - {max(v6_vals)} (raw 12-bit)")
        print(f"    speed range: {min(v6_vals)/10:.1f} - {max(v6_vals)/10:.1f} km/h")
        print(f"    peak speed at t={v6_max_ts:.3f}s")

        # Time series sample
        print(f"\n    {'t':>8s}  {'spd_kmh':>7s}  {'gear?':>5s}  RPM_LED%")
        rpm_led = load_rpm_led(f'{BASE}/{fname}.ndjson')
        rpm_dict = {round(ts, 1): pct for ts, pos, mx in rpm_led for pct in [pos / max(mx, 1) * 100]}

        for i in range(0, len(data), max(1, len(data) // 30)):
            ts, bts = data[i]
            v6 = decode_12bit(bts[12], bts[13])
            gear = decode_4bit(bts[12])
            # Find closest RPM LED
            rpm_pct = ""
            if rpm_led:
                closest = min(rpm_led, key=lambda x: abs(x[0] - ts))
                if abs(closest[0] - ts) < 1.0:
                    rpm_pct = f"{closest[1] / max(closest[2], 1) * 100:5.1f}%"
            print(f"    {ts:8.3f}  {v6/10:7.1f}  {gear:5d}  {rpm_pct}")


def decode_all_12bit_channels():
    """Decode all 8 byte pairs as 12-bit + 4-bit for 0-100 main dash."""
    print("\n" + "=" * 70)
    print("  ALL 12-BIT CHANNELS (0-100 main dash)")
    print("  v_i = decode_12bit(byte[2i], byte[2i+1])  |  n_i = byte[2i] & 0x0f")
    print("=" * 70)

    data = load_telem(f'{BASE}/0-100redline-0-main-dash.ndjson')
    rpm_led = load_rpm_led(f'{BASE}/0-100redline-0-main-dash.ndjson')

    print(f"\n  {'t':>8s} {'RPM%':>5s}", end="")
    for i in range(8):
        print(f"  v{i:d}(12b)", end="")
    print("  |", end="")
    for i in range(8):
        print(f" n{i}", end="")
    print()

    for idx in range(0, len(data), max(1, len(data) // 25)):
        ts, bts = data[idx]
        if len(bts) < 16:
            continue
        # RPM LED
        rpm_pct = "   - "
        if rpm_led:
            closest = min(rpm_led, key=lambda x: abs(x[0] - ts))
            if abs(closest[0] - ts) < 1.0:
                rpm_pct = f"{closest[1] / max(closest[2], 1) * 100:5.1f}"

        print(f"  {ts:8.3f} {rpm_pct}", end="")
        for i in range(8):
            v = decode_12bit(bts[2 * i], bts[2 * i + 1])
            print(f"  {v:7d}", end="")
        print("  |", end="")
        for i in range(8):
            n = decode_4bit(bts[2 * i])
            print(f"  {n:2d}", end="")
        print()


def decode_all_12bit_6thgear():
    """Same for 6th gear capture."""
    print("\n" + "=" * 70)
    print("  ALL 12-BIT CHANNELS (0-6thgear main dash)")
    print("=" * 70)

    data = load_telem(f'{BASE}/0-6thgear-0-main-dash.ndjson')
    rpm_led = load_rpm_led(f'{BASE}/0-6thgear-0-main-dash.ndjson')

    print(f"\n  {'t':>8s} {'RPM%':>5s}", end="")
    for i in range(8):
        print(f"  v{i:d}(12b)", end="")
    print("  |", end="")
    for i in range(8):
        print(f" n{i}", end="")
    print()

    for idx in range(0, len(data), max(1, len(data) // 30)):
        ts, bts = data[idx]
        if len(bts) < 16:
            continue
        rpm_pct = "   - "
        if rpm_led:
            closest = min(rpm_led, key=lambda x: abs(x[0] - ts))
            if abs(closest[0] - ts) < 1.0:
                rpm_pct = f"{closest[1] / max(closest[2], 1) * 100:5.1f}"

        print(f"  {ts:8.3f} {rpm_pct}", end="")
        for i in range(8):
            v = decode_12bit(bts[2 * i], bts[2 * i + 1])
            print(f"  {v:7d}", end="")
        print("  |", end="")
        for i in range(8):
            n = decode_4bit(bts[2 * i])
            print(f"  {n:2d}", end="")
        print()


def decode_all_12bit_burntyres():
    """Same for burn-tyres capture."""
    print("\n" + "=" * 70)
    print("  ALL 12-BIT CHANNELS (burn-tyres, LMU)")
    print("=" * 70)

    data = load_telem(f'{BASE}/burn-tyres.ndjson')

    print(f"\n  {'t':>8s}", end="")
    for i in range(8):
        print(f"  v{i:d}(12b)", end="")
    print("  |", end="")
    for i in range(8):
        print(f" n{i}", end="")
    print()

    for idx in range(0, len(data), max(1, len(data) // 35)):
        ts, bts = data[idx]
        if len(bts) < 16:
            continue
        print(f"  {ts:8.3f}", end="")
        for i in range(8):
            v = decode_12bit(bts[2 * i], bts[2 * i + 1])
            print(f"  {v:7d}", end="")
        print("  |", end="")
        for i in range(8):
            n = decode_4bit(bts[2 * i])
            print(f"  {n:2d}", end="")
        print()


def compare_with_other_dash():
    """Compare the 6-byte 'other dash' using same 12-bit decode."""
    print("\n" + "=" * 70)
    print("  OTHER DASH (6 bytes) — 12-bit decode attempt")
    print("=" * 70)

    data = load_telem(f'{BASE}/0-100redline-0-other-dash.ndjson')
    if not data:
        print("  No data")
        return

    nbytes = len(data[0][1])
    npairs = nbytes // 2
    print(f"  {nbytes} bytes = {npairs} pairs")

    print(f"\n  {'t':>8s}", end="")
    for i in range(npairs):
        print(f"  v{i:d}(12b)", end="")
    print("  |", end="")
    for i in range(npairs):
        print(f" n{i}", end="")
    print()

    for idx in range(0, len(data), max(1, len(data) // 25)):
        ts, bts = data[idx]
        print(f"  {ts:8.3f}", end="")
        for i in range(npairs):
            if 2 * i + 1 < len(bts):
                v = decode_12bit(bts[2 * i], bts[2 * i + 1])
                print(f"  {v:7d}", end="")
        print("  |", end="")
        for i in range(npairs):
            if 2 * i < len(bts):
                n = decode_4bit(bts[2 * i])
                print(f"  {n:2d}", end="")
        print()


if __name__ == '__main__':
    verify_speed_encoding()
    decode_all_12bit_channels()
    decode_all_12bit_6thgear()
    decode_all_12bit_burntyres()
    compare_with_other_dash()
