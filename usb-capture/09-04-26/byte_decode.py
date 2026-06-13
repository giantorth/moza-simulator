#!/usr/bin/env python3
"""
Try various byte decodings on the 16-byte main-dash telemetry to find
the right interpretation. Cross-reference against simple-rpm (known RPM values).
"""
import json, struct, sys


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
            live_bytes = bytes([int(b, 16) for b in live.split(':')])
            if len(live_bytes) >= 2:
                rows.append((float(r['ts']), live_bytes))
    return rows


BASE = 'usb-capture/09-04-29'


def check_nibble_patterns():
    """Check which bytes show low-nibble patterns (always 0, or always fixed)."""
    print("="*70)
    print("  NIBBLE PATTERN ANALYSIS (0-100 main dash)")
    print("="*70)

    data = load_telem(f'{BASE}/0-100redline-0-main-dash.ndjson')

    for bi in range(16):
        low_nibs = set()
        high_nibs = set()
        for ts, bts in data:
            if bi < len(bts):
                low_nibs.add(bts[bi] & 0x0f)
                high_nibs.add(bts[bi] >> 4)
        print(f"  byte[{bi:2d}]: low_nibble has {len(low_nibs):2d} unique values: {sorted(low_nibs)[:8]}{'...' if len(low_nibs) > 8 else ''}")
        print(f"            high_nibble has {len(high_nibs):2d} unique values: {sorted(high_nibs)[:8]}{'...' if len(high_nibs) > 8 else ''}")


def check_bit7_toggle():
    """For each byte, check if bit 7 shows an alternating/toggle pattern."""
    print("\n" + "="*70)
    print("  BIT 7 TOGGLE ANALYSIS (all 16-byte captures)")
    print("="*70)

    for fname in ['0-100redline-0-main-dash', '0-6thgear-0-main-dash', 'burn-tyres']:
        data = load_telem(f'{BASE}/{fname}.ndjson')
        print(f"\n  {fname} ({len(data)} packets):")

        for bi in range(16):
            vals = [d[1][bi] for d in data if bi < len(d[1])]
            # Check if bit 7 alternates
            bit7_vals = [v >> 7 for v in vals]
            transitions = sum(1 for i in range(1, len(bit7_vals)) if bit7_vals[i] != bit7_vals[i-1])
            low7_unique = len(set(v & 0x7f for v in vals))
            full_unique = len(set(vals))

            # A toggle byte: has both 0 and 1 in bit7, and stripping bit7 reduces unique count
            has_both_bit7 = 0 in set(bit7_vals) and 1 in set(bit7_vals)
            if has_both_bit7:
                print(f"    byte[{bi:2d}]: TOGGLE  full_unique={full_unique:3d} stripped_unique={low7_unique:3d} transitions={transitions:4d} bit7_0={bit7_vals.count(0)} bit7_1={bit7_vals.count(1)}")


def try_float_decodings():
    """Try interpreting 4-byte groups as IEEE 754 floats (both endians)."""
    print("\n" + "="*70)
    print("  IEEE 754 FLOAT DECODING (0-100 main dash, sampled)")
    print("="*70)

    data = load_telem(f'{BASE}/0-100redline-0-main-dash.ndjson')

    print("\n  Little-endian floats (bytes [0:4], [4:8], [8:12], [12:16]):")
    print(f"  {'t':>8s}  {'float0':>12s}  {'float1':>12s}  {'float2':>12s}  {'float3':>12s}")
    for i in range(0, len(data), max(1, len(data)//20)):
        ts, bts = data[i]
        floats = []
        for j in range(0, 16, 4):
            try:
                f = struct.unpack('<f', bts[j:j+4])[0]
                floats.append(f)
            except:
                floats.append(None)
        vals = [f'{v:12.4f}' if v is not None and abs(v) < 1e6 else f'{v:12.2e}' if v is not None else '         N/A' for v in floats]
        print(f"  {ts:8.3f}  {'  '.join(vals)}")

    print("\n  Big-endian floats (bytes [0:4], [4:8], [8:12], [12:16]):")
    print(f"  {'t':>8s}  {'float0':>12s}  {'float1':>12s}  {'float2':>12s}  {'float3':>12s}")
    for i in range(0, len(data), max(1, len(data)//20)):
        ts, bts = data[i]
        floats = []
        for j in range(0, 16, 4):
            try:
                f = struct.unpack('>f', bts[j:j+4])[0]
                floats.append(f)
            except:
                floats.append(None)
        vals = [f'{v:12.4f}' if v is not None and abs(v) < 1e6 else f'{v:12.2e}' if v is not None else '         N/A' for v in floats]
        print(f"  {ts:8.3f}  {'  '.join(vals)}")


def try_12bit_packing():
    """Try interpreting as 12-bit packed values (nibble packing)."""
    print("\n" + "="*70)
    print("  12-BIT PACKING ATTEMPT (0-100 main dash)")
    print("="*70)
    print("  Hypothesis: values are 12 bits, stored as [hi_byte, (lo_nibble << 4) | next_hi_nibble]")

    data = load_telem(f'{BASE}/0-100redline-0-main-dash.ndjson')

    # Try: value = (byte[N+1] << 4) | (byte[N] >> 4) — adjacent bytes share nibble
    print("\n  Attempt: val_i = byte[2i+1] << 4 | byte[2i] >> 4")
    print(f"  {'t':>8s}", end="")
    for vi in range(8):
        print(f"  {'v'+str(vi):>5s}", end="")
    print()
    for i in range(0, len(data), max(1, len(data)//20)):
        ts, bts = data[i]
        print(f"  {ts:8.3f}", end="")
        for vi in range(8):
            hi = bts[2*vi+1]
            lo = bts[2*vi] >> 4
            val = (hi << 4) | lo
            print(f"  {val:5d}", end="")
        print()


def try_le_uint16_pairs():
    """Try interpreting as LE uint16 pairs."""
    print("\n" + "="*70)
    print("  LE UINT16 PAIRS (0-100 main dash)")
    print("="*70)

    data = load_telem(f'{BASE}/0-100redline-0-main-dash.ndjson')

    print(f"  {'t':>8s}", end="")
    for vi in range(8):
        idx = vi * 2
        print(f"  [{idx:d}-{idx+1}]", end="")
    print()
    for i in range(0, len(data), max(1, len(data)//20)):
        ts, bts = data[i]
        print(f"  {ts:8.3f}", end="")
        for vi in range(8):
            val = bts[2*vi] | (bts[2*vi+1] << 8)
            print(f"  {val:6d}", end="")
        print()

    # Also do burn-tyres
    print("\n  SAME FOR BURN-TYRES:")
    data = load_telem(f'{BASE}/burn-tyres.ndjson')
    print(f"  {'t':>8s}", end="")
    for vi in range(8):
        idx = vi * 2
        print(f"  [{idx:d}-{idx+1}]", end="")
    print()
    for i in range(0, len(data), max(1, len(data)//25)):
        ts, bts = data[i]
        if len(bts) < 16:
            continue
        print(f"  {ts:8.3f}", end="")
        for vi in range(8):
            val = bts[2*vi] | (bts[2*vi+1] << 8)
            print(f"  {val:6d}", end="")
        print()


def try_be_uint16_pairs():
    """Try interpreting as BE uint16 pairs."""
    print("\n" + "="*70)
    print("  BE UINT16 PAIRS (0-100 main dash)")
    print("="*70)

    data = load_telem(f'{BASE}/0-100redline-0-main-dash.ndjson')

    print(f"  {'t':>8s}", end="")
    for vi in range(8):
        idx = vi * 2
        print(f"  [{idx:d}-{idx+1}]", end="")
    print()
    for i in range(0, len(data), max(1, len(data)//20)):
        ts, bts = data[i]
        print(f"  {ts:8.3f}", end="")
        for vi in range(8):
            val = (bts[2*vi] << 8) | bts[2*vi+1]
            print(f"  {val:6d}", end="")
        print()


def compare_rpm():
    """Cross-reference RPM LED with main-dash telemetry bytes."""
    print("\n" + "="*70)
    print("  RPM LED vs MAIN-DASH TELEM BYTES (0-100 redline)")
    print("="*70)

    # Load RPM LED data
    rpm_led = []
    with open(f'{BASE}/0-100redline-0-main-dash.ndjson') as f:
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
            data = r.get('data', '')
            if not data:
                continue
            data_bytes = [int(b, 16) for b in data.split(':')]
            if len(data_bytes) >= 8:
                rpm_val = data_bytes[0] | (data_bytes[1] << 8)  # LE uint16 RPM position
                rpm_max = data_bytes[4] | (data_bytes[5] << 8)  # should be 1023
                rpm_led.append((float(r['ts']), rpm_val, rpm_max))

    telem = load_telem(f'{BASE}/0-100redline-0-main-dash.ndjson')

    print(f"  RPM LED: {len(rpm_led)} packets")
    print(f"  Telem: {len(telem)} packets")

    if not rpm_led:
        print("  No RPM LED data found!")
        return

    # For each RPM LED timestamp, find closest telem packet
    print(f"\n  {'t':>8s}  {'RPM%':>5s}", end="")
    for bi in range(16):
        print(f"  [{bi:2d}]", end="")
    print()

    ti = 0
    for ts, rpm_val, rpm_max in rpm_led:
        pct = rpm_val / max(rpm_max, 1) * 100
        # Find closest telem
        while ti < len(telem) - 1 and abs(telem[ti+1][0] - ts) < abs(telem[ti][0] - ts):
            ti += 1
        tts, bts = telem[ti]
        print(f"  {ts:8.3f}  {pct:5.1f}", end="")
        for b in bts:
            print(f"  {b:4d}", end="")
        print()


if __name__ == '__main__':
    check_nibble_patterns()
    check_bit7_toggle()
    try_float_decodings()
    try_le_uint16_pairs()
    try_be_uint16_pairs()
    try_12bit_packing()
    compare_rpm()
