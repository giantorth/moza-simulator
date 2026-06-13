#!/usr/bin/env python3
"""
Validate the verified F1 dashboard bit-packed channel layout against capture data.

Uses the LSB-first bit-packing algorithm from pithouse-re.md to decode all 8 channels
from the 16-byte telemetry payload. This replaces the earlier decode_channels.py which
used incorrect 12-bit nibble packing heuristics.

Channel layout (verified from binary RE + capture correlation):
  Bits  0-31:  BestLapTime     float      32 bits  IEEE 754 single
  Bits 32-41:  Brake           percent_1  10 bits  0-1022 valid, 1023=N/A; game=raw/10.22
  Bits 42-73:  CurrentLapTime  float      32 bits  IEEE 754 single
  Bits    74:  DrsState        bool        1 bit
  Bits 75-78:  ErsState        uint3       4 bits   0-14 valid, 15=N/A
  Bits 79-83:  Gear            int30       5 bits   0=N, 1-6=gears
  Bits 84-93:  FuelRemainder   percent_1  10 bits  0-1022 valid, 1023=N/A; game=raw/10.22
  Bits 94-125: GAP             float      32 bits  IEEE 754 single (delta time)
  Bits 126-127: padding (2 bits)

Total: 126 data bits + 2 padding = 128 bits = 16 bytes.
"""
import json, struct, sys
from collections import Counter


# --- Bit read/write (LSB-first, from pithouse-re.md section 8) ---

def read_bits(buf, bit_pos, count):
    """Read `count` bits from byte buffer starting at `bit_pos`. LSB-first."""
    byte_off = bit_pos // 8
    bit_off = bit_pos % 8
    result = 0
    shift = 0
    remaining = count
    while remaining > 0:
        if byte_off >= len(buf):
            break
        take = min(remaining, 8 - bit_off)
        mask = ((1 << take) - 1) << bit_off
        result |= ((buf[byte_off] & mask) >> bit_off) << shift
        shift += take
        byte_off += 1
        bit_off = 0
        remaining -= take
    return result


def bits_to_float(raw_uint32):
    """Reinterpret a 32-bit unsigned integer as IEEE 754 single-precision float."""
    return struct.unpack('<f', struct.pack('<I', raw_uint32 & 0xFFFFFFFF))[0]


# --- Channel definitions ---

F1_CHANNELS = [
    # (name, compression, bit_width)
    ("BestLapTime",    "float",     32),
    ("Brake",          "percent_1", 10),
    ("CurrentLapTime", "float",     32),
    ("DrsState",       "bool",       1),
    ("ErsState",       "uint3",      4),
    ("Gear",           "int30",      5),
    ("FuelRemainder",  "percent_1", 10),
    ("GAP",            "float",     32),
]


def decode_raw(compression, raw):
    """Convert raw bit value to game value based on compression type."""
    if compression == "float":
        return bits_to_float(raw)
    elif compression == "percent_1":
        if raw >= 1023:
            return None  # N/A sentinel
        return raw / 10.22
    elif compression == "bool":
        return bool(raw)
    elif compression in ("uint3", "uint8", "uint15"):
        if raw >= 15:
            return None  # N/A sentinel for 4-bit types
        return raw
    elif compression == "int30":
        # 5-bit: 0=N, 1-6=gears; >30 might be N/A
        return raw
    else:
        return raw


def decode_telemetry(live_bytes, channels=F1_CHANNELS):
    """Decode a telemetry payload using the given channel layout."""
    bit_pos = 0
    result = {}
    for name, compression, width in channels:
        raw = read_bits(live_bytes, bit_pos, width)
        value = decode_raw(compression, raw)
        result[name] = {"raw": raw, "value": value, "bits": f"{bit_pos}-{bit_pos+width-1}"}
        bit_pos += width
    return result


# --- Load capture data ---

def load_telemetry_frames(path, majority_flag_only=True):
    """Load telemetry frames from ndjson capture file."""
    rows = []
    flag_counts = Counter()
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or not line.startswith('{'):
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
            rows.append({
                'ts': float(r.get('ts', 0)),
                'flag': flag,
                'live_bytes': bts,
                'live_hex': live,
            })

    if majority_flag_only and flag_counts:
        maj_flag = flag_counts.most_common(1)[0][0]
        rows = [r for r in rows if r['flag'] == maj_flag and len(r['live_bytes']) >= 16]
        print(f"# Flag distribution: {dict(flag_counts)}", file=sys.stderr)
        print(f"# Using majority flag: {maj_flag} ({len(rows)} frames)", file=sys.stderr)

    return rows


def load_rpm_led(path):
    """Load RPM LED data for cross-reference."""
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or not line.startswith('{'):
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if r.get('group') != '0x3f' or r.get('cmd') != '1a:00' or r.get('direction') != 'out':
                continue
            payload = r.get('payload', '') or r.get('data', '')
            if not payload:
                continue
            parts = [int(b, 16) for b in payload.split(':')]
            # RPM LED payload: after frame header (7e N group device cmd cmd) = 6 bytes,
            # then 8 data bytes before checksum
            # But in ndjson from extract_telem, 'data' field has the payload after cmd
            data_field = r.get('data', '')
            if data_field:
                data_bytes = [int(b, 16) for b in data_field.split(':')]
                if len(data_bytes) >= 8:
                    rpm_pos = data_bytes[0] | (data_bytes[1] << 8)
                    rpm_max = data_bytes[4] | (data_bytes[5] << 8)
                    rows.append({
                        'ts': float(r.get('ts', 0)),
                        'rpm_pos': rpm_pos,
                        'rpm_max': rpm_max,
                        'rpm_pct': rpm_pos / max(rpm_max, 1) * 100.0,
                    })
    return rows


# --- Main analysis ---

def format_time(seconds):
    """Format seconds as m:ss.fff"""
    if seconds is None or seconds != seconds:  # NaN check
        return "N/A"
    mins = int(seconds) // 60
    secs = seconds - mins * 60
    return f"{mins}:{secs:06.3f}"


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <capture.ndjson> [--summary | --csv | --all]")
        sys.exit(1)

    path = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else "--summary"

    frames = load_telemetry_frames(path)
    if not frames:
        print("No telemetry frames found.", file=sys.stderr)
        sys.exit(1)

    print(f"# Loaded {len(frames)} telemetry frames from {path}", file=sys.stderr)

    if mode == "--all":
        # Decode and print every frame
        for fr in frames:
            decoded = decode_telemetry(fr['live_bytes'])
            gear = decoded['Gear']['value']
            brake = decoded['Brake']['value']
            clap = decoded['CurrentLapTime']['value']
            blap = decoded['BestLapTime']['value']
            fuel = decoded['FuelRemainder']['value']
            gap = decoded['GAP']['value']
            drs = decoded['DrsState']['value']
            ers = decoded['ErsState']['value']

            print(f"t={fr['ts']:9.3f}  "
                  f"Gear={gear}  "
                  f"Brake={brake:5.1f}%  " if brake is not None else f"Brake=N/A    ",
                  end="")
            print(f"CLap={format_time(clap)}  "
                  f"BLap={format_time(blap)}  "
                  f"Fuel={'N/A' if fuel is None else f'{fuel:5.1f}%'}  "
                  f"GAP={gap:+8.3f}s  " if gap == gap else f"GAP=NaN       ",
                  end="")
            print(f"DRS={int(drs)}  ERS={ers}")

    elif mode == "--csv":
        print("ts,gear,brake_pct,current_lap_time,best_lap_time,fuel_pct,gap,drs,ers")
        for fr in frames:
            decoded = decode_telemetry(fr['live_bytes'])
            g = decoded['Gear']['value']
            b = decoded['Brake']['value']
            c = decoded['CurrentLapTime']['value']
            bl = decoded['BestLapTime']['value']
            fu = decoded['FuelRemainder']['value']
            ga = decoded['GAP']['value']
            d = decoded['DrsState']['value']
            e = decoded['ErsState']['value']
            print(f"{fr['ts']:.3f},{g},{b:.2f},{c:.4f},{bl:.4f},{fu if fu is not None else '':.2f},{ga:.4f},{int(d)},{e}")

    else:  # --summary
        # Decode all frames and summarize
        gears = set()
        brake_min, brake_max = 999, -999
        clap_values = []
        blap_values = []
        fuel_values = []
        gap_values = []
        drs_values = set()
        ers_values = set()
        nan_count = 0

        for fr in frames:
            decoded = decode_telemetry(fr['live_bytes'])
            g = decoded['Gear']['value']
            b = decoded['Brake']['value']
            c = decoded['CurrentLapTime']['value']
            bl = decoded['BestLapTime']['value']
            fu = decoded['FuelRemainder']['value']
            ga = decoded['GAP']['value']
            d = decoded['DrsState']['value']
            e = decoded['ErsState']['value']

            gears.add(g)
            if b is not None:
                brake_min = min(brake_min, b)
                brake_max = max(brake_max, b)
            if c == c:  # not NaN
                clap_values.append(c)
            if bl == bl:
                blap_values.append(bl)
            else:
                nan_count += 1
            if fu is not None:
                fuel_values.append(fu)
            if ga == ga:
                gap_values.append(ga)
            drs_values.add(int(d))
            ers_values.add(e)

        # Check CurrentLapTime monotonicity
        monotonic = 0
        total_pairs = 0
        for i in range(1, len(clap_values)):
            total_pairs += 1
            if clap_values[i] >= clap_values[i-1]:
                monotonic += 1
        mono_pct = monotonic / max(total_pairs, 1) * 100

        print(f"\n=== Telemetry Decode Summary ({len(frames)} frames) ===\n")
        print(f"Gear:           values = {sorted(gears)}")
        print(f"Brake:          {brake_min:.1f}% - {brake_max:.1f}%")
        print(f"CurrentLapTime: {mono_pct:.1f}% monotonic ({monotonic}/{total_pairs} pairs)")
        if clap_values:
            print(f"                range: {format_time(min(clap_values))} - {format_time(max(clap_values))}")
        print(f"BestLapTime:    {len(blap_values)} valid, {nan_count} NaN")
        if blap_values:
            non_zero = [v for v in blap_values if v > 0]
            if non_zero:
                print(f"                non-zero: {format_time(min(non_zero))} - {format_time(max(non_zero))}")
            else:
                print(f"                all zero (no completed laps)")
        if fuel_values:
            print(f"FuelRemainder:  {min(fuel_values):.1f}% - {max(fuel_values):.1f}%")
        if gap_values:
            print(f"GAP:            {min(gap_values):+.3f}s - {max(gap_values):+.3f}s")
        print(f"DRS:            values = {sorted(drs_values)}")
        print(f"ERS:            values = {sorted(ers_values)}")

        # Plausibility checks
        print(f"\n=== Plausibility Checks ===\n")
        checks = []

        # Gear should be 0-6 for typical sim racing
        gear_ok = all(0 <= g <= 12 for g in gears)
        checks.append(("Gear values in valid range (0-12)", gear_ok))

        # Brake should be 0-100%
        brake_ok = 0 <= brake_min and brake_max <= 100.5
        checks.append(("Brake in 0-100% range", brake_ok))

        # CurrentLapTime should be mostly monotonic (>90%)
        mono_ok = mono_pct > 90
        checks.append((f"CurrentLapTime >90% monotonic ({mono_pct:.1f}%)", mono_ok))

        # DRS/ERS should be small integers
        drs_ok = all(0 <= d <= 1 for d in drs_values)
        checks.append(("DRS is 0 or 1", drs_ok))

        ers_ok = all(0 <= e <= 14 for e in ers_values if e is not None)
        checks.append(("ERS in valid range (0-14)", ers_ok))

        for desc, ok in checks:
            status = "PASS" if ok else "FAIL"
            print(f"  [{status}] {desc}")

        all_pass = all(ok for _, ok in checks)
        print(f"\nOverall: {'ALL CHECKS PASSED' if all_pass else 'SOME CHECKS FAILED'}")


if __name__ == '__main__':
    main()
