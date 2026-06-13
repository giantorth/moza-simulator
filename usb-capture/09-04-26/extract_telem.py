#!/usr/bin/env python3
"""
Stream-extract moza telemetry from large Wireshark JSON exports.
Handles both:
  - Captures with the moza Lua dissector active (has 'moza' layer)
  - Captures without it (parses raw usbcom payload starting with 0x7e)

Emits one JSON line per moza frame.
"""
import json, sys, ijson


def parse_raw_moza(hex_str):
    """Parse a colon-separated hex payload into moza fields.
    Returns dict or None if not a moza frame."""
    parts = hex_str.split(':')
    raw = [int(b, 16) for b in parts]
    if not raw or raw[0] != 0x7e:
        return None
    if len(raw) < 5:
        return None
    n = raw[1]         # payload length (cmd + data)
    group = raw[2]
    device = raw[3]
    checksum = raw[-1]
    payload_bytes = raw[4:-1]  # everything between device and checksum

    result = {
        'n': n,
        'group': f'0x{group:02x}',
        'device': f'0x{device:02x}',
        'checksum': f'0x{checksum:02x}',
    }

    # For telemetry frames (group 0x43, cmd 7d:23), parse the telem structure
    if len(payload_bytes) >= 2:
        result['cmd'] = ':'.join(f'{b:02x}' for b in payload_bytes[:2])

    if group == 0x43 and len(payload_bytes) >= 2 and payload_bytes[0] == 0x7d and payload_bytes[1] == 0x23:
        # 7d:23 telemetry frame: 4 const + 1 flag + 1 const20 + N live bytes
        data = payload_bytes[2:]  # after cmd
        if len(data) >= 6:
            result['const4'] = ':'.join(f'{b:02x}' for b in data[:4])
            result['flag'] = f'0x{data[4]:02x}'
            result['const20'] = f'0x{data[5]:02x}'
            live = data[6:]
            result['live'] = ':'.join(f'{b:02x}' for b in live)
        else:
            result['data'] = ':'.join(f'{b:02x}' for b in data)
    elif len(payload_bytes) > 2:
        result['data'] = ':'.join(f'{b:02x}' for b in payload_bytes[2:])

    return result


def extract(path):
    """Extract moza telemetry packets using streaming JSON parser."""
    count = 0
    moza_count = 0
    with open(path, 'rb') as f:
        for packet in ijson.items(f, 'item'):
            count += 1
            layers = packet.get('_source', {}).get('layers', {})
            frame = layers.get('frame', {})
            ts = frame.get('frame.time_relative', '')
            usb = layers.get('usb', {})
            usbcom = layers.get('usbcom', {})
            direction = 'out' if usb.get('usb.src', '') == 'host' else 'in'

            # Try dissected moza layer first
            moza = layers.get('moza')
            if moza:
                moza_count += 1
                row = {
                    'ts': ts,
                    'direction': direction,
                    'group': moza.get('moza.group', ''),
                    'device': moza.get('moza.device', ''),
                    'n': moza.get('moza.n', ''),
                    'cmd': moza.get('moza.cmd', ''),
                    'flag': moza.get('moza.telem.flag', ''),
                    'const4': moza.get('moza.telem.const4', ''),
                    'const20': moza.get('moza.telem.const20', ''),
                    'live': moza.get('moza.telem.live', ''),
                    'checksum': moza.get('moza.checksum', ''),
                    'payload': usbcom.get('usbcom.data.out_payload', ''),
                }
                print(json.dumps(row))
                continue

            # Fall back: parse raw usbcom payload
            raw_payload = usbcom.get('usbcom.data.out_payload') or usbcom.get('usbcom.data.in_payload')
            if not raw_payload:
                continue

            # A single USB transfer can contain multiple concatenated moza frames
            parts = raw_payload.split(':')
            raw_bytes = [int(b, 16) for b in parts]

            i = 0
            while i < len(raw_bytes):
                if raw_bytes[i] != 0x7e:
                    i += 1
                    continue
                if i + 1 >= len(raw_bytes):
                    break
                n = raw_bytes[i + 1]
                # Total frame: start(1) + n(1) + group(1) + device(1) + payload(n) + checksum(1)
                frame_len = 1 + 1 + 1 + 1 + n + 1
                if i + frame_len > len(raw_bytes):
                    break
                frame_bytes = raw_bytes[i:i + frame_len]
                hex_str = ':'.join(f'{b:02x}' for b in frame_bytes)
                parsed = parse_raw_moza(hex_str)
                if parsed:
                    moza_count += 1
                    row = {
                        'ts': ts,
                        'direction': direction,
                        **parsed,
                        'payload': hex_str,
                    }
                    print(json.dumps(row))
                i += frame_len

    print(f"# total_packets={count} moza_packets={moza_count}", file=sys.stderr)


if __name__ == '__main__':
    extract(sys.argv[1])
