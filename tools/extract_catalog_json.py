#!/usr/bin/env python3
"""Extract a wheel's device-side session 1/2 catalog from a capture into a
committed JSON file, so the simulator can replay the real catalog on machines
without the (git-ignored) capture — e.g. a fresh Windows install of the
Universal Hub bridge.

    python3 tools/extract_catalog_json.py usb-capture/ksp/putOnWheelAndOpenPitHouse.pcapng \\
        sim/replay/kspro_catalog.json

Consumed by wheel_sim.load_catalog_json via a profile's `catalog_json` key; the
pcap named by `catalog_pcapng` still wins when it is present.
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / 'sim'))
import wheel_sim as ws  # noqa: E402


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    src, out = sys.argv[1], Path(sys.argv[2])
    raw = ws.extract_device_catalog(str(REPO / src))
    sessions = {s: frs for s, frs in raw.items() if s in (0x01, 0x02)}
    if not sessions:
        print('no session 1/2 catalog frames found', file=sys.stderr)
        return 1
    seqs = ws.extract_catalog_open_seqs(str(REPO / src))
    out.write_text(json.dumps({
        'schema': 1,
        'source': src,
        'sessions': {str(s): [f.hex() for f in frs] for s, frs in sorted(sessions.items())},
        'open_seqs': {str(s): seqs[s] for s in sorted(sessions) if s in seqs},
    }, indent=2) + '\n')
    print(f'wrote {sum(len(v) for v in sessions.values())} frames -> {out}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
