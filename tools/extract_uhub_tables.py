#!/usr/bin/env python3
"""Extract MOZA Universal Hub (PID 0x0020, bus device 0x12) response tables
from a USBPcap capture of a real hub.

    python3 tools/extract_uhub_tables.py [usb-capture/ksp/mozahubstartup.pcapng]

Writes:
    sim/replay/param_0e_uhub_dev12.json   group 0x0E parameter-table pairs

and prints the identity cascade (groups 02/04-11) + group 0x64 port-state
pairs so they can be checked against sim/profiles/hubs/uhub_kspro.py.

Pairing: a device->host frame from 0x21 (nibble-swap of 0x12) answers the most
recent unanswered host->device frame to 0x12 whose group | 0x80 matches, within
250 ms. First observed response per (group, payload) wins.

The hub's unique MCU id (group 0x06) and serials (group 0x10) are only printed,
never written — the profile carries redacted placeholders.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "sim"))
import wheel_sim as ws  # noqa: E402

DEFAULT_CAPTURE = "usb-capture/ksp/mozahubstartup.pcapng"
HUB = 0x12
HUB_RSP = ws.swap_nibbles(HUB)
PAIR_WINDOW_S = 0.25


def pair_hub_frames(path: Path) -> dict:
    entries = ws.extract_from_pcapng(str(path))
    pending = []
    pairs: dict = {}
    for direction, ts, frame in entries:
        if not ws.verify(frame) or len(frame) < 4:
            continue
        group, dev, payload = frame[2], frame[3], bytes(ws.frame_payload(frame))
        if direction == "host" and dev == HUB:
            pending.append((ts, group, payload))
        elif direction == "device" and dev == HUB_RSP:
            for i in range(len(pending) - 1, -1, -1):
                pts, pgroup, ppayload = pending[i]
                if (pgroup | 0x80) == group and ts - pts < PAIR_WINDOW_S:
                    pairs.setdefault((pgroup, ppayload), payload)
                    del pending[i]
                    break
    return pairs


def main() -> int:
    rel = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CAPTURE
    path = REPO / rel
    if not path.exists():
        print(f"capture not found: {rel}", file=sys.stderr)
        return 1
    pairs = pair_hub_frames(path)
    if not pairs:
        print("no hub request/response pairs found", file=sys.stderr)
        return 1

    param = {req.hex(): rsp.hex() for (g, req), rsp in sorted(pairs.items()) if g == 0x0E}
    out = REPO / "sim" / "replay" / "param_0e_uhub_dev12.json"
    out.write_text(json.dumps({
        "schema": 1,
        "group": "0x0E",
        "device": HUB,
        "label": "parameter table dev=0x12 (Universal Hub S03)",
        "source": rel,
        "entries": param,
    }, indent=2) + "\n")
    print(f"wrote {len(param)} param entries -> {out.relative_to(REPO)}")

    print("\nidentity / port-state pairs (verify against the uhub profile):")
    for (g, req), rsp in sorted(pairs.items()):
        if g == 0x0E:
            continue
        note = "  (redacted in profile)" if g in (0x06, 0x10) else ""
        text = "".join(chr(c) if 32 <= c < 127 else "." for c in rsp)
        print(f"  {g:02x} {req.hex():<10} -> {rsp.hex():<36} {text}{note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
