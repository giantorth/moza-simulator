#!/usr/bin/env python3
"""Drive a running CLI bridge (bridge.py) over its control socket.

    bridge_ctl.py status
    bridge_ctl.py recent [--count 20] [--dir h2b|b2h]
    bridge_ctl.py inject h2b "7e 03 26 1d 0d 00 00"          # to the device, as Pit House
    bridge_ctl.py inject b2h --grp 0x8e --dev 0x21 --payload 0500  # to Pit House, as the device
    bridge_ctl.py rule drop h2b --grp 0x26 --prefix 0c
    bridge_ctl.py rule replace h2b --grp 0x26 --prefix 0c --payload 0d0000
    bridge_ctl.py rules
    bridge_ctl.py unrule [id]        # all rules when id is omitted
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
from pathlib import Path


def _int(s: str) -> int:
    return int(s, 0)


def call(sock_path: Path, req: dict):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(str(sock_path))
        s.sendall((json.dumps(req) + "\n").encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    return json.loads(buf)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--control", type=Path, default=Path("/tmp/moza-bridge.sock"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    p = sub.add_parser("recent"); p.add_argument("--count", type=int, default=20); p.add_argument("--dir")
    p = sub.add_parser("inject"); p.add_argument("dir", choices=("h2b", "b2h"))
    p.add_argument("frame", nargs="?", default="")
    p.add_argument("--grp", type=_int); p.add_argument("--dev", type=_int); p.add_argument("--payload", default="")
    p = sub.add_parser("rule"); p.add_argument("action", choices=("drop", "replace"))
    p.add_argument("dir", choices=("h2b", "b2h"))
    p.add_argument("--grp", type=_int); p.add_argument("--dev", type=_int)
    p.add_argument("--prefix", default=""); p.add_argument("--payload", default="")
    sub.add_parser("rules")
    p = sub.add_parser("unrule"); p.add_argument("id", nargs="?", type=int)
    a = ap.parse_args()

    if a.cmd == "status":
        req = {"op": "status"}
    elif a.cmd == "recent":
        req = {"op": "recent", "count": a.count, "dir": a.dir}
    elif a.cmd == "inject":
        req = {"op": "inject", "direction": a.dir, "frame_hex": a.frame,
               "group": a.grp, "device": a.dev, "payload_hex": a.payload}
    elif a.cmd == "rule":
        req = {"op": "rule_add", "direction": a.dir, "action": a.action, "group": a.grp,
               "device": a.dev, "payload_prefix": a.prefix, "replace_payload": a.payload}
    elif a.cmd == "rules":
        req = {"op": "rules"}
    else:
        req = {"op": "rule_remove", "rule_id": a.id}
    print(json.dumps(call(a.control, req), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
