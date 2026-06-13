#!/usr/bin/env python3
"""Multi-device USB-gadget manager for the MOZA simulator rig.

A *rig* is one or more device-profile keys (sim/profiles/). This module computes
which USB gadgets the rig needs and how many dummy_hcd UDC slots, emits
shell-parseable gadget specs for setup_rig.sh, and launches the correct sim
engine on a gadget's ttyGS.

    python3 sim/gadget_manager.py spec <key> [<key>...]   # consumed by setup_rig.sh
    python3 sim/gadget_manager.py run  <key> <ttyGS>       # launch that gadget's engine
    python3 sim/gadget_manager.py list                     # show known profiles

Engine routing (GadgetSpec.engine):
    unified            -> wheel_sim.py --model <key> <port>   (wheel rig)
    standalone/mbooster-> engines.standalone.{StandaloneSimulator,MBoosterSimulator}
    ab9                -> ab9_sim.py <port>
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import wheel_sim as ws  # noqa: E402


def _profile(key: str):
    p = ws.DEVICE_PROFILES.get(key)
    if p is None:
        print(f"unknown profile '{key}'. known: {sorted(ws.DEVICE_PROFILES)}",
              file=sys.stderr)
        sys.exit(2)
    return p


def cmd_spec(keys):
    """Emit one UDC_NEEDED line + one GADGET line per gadget. Tab-separated so
    setup_rig.sh can `read` the fields directly. A key may be repeated (the
    canonical 3× mBooster layout) — each gadget gets a unique configfs key and
    serial so it can be enumerated/bound independently."""
    import re
    from collections import Counter

    total = Counter(keys)
    seen: Counter = Counter()
    gadget_lines = []
    udc = 0
    for key in keys:
        p = _profile(key)
        # Multiple gadgets if the key repeats in the rig or the profile itself
        # declares more than one gadget (e.g. a future composite).
        multi = total[key] > 1 or len(p.gadgets) > 1
        for g in p.gadgets:
            idx = seen[key]
            seen[key] += 1
            gkey = key if not multi else f"{key}{idx}"
            product = g.product_str or p.friendly
            base = re.sub(r"[^A-Z0-9]", "", key.upper())[:9] or "MOZA"
            serial = f"{base}{idx:03d}0001"[:16]
            maxpower = 250 if g.engine == "unified" else 100
            iad = 1 if "hid" in g.functions else 0
            gadget_lines.append(
                f"GADGET\t{gkey}\t{key}\t0x{g.pid:04x}\t{product}\t{serial}"
                f"\t{maxpower}\t{iad}\t{g.engine}")
            udc += 1
    print(f"UDC_NEEDED\t{udc}")
    for ln in gadget_lines:
        print(ln)


def cmd_run(key, port):
    p = _profile(key)
    if not p.gadgets:
        print(f"profile '{key}' declares no gadget", file=sys.stderr)
        sys.exit(2)
    engine = p.gadgets[0].engine
    if engine == "unified":
        os.execvp("python3", ["python3", os.path.join(HERE, "wheel_sim.py"),
                              "--model", key, port])
    elif engine in ("standalone", "mbooster", "cm1"):
        from engines.standalone import (StandaloneSimulator, MBoosterSimulator,
                                        Cm1Simulator)
        cls = {"mbooster": MBoosterSimulator, "cm1": Cm1Simulator}.get(
            engine, StandaloneSimulator)
        cls(p).run_serial(port)
    elif engine == "ab9":
        os.execvp("python3", ["python3", os.path.join(HERE, "ab9_sim.py"), port])
    else:
        print(f"profile '{key}' uses engine '{engine}' with no runner yet "
              f"(cm1/fsr1 dash engines are Phase 4e)", file=sys.stderr)
        sys.exit(2)


def cmd_list():
    for key in sorted(ws.DEVICE_PROFILES):
        p = ws.DEVICE_PROFILES[key]
        g = p.gadgets[0]
        print(f"  {key:10} {p.friendly:18} pid=0x{g.pid:04x} engine={g.engine}")


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    sub = sys.argv[1]
    if sub == "spec":
        if len(sys.argv) < 3:
            print("usage: gadget_manager.py spec <key> [<key>...]", file=sys.stderr)
            return 2
        cmd_spec(sys.argv[2:])
    elif sub == "run":
        if len(sys.argv) != 4:
            print("usage: gadget_manager.py run <key> <ttyGS>", file=sys.stderr)
            return 2
        cmd_run(sys.argv[2], sys.argv[3])
    elif sub == "list":
        cmd_list()
    else:
        print(f"unknown subcommand '{sub}'", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
