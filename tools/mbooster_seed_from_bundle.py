#!/usr/bin/env python3
"""Build an mBooster sim seed from real traffic.

Inputs, any mix of:
  * an AZOM diagnostics bundle's files dir — serial-capture-startup.txt /
    serial-capture-rolling.txt (one frame per line: host lines are full
    `7e N grp dev payload ck`, device lines are `grp dev payload`)
  * a Pit House USB capture (.pcapng, read with tshark via wheel_sim)

Writes, per unit on the lane (host 0x12, chained 0x1d/0x1e, routed 0x19):

  identity    request payload -> reply payload, per identity group
  registers   group-0x23 read / 0x24 write-echo values, latest wins
  params      group-0x0E parameter table: `0e <dev> 00 <idx:2>` ->
              `8e <src> 00 <idx:2> <value:4>` (Pit House reads it; the plugin
              never does, so only captures carry it)
  heartbeat   the unit's own firmware "Active pedal heartbeat" block (0x0E text)
  errors      error codes the unit reported (0x0E `03 <code> 00 01`) — info
              only; the engine models errors as state

Serial numbers (group 0x10) and MCU UIDs (group 0x06) are replaced with
synthetic per-unit values of the same length, so a seed never carries a user's
hardware identifiers. The motor effect stream (0x24 cmd 0xB1) is not a
register and is left out.

    python3 tools/mbooster_seed_from_bundle.py <bundle files dir> -o sim/profiles/standalone/seeds/<name>.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

IDENTITY_GROUPS = {0x02, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0F, 0x10, 0x11}
# Groups whose one-byte request is an index the reply starts with.
INDEXED_GROUPS = {0x07, 0x08, 0x0F, 0x10, 0x11}
READ_GROUP, WRITE_GROUP = 0x23, 0x24
# Commands addressed as cmd + 0x00 + selector (see the plugin's
# MozaCommandDatabase: 0xAB feel curve / deadzone / max force, 0xB2 end stop,
# 0xAE friction, 0xAD damping).
SELECTOR_CMDS = {0xAB, 0xB2, 0xAE, 0xAD}
MOTOR_CMD = 0xB1
PAIR_WINDOW = 0.25
PARAM_GROUP = 0x0E


def swap(b: int) -> int:
    return ((b & 0x0F) << 4) | (b >> 4)


def parse(path: Path):
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 6 or parts[2] not in ("T", "R"):
            continue
        h, m, s = parts[1].split(":")
        t = int(h) * 3600 + int(m) * 60 + float(s)
        try:
            raw = bytes(int(x, 16) for x in parts[4:])
        except ValueError:
            continue  # masked identifiers ("..")
        if parts[2] == "T":
            if len(raw) < 5 or raw[0] != 0x7E:
                continue
            n = raw[1]
            out.append(("T", t, raw[2], raw[3], raw[4:4 + n]))
        else:
            if len(raw) < 2:
                continue
            out.append(("R", t, raw[0], raw[1], raw[2:]))
    return out


def parse_pcap(path: Path):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "sim"))
    from wheel_sim import extract_from_pcapng, frame_payload  # type: ignore
    out = []
    for d, t, f in extract_from_pcapng(str(path)):
        if len(f) < 5:
            continue
        pl = bytes(frame_payload(f))
        out.append(("T" if d == "host" else "R", t, f[2], f[3], pl))
    return out


def reg_key(payload: bytes) -> tuple:
    if payload and payload[0] in SELECTOR_CMDS and len(payload) >= 3:
        return payload[:3], payload[3:]
    return payload[:1], payload[1:]


def synthetic(length: int, tag: str) -> bytes:
    base = (tag * (length // len(tag) + 1)).encode("ascii")
    return base[:length]


def sanitize(group: int, dev: int, payload: bytes) -> bytes:
    if group == 0x10 and len(payload) > 1:
        body = payload[1:]
        text_len = body.find(b"\x00")
        text_len = len(body) if text_len < 0 else text_len
        tag = f"AZ{dev:02X}S{payload[0]}"
        return payload[:1] + synthetic(text_len, tag) + body[text_len:]
    if group == 0x06:
        return synthetic(len(payload), f"AZ{dev:02X}UID")
    return payload


def build(frame_sets: list) -> dict:
    """Merge several traffic sources; each is paired on its own clock."""
    units: dict = {}
    for frames in frame_sets:
        frames.sort(key=lambda x: x[1])
        _build_one(frames, units)
    return units


def _build_one(frames: list, units: dict) -> None:
    def unit(dev: int) -> dict:
        return units.setdefault(f"0x{dev:02x}", {
            "identity": {}, "registers": {}, "params": {}, "heartbeat": [], "errors": []})

    # Pair host requests with the unit's reply.
    for i, (d, t, g, dev, pl) in enumerate(frames):
        if d != "T":
            continue
        if g in IDENTITY_GROUPS:
            for d2, t2, g2, dev2, pl2 in frames[i + 1:]:
                if t2 - t > PAIR_WINDOW:
                    break
                # A one-byte request is an index (08 01 / 08 02, 10 00 / 10 01)
                # the reply echoes; back-to-back requests make "first reply in
                # the window" pick the wrong one otherwise.
                if g in INDEXED_GROUPS and pl2[:1] != pl[:1]:
                    continue
                if d2 == "R" and g2 == (g | 0x80) and dev2 == swap(dev):
                    unit(dev)["identity"].setdefault(f"{g:02x}:{pl.hex()}", sanitize(g, dev, pl2).hex())
                    break
        elif g == PARAM_GROUP and len(pl) == 3 and pl[0] == 0x00:
            for d2, t2, g2, dev2, pl2 in frames[i + 1:]:
                if t2 - t > PAIR_WINDOW:
                    break
                if d2 == "R" and g2 == (PARAM_GROUP | 0x80) and dev2 == swap(dev) \
                        and pl2[:3] == pl and len(pl2) >= 4:
                    unit(dev)["params"][pl[1:3].hex()] = pl2[3:].hex()
                    break

    # Register values from read replies and write echoes, latest wins.
    for d, t, g, src, pl in frames:
        if d == "R" and g in (READ_GROUP | 0x80, WRITE_GROUP | 0x80) and pl:
            if pl[0] == MOTOR_CMD:
                continue
            k, v = reg_key(pl)
            unit(swap(src))["registers"][k.hex()] = v.hex()

    # Firmware 0x0E: text log (sub 0x05, split across frames) and short
    # binary status frames.
    text: dict = {}
    for d, t, g, src, pl in frames:
        if d != "R" or g != 0x0E or not pl:
            continue
        u = unit(swap(src))
        if pl[0] == 0x05:
            buf = text.get(src, "") + pl[1:].decode("latin-1")
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                u.setdefault("_lines", []).append(line)
            text[src] = buf
        elif pl[0] == 0x03 and len(pl) >= 3:
            code = int.from_bytes(pl[1:3], "big")
            if code not in u["errors"]:
                u["errors"].append(code)

    for u in units.values():
        lines = u.pop("_lines", [])
        block = []
        for ln in lines:
            if "Active pedal heartbeat log" in ln:
                block = [ln]
            elif block:
                block.append(ln)
                if "Log the end" in ln:
                    if not u["heartbeat"]:
                        u["heartbeat"] = block
                    break


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", type=Path, nargs="+", help="bundle files dirs and/or .pcapng captures")
    ap.add_argument("-o", "--out", type=Path, required=True)
    ap.add_argument("--source", default="", help="label stored in the seed (ticket ids / capture names, not user names)")
    a = ap.parse_args()
    frame_sets = []
    for inp in a.inputs:
        if inp.is_dir():
            files = sorted(inp.glob("serial-capture-*.txt"))
            if not files:
                sys.exit(f"no serial-capture-*.txt in {inp}")
            frames = []
            for f in files:
                frames.extend(parse(f))
            frame_sets.append(frames)
        else:
            frame_sets.append(parse_pcap(inp))
    seed = {"source": a.source, "units": build(frame_sets)}
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(seed, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    for dev, u in seed["units"].items():
        print(f"{dev}: identity={len(u['identity'])} registers={len(u['registers'])} "
              f"params={len(u['params'])} heartbeat_lines={len(u['heartbeat'])} errors={u['errors']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
