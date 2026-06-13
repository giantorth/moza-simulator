#!/usr/bin/env python3
"""Extract a MOZA wheel profile stub from a plugin diagnostics bundle.

The plugin's diagnostics bundle (Diagnostics tab → export ZIP) contains a
``diagnostics.txt`` with a clean identity dump (wheel + display sub-device) and a
``serial-capture.txt`` wire trace. This tool parses the identity dump into a
``sim/profiles/wheels/<key>.py`` stub in the same shape as the hand-written wheel
profiles (a ``LEGACY`` dict wrapped by ``DeviceProfile.from_legacy``), so a new
display wheel can be simulated from real hardware data.

Identity-only by default. Fields the bundle can't carry (LED counts, catalog /
session layout / 7c:23 payloads / factory state, and redacted serials / MCU UID)
are emitted with ``# TODO`` markers for review. Pass ``--replay`` to additionally
mine the wire trace for a dev-0x17 replay table (best-effort).

Usage:
    tools/extract_profile.py --bundle <bundle.zip> --key fsr2 [--out PATH] [--replay]
    tools/extract_profile.py --diagnostics diagnostics.txt --key gs
    tools/extract_profile.py --bundle <bundle.zip> --key fsr2 --print   # stdout only
"""
from __future__ import annotations

import argparse
import io
import re
import sys
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

REPO = Path(__file__).resolve().parent.parent
PROFILES_WHEELS = REPO / "sim" / "profiles" / "wheels"

# Friendly names for known model strings (from docs/protocol/identity +
# Devices/WheelModelInfo.cs). Used only for the `friendly` field; unknown models
# fall back to the raw model string.
FRIENDLY = {
    "W13": "FSR V2", "W17": "CS Pro", "W18": "KS Pro", "VGS": "Vision GS",
    "KS": "KS", "FSR": "FSR V1", "GS": "GS V2 Pro", "GS V2P": "GS V2 Pro",
    "CS V2.1": "CS V2", "CS": "CS", "TSW": "TSW", "RS V2": "RS V2", "ES": "ES",
}
# Known RPM/button LED counts (Devices/WheelModelInfo.cs KnownModels). Absent =>
# emitted as the default with a TODO.
LED_COUNTS = {
    "W13": (16, 10), "W17": (16, 8), "W18": (18, 14), "VGS": (10, 8),
    "KS": (10, 10), "FSR": (10, 10), "GS": (10, 10), "GS V2P": (10, 10),
    "CS V2.1": (10, 6), "CS": (10, 0), "ES": (10, 0),
}

_MISSING = {"", "—", "-"}


def _is_missing(v: str) -> bool:
    return v.strip() in _MISSING or v.strip().startswith("(")


def parse_sections(text: str) -> Dict[str, Dict[str, str]]:
    """Parse `=== Title ===` sections into {title: {label: value}}."""
    out: Dict[str, Dict[str, str]] = {}
    cur: Optional[Dict[str, str]] = None
    sec = re.compile(r"^===\s*(.+?)\s*===$")
    kv = re.compile(r"^([A-Za-z0-9 ()/_-]+?):\s*(.*)$")
    for line in text.splitlines():
        m = sec.match(line.strip())
        if m:
            cur = {}
            out[m.group(1)] = cur
            continue
        if cur is None:
            continue
        m = kv.match(line)
        if m:
            cur[m.group(1).strip()] = m.group(2).strip()
    return out


def parse_bytes_field(v: str) -> Optional[bytes]:
    """Parse a dash/space/colon-separated hex byte string ('01-02-04-06')."""
    if _is_missing(v):
        return None
    parts = re.split(r"[-:\s]+", v.strip())
    try:
        return bytes(int(p, 16) for p in parts if p)
    except ValueError:
        return None


def _ident_from_section(sec: Dict[str, str]) -> Dict[str, object]:
    """Extract identity fields shared by wheel + display sections."""
    out: Dict[str, object] = {}
    if not _is_missing(sec.get("Model", "")):
        out["name"] = sec["Model"]
    if not _is_missing(sec.get("FW (sw)", "")):
        out["sw_version"] = sec["FW (sw)"]
    if not _is_missing(sec.get("HW version", "")):
        out["hw_version"] = sec["HW version"]
    if not _is_missing(sec.get("HW sub", "")):
        out["hw_sub"] = sec["HW sub"]
    dt = parse_bytes_field(sec.get("Device type", ""))
    if dt:
        out["dev_type"] = dt
    caps = parse_bytes_field(sec.get("Capabilities", ""))
    if caps:
        out["caps"] = caps
    i11 = parse_bytes_field(sec.get("Identity-11", ""))
    if i11:
        out["identity_11"] = i11
    return out


# ── emit a profile module ───────────────────────────────────────────────────

def _b(prefix: str, val: object, todo: str = "") -> str:
    """Format one LEGACY dict line for value `val`."""
    suffix = f"  # TODO: {todo}" if todo else ""
    if isinstance(val, bytes):
        return f"    {prefix}: bytes.fromhex('{val.hex()}'),{suffix}"
    return f"    {prefix}: {val!r},{suffix}"


def emit_module(key: str, wheel: Dict[str, object], display: Dict[str, object],
                source: str) -> str:
    name = str(wheel.get("name", key))
    friendly = FRIENDLY.get(name, name)
    rpm, btn = LED_COUNTS.get(name, (10, 10))
    led_todo = "" if name in LED_COUNTS else "confirm against Devices/WheelModelInfo.cs"
    has_display = bool(display)

    L: List[str] = []
    L.append(f'"""{key} wheel profile — extracted from {source} by')
    L.append("tools/extract_profile.py. Identity fields are from the bundle's")
    L.append("diagnostics.txt; TODO-marked fields need deeper capture analysis")
    L.append('(catalog / session layout / 7c:23 payloads / factory state)."""')
    L.append("from ..schema import DeviceProfile")
    L.append("")
    L.append("LEGACY = {")
    L.append(_b("'name'", name))
    L.append(_b("'friendly'", friendly, "" if name in FRIENDLY else "confirm friendly name"))
    for fld in ("sw_version", "hw_version", "hw_sub"):
        if fld in wheel:
            L.append(_b(f"'{fld}'", wheel[fld]))
        else:
            L.append(f"    # TODO: '{fld}' not in bundle")
    # Serials + hw_id are redacted in the bundle — placeholders, matching the
    # convention in the hand-written profiles (distinct ...0 / ...1 endings).
    up = re.sub(r"[^A-Z0-9]", "", name.upper())[:6] or key.upper()
    base = (up + "0" * 16)[:15]
    L.append(_b("'serial0'", base + "0", "real serial redacted in bundle"))
    L.append(_b("'serial1'", base + "1", "real serial redacted in bundle"))
    if "caps" in wheel:
        L.append(_b("'caps'", wheel["caps"]))
    else:
        # caps is mandatory (_build_identity_tables subscripts model['caps']);
        # emit a no-display placeholder so the module loads. byte 2 bit 0x20 =
        # detachable RGB display — leave it clear here.
        L.append("    'caps': bytes([0x01, 0x02, 0x00, 0x00]),  # TODO: PLACEHOLDER "
                 "— caps not in bundle; needs the real 0x05 probe reply")
    L.append(_b("'hw_id'", bytes(12), "MCU UID redacted in bundle"))
    if "dev_type" in wheel:
        L.append(_b("'dev_type'", wheel["dev_type"]))
    else:
        L.append("    # TODO: 'dev_type' not in bundle")
    if "identity_11" in wheel:
        L.append(_b("'identity_11'", wheel["identity_11"]))
    L.append(_b("'rpm_led_count'", rpm, led_todo))
    L.append(_b("'button_led_count'", btn, led_todo))
    L.append(f"    'emits_7c23': {has_display},  # TODO: confirm + add "
             f"_7c23_payloads to PROFILE below (needs capture)" if has_display
             else "    'emits_7c23': False,")
    L.append("    'session_layout': 'legacy',  # TODO: confirm 'legacy' vs 'vgs_combined'")
    if has_display:
        L.append("    # TODO: factory_state_file + catalog_pcapng + session1_desc "
                 "from deeper capture analysis")
        L.append("    'display': {")
        L.append(f"        'name': {str(display.get('name', name + ' Display'))!r},")
        for fld in ("sw_version", "hw_version", "hw_sub"):
            if fld in display:
                L.append(f"        '{fld}': {display[fld]!r},")
        dbase = (up + "DISPLAY" + "0" * 16)[:15]
        L.append(f"        'serial0': {dbase + '0'!r},  # TODO redacted")
        L.append(f"        'serial1': {dbase + '1'!r},  # TODO redacted")
        if "dev_type" in display:
            L.append(f"        'dev_type': bytes.fromhex('{display['dev_type'].hex()}'),")
        if "caps" in display:
            L.append(f"        'caps': bytes.fromhex('{display['caps'].hex()}'),")
        L.append("        'hw_id': bytes.fromhex('000000000000000000000000'),  # TODO redacted")
        L.append("    },")
    L.append("}")
    L.append("")
    L.append(f"PROFILE = DeviceProfile.from_legacy({key!r}, LEGACY)")
    if has_display:
        L.append("")
        L.append("# TODO: PROFILE.blocks[0].extras['_7c23_payloads'] = [ ... ]  "
                 "(10B page-activate")
        L.append("#       payloads from a real connect capture — see other wheel profiles)")
    L.append("")
    return "\n".join(L)


# ── bundle / file IO ────────────────────────────────────────────────────────

def read_bundle(path: Path) -> Tuple[str, Optional[bytes]]:
    """Return (diagnostics_txt, serial_capture_bytes) from a bundle ZIP."""
    with zipfile.ZipFile(path) as z:
        diag = z.read("diagnostics.txt").decode("utf-8", "replace")
        cap = None
        if "serial-capture.txt" in z.namelist():
            cap = z.read("serial-capture.txt")
        return diag, cap


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--bundle", help="diagnostics bundle .zip")
    src.add_argument("--diagnostics", help="a diagnostics.txt path")
    ap.add_argument("--key", required=True, help="profile key (e.g. fsr2)")
    ap.add_argument("--out", help="output .py path (default sim/profiles/wheels/<key>.py)")
    ap.add_argument("--print", action="store_true", dest="to_stdout",
                    help="print to stdout instead of writing a file")
    ap.add_argument("--replay", action="store_true",
                    help="also mine the wire trace for a dev-0x17 replay table")
    args = ap.parse_args()

    cap_bytes = None
    source = ""
    if args.bundle:
        diag, cap_bytes = read_bundle(Path(args.bundle))
        source = Path(args.bundle).name
    else:
        diag = Path(args.diagnostics).read_text(encoding="utf-8", errors="replace")
        source = Path(args.diagnostics).name

    sections = parse_sections(diag)
    wsec = sections.get("Wheel identity", {})
    dsec = sections.get("Display sub-device identity", {})
    wheel = _ident_from_section(wsec)
    display = _ident_from_section(dsec)
    if "name" not in wheel:
        print("error: no wheel Model in diagnostics.txt (bundle didn't probe the "
              "wheel that session); pick a fuller bundle", file=sys.stderr)
        return 1

    module = emit_module(args.key, wheel, display, source)

    if args.to_stdout:
        sys.stdout.write(module)
    else:
        out = Path(args.out) if args.out else PROFILES_WHEELS / f"{args.key}.py"
        out.write_text(module)
        print(f"wrote {out}")

    if args.replay and cap_bytes is not None:
        n = _extract_replay(args.key, cap_bytes)
        print(f"replay: {n} dev-0x17 (group,payload)->response pairs "
              f"(see sim/replay/{args.key}_wheel_17.json)" if n else
              "replay: no pairs found")
    elif args.replay:
        print("replay: bundle had no serial-capture.txt", file=sys.stderr)

    print(f"\nparsed wheel fields: {sorted(wheel)}")
    if display:
        print(f"parsed display fields: {sorted(display)}")
    print("Review the TODOs, then it loads automatically via the registry.")
    return 0


_REPLAY_DEVS = {0x12: "hub", 0x13: "base", 0x17: "wheel", 0x19: "pedal"}


def _extract_replay(key: str, cap_bytes: bytes) -> int:
    """Best-effort: mine request→response pairs for the hub/base/wheel/pedal
    identity cascade from the bundle trace and write per-device replay tables.

    Pairs correctly by response group/device (resp_group == req_group|0x80,
    resp_dev == swap_nibbles(req_dev)) rather than "next frame", so unsolicited
    base traffic (0x2d sequence, 0xe4 hub status, …) isn't mis-paired. Plugin-only
    bundles (no PitHouse identity probes) yield few/no pairs — that's expected."""
    import json
    sys.path.insert(0, str(REPO / "sim"))
    import wheel_sim as ws  # noqa: E402

    line_re = re.compile(r"^\S+ \S+\s+([TR])\s+\S+\s+([0-9a-fA-F ]+)$")
    frames: List[Tuple[str, bytes]] = []
    for raw in io.StringIO(cap_bytes.decode("utf-8", "replace")):
        m = line_re.match(raw.rstrip("\n"))
        if not m:
            continue
        hexs = m.group(2).replace(" ", "")
        if len(hexs) % 2:
            continue
        frames.append(("h2b" if m.group(1) == "T" else "b2h", bytes.fromhex(hexs)))

    # pending[(resp_group, resp_dev)] = (req_dev, req_group, req_payload)
    pending: Dict[Tuple[int, int], Tuple[int, int, bytes]] = {}
    per_dev: Dict[int, Dict[str, str]] = {d: {} for d in _REPLAY_DEVS}
    for direction, fr in frames:
        if not ws.verify(fr) or len(fr) < 4:
            continue
        group, device = fr[2], fr[3]
        if direction == "h2b":
            # Identity/settings reads only — skip session/telemetry (0x43).
            if device in _REPLAY_DEVS and group != 0x43:
                resp_key = (group | 0x80, ws.swap_nibbles(device))
                pending[resp_key] = (device, group, bytes(ws.frame_payload(fr)))
        else:  # b2h reply
            hit = pending.pop((group, device), None)
            if hit is not None:
                req_dev, req_group, req_payload = hit
                per_dev[req_dev].setdefault(f"{req_group:02x}:{req_payload.hex()}", fr.hex())

    total = 0
    for dev, entries in per_dev.items():
        if not entries:
            continue
        role = _REPLAY_DEVS[dev]
        out = REPO / "sim" / "replay" / f"{key}_{role}_{dev:02x}.json"
        out.write_text(json.dumps(
            {"schema": 1, "device": dev, "label": f"{key} ({role})",
             "source": "diagnostics bundle serial-capture.txt", "entries": entries},
            indent=2))
        total += len(entries)
    return total


if __name__ == "__main__":
    raise SystemExit(main())
