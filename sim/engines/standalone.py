"""StandaloneSimulator — minimal MOZA device simulator for peripherals that
enumerate as their own USB gadget (mBooster, standalone pedals/handbrake,
dashboards) instead of behind a wheelbase.

It reuses wheel_sim's wire primitives (frame build/verify, identity-cascade
builder) and the same generic ANSWER/ABSORB model as the refactored
WheelSimulator, but skips all the wheelbase session / tier-def / configJson
machinery those devices don't have. A device is described entirely by its
DeviceProfile blocks:

  * answers_identity block.ident  -> identity cascade (groups 02/04/05/06/07/08/
    09/0F/10/11) via wheel_sim._build_device_identity
  * present                       -> heartbeat (group 0x00) + 0x43 keepalive ACK
  * echo_write_groups             -> settings-write echo + stored value for reads
  * absorb_groups                 -> swallow high-rate writes (no reply)

Device-specific quirks (e.g. mBooster's group-0x24 motor cmd 0xb1 vs settings
cmds 1-29) go in a `_device_specific` hook a subclass overrides.
"""
from __future__ import annotations

import collections
import os
import sys
from typing import Deque, Dict, FrozenSet, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wheel_sim import (  # noqa: E402
    verify, frame_payload, build_frame, swap_nibbles, _build_device_identity,
)

_RECENT = 2000


class StandaloneSimulator:
    """Profile-driven simulator for a single-gadget standalone device."""

    def __init__(self, profile):
        self.profile = profile
        self.blocks = list(profile.blocks)
        self._identity: Dict[Tuple[int, int, bytes], bytes] = {}
        self._present: set = set()
        self._settings_groups: Dict[int, FrozenSet[int]] = {}
        self._absorb_groups: Dict[int, FrozenSet[int]] = {}
        # Stored settings for read-back: {(device, cmd_id): value_bytes}.
        self._stored: Dict[Tuple[int, int], bytes] = {}
        for b in self.blocks:
            if b.present:
                self._present.add(b.address)
            if b.answers_identity and b.ident:
                self._identity.update(_build_device_identity(b.address, b.ident))
            if b.echo_write_groups:
                self._settings_groups[b.address] = frozenset(b.echo_write_groups)
            if b.absorb_groups:
                self._absorb_groups[b.address] = frozenset(b.absorb_groups)
        self.frames_total = 0
        self.unhandled_counts: Dict[Tuple[int, int, str], int] = {}
        self.cat_counts: Dict[str, int] = {}
        self.recent_frames: Deque[Tuple[str, str]] = collections.deque(maxlen=_RECENT)
        self.last_handler_tag = ""

    # ── public API ───────────────────────────────────────────────────────
    def handle(self, frame: bytes) -> List[bytes]:
        if not verify(frame) or len(frame) < 4:
            return []
        self.frames_total += 1
        group, device = frame[2], frame[3]
        payload = bytes(frame_payload(frame))

        # 1. device-specific hook (subclass)
        rsp = self._device_specific(frame, group, device, payload)
        if rsp is not None:
            return rsp

        # 2. heartbeat (group 0x00, empty) — ACK for present devices
        if group == 0x00 and not payload:
            if device in self._present:
                self._record('heartbeat', frame)
                return [build_frame(0x80, swap_nibbles(device), b'')]
            return []

        # 3. bare 0x43 keepalive ping (n=1, payload 0x00)
        if group == 0x43 and payload == b'\x00':
            if device in self._present:
                self._record('keepalive_43', frame)
                return [build_frame(0xC3, swap_nibbles(device), b'\x80')]
            return []

        # 4. identity cascade
        idr = self._identity.get((device, group, payload))
        if idr is not None:
            self._record('identity', frame)
            return [build_frame(group | 0x80, swap_nibbles(device), idr)]

        # 5. settings: write echo + store; read returns stored value
        sgroups = self._settings_groups.get(device)
        if sgroups and group in sgroups:
            return self._handle_settings_write(frame, group, device, payload)
        rsp = self._handle_settings_read(frame, group, device, payload)
        if rsp is not None:
            return rsp

        # 6. absorb (swallow high-rate writes)
        agroups = self._absorb_groups.get(device)
        if agroups and group in agroups:
            self._record('absorb', frame)
            return []

        self._record_unhandled(frame, group, device)
        return []

    # ── overridable hook ─────────────────────────────────────────────────
    def _device_specific(self, frame, group, device, payload) -> Optional[List[bytes]]:
        """Subclass hook, called first. Return a response list to handle the
        frame, or None to fall through to the generic pipeline."""
        return None

    # ── settings ─────────────────────────────────────────────────────────
    def _handle_settings_write(self, frame, group, device, payload) -> List[bytes]:
        """A settings write (group in echo_write_groups): store the value keyed
        by cmd id and echo the frame verbatim (real devices ack writes)."""
        if payload:
            self._stored[(device, payload[0])] = payload[1:]
        self._record('settings_write', frame)
        return [build_frame(group | 0x80, swap_nibbles(device), payload)]

    def _handle_settings_read(self, frame, group, device, payload) -> Optional[List[bytes]]:
        """A settings read (the write group minus 1, e.g. pedal 0x23 vs 0x24)
        returns the last-written value for that cmd, or a 2-byte zero default.
        Best-effort: exact read-reply width is per-cmd and capture-unverified."""
        sgroups = self._settings_groups.get(device)
        if not sgroups:
            return None
        read_group = group + 1
        if read_group not in sgroups or not payload:
            return None
        cmd = payload[0]
        val = self._stored.get((device, cmd), b'\x00\x00')
        self._record('settings_read', frame)
        return [build_frame(group | 0x80, swap_nibbles(device), bytes([cmd]) + val)]

    # ── live serial loop ─────────────────────────────────────────────────
    def run_serial(self, port: str) -> None:
        """Open the gadget's ttyGS and service it: read each MOZA frame, run
        handle(), write the responses with MOZA 0x7E byte-stuffing (same wire
        convention as wheel_sim cmd_live's _write)."""
        import serial  # type: ignore
        from wheel_sim import read_one_frame, MSG_START

        ser = serial.Serial(port, baudrate=115200, timeout=None)
        print(f"[{type(self).__name__} on {port} — "
              f"{self.profile.friendly} pid=0x{self.profile.gadgets[0].pid:04x}]",
              file=sys.stderr)
        while True:
            frame = read_one_frame(ser)
            if not frame:
                continue
            for rsp in self.handle(frame):
                # Stuff: keep the leading 0x7E + length byte, double any 0x7E
                # in the body (group/device/payload/checksum).
                body = bytearray(rsp[:2])
                for b in rsp[2:]:
                    body.append(b)
                    if b == MSG_START:
                        body.append(MSG_START)
                ser.write(bytes(body))

    # ── bookkeeping ──────────────────────────────────────────────────────
    def _record(self, tag: str, frame: bytes) -> None:
        self.last_handler_tag = tag
        self.cat_counts[tag] = self.cat_counts.get(tag, 0) + 1
        self.recent_frames.append((tag, frame.hex()))

    def _record_unhandled(self, frame, group, device) -> None:
        payload = bytes(frame_payload(frame))
        cmd = payload[:2].hex()
        key = (group, device, cmd)
        self.unhandled_counts[key] = self.unhandled_counts.get(key, 0) + 1
        self.recent_frames.append(('unhandled', frame.hex()))


class MBoosterSimulator(StandaloneSimulator):
    """MOZA mBooster vibration pedal (PID 0x0008, device byte 0x12).

    Wire reference: docs/protocol/devices/mbooster.md. The plugin streams motor
    writes (group 0x24 cmd 0xb1) at ~50 Hz plus a ~500 ms keepalive; both must be
    absorbed/acked or PitHouse/the plugin retransmits. Settings (group 0x23 read /
    0x24 write, cmds 1-29) are the experimental calibration surface — echoed.

    No real capture exists for mBooster, so identity bytes are spec-derived
    placeholders; confirm against a real diagnostics bundle when available."""

    MOTOR_GROUP = 0x24
    MOTOR_CMD = 0xb1
    DEVICE = 0x12

    def _device_specific(self, frame, group, device, payload):
        # Motor write (group 0x24 cmd 0xb1) — absorb; real motor sends no reply.
        if (device == self.DEVICE and group == self.MOTOR_GROUP
                and payload[:1] == bytes([self.MOTOR_CMD])):
            self._record('mbooster_motor', frame)
            return []
        return None


class Cm1Simulator(StandaloneSimulator):
    """MOZA CM1 Racing Dash (base-bridged dash, device byte 0x14).

    Wire reference: docs/protocol/devices/dash-0x14.md § "CM1 Racing Dash". The
    CM1 does NOT speak tier-def — PitHouse drives it with a flat keyed float32
    stream on group 0x35 (+ a lower-rate 0x36) and reads a param-manager register
    bank on group 0x0E. Handled here:
      * heartbeat 0x00 / keepalive 0x43 -> ack (StandaloneSimulator, present)
      * group 0x35 / 0x36 keyed value stream -> absorb (block.absorb_groups)
      * group 0x32 cmd 0x81 dashboard switch -> 0xB2 ack (block.echo_write_groups)
      * group 0x0E register read -> 0x8E reply with the captured value (below)

    NOTE: a real CM1 is a 0x14 sub-device on a wheelbase, not its own USB device.
    This standalone engine exists to exercise the plugin's Cm1DisplayDriver in
    isolation; modelling it as a sub-device of a wheel rig is future work.

    Param register values captured from FSR1_CM1.pcapng (49 registers, 4 banks).
    Keys are DECIMAL register addresses (matching the doc); 0xFFFF8000 (int32
    -32768) is the firmware "unset/NA" sentinel returned for any unlisted reg.
    Interpretation is unconfirmed — these are replayed verbatim for fidelity."""

    DEVICE = 0x14
    PARAM_SENTINEL = 0xFFFF8000
    PARAM_TABLE = {
        1: 27, 2: 22, 3: 26, 4: 35, 5: 24, 7: 12, 9: 23, 10: 32, 13: 825,
        300: 875, 301: 51, 302: 9318, 303: 0, 304: 0, 305: 223, 307: 70,
        309: 164, 310: 91, 313: 843,
        400: 839, 401: 878,
        3000: 100, 3001: 0, 3002: 0, 3003: 0, 3004: 1, 3005: 62,
    }

    def _device_specific(self, frame, group, device, payload):
        # Param-manager register read: host 7E 03 0E 14 00 <hi> <lo>
        #                         -> dash 7E 07 8E 41 <hi> <lo> 00 <BE u32>
        if (device == self.DEVICE and group == 0x0E
                and len(payload) >= 3 and payload[0] == 0x00):
            import struct
            reg = (payload[1] << 8) | payload[2]
            val = self.PARAM_TABLE.get(reg, self.PARAM_SENTINEL)
            body = bytes([payload[1], payload[2], 0x00]) + struct.pack('>I', val)
            self._record('cm1_param', frame)
            return [build_frame(0x8E, swap_nibbles(self.DEVICE), body)]
        return None


# ── offline self-test ───────────────────────────────────────────────────────

def _self_test() -> int:
    """Feed the known-good mBooster frames from docs/protocol/devices/mbooster.md
    through MBoosterSimulator and assert the ANSWER/ABSORB behaviour. No gadget
    or serial port required."""
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from profiles.standalone.mbooster import PROFILE

    sim = MBoosterSimulator(PROFILE)
    ok = True

    def check(engine, desc, hexframe, want):
        nonlocal ok
        rsp = engine.handle(bytes.fromhex(hexframe.replace(" ", "")))
        got = [r.hex() for r in rsp]
        if got == want:
            print(f"  ✓ {desc}: {got if got else '(absorbed)'}")
        else:
            ok = False
            print(f"  ✗ {desc}: want {want} got {got}")

    # Heartbeat / keepalive (group 0x00 dev 0x12) -> 0x80 presence ack.
    ack = build_frame(0x80, swap_nibbles(0x12), b'').hex()
    check(sim, "keepalive 7e000012 -> presence ack", "7e 00 00 12 9d", [ack])
    # Motor writes (group 0x24 cmd 0xb1) -> absorbed (no reply).
    check(sim, "motor ABS on (0xb1)", "7e 09 24 12 b1 01 01 00 5a 1c 28 08 e8 0b", [])
    check(sim, "motor ABS off (0xb1)", "7e 09 24 12 b1 01 00 00 00 00 00 00 00 7c", [])
    check(sim, "motor Engine on (0xb1)", "7e 09 24 12 b1 04 01 00 64 0c cc 02 0c ca", [])
    # Settings write (group 0x24, cmd != 0xb1) -> echoed; then read (0x23) returns it.
    w = build_frame(0x24, 0x12, b'\x02\x34\x12')          # throttle-min = 0x1234
    we = build_frame(0xA4, 0x21, b'\x02\x34\x12').hex()   # echo (group|0x80, swap dev)
    check(sim, "settings write cmd 0x02 -> echo", w.hex(), [we])
    r = build_frame(0x23, 0x12, b'\x02')                  # read throttle-min
    re_ = build_frame(0xA3, 0x21, b'\x02\x34\x12').hex()  # returns stored value
    check(sim, "settings read cmd 0x02 -> stored value", r.hex(), [re_])

    # ── Handbrake (StandaloneSimulator, dev 0x1B, partial identity) ──────
    from profiles.standalone.handbrake import PROFILE as HB
    hb = StandaloneSimulator(HB)
    print("\nHandbrake (0x1B):")
    name = build_frame(0x07, 0x1B, b'\x01')
    name_r = build_frame(0x87, swap_nibbles(0x1B), b'\x01' + b'HB # S01'.ljust(16, b'\x00')).hex()
    check(hb, "name probe 0x07 -> 'HB # S01'", name.hex(), [name_r])
    dt = build_frame(0x04, 0x1B, b'\x00\x00\x00\x00')
    dt_r = build_frame(0x84, swap_nibbles(0x1B), bytes([0x01, 0x02, 0x03, 0x01])).hex()
    check(hb, "dev_type 0x04 -> 01 02 03 01", dt.hex(), [dt_r])
    caps = build_frame(0x05, 0x1B, b'\x00\x00\x00\x00')   # not captured -> zero default
    caps_r = build_frame(0x85, swap_nibbles(0x1B), bytes([0x01, 0x02, 0x00, 0x00])).hex()
    check(hb, "caps 0x05 -> zero-default (uncaptured)", caps.hex(), [caps_r])
    sw = build_frame(0x5C, 0x1B, b'\x05\x10\x00')         # settings write
    sw_r = build_frame(0xDC, swap_nibbles(0x1B), b'\x05\x10\x00').hex()
    check(hb, "settings write 0x5C -> echo", sw.hex(), [sw_r])

    # ── SRP pedals (StandaloneSimulator, dev 0x19, full identity) ────────
    from profiles.pedals.srp import PROFILE as SRP
    srp = StandaloneSimulator(SRP)
    print("\nSRP pedals (0x19):")
    pname = build_frame(0x07, 0x19, b'\x01')
    pname_r = build_frame(0x87, swap_nibbles(0x19), b'\x01' + b'SRP'.ljust(16, b'\x00')).hex()
    check(srp, "name probe 0x07 -> 'SRP'", pname.hex(), [pname_r])
    pcal = build_frame(0x26, 0x19, b'\x0c\x00')           # calibration-start -> absorb
    check(srp, "calibration 0x26 -> absorbed", pcal.hex(), [])

    # ── CM1 Racing Dash (Cm1Simulator, dev 0x14) ────────────────────────
    import struct
    from profiles.dashes.cm1 import PROFILE as CM1
    cm1 = Cm1Simulator(CM1)
    print("\nCM1 dash (0x14):")
    hb = build_frame(0x00, 0x14, b'')                     # presence probe
    hb_r = build_frame(0x80, swap_nibbles(0x14), b'').hex()
    check(cm1, "presence 0x00 -> 0x80 ack", hb.hex(), [hb_r])
    ping = build_frame(0x43, 0x14, b'\x00')               # session ping
    ping_r = build_frame(0xC3, swap_nibbles(0x14), b'\x80').hex()
    check(cm1, "session ping 0x43 -> 0xC3 ack", ping.hex(), [ping_r])
    preg = build_frame(0x0E, 0x14, b'\x00\x01\x2c')       # read reg 300 (=875)
    preg_r = build_frame(0x8E, swap_nibbles(0x14),
                         b'\x01\x2c\x00' + struct.pack('>I', 875)).hex()
    check(cm1, "param read reg 300 -> 875", preg.hex(), [preg_r])
    pregx = build_frame(0x0E, 0x14, b'\x00\x00\x06')      # unlisted reg -> sentinel
    pregx_r = build_frame(0x8E, swap_nibbles(0x14),
                          b'\x00\x06\x00' + struct.pack('>I', 0xFFFF8000)).hex()
    check(cm1, "param read unlisted -> sentinel", pregx.hex(), [pregx_r])
    stream = build_frame(0x35, 0x14, b'\xf5\x4d\x42\x20\x00\x00')  # one 0x35 record
    check(cm1, "0x35 value stream -> absorbed", stream.hex(), [])
    sw = build_frame(0x32, 0x14, b'\x81\x00\x00\x00\x03')  # switch to index 3
    sw_r = build_frame(0xB2, swap_nibbles(0x14), b'\x81\x00\x00\x00\x03').hex()
    check(cm1, "switch 0x32/81 -> 0xB2 ack", sw.hex(), [sw_r])

    print("\n✓ standalone self-test passed" if ok else "\n✗ standalone self-test FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        raise SystemExit(_self_test())
    print("usage: standalone.py --self-test", file=sys.stderr)
    raise SystemExit(2)
