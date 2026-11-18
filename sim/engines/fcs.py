"""FcsSimulator — MOZA Farming Control System (PID 0x0030, Pit House "S14").

Wire reference: docs/protocol/devices/fcs.md (moza-simhub-plugin). On top of
StandaloneSimulator (identity cascade + heartbeat for root device 0x12):

  * group 0x4E  [op][param][index]?[value] — op 1 write (store + echo), op 2
    read (stored value), op 3 calibration start/stop/cancel (echo), op 4 status
    (rightRodType, per-axis calibration result)
  * group 0x0E  firmware debug log for every write / calibration step, one
    message per frame as `05` + text + '\\n' truncated to 63 bytes, the same
    text the real firmware prints
  * HID         29-byte joystick report (6 axes + 128 buttons) on /dev/hidg<N>
    when the gadget carries the f_hid function

Not modelled: the 60 s "Throttle Heart Beat Log", the power-on banner, the
XY-calibration success log (only failures were captured) and the telemetry
light mode (wire format unknown — any 0x4E frame that doesn't parse is counted
as unhandled so it shows up in rig_unhandled).
"""
from __future__ import annotations

import os
import struct
import sys
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wheel_sim import build_frame, frame_payload, swap_nibbles  # noqa: E402
from engines.standalone import StandaloneSimulator  # noqa: E402

DEV = 0x12
GRP_SETTINGS = 0x4E
GRP_LOG = 0x0E
LOG_MAX = 63

OP_WRITE, OP_READ, OP_CALIB, OP_STATUS = 1, 2, 3, 4
# Telemetry light mode (write-only, sent while a game runs): per-LED colours
# and the on/off mask. Seen against the simulator with DiRT Rally 2.0.
TELE_COLOURS, TELE_MASK = 0x08, 0x09

# param -> (valid indices or None, value width). Names in docs/protocol/devices/fcs.md.
PARAMS: Dict[int, Tuple[Optional[Tuple[int, ...]], int]] = {
    0x01: ((0, 1, 2), 1),           # axis mode: 0 thumbstick, 1 joystick XY, 2 joystick Z
    0x02: ((0, 1, 2), 2),           # axis-as-button threshold (same index order)
    0x03: (None, 1),                # buttonGroupState: 0 off, 1 non-telemetry, 2 telemetry
    0x04: (None, 1),                # buttonGroupBrightness 0..100
    0x05: (tuple(range(6)), 3),     # LED 1..6 colour RGB (six square base-plate buttons)
    0x06: (None, 1),                # buttonGroupStandbyMode 0..6
    0x07: ((2, 3, 4, 5, 6), 2),     # standby interval (ms) of effect <index>
}

# Device values read at power-on in usb-capture/fcs/pcap/FCS Capture 2.pcapng.
DEFAULT_SETTINGS: Dict[Tuple[int, int], int] = {}
for _g in (0, 1, 2):
    DEFAULT_SETTINGS[(0x01, _g)] = 0
    DEFAULT_SETTINGS[(0x02, _g)] = 0xCCCC
DEFAULT_SETTINGS[(0x03, 0)] = 2
DEFAULT_SETTINGS[(0x04, 0)] = 80
for _i in range(6):
    DEFAULT_SETTINGS[(0x05, _i)] = 0x56F7FC
DEFAULT_SETTINGS[(0x06, 0)] = 2
for _e in (2, 3, 4, 5, 6):
    DEFAULT_SETTINGS[(0x07, _e)] = 3000

# Calibration control -> firmware axes. 1 thumbstick, 2 joystick XY,
# 3 throttle lever, 4 joystick Z (twist).
CALIB_AXES: Dict[int, Tuple[int, ...]] = {1: (4, 5), 2: (1, 2), 3: (0,), 4: (3,)}
CALIB_NAMES = {1: "thumbstick", 2: "joystickXy", 3: "throttle", 4: "joystickZ"}

# Per-axis calibration result (max, mid, min) reported on "stop", from the
# capture's firmware log / Table-9 float writes. Throttle (axis 0) has no mid.
# Joystick XY (axes 1/2) only failed in the captures, so no values exist.
DEFAULT_CALIB: Dict[int, Tuple[float, Optional[float], float]] = {
    0: (3337.00415, None, 479.99713),
    3: (2541.00219, 2164.80297, 1711.00793),
    4: (3414.99853, 1981.28662, 646.99139),
    5: (3498.99902, 2165.40673, 662.98956),
}

# Firmware Table-9 param numbers per wire setting (from the 0x0E log).
_ENABLE_PARAMS = {0: (56, 57), 1: (58, 59), 2: (60,)}
_BOUND_PARAMS = {0: (51, 52), 1: (53, 54), 2: (55,)}

# HID report: X Y Rx Ry Rz Z. Rest values from the captures (throttle lever
# reads full-scale at rest).
HID_AXIS_NAMES = ("joystick_x", "joystick_y", "thumbstick_x", "thumbstick_y",
                  "throttle", "joystick_z")
HID_REST = (32767, 32767, 32767, 32767, 65535, 32767)


def build_hid_report(axes, buttons: int) -> bytes:
    return bytes([0x01]) + struct.pack("<6H", *axes) + (buttons & ((1 << 128) - 1)).to_bytes(16, "little")


def _f32_bits(v: float) -> int:
    return struct.unpack("<I", struct.pack("<f", v))[0]


def find_hidg(gadget_key: str) -> Optional[str]:
    """/dev/hidg<N> of the configfs gadget moza_<gadget_key>, if it has f_hid."""
    devfile = f"/sys/kernel/config/usb_gadget/moza_{gadget_key}/functions/hid.usb0/dev"
    try:
        majmin = open(devfile).read().strip()
        for line in open(f"/sys/dev/char/{majmin}/uevent"):
            if line.startswith("DEVNAME="):
                return "/dev/" + line.split("=", 1)[1].strip()
    except OSError:
        return None
    return None


class FcsSimulator(StandaloneSimulator):
    def __init__(self, profile):
        super().__init__(profile)
        blk = profile.block("fcs")
        self.firmware_log = bool(blk.extras.get("firmware_log", True)) if blk else True
        self.settings: Dict[Tuple[int, int], int] = dict(DEFAULT_SETTINGS)
        self.right_rod_type = 1
        self.calib = dict(DEFAULT_CALIB)
        self.calib_result = {a: 1 for a in range(6)}
        self.calib_running: Dict[int, bool] = {}
        self.tele_colours: Dict[int, int] = {}
        self.tele_lit: Optional[int] = None     # 09 byte 0: LEDs lit (bit0 = LED 1)
        self.tele_owned: Optional[int] = None   # 09 byte 1: LEDs under telemetry control
        self.tele_frames = 0
        self.axes = list(HID_REST)
        self.buttons = 0
        self._hid_fd: Optional[int] = None
        self.hid_path = ""

    # ── HID ──────────────────────────────────────────────────────────────
    def attach_hid(self, path: str) -> bool:
        try:
            self._hid_fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
        except OSError:
            self._hid_fd = None
            return False
        self.hid_path = path
        self._write_hid()
        return True

    def set_input(self, axes: Optional[Dict[str, int]] = None,
                  buttons: Optional[List[int]] = None) -> bytes:
        """Update axes (by HID_AXIS_NAMES) and/or the pressed buttons (1-based
        numbers, replaces the set), write a report, return it."""
        for name, v in (axes or {}).items():
            self.axes[HID_AXIS_NAMES.index(name)] = max(0, min(65535, int(v)))
        if buttons is not None:
            self.buttons = 0
            for n in buttons:
                if 1 <= n <= 128:
                    self.buttons |= 1 << (n - 1)
        return self._write_hid()

    def _write_hid(self) -> bytes:
        rep = build_hid_report(self.axes, self.buttons)
        if self._hid_fd is not None:
            try:
                os.write(self._hid_fd, rep)
            except BlockingIOError:
                pass  # host hasn't read the previous report; it keeps the last state
            except OSError:
                self._hid_fd = None
        return rep

    # ── state view (MCP / self-test) ─────────────────────────────────────
    def snapshot(self) -> dict:
        s = {f"{p:02x}" + (f"/{i}" if PARAMS[p][0] else ""): v
             for (p, i), v in sorted(self.settings.items())}
        return {"settings": s, "right_rod_type": self.right_rod_type,
                "calib_result": dict(self.calib_result),
                "calib_running": [CALIB_NAMES[c] for c, r in self.calib_running.items() if r],
                "axes": dict(zip(HID_AXIS_NAMES, self.axes)),
                "buttons": [n + 1 for n in range(128) if self.buttons >> n & 1],
                "hid": self.hid_path or None,
                "telemetry": {"frames": self.tele_frames,
                              "lit": None if self.tele_lit is None else f"{self.tele_lit:06b}",
                              "owned": None if self.tele_owned is None else f"{self.tele_owned:06b}",
                              "colours": {i + 1: f"#{c:06X}" for i, c in sorted(self.tele_colours.items())}}}

    # ── wire ─────────────────────────────────────────────────────────────
    def _device_specific(self, frame, group, device, payload):
        if device != DEV:
            return None
        if group != GRP_SETTINGS:
            return None
        rsp = self._settings(payload)
        if rsp is None:
            self._record_unhandled(frame, group, device)
            return []
        self._record(rsp[0], frame)
        return rsp[1]

    def _settings(self, p: bytes) -> Optional[Tuple[str, List[bytes]]]:
        if len(p) < 2:
            return None
        op, param = p[0], p[1]
        if op == OP_WRITE and param in (TELE_COLOURS, TELE_MASK):
            return self._telemetry(p)
        if op in (OP_WRITE, OP_READ):
            spec = PARAMS.get(param)
            if spec is None:
                return None
            indices, width = spec
            head = 3 if indices else 2
            if len(p) != head + width:
                return None
            idx = p[2] if indices else 0
            if indices and idx not in indices:
                return None
            if op == OP_READ:
                val = self.settings[(param, idx)]
                return ("fcs_read", [self._reply(p[:head] + val.to_bytes(width, "big"))])
            val = int.from_bytes(p[head:], "big")
            self.settings[(param, idx)] = val
            return ("fcs_write", [self._reply(p)] + self._log_write(param, idx, val))
        if op == OP_CALIB and len(p) == 3 and param in CALIB_AXES and p[2] in (0, 1, 2):
            return ("fcs_calib", [self._reply(p)] + self._calib(param, p[2]))
        if op == OP_STATUS:
            if param == 0x03 and len(p) == 3:
                return ("fcs_status", [self._reply(bytes([OP_STATUS, 0x03, self.right_rod_type]))])
            if param == 0x04 and len(p) == 4 and p[2] in self.calib_result:
                return ("fcs_status", [self._reply(bytes([OP_STATUS, 0x04, p[2], self.calib_result[p[2]]]))])
        return None

    def _telemetry(self, p: bytes) -> Optional[Tuple[str, List[bytes]]]:
        """Telemetry-mode LED frames Pit House sends while a game runs:
        08 = list of [index R G B]; 09 = [lit mask, telemetry-owned mask],
        bit0 = LED 1. Before game data arrives Pit House sends lit=0x3F owned=0.
        Echoed like every other write; no EEPROM log (reply/log behaviour of the
        real firmware not captured yet)."""
        body = p[2:]
        if p[1] == TELE_COLOURS:
            if not body or len(body) % 4:
                return None
            for i in range(0, len(body), 4):
                if body[i] > 5:
                    return None
                self.tele_colours[body[i]] = int.from_bytes(body[i + 1:i + 4], "big")
            self.tele_frames += 1
            return ("fcs_tele_colours", [self._reply(p)])
        if len(body) != 2:
            return None
        self.tele_lit, self.tele_owned = body[0], body[1]
        self.tele_frames += 1
        return ("fcs_tele_mask", [self._reply(p)])

    def _reply(self, payload: bytes) -> bytes:
        return build_frame(GRP_SETTINGS | 0x80, swap_nibbles(DEV), payload)

    # ── calibration ──────────────────────────────────────────────────────
    def _calib(self, cal: int, action: int) -> List[bytes]:
        axes = CALIB_AXES[cal]
        lines: List[str] = []
        if action == 1:
            self.calib_running[cal] = True
            lines = [f"[INFO]farm_axis.c:1390 axis_{a} calib start" for a in axes]
        elif action == 2:
            self.calib_running[cal] = False
            lines = [f"[INFO]farm_axis.c:1448 axis_{a} calib cancelled" for a in axes]
        else:
            self.calib_running[cal] = False
            for a in axes:
                if a not in self.calib:
                    continue  # axes 1/2 (XY): no successful-calibration log was captured
                mx, md, mn = self.calib[a]
                if a == 0:
                    lines += ["[INFO]farm_axis.c:1537 axis 0 calib complete",
                              f"[INFO]farm_axis.c:1545 axis 0 max: {mx:.5f}, min: {mn:.5f}"]
                    lines += [self._param_line(32, _f32_bits(mx)), self._param_line(34, _f32_bits(mn))]
                else:
                    lines += [f"[INFO]farm_axis.c:1516 axis {a} calib complete",
                              f"[INFO]farm_axis.c:1524 axis {a} max: {mx:.5f}, mid: {md:.5f}, min: {mn:.5f}"]
                    lines += [self._param_line(32 + 3 * a + k, _f32_bits(v))
                              for k, v in enumerate((mx, md, mn))]
        return self._log(lines)

    # ── firmware log ─────────────────────────────────────────────────────
    @staticmethod
    def _param_line(param: int, value: int) -> str:
        return f"[INFO]param_manage.c:340 Table 9, Param {param} Written: {value} 0.00000"

    def _log_write(self, param: int, idx: int, val: int) -> List[bytes]:
        pl = self._param_line
        if param == 0x01:
            lines = [f"[INFO]serial_reply_app.c:381 AxisMappingButton group:{idx} enable:{val}"]
            lines += [pl(n, val) for n in _ENABLE_PARAMS[idx]]
        elif param == 0x02:
            lines = [pl(n, val) for n in _BOUND_PARAMS[idx]]
        elif param == 0x03:
            lines = [f"[INFO]farm_indicator.c:972 set mode:{val}"]
            if val:
                lines.append("[INFO]farm_indicator.c:482 led_state set: 2")
            lines.append(pl(7, val))
        elif param == 0x04:
            lines = [f"[INFO]farm_indicator.c:923 set brightness:{val}", pl(6, val)]
        elif param == 0x05:
            r, g, b = val >> 16, (val >> 8) & 0xFF, val & 0xFF
            lines = [f"[INFO]farm_indicator.c:947 led_{idx} set color: r:{r}, g:{g}, b:{b}"]
            lines += [pl(14 + idx * 3 + k, c) for k, c in enumerate((r, g, b))]
        elif param == 0x06:
            lines = [f"[INFO]farm_indicator.c:992 set effect:{val}",
                     "[INFO]farm_indicator.c:482 led_state set: 2", pl(8, val)]
        else:  # 0x07
            lines = [f"[INFO]farm_indicator.c:1017 set led frequency effect:{idx} frequency:{val}",
                     "[INFO]farm_indicator.c:482 led_state set: 2", pl(9 + idx - 2, val)]
        return self._log(lines)

    def _log(self, lines: List[str]) -> List[bytes]:
        if not self.firmware_log:
            return []
        rsp = swap_nibbles(DEV)
        return [build_frame(GRP_LOG, rsp, b"\x05" + (ln + "\n").encode("ascii")[:LOG_MAX])
                for ln in lines]


# ── offline self-test ───────────────────────────────────────────────────────

def _self_test() -> int:
    """Byte-exact checks against frames from usb-capture/fcs/pcap/FCS Capture 2.pcapng."""
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from profiles.standalone.fcs import PROFILE, HID_REPORT_DESCRIPTOR, HID_REPORT_LEN

    ok = True

    def check(desc, got, want):
        nonlocal ok
        if got == want:
            print(f"  ✓ {desc}")
        else:
            ok = False
            print(f"  ✗ {desc}\n      want {want}\n      got  {got}")

    def run(sim, hexframe):
        return [r.hex() for r in sim.handle(bytes.fromhex(hexframe))]

    sim = FcsSimulator(PROFILE)
    sim.firmware_log = False
    rsp21 = swap_nibbles(DEV)
    captured = [
        ("heartbeat", "7e0000129d", "7e0080212c"),
        ("caps 0x05", "7e04051200000000a6", "7e048521010200043c"),
        ("name 0x07", "7e01071201a6", "7e11872101464353202320533134000000000000003c"),
        ("mcu 0x0F", "7e010f1201ae", "7e118f2101525332312d5331342d4d432046435300f3"),
        ("0x11", "7e01111204b3", "7e029121040144"),
        ("hw 0x08/01", "7e01081201a7", "7e11882101525332312d5331342d48572054502d4333"),
        ("hw 0x08/02", "7e01081202a8", "7e11882102552d563130000000000000000000000080"),
        ("read led2", "7e064e12020501000000f9", "7e06ce2102050156f7fcd1"),
        ("read thumbstick mode", "7e044e1202010000f2", "7e04ce210201000081"),
        ("read XY threshold", "7e054e120202010000f5", "7e05ce21020201cccc1c"),
        ("read breath interval", "7e054e120207020000fb", "7e05ce210207020bb84d"),
        ("calib throttle start", "7e034e12030301f5", "7e03ce2103030184"),
        ("checkCalib thumbstick X", "7e044e1204040500fc", "7e04ce21040405018c"),
        ("write brightness 100", "7e034e1201046457", "7e03ce21010464e6"),
        ("write breath interval 3547", "7e054e120107020ddbe2", "7e05ce210107020ddb71"),
    ]
    print("FCS (0x12) — captured request/reply pairs:")
    for desc, req, want in captured:
        check(desc, run(sim, req), [want])

    for desc, req, want in [
        ("presence 0x09 -> 00 0b", build_frame(0x09, DEV, b""), b"\x00\x0b"),
        ("fw 0x04 -> 01 02 0a 00", build_frame(0x04, DEV, bytes(4)), b"\x01\x02\x0a\x00"),
        ("0x02 -> 02", build_frame(0x02, DEV, b"\x00"), b"\x02"),
        ("read brightness -> 80", build_frame(0x4E, DEV, b"\x02\x04\x00"), b"\x02\x04\x50"),
        ("read light mode -> 2", build_frame(0x4E, DEV, b"\x02\x03\x00"), b"\x02\x03\x02"),
        ("read standby effect -> 2", build_frame(0x4E, DEV, b"\x02\x06\x00"), b"\x02\x06\x02"),
        ("rightRodType -> 1", build_frame(0x4E, DEV, b"\x04\x03\x00"), b"\x04\x03\x01"),
    ]:
        g = req[2] | 0x80
        fresh = FcsSimulator(PROFILE)   # defaults, untouched by the writes above
        check(desc, run(fresh, req.hex()), [build_frame(g, rsp21, want).hex()])

    # write persists; read returns it
    run(sim, build_frame(0x4E, DEV, b"\x01\x05\x03\xc1\x6b\x10").hex())
    check("write led4 then read", run(sim, build_frame(0x4E, DEV, b"\x02\x05\x03\x00\x00\x00").hex()),
          [build_frame(0xCE, rsp21, b"\x02\x05\x03\xc1\x6b\x10").hex()])
    check("bad index -> unhandled", run(sim, build_frame(0x4E, DEV, b"\x02\x07\x01\x00\x00").hex()), [])
    check("unknown op -> unhandled", run(sim, build_frame(0x4E, DEV, b"\x05\x01\x00").hex()), [])
    check("wheelbase probe dropped", run(sim, build_frame(0x2B, 0x13, b"\x02\x00\x00").hex()), [])

    print("Firmware log (captured frames):")
    logsim = FcsSimulator(PROFILE)
    out = run(logsim, "7e034e1201046457")
    check("brightness 100 -> echo + 2 log frames", out, [
        "7e03ce21010464e6",
        "7e2f0e21055b494e464f5d6661726d5f696e64696361746f722e633a39323320736574206272696768746e6573733a3130300a97",
        "7e400e21055b494e464f5d706172616d5f6d616e6167652e633a333430205461626c6520392c20506172616d2036205772697474656e3a2031303020302e30303030300a82",
    ])
    out = run(logsim, build_frame(0x4E, DEV, b"\x01\x05\x00\xcb\x82\xff").hex())
    check("led_0 colour line truncated at 63 bytes", out[1],
          "7e400e21055b494e464f5d6661726d5f696e64696361746f722e633a393437206c65645f302073657420636f6c6f723a20723a3230332c20673a3133302c20623a32353543")
    out = run(logsim, build_frame(0x4E, DEV, b"\x03\x04\x01").hex())
    check("calib joystickZ start -> axis_3 log", out[1],
          "7e2b0e21055b494e464f5d6661726d5f617869732e633a3133393020617869735f332063616c69622073746172740afa")

    out = run(logsim, build_frame(0x4E, DEV, b"\x03\x04\x00").hex())
    texts = [bytes.fromhex(h)[5:-1].decode() for h in out[1:]]
    check("calib joystickZ stop -> complete + truncated max/mid line",
          texts[:2], ["[INFO]farm_axis.c:1516 axis 3 calib complete\n",
                      "[INFO]farm_axis.c:1524 axis 3 max: 2541.00219, mid: 2164.80297,"])
    # Table 9 params 41..43 / 32,34 / 44..49 as written by the real firmware.
    want_bits = {32: 1162907665, 34: 1139802018, 41: 1159647241, 42: 1158106329,
                 43: 1154867265, 44: 1163227130, 45: 1157081388, 46: 1143062387,
                 47: 1163571196, 48: 1158108802, 49: 1143324501}
    got_bits = {32: _f32_bits(DEFAULT_CALIB[0][0]), 34: _f32_bits(DEFAULT_CALIB[0][2])}
    for a in (3, 4, 5):
        for k in range(3):
            got_bits[32 + 3 * a + k] = _f32_bits(DEFAULT_CALIB[a][k])
    check("calibration float bits match captured Table 9 writes", got_bits, want_bits)

    print("HID:")
    check("descriptor length 52", len(HID_REPORT_DESCRIPTOR), 52)
    rest = build_hid_report(HID_REST, 0)
    check("rest report = captured idle report", rest.hex(),
          "01ff7fff7fff7fff7fffffff7f" + "00" * 16)
    check("report length", len(rest), HID_REPORT_LEN)
    rep = FcsSimulator(PROFILE).set_input({"throttle": 0}, [1, 128])
    check("throttle 0 + buttons 1,128", rep.hex(),
          "01ff7fff7fff7fff7f0000ff7f01" + "00" * 14 + "80")

    print("\n✓ fcs self-test passed" if ok else "\n✗ fcs self-test FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        raise SystemExit(_self_test())
    print("usage: fcs.py --self-test", file=sys.stderr)
    raise SystemExit(2)
