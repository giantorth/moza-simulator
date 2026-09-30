"""MOZA mBooster lane simulator — a host unit plus optional chained units.

Wire reference: the AZOM plugin's docs/protocol/devices/mbooster.md. Everything
a unit answers comes from a seed built from a real diagnostics bundle
(tools/mbooster_seed_from_bundle.py): identity replies, register values and
the firmware's own heartbeat block. The behaviour on top of the seed is what
those captures showed:

* Settings (group 0x23 read / 0x24 write) are stored per unit; writes are
  echoed, the motor effect stream (0x24 cmd 0xB1) included — real units echo
  it too.
* The host prints the lane's heartbeat block once a minute (plus once on
  connect): pedal types, per-role link statistics for chained pedals,
  `PD Linked`, per-role angle lines. A chained unit prints its own shorter
  block. The per-role lines are regenerated from the topology, so a chained
  unit that is rebooting shows up as not connected — the same transient a real
  lane shows.
* Travel calibration (group 0x26): the cmd id names a ROLE (12/13/14 start,
  16/17/18 stop for T/B/C) and the unit resolves it through its own
  pedal-role map, 0x21/0x22/0x23 (Pit House's `<role>_channlRoleType` — the
  role of local channels T/B/C). The motor pedal is channel B, so a role
  mapped there sweeps and commits; a role mapped anywhere else logs
  `<X>-PD-C-S`, never sweeps, and fails on stop (`Err:3` on the host —
  KG143GNC; `Err:2` on a chained unit — JCJ5AEA2, whose map already read
  1/2/3). Pit House 1.4.1.13 sends the throttle pair to a chained throttle
  unit and the brake pair to the host brake (2026-09-29, this engine).
* Soft reboot (group 0x01 cmd 0x02, no reply) takes the unit offline for
  ~4.6 s. A chained unit going offline makes the host log `<R>-PD Offline!`.
* Motor rotor-locate (group 0x2A) reports running (1) until 59.5 s after the
  locate, then complete (3).
* An active firmware error is reported once a second as 0x0E
  `03 <code:2> 00 01`. In JCJ5AEA2 the chained unit sent `03 00 32 00 01`
  (50) all session after logging `error_code 50 occurs` (Brake Encoder
  Abnormal Reset), and the host sent `03 00 28 00 01` (40) only between its
  `error_code 40 occurs` / `clear` around the chained unit dropping offline.
  The engine raises 40 on the host while a chained unit is offline; any other
  code only when a profile sets it (extras "errors").

Identity a chained unit was never asked for in the capture falls back to the
host's — they are the same product and firmware.
"""
from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wheel_sim import build_frame, frame_payload, swap_nibbles  # type: ignore  # noqa: E402

from engines.standalone import StandaloneSimulator

SEED_DIR = Path(__file__).resolve().parent.parent / "profiles" / "standalone" / "seeds"

ROLE_NAMES = ("Throttle", "Brake", "Clutch")
ROLE_LETTERS = ("T", "B", "C")
# Travel calibration command pairs by pedal role (throttle, brake, clutch).
CAL_START = (12, 13, 14)
CAL_STOP = (16, 17, 18)
MOTOR_CHANNEL = 1              # the motor pedal is local channel B
IDENTITY_GROUPS = {0x02, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0F, 0x10, 0x11}
SELECTOR_CMDS = {0xAB, 0xB2, 0xAE, 0xAD}
MOTOR_CMD = 0xB1
REBOOT_SECONDS = 4.6
HEARTBEAT_SECONDS = 60.0
LOCATE_SECONDS = 59.5
ERROR_REPORT_SECONDS = 1.0
PARAM_UNSET = bytes.fromhex("00008000")
ERR_CHAINED_OFFLINE = 40
TEXT_CHUNK = 60                # 0x0E text frames carry 05 + <= 63 bytes
# The firmware prints its degree sign as UTF-8; seed text is latin-1 decoded,
# so it reads back as these two characters and re-encodes to the same bytes.
DEG = "\u00c2\u00b0"
# `<R>-PD:[min … max … angle …]`: the host prints min 65535 for a role that
# is not physically on it (absent or chained) — the plugin's locality test.
PD_SENTINEL_MIN = "65535.00000"


def _reg_key(payload: bytes) -> Tuple[bytes, bytes]:
    if payload and payload[0] in SELECTOR_CMDS and len(payload) >= 3:
        return payload[:3], payload[3:]
    return payload[:1], payload[1:]


@dataclass
class Unit:
    dev: int
    default_role: int                       # profile's role, until 0x22 says otherwise
    identity: Dict[Tuple[int, bytes], bytes] = field(default_factory=dict)
    regs: Dict[bytes, bytes] = field(default_factory=dict)
    params: Dict[bytes, bytes] = field(default_factory=dict)   # 0x0E table
    heartbeat: List[str] = field(default_factory=list)
    errors: set = field(default_factory=set)   # active firmware error codes
    acked: set = field(default_factory=set)    # codes the host acknowledged
    offline_until: float = 0.0
    cal: Optional[dict] = None              # running travel calibration
    locate_started: float = 0.0
    last_error_report: float = 0.0
    boot_due: bool = False                  # print boot lines once back online
    sleep_before_cal: Optional[bytes] = None  # 0xB4 reads 0 until the post-cal reboot

    def online(self, now: float) -> bool:
        return now >= self.offline_until

    @property
    def role(self) -> int:
        """Host-facing role of this unit's motor pedal (0 T, 1 B, 2 C). The
        unit's registers 0x21/0x22/0x23 hold the role (1-3) of its local
        channels T/B/C, and the motor pedal is always channel B — Pit House
        assigns roles by writing 0x22 (captured with this engine, 2026-09-29:
        `writeRole Slot` -> `24 <dev> 22 00 <role>`)."""
        v = self.regs.get(b"\x22")
        if v and 1 <= int.from_bytes(v, "big") <= 3:
            return int.from_bytes(v, "big") - 1
        return self.default_role


class MBoosterSimulator(StandaloneSimulator):
    """Seed-driven mBooster lane. Topology comes from the profile's first
    block extras:

        seed        seed file name under profiles/standalone/seeds/
        units       [{"dev": 0x12, "role": 1}, {"dev": 0x1d, "role": 0,
                      "regs": {"21": "0002"}}]   # optional register overrides
        passive     role indexes wired to the host as passive pedals
        host_dev    the lane's host id (0x12 USB, 0x19 routed)
        errors      {dev: [code, ...]} firmware errors active from start
    """

    def __init__(self, profile, clock=time.monotonic):
        super().__init__(profile)
        self._clock = clock
        extras = profile.blocks[0].extras if profile.blocks else {}
        seed = json.loads((SEED_DIR / extras["seed"]).read_text(encoding="utf-8"))
        self.host_dev: int = extras.get("host_dev", 0x12)
        self.passive: Tuple[int, ...] = tuple(extras.get("passive", ()))
        seed_units = seed["units"]
        host_seed = seed_units.get(f"0x{self.host_dev:02x}") or next(iter(seed_units.values()))
        self.units: Dict[int, Unit] = {}
        for spec in extras["units"]:
            dev = spec["dev"]
            s = seed_units.get(f"0x{dev:02x}", host_seed)
            ident = self._load_identity(host_seed)
            own = self._load_identity(s) if f"0x{dev:02x}" in seed_units else {}
            ident.update(own)
            # MCU UID and serial identify the unit: Pit House merges units
            # that report the same UID into one controller. A unit the capture
            # never asked gets its own synthetic values, never the host's.
            for key in ((0x06, b""), (0x10, b"\x00"), (0x10, b"\x01")):
                if key not in own and key in ident:
                    ident[key] = self._synthetic_id(key, ident[key], dev)
            u = Unit(dev=dev, default_role=spec["role"], identity=ident,
                     regs={bytes.fromhex(k): bytes.fromhex(v) for k, v in s["registers"].items()},
                     heartbeat=list(s["heartbeat"]),
                     params={bytes.fromhex(k): bytes.fromhex(v) for k, v in s.get("params", {}).items()},
                     errors=set(extras.get("errors", {}).get(dev, ())))
            for k, v in spec.get("regs", {}).items():
                u.regs[bytes.fromhex(k)] = bytes.fromhex(v)
            self.units[dev] = u
        self._pending: List[bytes] = []
        self._next_heartbeat: Optional[float] = None

    @staticmethod
    def _synthetic_id(key: Tuple[int, bytes], template: bytes, dev: int) -> bytes:
        group, req = key
        tag = (f"AZ{dev:02X}UID" if group == 0x06 else f"AZ{dev:02X}S{req[0]}").encode("ascii")
        if group == 0x06:
            return (tag * (len(template) // len(tag) + 1))[:len(template)]
        body = template[1:]
        n = body.find(b"\x00")
        n = len(body) if n < 0 else n
        return template[:1] + (tag * (n // len(tag) + 1))[:n] + body[n:]

    @staticmethod
    def _load_identity(s: dict) -> Dict[Tuple[int, bytes], bytes]:
        out = {}
        for k, v in s.get("identity", {}).items():
            g, req = k.split(":")
            out[(int(g, 16), bytes.fromhex(req))] = bytes.fromhex(v)
        return out

    # ── helpers ──────────────────────────────────────────────────────────
    def _reply(self, group: int, dev: int, payload: bytes) -> bytes:
        return build_frame(group | 0x80, swap_nibbles(dev), payload)

    def _log(self, dev: int, *lines: str) -> None:
        """Queue firmware 0x0E text lines from unit `dev`. Each line starts a
        new frame and only a long line continues into the next, as the real
        firmware frames it (a lone `05 0a` carries a line's trailing newline);
        consumers read a frame's text on its own, so two lines sharing a frame
        would be misread."""
        for ln in lines:
            text = (ln + "\n").encode("latin-1", errors="replace")
            for i in range(0, len(text), TEXT_CHUNK):
                self._pending.append(build_frame(0x0E, swap_nibbles(dev), b"\x05" + text[i:i + TEXT_CHUNK]))

    @property
    def host(self) -> Unit:
        return self.units[self.host_dev]

    def _chained(self) -> List[Unit]:
        return [u for d, u in self.units.items() if d != self.host_dev]

    def _unit_for_role(self, role: int) -> Optional[Unit]:
        for u in self.units.values():
            if u.role == role:
                return u
        return None

    # ── dispatch ─────────────────────────────────────────────────────────
    def _device_specific(self, frame, group, device, payload):
        u = self.units.get(device)
        if u is None:
            return None
        now = self._clock()
        if self._next_heartbeat is None:
            self._next_heartbeat = now + 1.0
        if not u.online(now):
            self._record("offline", frame)
            return []

        if group == 0x00 and not payload:
            self._record("heartbeat", frame)
            return [self._reply(0x00, device, b"")]
        if group == 0x0E and payload[:1] == b"\x04" and len(payload) >= 3:
            # Host acknowledges an error report (03 <code> 00 01 -> 04 <code> 01);
            # the unit confirms on 0x8E (04 <code> 00 01) and stops repeating
            # that code — Pit House captures, 2026-09-08.
            code = payload[1:3]
            u.acked.add(int.from_bytes(code, "big"))
            self._record("error_ack", frame)
            return [self._reply(0x0E, device, b"\x04" + code + b"\x00\x01")]
        if group == 0x0E and len(payload) == 3 and payload[0] == 0x00:
            # Parameter table read: 00 <idx:2> -> 00 <idx:2> <value:4>. The
            # real units answer every index; unset ones read 0x00008000.
            val = u.params.get(payload[1:3], PARAM_UNSET)
            self._record("param", frame)
            return [self._reply(0x0E, device, payload + val)]
        if group in IDENTITY_GROUPS:
            rsp = u.identity.get((group, payload))
            if rsp is None:
                self._record_unhandled(frame, group, device)
                return []
            self._record("identity", frame)
            return [self._reply(group, device, rsp)]
        if group == 0x23:
            key, _ = _reg_key(payload)
            val = u.regs.get(key)
            if val is None:
                self._record_unhandled(frame, group, device)
                return []
            self._record("read", frame)
            return [self._reply(group, device, key + val)]
        if group == 0x24:
            if payload[:1] == bytes([MOTOR_CMD]):
                self._record("mbooster_motor", frame)
            else:
                key, val = _reg_key(payload)
                u.regs[key] = val
                self._record("write", frame)
            return [self._reply(group, device, payload)]
        if group == 0x25:
            # Output position per role (cmd 1..3) — no pedal is being pressed.
            self._record("output", frame)
            return [self._reply(group, device, payload[:1] + b"\x00\x00")]
        if group == 0x26 and payload:
            self._calibration(u, payload[0], now)
            self._record("calibration", frame)
            return [self._reply(group, device, payload)]
        if group == 0x2A and payload:
            return self._motor_cal(u, payload, now, frame)
        if group == 0x01 and payload[:1] == b"\x02":
            self._record("soft_reboot", frame)
            self._reboot(u, now)
            return []
        return None

    # ── calibration ──────────────────────────────────────────────────────
    @staticmethod
    def _channel_for_role(u: Unit, role: int) -> Optional[int]:
        """The unit's local channel carrying `role`, per its 0x21-0x23 map."""
        for c in range(3):
            v = u.regs.get(bytes([0x21 + c]))
            if v and int.from_bytes(v, "big") == role + 1:
                return c
        return None

    def _calibration(self, u: Unit, cmd: int, now: float) -> None:
        if cmd in CAL_START:
            role = CAL_START.index(cmd)
            # 0xB4 (auto-sleep minutes) read 0 from cal-start to the reboot
            # in the 2026-09-08 captures.
            if u.sleep_before_cal is None:
                u.sleep_before_cal = u.regs.get(b"\xb4", (0).to_bytes(4, "big"))
            u.regs[b"\xb4"] = (0).to_bytes(4, "big")
            if self._channel_for_role(u, role) == MOTOR_CHANNEL:
                u.cal = {"ok": True, "t0": now, "steps": [
                    (2.5, "[INFO]common_wrapper.c:57 Pedal Calib Backward"),
                    (6.1, "[INFO]common_wrapper.c:57 Pedal Calib Forward"),
                    (9.7, "[INFO]common_wrapper.c:57 Pedal Calib pressure Calculating....")]}
                self._log(u.dev, f"[INFO]pedal_cmd.c:781 {ROLE_LETTERS[role]}-PD-C-S",
                          "[INFO]model_app.c:65 pedal_active_mode changed: 4",
                          "[INFO]motor_mode.c:28 Set MotorMode to:12",
                          "[INFO]pedal_active.c:387 Foot on, motor enabled",
                          "[INFO]common_wrapper.c:57 Pedal Calib Start")
            else:
                u.cal = {"ok": False, "t0": now, "steps": []}
                self._log(u.dev, f"[INFO]pedal_cmd.c:768 {ROLE_LETTERS[role]}-PD-C-S")
        elif cmd in CAL_STOP and u.cal is not None:
            role = CAL_STOP.index(cmd)
            if u.cal["ok"] and self._channel_for_role(u, role) == MOTOR_CHANNEL:
                self._log(u.dev, "[INFO]common_wrapper.c:57 Pedal Calib End")
            else:
                err = 3 if u.dev == self.host_dev else 2
                self._log(u.dev, f"[ERRO]pedal_cmd.c:818 {ROLE_LETTERS[role]}-PD-C Err:{err}",
                          "[INFO]param_manage.c:312 Table Id 6, ParamAddr 28: Failed to Write")
            u.cal = None

    def _motor_cal(self, u: Unit, payload: bytes, now: float, frame) -> List[bytes]:
        cmd = payload[0]
        param = int.from_bytes(payload[1:3], "big") if len(payload) >= 3 else 0
        if cmd == 0x15 and param == 0x0103:
            u.locate_started = now
            self._log(u.dev, "[INFO]motor_wrapper.c:58 Motor Locate Start")
        state = 0
        if u.locate_started:
            state = 3 if now - u.locate_started >= LOCATE_SECONDS else 1
        self._record("motor_cal", frame)
        if cmd == 0x15 and param == 0:
            return [self._reply(0x2A, u.dev, bytes([0x15, 0x00, state]))]
        return [self._reply(0x2A, u.dev, payload)]

    def _reboot(self, u: Unit, now: float) -> None:
        self._log(u.dev, "[INFO]serial_cmd_com.c:262 Software reset")
        u.cal = None
        u.locate_started = 0.0
        if u.sleep_before_cal is not None:
            u.regs[b"\xb4"] = u.sleep_before_cal
            u.sleep_before_cal = None
        u.offline_until = now + REBOOT_SECONDS
        targets = list(self.units.values()) if u.dev == self.host_dev else [u]
        for t in targets:
            t.offline_until = now + REBOOT_SECONDS
        if u.dev != self.host_dev:
            # The host names the lost pedal by ITS channel T (the chain link),
            # not the unit's own 0x22 — JCJ5AEA2 logged T-PD Offline! with
            # the chained unit's 0x22 reading Brake.
            link = self.host.regs.get(b"\x21")
            link_role = int.from_bytes(link, "big") - 1 if link and 1 <= int.from_bytes(link, "big") <= 3 else u.role
            letter = ROLE_LETTERS[link_role]
            self._log(self.host_dev, "[INFO]motor_mode.c:28 Set MotorMode to:0",
                      "[INFO]pedal_active.c:367 Foot off, motor disabled",
                      f"[ERRO]diag_svr_event.c:86 error_code {ERR_CHAINED_OFFLINE} occurs",
                      f"[ERRO]pedal_diagnostic.c:69 {letter}-PD Offline!")
            self.host.errors.add(ERR_CHAINED_OFFLINE)
            self.host.acked.discard(ERR_CHAINED_OFFLINE)
        u.boot_due = True

    # ── unprompted frames ────────────────────────────────────────────────
    def poll(self) -> List[bytes]:
        now = self._clock()
        for u in self.units.values():
            if u.boot_due and u.online(now):
                u.boot_due = False
                self._boot(u)
            if u.cal and u.cal["steps"]:
                while u.cal["steps"] and now - u.cal["t0"] >= u.cal["steps"][0][0]:
                    self._log(u.dev, u.cal["steps"].pop(0)[1])
            if not u.online(now):
                continue
            pending = u.errors - u.acked
            if pending and now - u.last_error_report >= ERROR_REPORT_SECONDS:
                u.last_error_report = now
                for code in sorted(pending):
                    self._pending.append(build_frame(
                        0x0E, swap_nibbles(u.dev), b"\x03" + code.to_bytes(2, "big") + b"\x00\x01"))
        if self._next_heartbeat is not None and now >= self._next_heartbeat:
            self._next_heartbeat = now + HEARTBEAT_SECONDS
            if self.host.online(now):
                self._log(self.host_dev, *self._host_heartbeat(now))
            for c in self._chained():
                if c.online(now) and c.heartbeat:
                    self._log(c.dev, *c.heartbeat)
        out, self._pending = self._pending, []
        return out

    def _boot(self, u: Unit) -> None:
        if u.dev != self.host_dev and all(c.online(self._clock()) for c in self._chained()):
            self.host.errors.discard(ERR_CHAINED_OFFLINE)
            self._log(self.host_dev, f"[INFO]diag_svr_event.c:108 error_code {ERR_CHAINED_OFFLINE} clear")
        if u.dev != self.host_dev:
            # JCJ5AEA2's chained unit printed its map at boot (Table 6 params
            # 44/45/46) — the values it already held.
            vals = [int.from_bytes(u.regs.get(bytes([0x21 + i]), b"\x00\x00"), "big") for i in range(3)]
            self._log(u.dev, *[f"[INFO]param_manage.c:340 Table 6, Param {44 + i} Written: {v} 0.00000"
                               for i, v in enumerate(vals)])
        self._log(u.dev, "[INFO]motor_wrapper.c:58 Motor StartupCheck Success")

    def _host_heartbeat(self, now: float) -> List[str]:
        """The host's block. The per-role lines (type, chained-link statistics,
        PD Linked, <R>-PD angles) are rebuilt from the topology in the captured
        order; every other line is the captured one."""
        tpl = self.host.heartbeat
        if not tpl:
            return []
        role_block: List[str] = []
        linked: List[int] = []
        pd: Dict[int, bool] = {}               # role -> physically on the host
        # The host reports by ITS channels: 0x21/0x22/0x23 give each channel's
        # role. Channel B is the host's own motor pedal, channel T the chain
        # link (JCJ5AEA2: host 1/2/3 still reported the Throttle connected and
        # active while the chained unit's own 0x22 said Brake), channel C and
        # an unchained T take passive pedals.
        chained = self._chained()
        channel_of_role: Dict[int, int] = {}
        for c in range(3):
            v = self.host.regs.get(bytes([0x21 + c]))
            r = int.from_bytes(v, "big") - 1 if v and 1 <= int.from_bytes(v, "big") <= 3 else c
            channel_of_role.setdefault(r, c)
        for r, name in enumerate(ROLE_NAMES):
            c = channel_of_role.get(r)
            link = chained[0] if (c == 0 and chained) else None
            if c == 1 or (link is not None and link.online(now)):
                pd[r] = c == 1
                linked.append(1)
                role_block.append(f"{name} pedal is connected, type: active pedal")
                if link is not None:
                    captured = [ln for ln in tpl if ln.startswith(f"{name} M")]
                    role_block += captured or [f"{name} Mean Loss Rate : 0.00000 (%)",
                                               f"{name} Max Loss  Rate : 1.00000 (%)",
                                               f"{name} Max Recv  Gap  : 10.00000 (ms)"]
            elif c is not None and link is None and c in self.passive:
                pd[r] = True
                linked.append(1)
                role_block.append(f"{name} pedal is connected, type: passive pedal")
            else:
                linked.append(0)
                role_block.append(f"{name} pedal is not connected !")
                pd[r] = False

        def is_role_line(ln: str) -> bool:
            return " pedal is " in ln or "Loss Rate" in ln or "Loss  Rate" in ln or "Recv  Gap" in ln

        out: List[str] = []
        placed = False
        for ln in tpl:
            if is_role_line(ln):
                if not placed:
                    out += role_block
                    placed = True
                continue
            if ln.startswith("PD Linked:"):
                out.append("PD Linked:[" + " ".join(
                    f"{ROLE_LETTERS[i]} {v}" for i, v in enumerate(linked)) + "]")
                continue
            if ln[1:6] == "-PD:[" and ln[:1] in ROLE_LETTERS and " max " in ln:
                # Keep the captured max/angle; only the min sentinel follows
                # where the pedal actually is.
                local = pd.get(ROLE_LETTERS.index(ln[:1]), False)
                head, rest = ln.split(" max ", 1)
                cur = head[len("T-PD:[min "):]
                if not local:
                    cur = PD_SENTINEL_MIN + DEG
                elif cur.startswith(PD_SENTINEL_MIN):
                    cur = "0.00000" + DEG
                out.append(f"{ln[:1]}-PD:[min {cur} max {rest}")
                continue
            out.append(ln)
        return out


# ── self-test ────────────────────────────────────────────────────────────────

def _text(frames: List[bytes]) -> Dict[int, List[str]]:
    """0x0E text lines per source unit (device id, unswapped)."""
    bufs: Dict[int, str] = {}
    out: Dict[int, List[str]] = {}
    for f in frames:
        if f[2] != 0x0E:
            continue
        pl = frame_payload(f)
        if pl[:1] != b"\x05":
            continue
        dev = swap_nibbles(f[3])
        buf = bufs.get(dev, "") + pl[1:].decode("latin-1")
        while "\n" in buf:
            ln, buf = buf.split("\n", 1)
            out.setdefault(dev, []).append(ln)
        bufs[dev] = buf
    return out


def _self_test() -> int:
    from profiles.standalone.mbooster_chain import PROFILE

    t = [0.0]
    sim = MBoosterSimulator(PROFILE, clock=lambda: t[0])
    ok = True

    def expect(desc, cond):
        nonlocal ok
        print(("  \u2713 " if cond else "  \u2717 ") + desc)
        ok = ok and cond

    def send(grp, dev, pl=b""):
        return sim.handle(build_frame(grp, dev, pl))

    def run(seconds, step=0.25):
        frames = []
        end = t[0] + seconds
        while t[0] < end:
            t[0] += step
            frames += sim.poll()
        return frames

    expect("host keepalive acked", send(0x00, 0x12) == [build_frame(0x80, 0x21, b"")])
    expect("chained 0x1d keepalive acked", send(0x00, 0x1D) == [build_frame(0x80, 0xD1, b"")])
    expect("0x1e never answers", send(0x00, 0x1E) == [])
    p1 = send(0x0E, 0x1D, b"\x00\x00\x01")
    expect("param table read answered", bool(p1) and frame_payload(p1[0])[:3] == b"\x00\x00\x01"
           and len(frame_payload(p1[0])) == 7)
    expect("unset param reads 0x8000",
           send(0x0E, 0x12, b"\x00\xff\xfe") == [build_frame(0x8E, 0x21, b"\x00\xff\xfe\x00\x00\x80\x00")])
    uid_h, uid_c = send(0x06, 0x12), send(0x06, 0x1D)
    expect("host and chained report different MCU UIDs",
           bool(uid_h) and bool(uid_c) and frame_payload(uid_h[0]) != frame_payload(uid_c[0]))
    name = send(0x07, 0x1D, b"\x01")
    expect("chained model name 'mBooster'", bool(name) and b"mBooster" in frame_payload(name[0]))

    hb = _text(run(1.5))
    host = hb.get(0x12, [])
    expect("host heartbeat names Throttle active", "Throttle pedal is connected, type: active pedal" in host)
    expect("host heartbeat has chained-link stats", any("Throttle Mean Loss Rate" in x for x in host))
    expect("host heartbeat PD Linked all up", "PD Linked:[T 1 B 1 C 1]" in host)
    expect("host heartbeat clutch passive", "Clutch pedal is connected, type: passive pedal" in host)
    expect("chained unit prints its own block", any("PD Linked: 1" in x for x in hb.get(0x1D, [])))

    # Auto-sleep (0xB4, minutes): Pit House's 5 h write.
    sleep300 = b"\xb4\x00\x00\x01\x2c"
    expect("sleep write echoed", send(0x24, 0x12, sleep300) == [build_frame(0xA4, 0x21, sleep300)])
    expect("sleep reads back 300", send(0x23, 0x12, b"\xb4\x00\x00\x00\x00") == [build_frame(0xA3, 0x21, sleep300)])

    # Brake calibration on the host: sweeps and commits.
    send(0x26, 0x12, bytes([13, 0, 0]))
    lines = _text(sim.poll() + run(10.5)).get(0x12, [])
    expect("brake cal start B-PD-C-S", any("B-PD-C-S" in x for x in lines))
    expect("brake cal sweeps (Backward/Forward/pressure)",
           all(any(k in x for x in lines) for k in ("Backward", "Forward", "pressure")))
    send(0x26, 0x12, bytes([17, 0, 0]))
    expect("brake cal stop commits", any("Pedal Calib End" in x for x in _text(sim.poll()).get(0x12, [])))
    expect("sleep reads 0 until the reboot",
           send(0x23, 0x12, b"\xb4\x00\x00\x00\x00") == [build_frame(0xA3, 0x21, b"\xb4\x00\x00\x00\x00")])
    send(0x01, 0x12, b"\x02")
    run(6)
    expect("reboot restores the sleep timeout",
           send(0x23, 0x12, b"\xb4\x00\x00\x00\x00") == [build_frame(0xA3, 0x21, sleep300)])

    # Throttle calibration to the chained throttle unit, as Pit House sends
    # it: with its map healthy (2/1/3 — throttle on its motor channel B) it
    # sweeps; with JCJ5AEA2's 1/2/3 the throttle role points at channel T,
    # which has no motor, and it fails (Err:2) — the map is left as it was.
    c = sim.units[0x1D]
    c.regs[b"\x21"], c.regs[b"\x22"] = b"\x00\x02", b"\x00\x01"
    send(0x26, 0x1D, bytes([12, 0, 0]))
    lines = _text(sim.poll() + run(10.5)).get(0x1D, [])
    expect("throttle cal on a healthy chained unit sweeps",
           any("T-PD-C-S" in x for x in lines) and any("Pedal Calib Forward" in x for x in lines))
    send(0x26, 0x1D, bytes([16, 0, 0]))
    expect("stop -> Pedal Calib End", any("Pedal Calib End" in x for x in _text(sim.poll()).get(0x1D, [])))
    c.regs[b"\x21"], c.regs[b"\x22"] = b"\x00\x01", b"\x00\x02"
    send(0x26, 0x1D, bytes([12, 0, 0]))
    lines = _text(sim.poll() + run(20)).get(0x1D, [])
    expect("throttle cal with map 1/2/3 logs T-PD-C-S only",
           any("T-PD-C-S" in x for x in lines) and not any("Pedal Calib" in x for x in lines))
    send(0x26, 0x1D, bytes([16, 0, 0]))
    expect("stop -> T-PD-C Err:2", any("T-PD-C Err:2" in x for x in _text(sim.poll()).get(0x1D, [])))
    send(0x01, 0x1D, b"\x02")
    expect("rebooting unit is silent", send(0x00, 0x1D) == [])
    offline = sim.poll()
    host = _text(offline).get(0x12, [])
    expect("host logs T-PD Offline!", any("T-PD Offline!" in x for x in host))
    err40 = build_frame(0x0E, 0x21, b"\x03\x00\x28\x00\x01")
    expect("host reports error 40 while chained unit is down", err40 in offline + run(1.5))
    sim._next_heartbeat = t[0] + 0.2          # a heartbeat inside the reboot window
    hb = _text(run(0.5)).get(0x12, [])
    expect("heartbeat during reboot: Throttle not connected",
           "Throttle pedal is not connected !" in hb and "PD Linked:[T 0 B 1 C 1]" in hb)
    after = run(5)
    boot = _text(after).get(0x1D, [])
    expect("error 40 cleared once it is back", err40 not in run(3))
    sim.host.errors.add(50)
    rep50 = build_frame(0x0E, 0x21, b"\x03\x00\x32\x00\x01")
    expect("unacked error repeats", run(2.5).count(rep50) >= 2)
    expect("ack -> unit confirms on 0x8E",
           send(0x0E, 0x12, b"\x04\x00\x32\x01") == [build_frame(0x8E, 0x21, b"\x04\x00\x32\x00\x01")])
    expect("acked error stops repeating", rep50 not in run(3))
    expect("boot prints its map (Table 6 params 44-46)", any("Param 44 Written: 1" in x for x in boot))
    r22 = send(0x23, 0x1D, b"\x22\x00\x00")
    expect("map unchanged by the failed run", r22 == [build_frame(0xA3, 0xD1, b"\x22\x00\x02")])

    # Pit House's role write: 24 <dev> 22 00 <role>. Put the chained unit
    # back on the Throttle (the JCJ5AEA2 repair) and swap it to Brake.
    send(0x24, 0x1D, b"\x22\x00\x01")
    expect("0x22 = 1 -> chained unit is the Throttle", sim.units[0x1D].role == 0)
    send(0x24, 0x1D, b"\x22\x00\x02")        # JCJ5AEA2's state: chained says Brake
    sim._next_heartbeat = t[0] + 0.2
    hb = _text(run(0.5)).get(0x12, [])
    expect("host still reports the chain link as Throttle, active",
           "Throttle pedal is connected, type: active pedal" in hb and "PD Linked:[T 1 B 1 C 1]" in hb)
    send(0x24, 0x12, b"\x21\x00\x03")        # host channel T -> Clutch
    sim._next_heartbeat = t[0] + 0.2
    hb = _text(run(0.5)).get(0x12, [])
    expect("host 0x21 = 3 -> the chain link reports as the Clutch",
           "Clutch pedal is connected, type: active pedal" in hb)

    print("\n\u2713 mbooster chain self-test passed" if ok else "\n\u2717 mbooster chain self-test FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        raise SystemExit(_self_test())
    print("usage: mbooster.py --self-test", file=sys.stderr)
    raise SystemExit(2)
