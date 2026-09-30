#!/usr/bin/env python3
"""USB-MITM bridge: forward bytes between a real MOZA base and the libcomposite
gadget ACM endpoint, while logging every framed message both directions.

Pipeline:

    PitHouse ─usbip─► /dev/ttyGS0 ◄─► bridge.py ◄─► /dev/ttyACMx ─USB─► real MOZA base + wheel

The gadget is published over usbipd by setup_usbip_gadget.sh exactly as for
the simulator. Windows attaches the gadget busid; PitHouse opens the COM port
and talks to it. Every byte landing on /dev/ttyGS0 is copied verbatim to the
real base on /dev/ttyACMx, and vice versa. A JSONL log records each parsed
frame with timestamp + direction so the conversation can be replayed or
diffed against captures.

The host side can also be one end of a tty0tty pair (/dev/tntN) — Pit House
running under Wine on the other end (see pithouse_wine.py) — and the device side
can be an in-process sim engine instead of hardware: `sim:<profile-key>`
(standalone engines only, e.g. `sim:mbooster`).

Forwarding is frame-level: each side's bytes are split into MOZA frames and
re-sent whole, so frames injected with inject() (or the bridge_inject MCP tool)
can never land in the middle of a real one, and rules can drop or rewrite
matching frames in flight.

Usage:
    sudo bash sim/setup_usbip_gadget.sh                # build gadget + start usbipd
    python3 sim/bridge.py /dev/ttyACM0 /dev/ttyGS0     # CLI mode
    python3 sim/bridge.py /dev/ttyACM1 /dev/tnt0       # Pit House under Wine on /dev/tnt1
    python3 sim/bridge.py sim:mbooster /dev/tnt0       # Pit House against the mBooster sim
    python3 sim/bridge.py --mcp                        # MCP stdio server

The first port is the device side (real base CDC ACM or sim:<key>); the second
is the host side Pit House opens. Default log path is sim/logs/bridge-<ts>.jsonl;
override with --log.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import signal
import sys
import threading
import time
from collections import Counter, deque
from pathlib import Path
from typing import BinaryIO, Optional

sys.path.insert(0, str(Path(__file__).parent))
from wheel_sim import MSG_START, verify, frame_payload  # type: ignore

import serial  # type: ignore
from wheel_sim import build_frame  # type: ignore


HOST_TO_BASE = "h2b"   # PitHouse → real base
BASE_TO_HOST = "b2h"   # real base → PitHouse
SIM_PREFIX = "sim:"

_RECENT_CAP = 2000     # ring buffer size for bridge_recent MCP tool


def _open_serial(path: str, baud: int):
    if path.startswith(SIM_PREFIX):
        return EngineEndpoint.for_profile(path[len(SIM_PREFIX):])
    return serial.Serial(path, baudrate=baud, timeout=0.0, write_timeout=1.0)


def _port_exists(path: Optional[str]) -> bool:
    return bool(path) and (path.startswith(SIM_PREFIX) or os.path.exists(path))


def stuff_frame(frame: bytes) -> bytes:
    """Decoded frame -> wire bytes: keep 7E + N, double every 0x7E after them."""
    out = bytearray(frame[:2])
    for b in frame[2:]:
        out.append(b)
        if b == MSG_START:
            out.append(MSG_START)
    return bytes(out)


class EngineEndpoint:
    """A sim engine dressed as the device-side serial port. write() takes wire
    bytes from the host, runs each frame through engine.handle(), and queues
    the stuffed responses for read(). An engine with a poll() method (frames it
    sends unprompted, e.g. a firmware heartbeat) is polled on every read.
    Survives the supervisor's reopen cycle: close() is a no-op and the same
    instance is handed back, so engine state outlives a host-side reconnect."""

    _cache: dict = {}

    def __init__(self, key: str, engine) -> None:
        self.key = key
        self.engine = engine
        self.timeout = 0.05
        self._splitter = FrameSplitter()
        self._out = bytearray()
        self._cv = threading.Condition()

    @classmethod
    def for_profile(cls, key: str) -> "EngineEndpoint":
        if key in cls._cache:
            return cls._cache[key]
        import wheel_sim as ws  # type: ignore
        from engines.standalone import (StandaloneSimulator, MBoosterSimulator,  # type: ignore
                                        Cm1Simulator)
        prof = ws.DEVICE_PROFILES.get(key)
        if prof is None or not prof.gadgets:
            raise serial.SerialException(f"unknown sim profile '{key}'")
        kind = prof.gadgets[0].engine
        engine_cls = {"mbooster": MBoosterSimulator, "cm1": Cm1Simulator,
                      "standalone": StandaloneSimulator}.get(kind)
        if engine_cls is None:
            raise serial.SerialException(
                f"sim profile '{key}' uses engine '{kind}', which runs as its own process")
        ep = cls(key, engine_cls(prof))
        cls._cache[key] = ep
        return ep

    def write(self, data: bytes) -> int:
        replies = []
        for frame in self._splitter.feed(data):
            replies.extend(self.engine.handle(frame))
        if replies:
            with self._cv:
                for r in replies:
                    self._out.extend(stuff_frame(r))
                self._cv.notify_all()
        return len(data)

    def read(self, n: int) -> bytes:
        poll = getattr(self.engine, "poll", None)
        if poll is not None:
            spontaneous = poll()
            if spontaneous:
                with self._cv:
                    for r in spontaneous:
                        self._out.extend(stuff_frame(r))
        with self._cv:
            if not self._out:
                self._cv.wait(self.timeout or 0.05)
            chunk = bytes(self._out[:n])
            del self._out[:n]
            return chunk

    def close(self) -> None:
        pass


class FrameSplitter:
    """Incremental parser that yields complete 7E [N] [...] [checksum] frames
    from a byte stream, handling MOZA byte-stuffing (0x7E in the frame body is
    doubled on the wire — collapse 7E 7E → 7E while decoding). Validates N
    range and checksum; on any failure, advances one byte and resyncs on the
    next 0x7E rather than swallowing the frames that follow.

    Mirrors the un-stuffing rules in `wheel_sim.parse_frames` so the emitted
    frames match what `verify()` and `frame_payload()` expect."""

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, data: bytes):
        self._buf.extend(data)
        out = []
        while self._buf:
            try:
                start = self._buf.index(MSG_START)
            except ValueError:
                self._buf.clear()
                break
            if start:
                del self._buf[:start]
            if len(self._buf) < 2:
                break
            n = self._buf[1]
            # N is 0..64 — 0 is the bare keepalive `7e 00 00 <dev> <ck>`.
            # 0x7E in particular cannot be a real length — that's two adjacent
            # 7Es from a frame boundary, not a length byte. Slip past this 7E
            # and resync.
            if n > 64:
                del self._buf[:1]
                continue
            need = n + 3  # group + device + payload(n) + checksum (decoded)
            decoded = bytearray()
            j = 2
            incomplete = False
            truncated = False
            while len(decoded) < need:
                if j >= len(self._buf):
                    incomplete = True
                    break
                b = self._buf[j]
                if b == MSG_START:
                    if j + 1 >= len(self._buf):
                        incomplete = True
                        break
                    if self._buf[j + 1] == MSG_START:
                        decoded.append(MSG_START)
                        j += 2
                    else:
                        # Bare 7E inside body = next frame's start. Current
                        # candidate is desync; resync on next 7E.
                        truncated = True
                        break
                else:
                    decoded.append(b)
                    j += 1
            if incomplete:
                break  # wait for more bytes
            if truncated:
                del self._buf[:1]
                continue
            frame = bytes([MSG_START, n]) + bytes(decoded)
            if not verify(frame):
                # Either real wire corruption or a 7E we mistook as a frame
                # start. Slip one byte and let the resync find the real start.
                del self._buf[:1]
                continue
            del self._buf[:j]
            out.append(frame)
        return out


class BridgeLogger:
    """Append-only JSONL logger plus in-memory counters and ring buffer.

    Persistent JSONL trace: one record per frame, flushed immediately so
    `tail -f` shows live conversation and a crash loses at most the in-flight
    frame.

    Volatile state for MCP introspection:
      frames, bad_checksum                — totals
      counts_by_dir[dir]                  — frame counts per direction
      bytes_by_dir[dir]                   — byte counts per direction
      counts_by_key[(dir, grp, dev, cmd)] — per-shape histogram
      recent (deque)                      — last N (t, dir, hex) tuples
    """

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh: BinaryIO = open(path, "ab", buffering=0)
        self._lock = threading.Lock()
        self.path = path
        self.frames = 0
        self.bad_checksum = 0
        self.counts_by_dir: Counter = Counter()
        self.bytes_by_dir: Counter = Counter()
        self.counts_by_key: Counter = Counter()
        self.recent: deque = deque(maxlen=_RECENT_CAP)
        self.started = time.time()

    def add_bytes(self, direction: str, n: int) -> None:
        with self._lock:
            self.bytes_by_dir[direction] += n

    def log(self, direction: str, frame: bytes) -> None:
        ok = verify(frame)
        rec = {
            "t": time.time(),
            "dir": direction,
            "len": len(frame),
            "ok": ok,
            "hex": frame.hex(),
        }
        if len(frame) >= 4 and ok:
            rec["grp"] = frame[2]
            rec["dev"] = frame[3]
            payload = frame_payload(frame)
            rec["payload"] = payload.hex()
            cmd = payload[:2].hex() if payload else ""
            key = (direction, frame[2], frame[3], cmd)
        else:
            key = (direction, -1, -1, "")
        line = (json.dumps(rec, separators=(",", ":")) + "\n").encode("utf-8")
        with self._lock:
            self._fh.write(line)
            self.frames += 1
            if not ok:
                self.bad_checksum += 1
            self.counts_by_dir[direction] += 1
            self.counts_by_key[key] += 1
            self.recent.append((rec["t"], direction, frame.hex()))

    def reset_counters(self) -> None:
        with self._lock:
            self.frames = 0
            self.bad_checksum = 0
            self.counts_by_dir.clear()
            self.bytes_by_dir.clear()
            self.counts_by_key.clear()
            self.recent.clear()
            self.started = time.time()

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "frames": self.frames,
                "bad_checksum": self.bad_checksum,
                "counts_by_dir": dict(self.counts_by_dir),
                "bytes_by_dir": dict(self.bytes_by_dir),
                "uptime_s": round(time.time() - self.started, 2),
            }

    def recent_snapshot(self, count: int, direction: Optional[str]) -> list:
        with self._lock:
            items = list(self.recent)
        if direction:
            items = [it for it in items if it[1] == direction]
        return items[-count:]

    def histogram_snapshot(self) -> list:
        with self._lock:
            items = list(self.counts_by_key.items())
        items.sort(key=lambda kv: -kv[1])
        return items

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass


class Rules:
    """In-flight frame rules. Each rule matches a direction, group, device and
    an optional payload hex prefix, and either drops the frame or replaces its
    payload (checksum rebuilt). First matching rule wins."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._rules: list = []
        self._next_id = 1

    def add(self, direction: str, action: str, group: Optional[int] = None,
            device: Optional[int] = None, payload_prefix: str = "",
            replace_payload: str = "") -> dict:
        if direction not in (HOST_TO_BASE, BASE_TO_HOST):
            return {"error": f"direction must be {HOST_TO_BASE} or {BASE_TO_HOST}"}
        if action not in ("drop", "replace"):
            return {"error": "action must be drop or replace"}
        if action == "replace":
            bytes.fromhex(replace_payload)
        rule = {"id": self._next_id, "dir": direction, "action": action,
                "grp": group, "dev": device,
                "prefix": payload_prefix.replace(" ", "").lower(),
                "replace": replace_payload.replace(" ", "").lower(), "hits": 0}
        with self._lock:
            self._rules.append(rule)
            self._next_id += 1
        return dict(rule)

    def remove(self, rule_id: Optional[int] = None) -> int:
        with self._lock:
            before = len(self._rules)
            self._rules = [] if rule_id is None else [r for r in self._rules if r["id"] != rule_id]
            return before - len(self._rules)

    def list(self) -> list:
        with self._lock:
            return [dict(r) for r in self._rules]

    def apply(self, direction: str, frame: bytes) -> Optional[bytes]:
        """Frame to forward (possibly rewritten), or None to drop it."""
        if len(frame) < 5:
            return frame
        with self._lock:
            if not self._rules:
                return frame
            payload = frame_payload(frame).hex()
            for r in self._rules:
                if r["dir"] != direction:
                    continue
                if r["grp"] is not None and r["grp"] != frame[2]:
                    continue
                if r["dev"] is not None and r["dev"] != frame[3]:
                    continue
                if not payload.startswith(r["prefix"]):
                    continue
                r["hits"] += 1
                if r["action"] == "drop":
                    return None
                return build_frame(frame[2], frame[3], bytes.fromhex(r["replace"]))
        return frame


class Pump(threading.Thread):
    """One direction of the frame pump. Reads from `src`, splits the stream
    into frames, applies the rules, and writes each surviving frame to `dst`
    whole, under `dst`'s write lock (shared with inject()). Stops when the stop
    event fires or either port goes EBADF."""

    def __init__(
        self,
        name: str,
        direction: str,
        src,
        dst,
        logger: BridgeLogger,
        stop: threading.Event,
        rules: "Rules",
        dst_lock: threading.Lock,
    ) -> None:
        super().__init__(name=name, daemon=True)
        self.direction = direction
        self.src = src
        self.dst = dst
        self.logger = logger
        self.stop = stop
        self.rules = rules
        self.dst_lock = dst_lock
        self.splitter = FrameSplitter()

    def run(self) -> None:
        # Pumps stop on serial errors; BridgeEngine._supervise handles
        # reconnect (USBIP detach / PitHouse closing the COM port). The
        # supervisor relaunches a fresh pump pair without disturbing logger
        # counters or the JSONL output file.
        while not self.stop.is_set():
            try:
                self.src.timeout = 0.05
                chunk = self.src.read(4096)
            except serial.SerialException as e:
                print(f"[{self.name}] read error: {e}", file=sys.stderr)
                self.stop.set()
                return
            if not chunk:
                continue
            self.logger.add_bytes(self.direction, len(chunk))
            for frame in self.splitter.feed(chunk):
                out = self.rules.apply(self.direction, frame)
                if out is None:
                    self.logger.log(self.direction + "-dropped", frame)
                    continue
                if out is not frame:
                    self.logger.log(self.direction + "-orig", frame)
                try:
                    with self.dst_lock:
                        self.dst.write(stuff_frame(out))
                except serial.SerialTimeoutException:
                    # Nobody reading the other end yet (a tty0tty pair whose
                    # peer isn't open blocks once its buffer fills) — not a
                    # dead port, so keep pumping.
                    self.logger.log(self.direction + "-undelivered", out)
                    continue
                except serial.SerialException as e:
                    print(f"[{self.name}] write error: {e}", file=sys.stderr)
                    self.stop.set()
                    return
                self.logger.log(self.direction, out)


class BridgeEngine:
    """Owns serial ports, pumps, and logger. Single-instance per process —
    used both by the CLI main() and the MCP server tool layer.

    Auto-restart: when pumps die from a transient serial error (USBIP detach,
    PitHouse closing the COM port, etc.), a supervisor thread re-opens both
    ports with bounded backoff and relaunches the pumps. Counters and the
    JSONL log file are preserved across reconnect cycles. Only user-initiated
    stop() halts the supervisor."""

    # Backoff for serial-port re-open attempts (seconds).
    _REOPEN_BACKOFF = (0.25, 0.5, 1.0, 2.0, 4.0)

    def __init__(self) -> None:
        self.base_port: Optional[str] = None
        self.gadget_port: Optional[str] = None
        self._baud: int = 115200
        self.log_path: Optional[Path] = None
        self.logger: Optional[BridgeLogger] = None
        self._base: Optional[serial.Serial] = None
        self._gadget: Optional[serial.Serial] = None
        self._user_stop = threading.Event()       # set only by stop()
        self._pump_stop: Optional[threading.Event] = None  # per-cycle, set by dying pump
        self._pumps: list = []
        self._supervisor: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self.reconnect_count: int = 0
        self.rules = Rules()
        self._base_wlock = threading.Lock()
        self._gadget_wlock = threading.Lock()

    def is_running(self) -> bool:
        return self._supervisor is not None and self._supervisor.is_alive() and not self._user_stop.is_set()

    def start(self, base_port: str, gadget_port: str = "/dev/ttyGS0",
              baud: int = 115200, log_path: Optional[Path] = None) -> dict:
        with self._lock:
            if self.is_running():
                return {"error": "bridge already running",
                        "base_port": self.base_port,
                        "gadget_port": self.gadget_port}
            if base_port == gadget_port:
                return {"error": "base_port and gadget_port must differ"}
            for p in (base_port, gadget_port):
                if not _port_exists(p):
                    return {"error": f"port not found: {p}"}
            log_path = log_path or _default_log_path()
            try:
                base = _open_serial(base_port, baud)
                gadget = _open_serial(gadget_port, baud)
            except (serial.SerialException, OSError) as e:
                return {"error": f"open failed: {e}"}
            self.base_port = base_port
            self.gadget_port = gadget_port
            self._baud = baud
            self.log_path = log_path
            self.logger = BridgeLogger(log_path)
            self._base = base
            self._gadget = gadget
            self._user_stop = threading.Event()
            self.reconnect_count = 0
            self._supervisor = threading.Thread(
                target=self._supervise, name="bridge-sup", daemon=True)
            self._supervisor.start()
            return {
                "status": "running",
                "base_port": base_port,
                "gadget_port": gadget_port,
                "log_path": str(log_path),
            }

    def _supervise(self) -> None:
        """Run pump pair until user_stop. On pump-death without user_stop,
        close ports and re-open with backoff, then relaunch pumps."""
        while not self._user_stop.is_set():
            self._pump_stop = threading.Event()
            pumps = [
                Pump("h→b", HOST_TO_BASE, self._gadget, self._base, self.logger,
                     self._pump_stop, self.rules, self._base_wlock),
                Pump("b→h", BASE_TO_HOST, self._base, self._gadget, self.logger,
                     self._pump_stop, self.rules, self._gadget_wlock),
            ]
            self._pumps = pumps
            for p in pumps:
                p.start()
            # Wait for either pump to die or user stop.
            while not self._user_stop.is_set() and not self._pump_stop.is_set():
                self._user_stop.wait(0.1)
                if self._pump_stop.is_set():
                    break
            # Drain pumps.
            for p in pumps:
                p.join(timeout=1.0)
            self._pumps = []
            if self._user_stop.is_set():
                return
            # Pump death without user stop = transient failure. Close ports and reopen.
            for s in (self._base, self._gadget):
                try:
                    if s is not None: s.close()
                except Exception: pass
            self._base = None
            self._gadget = None
            print(f"[bridge-sup] pumps dropped; will reattempt re-open of "
                  f"{self.base_port} / {self.gadget_port}", file=sys.stderr)
            attempt = 0
            while not self._user_stop.is_set():
                # Wait for ports to exist (USBIP gadget may take a moment to re-bind).
                if not (_port_exists(self.base_port) and _port_exists(self.gadget_port)):
                    self._user_stop.wait(0.5)
                    continue
                try:
                    self._base = _open_serial(self.base_port, self._baud)
                    self._gadget = _open_serial(self.gadget_port, self._baud)
                    self.reconnect_count += 1
                    print(f"[bridge-sup] reconnected (attempt {attempt+1}, "
                          f"total reconnects {self.reconnect_count})", file=sys.stderr)
                    break
                except (serial.SerialException, OSError) as e:
                    delay = self._REOPEN_BACKOFF[min(attempt, len(self._REOPEN_BACKOFF) - 1)]
                    print(f"[bridge-sup] re-open failed ({e!s}); retry in {delay}s",
                          file=sys.stderr)
                    self._user_stop.wait(delay)
                    attempt += 1

    def stop(self) -> dict:
        with self._lock:
            if not self.is_running() and self.logger is None:
                return {"error": "bridge not running"}
            self._user_stop.set()
            if self._pump_stop is not None:
                self._pump_stop.set()
            for p in list(self._pumps):
                p.join(timeout=1.0)
            self._pumps = []
            if self._supervisor is not None:
                self._supervisor.join(timeout=2.0)
                self._supervisor = None
            for s in (self._base, self._gadget):
                try:
                    if s is not None:
                        s.close()
                except Exception:
                    pass
            self._base = None
            self._gadget = None
            snap = self.logger.snapshot() if self.logger else {}
            log_path = str(self.log_path) if self.log_path else None
            if self.logger:
                self.logger.close()
            return {"status": "stopped", "log_path": log_path, **snap}

    def inject(self, direction: str, frame_hex: str = "", group: Optional[int] = None,
               device: Optional[int] = None, payload_hex: str = "") -> dict:
        """Send a frame to one side as if the other side had sent it.
        h2b = to the device (as Pit House), b2h = to Pit House (as the device).
        Either a complete decoded frame (frame_hex, checksum optional — it is
        rebuilt) or group + device + payload_hex."""
        if direction not in (HOST_TO_BASE, BASE_TO_HOST):
            return {"error": f"direction must be {HOST_TO_BASE} or {BASE_TO_HOST}"}
        try:
            if frame_hex:
                raw = bytes.fromhex(frame_hex.replace(" ", ""))
                if len(raw) < 4 or raw[0] != MSG_START:
                    return {"error": "frame_hex must start 7e <n> <grp> <dev>"}
                n = raw[1]
                frame = build_frame(raw[2], raw[3], raw[4:4 + n])
            else:
                if group is None or device is None:
                    return {"error": "give frame_hex, or group + device + payload_hex"}
                frame = build_frame(group, device, bytes.fromhex(payload_hex.replace(" ", "")))
        except ValueError as e:
            return {"error": f"bad hex: {e}"}
        dst = self._base if direction == HOST_TO_BASE else self._gadget
        lock = self._base_wlock if direction == HOST_TO_BASE else self._gadget_wlock
        if dst is None or self.logger is None:
            return {"error": "bridge not running (or reconnecting)"}
        try:
            with lock:
                dst.write(stuff_frame(frame))
        except (serial.SerialException, OSError) as e:
            return {"error": f"write failed: {e}"}
        self.logger.log("inj-" + direction, frame)
        return {"sent": frame.hex(), "dir": direction}

    def status(self) -> dict:
        out = {
            "running": self.is_running(),
            "base_port": self.base_port,
            "gadget_port": self.gadget_port,
            "log_path": str(self.log_path) if self.log_path else None,
            "reconnect_count": self.reconnect_count,
        }
        if self.logger is not None:
            out.update(self.logger.snapshot())
        return out


_engine_singleton: Optional[BridgeEngine] = None


def get_engine() -> BridgeEngine:
    global _engine_singleton
    if _engine_singleton is None:
        _engine_singleton = BridgeEngine()
    return _engine_singleton


def serve_control(engine: BridgeEngine, path: Path) -> None:
    """JSON-lines control socket for a CLI bridge — bridge_ctl.py talks to it.
    One request per line, one JSON reply per line. Ops: status, recent, inject,
    rule_add, rules, rule_remove."""
    import socketserver

    def dispatch(req: dict):
        op = req.pop("op", "")
        if op == "status":
            return engine.status()
        if op == "recent":
            if engine.logger is None:
                return {"error": "not running"}
            return [{"t": t, "dir": d, "hex": h} for t, d, h in
                    engine.logger.recent_snapshot(int(req.get("count", 20)), req.get("dir"))]
        if op == "inject":
            return engine.inject(**req)
        if op == "rule_add":
            return engine.rules.add(**req)
        if op == "rules":
            return engine.rules.list()
        if op == "rule_remove":
            return {"removed": engine.rules.remove(req.get("rule_id"))}
        return {"error": f"unknown op '{op}'"}

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            for line in self.rfile:
                try:
                    reply = dispatch(json.loads(line))
                except Exception as e:  # report, keep serving
                    reply = {"error": f"{type(e).__name__}: {e}"}
                self.wfile.write((json.dumps(reply) + "\n").encode("utf-8"))

    if path.exists():
        path.unlink()
    server = socketserver.ThreadingUnixStreamServer(str(path), Handler)
    threading.Thread(target=server.serve_forever, name="bridge-ctl", daemon=True).start()


def _default_log_path() -> Path:
    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path(__file__).parent / "logs" / f"bridge-{ts}.jsonl"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument("base_port", nargs="?",
                    help="Device side: real CDC ACM (/dev/ttyACM0) or sim:<profile-key>")
    ap.add_argument("gadget_port", nargs="?", default="/dev/ttyGS0",
                    help="libcomposite gadget endpoint (default /dev/ttyGS0)")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--log", type=Path, default=None,
                    help="JSONL log path (default sim/logs/bridge-<ts>.jsonl)")
    ap.add_argument("--quiet", action="store_true",
                    help="Suppress periodic stats line on stdout")
    ap.add_argument("--mcp", action="store_true",
                    help="Run as MCP server (stdio transport); ports become bridge_start args")
    ap.add_argument("--control", type=Path, default=Path("/tmp/moza-bridge.sock"),
                    help="Unix control socket for bridge_ctl.py (default /tmp/moza-bridge.sock)")
    args = ap.parse_args()

    if args.mcp:
        import importlib.util
        mcp_path = Path(__file__).parent / "bridge_mcp.py"
        spec = importlib.util.spec_from_file_location("bridge_mcp", mcp_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.configure(default_base=args.base_port,
                      default_gadget=args.gadget_port,
                      baud=args.baud)
        print("[bridge MCP server starting — use bridge_start to connect]",
              file=sys.stderr)
        mod.run_stdio()
        return 0

    if not args.base_port:
        ap.error("base_port is required in CLI mode (or use --mcp)")

    engine = get_engine()
    res = engine.start(args.base_port, args.gadget_port, baud=args.baud,
                       log_path=args.log)
    if "error" in res:
        print(f"start failed: {res['error']}", file=sys.stderr)
        return 1
    print(f"bridge: {res['base_port']} ↔ {res['gadget_port']}  log → {res['log_path']}")
    serve_control(engine, args.control)
    print(f"control socket: {args.control}")

    def _sig(_signum, _frame):
        engine._user_stop.set()
        if engine._pump_stop is not None:
            engine._pump_stop.set()
    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    last_print = time.time()
    try:
        while engine.is_running():
            time.sleep(0.5)
            now = time.time()
            if not args.quiet and now - last_print >= 2.0:
                snap = engine.logger.snapshot() if engine.logger else {}
                print(
                    f"  frames={snap.get('frames', 0)}  bad_ck={snap.get('bad_checksum', 0)}  "
                    f"h→b={snap.get('bytes_by_dir', {}).get(HOST_TO_BASE, 0)}B  "
                    f"b→h={snap.get('bytes_by_dir', {}).get(BASE_TO_HOST, 0)}B",
                    flush=True,
                )
                last_print = now
    finally:
        result = engine.stop()
        print(
            f"\nbridge stopped. frames={result.get('frames', 0)}  "
            f"bad_ck={result.get('bad_checksum', 0)}  "
            f"log={result.get('log_path')}",
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
