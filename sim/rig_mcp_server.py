#!/usr/bin/env python3
"""Unified rig MCP server — start / stop / inspect a multi-device MOZA sim rig.

A rig is several device-sim engines, each serving one gadget's ttyGS. This server
runs the standalone device engines (StandaloneSimulator, MBoosterSimulator,
Cm1Simulator, FcsSimulator) IN-PROCESS with full frame / unhandled / recent inspection — the
gap the wheel-only mcp_server.py and ab9_mcp_server.py don't fill. Wheel
(engine=unified) and AB9 engines are launched as subprocesses via
gadget_manager.py (they have their own rich machinery + MCPs), so a whole rig can
still be assembled from one place.

Gadget bring-up (configfs, needs root) is NOT done here — run
`sudo bash sim/setup_rig.sh <keys...>` first, then point rig_start at each ttyGS.

Tools: rig_list, rig_start, rig_stop, rig_status, rig_recent, rig_unhandled,
rig_counters, rig_set_cm1_param, rig_fcs_state, rig_fcs_set_status, rig_fcs_input.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

from mcp.server.fastmcp import FastMCP

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import wheel_sim as ws  # noqa: E402
from engines.standalone import (  # noqa: E402
    StandaloneSimulator, MBoosterSimulator, Cm1Simulator,
)
from engines.fcs import FcsSimulator, find_hidg, HID_AXIS_NAMES  # noqa: E402

_server = FastMCP("moza-rig")

# GadgetSpec.engine -> in-process engine class. Wheel/ab9 are subprocesses.
_INPROC_ENGINES = {
    "standalone": StandaloneSimulator,
    "mbooster": MBoosterSimulator,
    "cm1": Cm1Simulator,
    "fcs": FcsSimulator,
}
_SUBPROC_ENGINES = {"unified", "ab9"}

# port -> running-engine record
_engines: Dict[str, dict] = {}
_lock = threading.Lock()


def _stuff(frame: bytes) -> bytes:
    """MOZA 0x7E byte-stuffing for the wire (matches wheel_sim cmd_live)."""
    body = bytearray(frame[:2])
    for b in frame[2:]:
        body.append(b)
        if b == ws.MSG_START:
            body.append(ws.MSG_START)
    return bytes(body)


def _serve(engine, ser, alive: threading.Event, wire_fh) -> None:
    """Read frames off the port, run engine.handle(), write stuffed responses.
    Uses a short read timeout so the loop can honour the alive flag for stop."""
    from wheel_sim import read_one_frame
    while alive.is_set():
        try:
            frame = read_one_frame(ser)
        except Exception:
            break
        if frame is None:
            continue  # idle read timeout — re-check alive
        if wire_fh:
            wire_fh.write(json.dumps({"t": time.time(), "dir": "h2b",
                                      "hex": frame.hex(), "len": len(frame)}) + "\n")
        try:
            responses = engine.handle(frame)
        except Exception:
            responses = []
        for rsp in responses:
            ser.write(_stuff(rsp))
            if wire_fh:
                wire_fh.write(json.dumps({"t": time.time(), "dir": "b2h",
                                          "hex": rsp.hex(), "len": len(rsp)}) + "\n")
    try:
        ser.close()
    except Exception:
        pass
    if wire_fh:
        try:
            wire_fh.close()
        except Exception:
            pass


# ── tools ────────────────────────────────────────────────────────────────────

@_server.tool()
def rig_list() -> dict:
    """List every device profile the rig can run, with PID and engine kind."""
    out = {}
    for k, p in sorted(ws.DEVICE_PROFILES.items()):
        g = p.gadgets[0]
        out[k] = {
            "friendly": p.friendly,
            "pid": f"0x{g.pid:04x}",
            "engine": g.engine,
            "managed": "in-process" if g.engine in _INPROC_ENGINES else "subprocess",
        }
    return {"profiles": out}


@_server.tool()
def rig_start(profile_key: str, port: str, wire_trace: bool = False) -> dict:
    """Start a device engine on an existing ttyGS. Standalone/mbooster/cm1 run
    in-process (inspectable); unified (wheel) / ab9 launch as subprocesses."""
    p = ws.DEVICE_PROFILES.get(profile_key)
    if p is None:
        return {"error": f"unknown profile '{profile_key}'",
                "known": sorted(ws.DEVICE_PROFILES)}
    engine_kind = p.gadgets[0].engine
    with _lock:
        if port in _engines:
            return {"error": f"port {port} already runs '{_engines[port]['key']}' "
                             f"— rig_stop it first"}
        if engine_kind in _INPROC_ENGINES:
            try:
                import serial  # type: ignore
                ser = serial.Serial(port, baudrate=115200, timeout=0.3)
            except Exception as e:
                return {"error": f"cannot open {port}: {e}"}
            engine = _INPROC_ENGINES[engine_kind](p)
            hid = None
            if isinstance(engine, FcsSimulator):
                hid = os.environ.get("FCS_HID_DEV") or find_hidg(profile_key)
                if hid and not engine.attach_hid(hid):
                    hid = None
            alive = threading.Event()
            alive.set()
            wire_fh = None
            if wire_trace:
                safe = port.replace("/", "_").lstrip("_")
                wp = ws._LOG_DIR / f"rig-{profile_key}-{safe}.jsonl"
                wp.parent.mkdir(parents=True, exist_ok=True)
                wire_fh = open(wp, "w", buffering=1)
            t = threading.Thread(target=_serve, args=(engine, ser, alive, wire_fh),
                                 daemon=True)
            t.start()
            _engines[port] = {"key": profile_key, "kind": "inproc", "engine": engine,
                              "thread": t, "alive": alive, "started": time.time()}
            out = {"status": "started", "port": port, "profile": profile_key,
                   "engine": engine_kind, "kind": "in-process"}
            if isinstance(engine, FcsSimulator):
                out["hid"] = hid
            return out
        # wheel / ab9 -> subprocess
        proc = subprocess.Popen(["python3", str(HERE / "gadget_manager.py"),
                                 "run", profile_key, port])
        _engines[port] = {"key": profile_key, "kind": "subproc", "proc": proc,
                          "started": time.time()}
        return {"status": "started", "port": port, "profile": profile_key,
                "engine": engine_kind, "kind": "subprocess", "pid": proc.pid,
                "note": "wheel/ab9 run as a subprocess — use mcp_server (sim_*) / "
                        "ab9_mcp_server for deep inspection"}


@_server.tool()
def rig_stop(port: Optional[str] = None) -> dict:
    """Stop one engine (by port) or all engines. Releases the port."""
    with _lock:
        ports = [port] if port else list(_engines)
        stopped = []
        for pt in ports:
            e = _engines.pop(pt, None)
            if not e:
                continue
            if e["kind"] == "inproc":
                e["alive"].clear()
            else:
                try:
                    e["proc"].terminate()
                except Exception:
                    pass
            stopped.append(pt)
    return {"status": "stopped", "ports": stopped}


@_server.tool()
def rig_status() -> dict:
    """Per-engine status: profile, port, kind, liveness, and (in-process) frame /
    unhandled counts."""
    out = []
    with _lock:
        for pt, e in _engines.items():
            if e["kind"] == "inproc":
                eng = e["engine"]
                out.append({
                    "port": pt, "profile": e["key"], "kind": "in-process",
                    "alive": e["alive"].is_set(),
                    "frames": eng.frames_total,
                    "unhandled": sum(eng.unhandled_counts.values()),
                    "handlers": dict(eng.cat_counts),
                })
            else:
                out.append({
                    "port": pt, "profile": e["key"], "kind": "subprocess",
                    "pid": e["proc"].pid, "alive": e["proc"].poll() is None,
                })
    return {"engines": out, "count": len(out)}


def _inproc(port: str):
    e = _engines.get(port)
    if not e or e["kind"] != "inproc":
        return None
    return e["engine"]


@_server.tool()
def rig_recent(port: str, count: int = 20) -> dict:
    """Recent (tag, hex) frames for an in-process engine."""
    eng = _inproc(port)
    if eng is None:
        return {"error": f"no in-process engine on {port}"}
    items = list(eng.recent_frames)[-count:]
    return {"port": port, "recent": [{"tag": t, "hex": h} for t, h in items]}


@_server.tool()
def rig_unhandled(port: str) -> dict:
    """Unhandled-frame summary for an in-process engine."""
    eng = _inproc(port)
    if eng is None:
        return {"error": f"no in-process engine on {port}"}
    items = sorted(eng.unhandled_counts.items(), key=lambda x: -x[1])
    return {"port": port, "total": sum(eng.unhandled_counts.values()),
            "items": [{"group": f"0x{g:02x}", "device": f"0x{d:02x}",
                       "cmd": c, "count": n} for (g, d, c), n in items]}


@_server.tool()
def rig_counters(port: str) -> dict:
    """Per-handler-tag frame counts for an in-process engine."""
    eng = _inproc(port)
    if eng is None:
        return {"error": f"no in-process engine on {port}"}
    return {"port": port, "frames": eng.frames_total, "handlers": dict(eng.cat_counts)}


@_server.tool()
def rig_set_cm1_param(port: str, reg: int, value: int) -> dict:
    """Override a CM1 param-register value (group 0x0E reply) on a running cm1
    engine. reg is the decimal register address; value the u32 returned."""
    eng = _inproc(port)
    if not isinstance(eng, Cm1Simulator):
        return {"error": f"no cm1 engine on {port}"}
    eng.PARAM_TABLE = dict(eng.PARAM_TABLE)
    eng.PARAM_TABLE[reg] = value & 0xFFFFFFFF
    return {"status": "set", "port": port, "reg": reg, "value": value}


def _fcs(port: str):
    eng = _inproc(port)
    return eng if isinstance(eng, FcsSimulator) else None


@_server.tool()
def rig_fcs_state(port: str) -> dict:
    """FCS engine state: every group-0x4E setting (key "param/index", values as
    stored on the wire), rightRodType, per-axis calibration results, running
    calibrations, HID axes/buttons."""
    eng = _fcs(port)
    if eng is None:
        return {"error": f"no fcs engine on {port}"}
    return {"port": port, **eng.snapshot()}


@_server.tool()
def rig_fcs_set_status(port: str, right_rod_type: Optional[int] = None,
                       calib_axis: Optional[int] = None,
                       calib_result: Optional[int] = None,
                       firmware_log: Optional[bool] = None) -> dict:
    """Change what the FCS reports. right_rod_type: 0 none, 1 built-in joystick,
    2 MHG, 3 MA3X, 4 MH16 (status 04 03). calib_axis 0..5 + calib_result: the
    checkCalib answer (status 04 04 <axis>; 1 = pass). firmware_log toggles the
    group-0x0E log lines."""
    eng = _fcs(port)
    if eng is None:
        return {"error": f"no fcs engine on {port}"}
    if right_rod_type is not None:
        eng.right_rod_type = right_rod_type & 0xFF
    if calib_axis is not None and calib_result is not None:
        if calib_axis not in eng.calib_result:
            return {"error": "calib_axis must be 0..5"}
        eng.calib_result[calib_axis] = calib_result & 0xFF
    if firmware_log is not None:
        eng.firmware_log = firmware_log
    return {"port": port, **eng.snapshot()}


@_server.tool()
def rig_fcs_input(port: str, axes: Optional[Dict[str, int]] = None,
                  buttons: Optional[List[int]] = None) -> dict:
    """Drive the FCS HID report. axes: {name: 0..65535} with names
    joystick_x, joystick_y, thumbstick_x, thumbstick_y, throttle, joystick_z
    (rest 32767, throttle rest 65535). buttons: pressed button numbers 1..128
    (replaces the pressed set; [] releases all). Needs the gadget's f_hid."""
    eng = _fcs(port)
    if eng is None:
        return {"error": f"no fcs engine on {port}"}
    bad = [a for a in (axes or {}) if a not in HID_AXIS_NAMES]
    if bad:
        return {"error": f"unknown axes {bad}", "axes": list(HID_AXIS_NAMES)}
    rep = eng.set_input(axes, buttons)
    return {"port": port, "report": rep.hex(), "hid": eng.hid_path or None,
            "written": eng.hid_path != ""}


def run_stdio():
    _server.run()


if __name__ == "__main__":
    run_stdio()
