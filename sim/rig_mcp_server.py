#!/usr/bin/env python3
"""Unified rig MCP server — start / stop / inspect a multi-device MOZA sim rig.

A rig is several device-sim engines, each serving one gadget's ttyGS. This server
runs the standalone device engines (StandaloneSimulator, MBoosterSimulator,
Cm1Simulator) IN-PROCESS with full frame / unhandled / recent inspection — the
gap the wheel-only mcp_server.py and ab9_mcp_server.py don't fill. Wheel
(engine=unified) and AB9 engines are launched as subprocesses via
gadget_manager.py (they have their own rich machinery + MCPs), so a whole rig can
still be assembled from one place.

Gadget bring-up (configfs, needs root) is NOT done here — run
`sudo bash sim/setup_rig.sh <keys...>` first, then point rig_start at each ttyGS.

Tools: rig_list, rig_start, rig_stop, rig_status, rig_recent, rig_unhandled,
rig_counters, rig_set_cm1_param.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Dict, Optional

from mcp.server.fastmcp import FastMCP

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import wheel_sim as ws  # noqa: E402
from engines.standalone import (  # noqa: E402
    StandaloneSimulator, MBoosterSimulator, Cm1Simulator,
)

_server = FastMCP("moza-rig")

# GadgetSpec.engine -> in-process engine class. Wheel/ab9 are subprocesses.
_INPROC_ENGINES = {
    "standalone": StandaloneSimulator,
    "mbooster": MBoosterSimulator,
    "cm1": Cm1Simulator,
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
            return {"status": "started", "port": port, "profile": profile_key,
                    "engine": engine_kind, "kind": "in-process"}
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


def run_stdio():
    _server.run()


if __name__ == "__main__":
    run_stdio()
