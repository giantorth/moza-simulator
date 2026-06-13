#!/usr/bin/env python3
"""Byte-exact regression harness for the MOZA wheel simulator.

Replays canonical host captures through ``WheelSimulator.handle()`` for every
shipped wheel model and records each ``(input_frame -> [output_frames])`` event
that produced a non-empty response to ``sim/golden/<model>.jsonl``. A ``--check``
run regenerates the same events and asserts byte-identical equality, so the
upcoming data-driven refactor of ``WHEEL_MODELS`` (DeviceProfile registry,
generic settings/absorb handlers, ``_7c23`` de-hardcoding) can be proven not to
change any wheel's wire output.

Determinism
-----------
``threading.Timer`` is stubbed to a no-op for the duration of a run, so only the
synchronous ``_handle_core`` dispatch (identity / session acks / settings echo /
write echo / heartbeat / replay / param_0e) contributes bytes. The proactive
device-init, dashboard-upload reply, and session-09 keepalive emission all ride
background timers and are intentionally excluded — they are not what the profile
refactor touches, and they are the only non-deterministic part of the sim.

Usage
-----
    tools/sim_golden.py --update [--model M] [--limit N]   # (re)generate goldens
    tools/sim_golden.py --check  [--model M]               # CI gate: byte-identical
    tools/sim_golden.py --list                             # show model/capture plan

``--update`` and ``--check`` must use the same ``--limit`` (the value is stored in
the golden header and ``--check`` reuses it automatically).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pickle
import sys
import tempfile
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple

REPO = Path(__file__).resolve().parent.parent
SIM_DIR = REPO / "sim"
GOLDEN_DIR = SIM_DIR / "golden"
CACHE_DIR = Path(os.environ.get("TMPDIR", "/tmp")) / "moza-sim-golden-cache"

sys.path.insert(0, str(SIM_DIR))
import wheel_sim as ws  # noqa: E402

# ── Capture plan ────────────────────────────────────────────────────────────
# Per model, the ordered list of host-frame source captures fed through a fresh
# simulator. connect-wheel-start-game.pcapng is a real plugin+PitHouse VGS
# handshake (identity cascade, session opens, tier-def, echoes) and exercises
# the dispatch chain for every model under that model's identity tables. csp and
# kspro additionally replay the captures their replay tables were extracted from,
# so the hub/base/pedal identity + param_0e replay paths are covered too.
_COMMON = "usb-capture/connect-wheel-start-game.pcapng"
MODEL_CAPTURES: Dict[str, List[str]] = {
    "vgs":   [_COMMON],
    "ks":    [_COMMON],
    "es":    [_COMMON],
    "csp":   [_COMMON,
              "usb-capture/CSP captures/latestcaps/"
              "pithouse-switch-list-delete-upload-reupload.pcapng"],
    "kspro": [_COMMON,
              "usb-capture/ksp/putOnWheelAndOpenPitHouse.pcapng"],
}


class _NoopTimer:
    """Replacement for threading.Timer that never fires — neutralises every
    proactive/upload/keepalive background emission so handle() output is purely
    synchronous and reproducible."""

    def __init__(self, *a, **k):
        pass

    def start(self):
        pass

    def cancel(self):
        pass

    def is_alive(self):
        return False


# ── Cached capture extraction (tshark is the slow part) ─────────────────────

def _cache_path(kind: str, path: Path) -> Path:
    st = path.stat()
    key = f"{kind}|{path}|{st.st_size}|{int(st.st_mtime)}"
    h = hashlib.sha1(key.encode()).hexdigest()[:16]
    return CACHE_DIR / f"{kind}-{h}.pkl"


def _cached(kind: str, path: Path, produce):
    cp = _cache_path(kind, path)
    if cp.exists():
        try:
            return pickle.loads(cp.read_bytes())
        except Exception:
            pass
    val = produce()
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        cp.write_bytes(pickle.dumps(val))
    except Exception:
        pass
    return val


def host_frames(path: Path) -> List[bytes]:
    """Verified host→device frames from a capture, in order."""
    def produce():
        out = []
        for direction, _ts, frame in ws.extract_from_pcapng(str(path)):
            if direction == "host" and ws.verify(frame) and len(frame) >= 4:
                out.append(bytes(frame))
        return out
    return _cached("hostframes", path, produce)


def device_catalog_for(model: dict) -> Dict[int, List[bytes]]:
    """Reproduce main()'s device-catalog construction for a model."""
    src = model.get("catalog_pcapng")
    if src:
        cap = REPO / src
        if cap.exists():
            raw = _cached("catalog", cap, lambda: ws.extract_device_catalog(str(cap)))
            return {s: frs for s, frs in raw.items() if s in (0x01, 0x02)}
    db = _DB
    channel_urls = [v["url"] for v in db.values()] if db else []
    return ws.build_device_catalog(model, channel_urls)


_DB = None  # type: Optional[dict]


def build_sim_for_model(model_key: str):
    """Mirror sim/wheel_sim.py main() model setup, returning a configured
    WheelSimulator. Sets the module-global identity tables BEFORE construction
    (WheelSimulator snapshots them in __init__).

    Isolates ALL persistent state by pointing the module-global _LOG_DIR at a
    fresh empty temp dir: the virtual FS (wheel_fs.json), configjson_versions.json,
    and stored_dashboards.json otherwise carry upload/version state across runs and
    make the configJson state push non-deterministic (CSP's capture uploads dashes)."""
    ws._LOG_DIR = Path(tempfile.mkdtemp(prefix="moza-golden-"))  # type: ignore[attr-defined]
    model = ws.WHEEL_MODELS[model_key]
    (ws._PLUGIN_PROBE_RSP,
     ws._PITHOUSE_ID_RSP,
     ws._DEVICE_ID_RSP) = ws._build_identity_tables(model)
    ws._DISPLAY_MODEL_NAME = model.get("display", {}).get("name", "")
    ws._WHEEL_DEVICE = model.get("wheel_device", ws.DEV_WHEEL)
    ws._DEVICE_BLOCKS = ws.DEVICE_PROFILES[model_key].blocks

    replay = None
    for rel in model.get("replay_tables") or []:
        p = REPO / rel
        if p.exists():
            replay = replay or ws.ResponseReplay()
            replay.load_json(str(p))

    sim = ws.WheelSimulator(
        _DB, replay, device_catalog_for(model),
        rpm_led_count=model.get("rpm_led_count", ws._DEFAULT_RPM_LED_COUNT),
        button_led_count=model.get("button_led_count", ws._DEFAULT_BUTTON_LED_COUNT),
        factory_state_file=model.get("factory_state_file"),
        proactive_session09=model.get("proactive_session09", True),
        configjson_session=model.get("configjson_session", 0x09),
    )
    return sim


def run_model(model_key: str, limit: Optional[int]) -> Tuple[dict, List[dict]]:
    """Replay every capture for a model and return (meta, events)."""
    captures = MODEL_CAPTURES[model_key]
    events: List[dict] = []
    total_host = 0
    cap_meta = []
    for rel in captures:
        path = REPO / rel
        if not path.exists():
            raise FileNotFoundError(f"capture missing: {rel}")
        frames = host_frames(path)
        st = path.stat()
        cap_meta.append({"path": rel, "size": st.st_size, "host_frames": len(frames)})
        sim = build_sim_for_model(model_key)  # fresh sim per capture
        n = 0
        for fr in frames:
            if limit is not None and n >= limit:
                break
            n += 1
            total_host += 1
            out = sim.handle(fr)
            if out:
                events.append({"cap": rel, "in": fr.hex(), "out": [b.hex() for b in out]})
    meta = {
        "model": model_key,
        "captures": cap_meta,
        "limit": limit,
        "host_frames": total_host,
        "events": len(events),
    }
    return meta, events


def golden_file(model_key: str) -> Path:
    return GOLDEN_DIR / f"{model_key}.jsonl"


def write_golden(model_key: str, meta: dict, events: List[dict]) -> None:
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    with golden_file(model_key).open("w") as fh:
        fh.write(json.dumps({"_meta": meta}, sort_keys=True) + "\n")
        for ev in events:
            fh.write(json.dumps(ev, sort_keys=True) + "\n")


def read_golden(model_key: str) -> Tuple[dict, List[dict]]:
    lines = golden_file(model_key).read_text().splitlines()
    meta = json.loads(lines[0])["_meta"]
    events = [json.loads(l) for l in lines[1:] if l.strip()]
    return meta, events


def cmd_update(models: List[str], limit: Optional[int]) -> int:
    for m in models:
        meta, events = run_model(m, limit)
        write_golden(m, meta, events)
        print(f"  ✓ {m:6} — {meta['host_frames']} host frames → "
              f"{meta['events']} response events  →  {golden_file(m).name}")
    print(f"\nWrote {len(models)} golden(s) to {GOLDEN_DIR}")
    return 0


def cmd_check(models: List[str]) -> int:
    rc = 0
    for m in models:
        gf = golden_file(m)
        if not gf.exists():
            print(f"  ✗ {m:6} — no golden ({gf.name}); run --update first")
            rc = 1
            continue
        want_meta, want = read_golden(m)
        got_meta, got = run_model(m, want_meta.get("limit"))
        diff = _diff_events(want, got)
        if diff is None and got_meta["host_frames"] == want_meta["host_frames"]:
            print(f"  ✓ {m:6} — {len(got)} events byte-identical")
        else:
            rc = 1
            if got_meta["host_frames"] != want_meta["host_frames"]:
                print(f"  ✗ {m:6} — host-frame count changed "
                      f"{want_meta['host_frames']} → {got_meta['host_frames']} "
                      f"(capture changed?)")
            if diff is not None:
                idx, why, w, g = diff
                print(f"  ✗ {m:6} — event {idx}/{max(len(want), len(got))} {why}")
                print(f"        want: {w}")
                print(f"        got:  {g}")
    print()
    print("✓ all goldens byte-identical" if rc == 0 else "✗ golden mismatch — refactor changed sim output")
    return rc


def _diff_events(want: List[dict], got: List[dict]):
    n = min(len(want), len(got))
    for i in range(n):
        if want[i] != got[i]:
            return (i, "differs", json.dumps(want[i]), json.dumps(got[i]))
    if len(want) != len(got):
        i = n
        w = json.dumps(want[i]) if i < len(want) else "(end)"
        g = json.dumps(got[i]) if i < len(got) else "(end)"
        return (i, f"length {len(want)} → {len(got)}", w, g)
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--update", action="store_true", help="(re)generate goldens")
    g.add_argument("--check", action="store_true", help="assert byte-identical (CI gate)")
    g.add_argument("--list", action="store_true", help="print the model/capture plan")
    ap.add_argument("--model", help="restrict to one model (default: all)")
    ap.add_argument("--limit", type=int, default=None,
                    help="cap host frames per capture (default: full capture)")
    args = ap.parse_args()

    if args.list:
        for m, caps in MODEL_CAPTURES.items():
            print(f"{m:6} -> {caps}")
        return 0

    models = [args.model] if args.model else list(MODEL_CAPTURES.keys())
    for m in models:
        if m not in MODEL_CAPTURES:
            print(f"unknown model: {m}", file=sys.stderr)
            return 2

    # Determinism: neutralise every background emission, and freeze wall-clock.
    # threading.Timer drives the proactive/upload/keepalive emission (excluded);
    # time.time() is the only entropy in the synchronous path — it stamps
    # modifyTime into the session-0x04 dir-listing / file-transfer replies, whose
    # zlib body then varies per call. Freezing it makes handle() reproducible.
    threading.Timer = _NoopTimer  # type: ignore[assignment]
    ws.threading.Timer = _NoopTimer  # type: ignore[attr-defined]
    _frozen = 1_700_000_000.0
    ws.time.time = lambda: _frozen  # type: ignore[assignment]

    global _DB
    _DB = ws.load_telemetry_db()

    if args.update:
        return cmd_update(models, args.limit)
    return cmd_check(models)


if __name__ == "__main__":
    raise SystemExit(main())
