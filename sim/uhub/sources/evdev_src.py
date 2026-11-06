"""Linux evdev source (optional; Linux only) — for devices SDL doesn't treat as
joysticks (keyboards, macro pads, odd button boxes) and for exclusive `grab`.

    "evdev": {
      "devices": [
        {"path": "/dev/input/by-id/usb-...-event-joystick",
         "grab": false,
         "keys": {"BTN_TRIGGER": 0, "KEY_A": 12, "290": 13},
         "abs":  {"ABS_X": {"to": 0, "invert": false}},
         "hat": true}
      ]
    }
`keys` maps evdev key codes (name or number) -> KS Pro button; unmapped keys
are ignored. `abs` maps absolute axes -> KS Pro axis slot, scaled from the
device's reported min/max to 0..65535. ABS_HAT0X/Y drive the hat when
`hat` is true.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Callable, Dict, List, Optional, Set

from ..state import HAT_CENTRED, NUM_AXES, NUM_BUTTONS, SourceState

log = logging.getLogger('uhub.evdev')

# (x, y) of ABS_HAT0X/Y -> HID hat
_HAT = {(0, -1): 0, (1, -1): 1, (1, 0): 2, (1, 1): 3, (0, 1): 4,
        (-1, 1): 5, (-1, 0): 6, (-1, -1): 7, (0, 0): HAT_CENTRED}


def _evdev():
    try:
        import evdev  # type: ignore
    except ImportError as e:  # pragma: no cover
        raise RuntimeError('evdev source needs python-evdev (Linux only): pip install evdev') from e
    return evdev


def _code(ecodes, name_or_num, table: str) -> int:
    s = str(name_or_num)
    if s.lstrip('-').isdigit():
        return int(s)
    val = getattr(ecodes, s, None)
    if not isinstance(val, int):
        raise ValueError(f'unknown evdev {table} code {s!r}')
    return val


def list_devices() -> List[dict]:
    evdev = _evdev()
    out = []
    for path in evdev.list_devices():
        try:
            d = evdev.InputDevice(path)
        except OSError:
            continue
        caps = d.capabilities()
        out.append({'path': path, 'name': d.name, 'phys': d.phys,
                    'vid': d.info.vendor, 'pid': d.info.product,
                    'keys': len(caps.get(evdev.ecodes.EV_KEY, [])),
                    'abs': len(caps.get(evdev.ecodes.EV_ABS, []))})
        d.close()
    return out


class _Dev:
    def __init__(self, evdev, cfg: dict):
        e = evdev.ecodes
        self.path = cfg['path']
        self.grab = bool(cfg.get('grab', False))
        self.use_hat = bool(cfg.get('hat', True))
        self.keys: Dict[int, int] = {}
        for k, v in (cfg.get('keys') or {}).items():
            if v is not None and 0 <= int(v) < NUM_BUTTONS:
                self.keys[_code(e, k, 'key')] = int(v)
        self.abs: Dict[int, tuple] = {}
        for k, v in (cfg.get('abs') or {}).items():
            t = {'to': v} if isinstance(v, int) else v
            if 0 <= int(t['to']) < NUM_AXES:
                self.abs[_code(e, k, 'abs')] = (int(t['to']), bool(t.get('invert', False)))
        self.pressed: Set[int] = set()
        self.axes: Dict[int, int] = {}
        self.hat_xy = [0, 0]
        self.dev = None
        self.ranges: Dict[int, tuple] = {}

    @property
    def source_id(self) -> str:
        return f'evdev:{self.path}'

    def state(self) -> SourceState:
        bits = 0
        for b in self.pressed:
            bits |= 1 << b
        hat = _HAT.get(tuple(self.hat_xy), HAT_CENTRED) if self.use_hat else HAT_CENTRED
        return SourceState(buttons=bits, hat=hat, axes=dict(self.axes))


class EvdevSource:
    def __init__(self, sink: Callable[[str, SourceState], None],
                 sink_remove: Callable[[str], None], cfg: Optional[dict] = None):
        self._evdev = _evdev()
        self._sink = sink
        self._sink_remove = sink_remove
        self._devs = [_Dev(self._evdev, d) for d in (cfg or {}).get('devices') or []]
        self._tasks: List[asyncio.Task] = []

    async def start(self) -> None:
        for d in self._devs:
            self._tasks.append(asyncio.create_task(self._run(d)))

    def close(self) -> None:
        for t in self._tasks:
            t.cancel()

    async def _run(self, d: _Dev) -> None:
        evdev = self._evdev
        e = evdev.ecodes
        while True:
            try:
                d.dev = evdev.InputDevice(d.path)
                if d.grab:
                    d.dev.grab()
                for code, info in d.dev.capabilities(absinfo=True).get(e.EV_ABS, []):
                    d.ranges[code] = (info.min, info.max)
                    if code in d.abs:
                        self._set_abs(d, code, info.value)
                log.info('evdev device opened: %s (%s)', d.dev.name, d.path)
                self._sink(d.source_id, d.state())
                async for ev in d.dev.async_read_loop():
                    if ev.type == e.EV_KEY and ev.code in d.keys:
                        (d.pressed.add if ev.value else d.pressed.discard)(d.keys[ev.code])
                    elif ev.type == e.EV_ABS:
                        if ev.code == e.ABS_HAT0X:
                            d.hat_xy[0] = ev.value
                        elif ev.code == e.ABS_HAT0Y:
                            d.hat_xy[1] = ev.value
                        elif ev.code in d.abs:
                            self._set_abs(d, ev.code, ev.value)
                        else:
                            continue
                    elif ev.type == e.EV_SYN:
                        self._sink(d.source_id, d.state())
                    continue
            except asyncio.CancelledError:
                raise
            except OSError as exc:
                log.warning('evdev %s unavailable (%s) — retrying in 2 s', d.path, exc)
            finally:
                if d.dev is not None:
                    try:
                        d.dev.close()
                    except OSError:
                        pass
                    d.dev = None
                d.pressed.clear()
                self._sink_remove(d.source_id)
            await asyncio.sleep(2)

    @staticmethod
    def _set_abs(d: _Dev, code: int, value: int) -> None:
        slot, invert = d.abs[code]
        lo, hi = d.ranges.get(code, (0, 65535))
        span = (hi - lo) or 1
        v = int(round((value - lo) * 65535 / span))
        v = max(0, min(65535, v))
        d.axes[slot] = 65535 - v if invert else v
