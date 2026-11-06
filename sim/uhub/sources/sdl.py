"""SDL2 joystick source (Windows + Linux) via pysdl2.

    pip install pysdl2            # Linux: uses the system libSDL2
    pip install pysdl2 pysdl2-dll # Windows: bundles SDL2.dll

Runs SDL's event loop on a worker thread with background joystick events
enabled (the bridge has no window, so focus never arrives). Only devices
matched by a config entry are mapped unless `map_unconfigured` is true.
The hub's own virtual joystick (VID 0x346E PID 0x0020) is always ignored —
once attached locally it shows up as an SDL joystick and would loop back.

Config:
    "sdl": {
      "map_unconfigured": false,
      "devices": [
        {"match": "Button Box", "button_offset": 32, ...DeviceMapping keys...}
      ]
    }
`match` is a case-insensitive substring of the SDL name, or an exact GUID.
"""
from __future__ import annotations

import asyncio
import logging
import threading
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

from ..descriptors import PID as HUB_PID, VID as HUB_VID
from ..mapping import DeviceMapping
from ..state import HAT_CENTRED, SourceState

log = logging.getLogger('uhub.sdl')

# SDL hat bitmask -> HID hat (0 = N, clockwise, 8 = centred)
_HAT = {0x00: 8, 0x01: 0, 0x03: 1, 0x02: 2, 0x06: 3, 0x04: 4, 0x0C: 5, 0x08: 6, 0x09: 7}


def _sdl():
    try:
        import sdl2  # type: ignore
    except ImportError as e:  # pragma: no cover - depends on host
        raise RuntimeError('SDL source needs pysdl2: pip install pysdl2 '
                           '(Windows: also pysdl2-dll)') from e
    return sdl2


@dataclass
class _Pad:
    instance_id: int
    name: str
    guid: str
    mapping: DeviceMapping
    handle: object
    pressed: Set[int] = field(default_factory=set)
    axes: Dict[int, int] = field(default_factory=dict)
    hat: int = HAT_CENTRED

    @property
    def source_id(self) -> str:
        return f'sdl:{self.instance_id}:{self.name}'


def _guid_str(sdl2, guid) -> str:
    import ctypes
    buf = ctypes.create_string_buffer(33)
    sdl2.SDL_JoystickGetGUIDString(guid, buf, 33)
    return buf.value.decode()


def list_devices() -> List[dict]:
    sdl2 = _sdl()
    sdl2.SDL_SetHint(sdl2.SDL_HINT_JOYSTICK_ALLOW_BACKGROUND_EVENTS, b'1')
    if sdl2.SDL_Init(sdl2.SDL_INIT_JOYSTICK) != 0:
        raise RuntimeError(f'SDL_Init failed: {sdl2.SDL_GetError().decode()}')
    out = []
    try:
        for i in range(sdl2.SDL_NumJoysticks()):
            js = sdl2.SDL_JoystickOpen(i)
            if not js:
                continue
            out.append({
                'index': i,
                'name': (sdl2.SDL_JoystickName(js) or b'').decode(errors='replace'),
                'guid': _guid_str(sdl2, sdl2.SDL_JoystickGetGUID(js)),
                'vid': sdl2.SDL_JoystickGetVendor(js),
                'pid': sdl2.SDL_JoystickGetProduct(js),
                'buttons': sdl2.SDL_JoystickNumButtons(js),
                'axes': sdl2.SDL_JoystickNumAxes(js),
                'hats': sdl2.SDL_JoystickNumHats(js),
            })
            sdl2.SDL_JoystickClose(js)
    finally:
        sdl2.SDL_Quit()
    return out


class SdlSource:
    def __init__(self, loop: asyncio.AbstractEventLoop,
                 sink: Callable[[str, SourceState], None],
                 sink_remove: Callable[[str], None], cfg: Optional[dict] = None):
        cfg = cfg or {}
        self._loop = loop
        self._sink = sink
        self._sink_remove = sink_remove
        self._map_unconfigured = bool(cfg.get('map_unconfigured', False))
        self._entries: List[Tuple[str, DeviceMapping]] = [
            (str(d.get('match', '')), DeviceMapping.from_json(d)) for d in cfg.get('devices') or []]
        self._pads: Dict[int, _Pad] = {}
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        _sdl()   # fail fast on missing pysdl2
        self._thread = threading.Thread(target=self._run, name='sdl-joystick', daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _match(self, name: str, guid: str) -> Optional[DeviceMapping]:
        for pat, m in self._entries:
            if pat and (pat.lower() in name.lower() or pat.lower() == guid.lower()):
                return m
        return DeviceMapping() if self._map_unconfigured else None

    def _emit(self, pad: _Pad) -> None:
        st = pad.mapping.translate(pad.pressed, pad.axes, pad.hat)
        self._loop.call_soon_threadsafe(self._sink, pad.source_id, st)

    def _run(self) -> None:
        import ctypes
        sdl2 = _sdl()
        sdl2.SDL_SetHint(sdl2.SDL_HINT_JOYSTICK_ALLOW_BACKGROUND_EVENTS, b'1')
        if sdl2.SDL_Init(sdl2.SDL_INIT_JOYSTICK) != 0:
            log.error('SDL_Init failed: %s', sdl2.SDL_GetError().decode())
            return
        sdl2.SDL_JoystickEventState(sdl2.SDL_ENABLE)
        ev = sdl2.SDL_Event()
        try:
            while not self._stop.is_set():
                if not sdl2.SDL_WaitEventTimeout(ctypes.byref(ev), 100):
                    continue
                t = ev.type
                if t == sdl2.SDL_JOYDEVICEADDED:
                    self._added(sdl2, ev.jdevice.which)
                elif t == sdl2.SDL_JOYDEVICEREMOVED:
                    pad = self._pads.pop(ev.jdevice.which, None)
                    if pad is not None:
                        log.info('SDL device removed: %s', pad.name)
                        sdl2.SDL_JoystickClose(pad.handle)
                        self._loop.call_soon_threadsafe(self._sink_remove, pad.source_id)
                elif t in (sdl2.SDL_JOYBUTTONDOWN, sdl2.SDL_JOYBUTTONUP):
                    pad = self._pads.get(ev.jbutton.which)
                    if pad is not None:
                        (pad.pressed.add if t == sdl2.SDL_JOYBUTTONDOWN
                         else pad.pressed.discard)(ev.jbutton.button)
                        self._emit(pad)
                elif t == sdl2.SDL_JOYAXISMOTION:
                    pad = self._pads.get(ev.jaxis.which)
                    if pad is not None:
                        pad.axes[ev.jaxis.axis] = ev.jaxis.value + 32768
                        self._emit(pad)
                elif t == sdl2.SDL_JOYHATMOTION:
                    pad = self._pads.get(ev.jhat.which)
                    if pad is not None and ev.jhat.hat == 0:
                        pad.hat = _HAT.get(ev.jhat.value, HAT_CENTRED)
                        self._emit(pad)
        finally:
            for pad in self._pads.values():
                sdl2.SDL_JoystickClose(pad.handle)
            sdl2.SDL_Quit()

    def _added(self, sdl2, index: int) -> None:
        if sdl2.SDL_JoystickGetDeviceVendor(index) == HUB_VID and \
                sdl2.SDL_JoystickGetDeviceProduct(index) == HUB_PID:
            log.info('ignoring our own hub joystick (SDL index %d)', index)
            return
        js = sdl2.SDL_JoystickOpen(index)
        if not js:
            return
        name = (sdl2.SDL_JoystickName(js) or b'').decode(errors='replace')
        guid = _guid_str(sdl2, sdl2.SDL_JoystickGetGUID(js))
        mapping = self._match(name, guid)
        if mapping is None:
            log.info('SDL device not mapped (no config match): %r guid=%s', name, guid)
            sdl2.SDL_JoystickClose(js)
            return
        iid = sdl2.SDL_JoystickInstanceID(js)
        pad = _Pad(iid, name, guid, mapping, js)
        for a in range(sdl2.SDL_JoystickNumAxes(js)):
            pad.axes[a] = sdl2.SDL_JoystickGetAxis(js, a) + 32768
        self._pads[iid] = pad
        log.info('SDL device mapped: %r (instance %d)', name, iid)
        self._emit(pad)
