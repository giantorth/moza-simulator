"""Merged KS Pro input state and the 42-byte HID input report.

Every input source (an ESP32, an SDL joystick, an evdev device) owns a
`SourceState` already translated into KS Pro terms (button indices 0..127,
axis slots 0..7, hat 0..8). `InputMerger` combines them:
  - buttons: OR across sources
  - hat:     first non-centred hat wins (source registration order)
  - axes:    each axis slot takes the value from the source that most recently
             changed it; with no source driving it, the idle default applies
Removing a source (disconnect / timeout) releases everything it held.

Not thread-safe by itself — the bridge calls it from its asyncio loop only;
worker threads hop in via loop.call_soon_threadsafe.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

NUM_BUTTONS = 128
NUM_AXES = 8
HAT_CENTRED = 8
REPORT_ID = 0x01
REPORT_LEN = 42

AXIS_NAMES = ('X', 'Y', 'Z', 'Rx', 'Ry', 'Rz', 'Slider', 'Dial')

# Idle axis values from the real hub's idle reports (mozahubstartup.pcapng:
# 4348 identical reports `01 0000 0180 0080 0180 0180 0080 0000 0080 08 00...`).
IDLE_AXES = (0x0000, 0x8001, 0x8000, 0x8001, 0x8001, 0x8000, 0x0000, 0x8000)


@dataclass
class SourceState:
    buttons: int = 0                                  # bit i = KS Pro button i
    hat: int = HAT_CENTRED
    axes: Dict[int, int] = field(default_factory=dict)  # slot -> 0..65535


def build_report(buttons: int, hat: int, axes: List[int]) -> bytes:
    """Serialise one 42-byte report-ID-1 joystick input report."""
    if len(axes) != NUM_AXES:
        raise ValueError(f'need {NUM_AXES} axes')
    hat = hat if 0 <= hat <= 7 else HAT_CENTRED
    return (bytes([REPORT_ID])
            + struct.pack('<8H', *(max(0, min(0xFFFF, a)) for a in axes))
            + bytes([hat & 0x0F])
            + (buttons & ((1 << NUM_BUTTONS) - 1)).to_bytes(16, 'little')
            + bytes(8))


def parse_report(report: bytes) -> SourceState:
    """Inverse of build_report (tests / diagnostics)."""
    if len(report) != REPORT_LEN or report[0] != REPORT_ID:
        raise ValueError('not a 42-byte report-ID-1 report')
    axes = struct.unpack('<8H', report[1:17])
    return SourceState(buttons=int.from_bytes(report[18:34], 'little'),
                       hat=report[17] & 0x0F,
                       axes=dict(enumerate(axes)))


class InputMerger:
    def __init__(self, on_change: Optional[Callable[[bytes], None]] = None):
        self._sources: Dict[str, SourceState] = {}
        self._axis_owner: Dict[int, str] = {}
        self._on_change = on_change
        self._report = self._compute()

    @property
    def report(self) -> bytes:
        return self._report

    @property
    def sources(self) -> Dict[str, SourceState]:
        return self._sources

    def update(self, source_id: str, state: SourceState) -> None:
        prev = self._sources.get(source_id)
        for slot, val in state.axes.items():
            if not 0 <= slot < NUM_AXES:
                continue
            if prev is None or prev.axes.get(slot) != val or slot not in self._axis_owner:
                self._axis_owner[slot] = source_id
        self._sources[source_id] = state
        self._refresh()

    def remove(self, source_id: str) -> None:
        if self._sources.pop(source_id, None) is None:
            return
        for slot in [s for s, o in self._axis_owner.items() if o == source_id]:
            # Hand the axis to any other source still driving it, else idle.
            other = next((sid for sid, st in self._sources.items() if slot in st.axes), None)
            if other is None:
                del self._axis_owner[slot]
            else:
                self._axis_owner[slot] = other
        self._refresh()

    def _compute(self) -> bytes:
        buttons = 0
        hat = HAT_CENTRED
        for st in self._sources.values():
            buttons |= st.buttons
            if hat == HAT_CENTRED and 0 <= st.hat <= 7:
                hat = st.hat
        axes = list(IDLE_AXES)
        for slot, owner in self._axis_owner.items():
            st = self._sources.get(owner)
            if st is not None and slot in st.axes:
                axes[slot] = st.axes[slot]
        return build_report(buttons, hat, axes)

    def _refresh(self) -> None:
        new = self._compute()
        if new != self._report:
            self._report = new
            if self._on_change is not None:
                self._on_change(new)
