"""Per-device translation from a source's native inputs to KS Pro inputs.

All indices are 0-based. KS Pro button N appears as button N+1 in Windows
"Game Controllers" (joy.cpl). Axis slots: 0 X, 1 Y, 2 Z, 3 Rx, 4 Ry, 5 Rz,
6 Slider, 7 Dial.

A mapping entry (JSON), every key optional:
    {
      "button_offset": 0,              # unmapped source button i -> i + offset
      "buttons": {"3": 40, "4": null}, # explicit source -> KS Pro (null drops it)
      "only_mapped_buttons": false,    # true: drop buttons not in "buttons"
      "axes": {"0": {"to": 6, "invert": false}},   # source axis -> slot
      "hat": true                      # forward the source's first hat
    }
With no "axes" key, source axis i drives slot i (for i < 8).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, Optional

from .state import NUM_AXES, NUM_BUTTONS, HAT_CENTRED, SourceState


@dataclass
class AxisTarget:
    slot: int
    invert: bool = False


@dataclass
class DeviceMapping:
    button_offset: int = 0
    buttons: Dict[int, Optional[int]] = field(default_factory=dict)
    only_mapped_buttons: bool = False
    axes: Optional[Dict[int, AxisTarget]] = None
    hat: bool = True

    @classmethod
    def from_json(cls, obj: Optional[dict]) -> 'DeviceMapping':
        obj = obj or {}
        buttons = {int(k): (None if v is None else int(v))
                   for k, v in (obj.get('buttons') or {}).items()}
        axes = None
        if 'axes' in obj:
            axes = {}
            for k, v in (obj.get('axes') or {}).items():
                if isinstance(v, int):
                    axes[int(k)] = AxisTarget(v)
                elif v is not None:
                    axes[int(k)] = AxisTarget(int(v['to']), bool(v.get('invert', False)))
        return cls(button_offset=int(obj.get('button_offset', 0)), buttons=buttons,
                   only_mapped_buttons=bool(obj.get('only_mapped_buttons', False)),
                   axes=axes, hat=bool(obj.get('hat', True)))

    def target_button(self, src: int) -> Optional[int]:
        if src in self.buttons:
            dst = self.buttons[src]
        elif self.only_mapped_buttons:
            return None
        else:
            dst = src + self.button_offset
        return dst if dst is not None and 0 <= dst < NUM_BUTTONS else None

    def target_axis(self, src: int) -> Optional[AxisTarget]:
        if self.axes is None:
            return AxisTarget(src) if 0 <= src < NUM_AXES else None
        t = self.axes.get(src)
        return t if t is not None and 0 <= t.slot < NUM_AXES else None

    def translate(self, pressed: Iterable[int], axes: Dict[int, int],
                  hat: int = HAT_CENTRED) -> SourceState:
        """pressed: source button indices held; axes: source axis -> 0..65535."""
        bits = 0
        for b in pressed:
            dst = self.target_button(b)
            if dst is not None:
                bits |= 1 << dst
        out_axes: Dict[int, int] = {}
        for a, val in axes.items():
            t = self.target_axis(a)
            if t is not None:
                out_axes[t.slot] = 0xFFFF - val if t.invert else val
        return SourceState(buttons=bits, hat=hat if self.hat else HAT_CENTRED, axes=out_axes)
