"""Unified device-profile schema for the MOZA simulator.

A ``DeviceProfile`` describes a *rig* — one or more USB gadgets, each fronting
one or more bus devices ("blocks"). It generalises the legacy per-wheel
``WHEEL_MODELS`` dict to every MOZA device category (wheelbase / hub / wheel /
display / pedal / handbrake / shifter / dash-cm2 / dash-cm1 / dash-fsr1 /
mbooster / estop), so a new device type plugs in as a block instead of new
dispatch code.

Refactor-safety: the 5 shipped wheels are authored as their exact legacy dict
(``LEGACY`` in each module) wrapped by ``DeviceProfile.from_legacy``. The legacy
dict stays the single source consumed by the existing engine via
``to_legacy_dict()`` (byte-identical, golden-gated), while ``blocks`` exposes the
structured view that the Phase-2 generic handlers and new engines consume.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# Protocol bus device bytes (mirror of the constants in wheel_sim.py — kept
# local so this module never imports wheel_sim, which imports the registry).
DEV_HUB = 0x12
DEV_BASE = 0x13
DEV_DASH = 0x14
DEV_WHEEL = 0x17
DEV_WHEEL_ES = 0x18
DEV_PEDAL = 0x19
DEV_SHIFTER = 0x1A
DEV_HANDBRAKE = 0x1B
DEV_ESTOP = 0x1C

# USB product IDs (mirror of Protocol/MozaUsbIds.cs — drives the gadget PID).
PID_WHEELBASE_R12 = 0x0006
PID_PEDALS_CRP = 0x0001
PID_PEDALS_SRP = 0x0003
PID_MBOOSTER = 0x0008
PID_HUB = 0x0020
PID_DASH_CM2 = 0x0025
PID_AB9 = 0x1000

# Identity-cascade keys a block's ``ident`` dict may carry (fed verbatim to
# wheel_sim._build_device_identity / _build_identity_tables).
IDENT_KEYS = (
    "name", "hw_version", "hw_sub", "sw_version", "serial0", "serial1",
    "hw_id", "caps", "dev_type", "identity_09", "identity_11",
)


@dataclass
class GadgetSpec:
    """One USB gadget the rig brings up. Most rigs have a single gadget; AB9,
    mBooster and standalone dashboards add their own with their own PID."""

    pid: int
    product_str: str = ""
    serial_str: str = ""
    functions: Tuple[str, ...] = ("acm",)   # ("acm",) or ("acm", "hid")
    # which sim engine drives this gadget's ttyGS:
    #   unified    -> WheelSimulator (wheel-rig: base+wheel+display+pedal+sessions)
    #   standalone -> engines.standalone.StandaloneSimulator (pedals/handbrake)
    #   mbooster   -> engines.standalone.MBoosterSimulator
    #   ab9        -> ab9_sim (kept separate; its FFB state machine)
    #   cm1 | fsr1 -> dash engines (Phase 4e, TODO)
    engine: str = "unified"


@dataclass
class DeviceBlock:
    """One bus device behind a gadget."""

    role: str
    address: int
    ident: Dict[str, Any] = field(default_factory=dict)
    present: bool = True            # joins _simulated_devices (heartbeat/keepalive ACK)
    answers_identity: bool = True   # False => absorb-only, no identity cascade
    # Groups whose WRITES the generic settings handler echoes verbatim (e.g.
    # pedal 0x24, handbrake 0x5C). NOT the read groups — reads are answered by
    # the replay table / identity cascade, so echoing them would return wrong
    # bytes. Mirrors the pre-refactor _try_pedal_write_echo semantics.
    echo_write_groups: Tuple[int, ...] = ()
    # Groups whose frames are swallowed + ACKed (high-rate writes a sim must not
    # count as unhandled: mbooster motor 0x24/0xb1, AB9 FFB 0x20, FSR1 0x42).
    absorb_groups: Tuple[int, ...] = ()
    extras: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DeviceProfile:
    key: str
    friendly: str
    gadgets: List[GadgetSpec] = field(default_factory=list)
    blocks: List[DeviceBlock] = field(default_factory=list)
    # Verbatim legacy dict for the existing engine. None for natively-authored
    # (non-wheel) profiles, where to_legacy_dict() synthesises one.
    _legacy: Optional[Dict[str, Any]] = None

    # ── Legacy bridge ────────────────────────────────────────────────────
    def to_legacy_dict(self) -> Dict[str, Any]:
        """Return the dict the existing WheelSimulator/_apply_model consume.

        For wheel profiles this is the original ``LEGACY`` dict verbatim (the
        byte-for-byte source of every shipped model). Callers deepcopy as needed
        (``_apply_model`` does); we return the stored object to match the prior
        module-literal semantics exactly."""
        if self._legacy is not None:
            return self._legacy
        return self._synthesise_legacy()

    def _synthesise_legacy(self) -> Dict[str, Any]:
        """Build a legacy-compatible dict from blocks for natively-authored
        profiles (Phase 4 device types that have no hand-written LEGACY)."""
        wheel = self.block("wheel") or (self.blocks[0] if self.blocks else None)
        d: Dict[str, Any] = {"friendly": self.friendly}
        if wheel is not None:
            d.update({k: v for k, v in wheel.ident.items()})
            d.update(wheel.extras)
            if wheel.address != DEV_WHEEL:
                d["wheel_device"] = wheel.address
        disp = self.block("display")
        if disp is not None:
            d["display"] = disp.ident
        base = self.block("wheelbase")
        if base is not None:
            d["base_identity"] = base.ident
        ped = self.block("pedal")
        if ped is not None:
            d["pedal_identity"] = ped.ident
        return d

    # ── Lookup helpers ───────────────────────────────────────────────────
    def block(self, role: str) -> Optional[DeviceBlock]:
        for b in self.blocks:
            if b.role == role:
                return b
        return None

    def present_addresses(self) -> List[int]:
        return [b.address for b in self.blocks if b.present]

    # ── Construction from a legacy wheel dict ────────────────────────────
    @classmethod
    def from_legacy(cls, key: str, legacy: Dict[str, Any]) -> "DeviceProfile":
        """Wrap an exact legacy WHEEL_MODELS entry. Parses a structured block
        view (wheel + optional display/base/pedal) for Phase-2 consumers while
        preserving the dict verbatim for the current engine."""
        wheel_addr = legacy.get("wheel_device", DEV_WHEEL)
        wheel_ident = {k: legacy[k] for k in IDENT_KEYS if k in legacy}
        extras = {k: v for k, v in legacy.items()
                  if k not in IDENT_KEYS
                  and k not in ("display", "base_identity", "pedal_identity",
                                "wheel_device", "friendly")}
        blocks: List[DeviceBlock] = [
            DeviceBlock(role="wheel", address=wheel_addr,
                        ident=wheel_ident, extras=extras)
        ]
        if "display" in legacy:
            # Display is a sub-device probed through the wheel address (0x43
            # tunnel), not a separate bus byte.
            blocks.append(DeviceBlock(role="display", address=wheel_addr,
                                      ident=copy.deepcopy(legacy["display"]),
                                      present=False))
        if "base_identity" in legacy:
            # Real wheelbase answers identically on hub 0x12 and base 0x13.
            blocks.append(DeviceBlock(role="wheelbase", address=DEV_BASE,
                                      ident=copy.deepcopy(legacy["base_identity"])))
            blocks.append(DeviceBlock(role="hub", address=DEV_HUB,
                                      ident=copy.deepcopy(legacy["base_identity"])))
        if "pedal_identity" in legacy:
            # Pedal settings: reads on 0x23 come from the replay table; writes on
            # 0x24 are echoed (the old _try_pedal_write_echo behaviour).
            blocks.append(DeviceBlock(role="pedal", address=DEV_PEDAL,
                                      ident=copy.deepcopy(legacy["pedal_identity"]),
                                      echo_write_groups=(0x24,)))
        gadget = GadgetSpec(pid=PID_WHEELBASE_R12,
                            product_str=legacy.get("friendly", key),
                            engine="unified")
        return cls(key=key, friendly=legacy.get("friendly", key),
                   gadgets=[gadget], blocks=blocks, _legacy=legacy)
