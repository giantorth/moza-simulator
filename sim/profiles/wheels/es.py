"""es wheel profile — MOZA ES (entry) wheel on an R5 base.

CORRECTED 2026-06-12 (live R5 + ES scan; docs/protocol/identity/known-wheel-models.md
§ "ES wheel identity (device 0x18)"): the ES wheel answers its own identity at
device **0x18**, NOT 0x13. The previous profile emitted the BASE identity (read
from 0x13) mislabelled as the wheel. Split correctly now:
  * wheel @ 0x18      -> model "ES",            hw "...SM-C" (Steering Module)
  * base  @ 0x12/0x13 -> "R5 Black # MOT-1",    hw "...BM-C" (Base Module)
sw-version, MCU UID and dev_type are shared across the base MCU's modules
(0x12 / 0x13 / 0x18 / 0x19). The ES wheel's hw_sub / serials / caps were not
captured at 0x18 — _build_identity_tables zero-defaults them rather than reuse
the base's values.

This is the one sanctioned wire change to an existing model; sim/golden/es.jsonl
was re-baselined for it. The base dev_type differs between captures (2026-04
direct read of 0x13 = 01-02-12-08; 2026-06 scan says the shared dev_type is
01-02-10-09) — the 2026-06 live scan is authoritative, so both use 01-02-10-09.
"""
from ..schema import DeviceProfile

LEGACY = {
    'name': 'ES',
    'friendly': 'ES (R5 base)',
    # ES answers at 0x18; frames to 0x17 are dropped (real ES doesn't enumerate
    # there). wheel_device=0x18 -> response device swap_nibbles(0x18) = 0x81.
    'wheel_device': 0x18,
    # ES is RPM-only (no buttons, no display). Brightness 0-15, bitmask LEDs.
    'rpm_led_count': 10,
    'button_led_count': 0,
    # ── ES wheel identity (device 0x18), live scan 2026-06-12 ──
    'sw_version': 'RS21-D05-MC WB',     # shared with the base MCU
    'hw_version': 'RS21-D05-HW SM-C',   # SM = Steering Module (the wheel head)
    'hw_id': bytes.fromhex('000000000000000000000000'),  # shared base UID, redacted
    'dev_type': bytes([0x01, 0x02, 0x10, 0x09]),
    # hw_sub / serial0 / serial1 / caps were NOT captured at 0x18 -> the tolerant
    # _build_identity_tables answers them with neutral zero defaults. TODO:
    # capture from a real ES bundle if exact bytes ever matter.
    'emits_7c23': False,
    'session_layout': 'legacy',
    # ── Base / motor identity (devices 0x12 + 0x13), read 2026-04-23 from 0x13 ──
    'base_identity': {
        'name': 'R5 Black # MOT-1',
        'hw_version': 'RS21-D05-HW BM-C',   # BM = Base Module
        'hw_sub': 'U-V10',
        'sw_version': 'RS21-D05-MC WB',
        'serial0': 'R5BASE0000000000',
        'serial1': 'R5BASE0000000001',
        'hw_id': bytes.fromhex('000000000000000000000000'),
        'caps': bytes([0x01, 0x02, 0x54, 0x00]),
        'dev_type': bytes([0x01, 0x02, 0x10, 0x09]),
    },
}

PROFILE = DeviceProfile.from_legacy('es', LEGACY)
