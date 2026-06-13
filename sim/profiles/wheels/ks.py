"""ks wheel profile — verbatim legacy WHEEL_MODELS['ks'] entry plus its
structured DeviceProfile view. Do not edit the LEGACY bytes by hand; they are
golden-gated (tools/sim_golden.py)."""
from .._const import (  # noqa: F401  (referenced inside LEGACY for some models)
    _FACTORY_STATE_FILE_W17_RGB,
    _FACTORY_STATE_FILE_W08_SM,
    _FACTORY_STATE_FILE_KSPRO,
)
from ..schema import DeviceProfile

LEGACY = {
        # MOZA KS race wheel (RS21-W04). Integrated button LEDs, no detachable
        # display — caps byte 2 = 0x1a has no 0x20 bit. Identity bytes captured
        # 2026-04-20 from real hardware via sim/probe_wheel.py against R5 base.
        'name': 'KS',
        'friendly': 'KS',
        'rpm_led_count': 10,
        'button_led_count': 10,
        'sw_version': 'RS21-W04-MC SW',
        'hw_version': 'RS21-W04-HW SM-C',
        'hw_sub': 'U-V04B',
        # Serials redacted.
        'serial0': 'KS00000000000000',
        'serial1': 'KS00000000000001',
        'caps': bytes([0x01, 0x02, 0x1a, 0x00]),
        'hw_id': bytes.fromhex('000000000000000000000000'),
        # Real KS returns cmd-echo 04 + 00, not 04:01 like VGS/CSP. Must match
        # or PitHouse mis-identifies the wheel (see VGS comment above).
        'identity_11': bytes([0x04, 0x00]),
        # KS uses sub-byte 0x05 in dev_type where VGS/CSP use 0x04.
        'dev_type': bytes([0x01, 0x02, 0x05, 0x06]),
        # No dashboard screen — doesn't emit 7c:23 page-activate frames and
        # doesn't need a session1_desc/catalog replay.
        'emits_7c23': False,
        'session_layout': 'legacy',
}

PROFILE = DeviceProfile.from_legacy('ks', LEGACY)
