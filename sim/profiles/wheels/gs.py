"""gs wheel profile — extracted from GS-moza-diagnostics-bundle-20260528-191216.zip by
tools/extract_profile.py. Identity fields are from the bundle's
diagnostics.txt; TODO-marked fields need deeper capture analysis
(catalog / session layout / 7c:23 payloads / factory state)."""
from ..schema import DeviceProfile

LEGACY = {
    'name': 'GS',
    'friendly': 'GS V2 Pro',
    'sw_version': 'RS21-D02-MC GW',
    'hw_version': 'RS21-W02-HW GW-C',
    'hw_sub': 'U-V02',
    'serial0': 'GS00000000000000',  # TODO: real serial redacted in bundle
    'serial1': 'GS00000000000001',  # TODO: real serial redacted in bundle
    'caps': bytes([0x01, 0x02, 0x00, 0x00]),  # TODO: PLACEHOLDER — caps not in bundle; needs the real 0x05 probe reply
    'hw_id': bytes.fromhex('000000000000000000000000'),  # TODO: MCU UID redacted in bundle
    'dev_type': bytes.fromhex('01020207'),
    'rpm_led_count': 10,
    'button_led_count': 10,
    'emits_7c23': False,
    'session_layout': 'legacy',  # TODO: confirm 'legacy' vs 'vgs_combined'
}

PROFILE = DeviceProfile.from_legacy('gs', LEGACY)
