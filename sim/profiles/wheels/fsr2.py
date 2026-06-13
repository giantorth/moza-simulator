"""fsr2 wheel profile — extracted from FSR-V2-moza-diagnostics-bundle-20260613-022824.zip by
tools/extract_profile.py. Identity fields are from the bundle's
diagnostics.txt; TODO-marked fields need deeper capture analysis
(catalog / session layout / 7c:23 payloads / factory state)."""
from ..schema import DeviceProfile

LEGACY = {
    'name': 'W13',
    'friendly': 'FSR V2',
    'sw_version': 'RS21-W13-MC SW',
    'hw_version': 'RS21-W13-HW SM-C',
    'hw_sub': 'U-V10',
    'serial0': 'W130000000000000',  # TODO: real serial redacted in bundle
    'serial1': 'W130000000000001',  # TODO: real serial redacted in bundle
    'caps': bytes.fromhex('01023001'),
    'hw_id': bytes.fromhex('000000000000000000000000'),  # TODO: MCU UID redacted in bundle
    'dev_type': bytes.fromhex('01020406'),
    'rpm_led_count': 16,
    'button_led_count': 10,
    'emits_7c23': True,  # TODO: confirm + add _7c23_payloads to PROFILE below (needs capture)
    'session_layout': 'legacy',  # TODO: confirm 'legacy' vs 'vgs_combined'
    # TODO: factory_state_file + catalog_pcapng + session1_desc from deeper capture analysis
    'display': {
        'name': 'W13 Display',
        'sw_version': 'RS21-W08-HW SM-D',
        'hw_version': 'RS21-W08-HW SM-D',
        'serial0': 'W13DISPLAY000000',  # TODO redacted
        'serial1': 'W13DISPLAY000001',  # TODO redacted
        'dev_type': bytes.fromhex('01020806'),
        'caps': bytes.fromhex('01020000'),
        'hw_id': bytes.fromhex('000000000000000000000000'),  # TODO redacted
    },
}

PROFILE = DeviceProfile.from_legacy('fsr2', LEGACY)

# TODO: PROFILE.blocks[0].extras['_7c23_payloads'] = [ ... ]  (10B page-activate
#       payloads from a real connect capture — see other wheel profiles)
