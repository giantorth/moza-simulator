"""vgs wheel profile — verbatim legacy WHEEL_MODELS['vgs'] entry plus its
structured DeviceProfile view. Do not edit the LEGACY bytes by hand; they are
golden-gated (tools/sim_golden.py)."""
from .._const import (  # noqa: F401  (referenced inside LEGACY for some models)
    _FACTORY_STATE_FILE_W17_RGB,
    _FACTORY_STATE_FILE_W08_SM,
    _FACTORY_STATE_FILE_KSPRO,
)
from ..schema import DeviceProfile

LEGACY = {
        'name': 'VGS',
        'friendly': 'Vision GS',
        'rpm_led_count': 10,
        'button_led_count': 10,
        'sw_version': 'RS21-W08-MC SW',
        'hw_version': 'RS21-W08-HW SM-C',
        'hw_sub': 'U-V12',
        # Wheel serials — zeroed placeholders (real serials redacted).
        'serial0': 'VGS00000000000',
        'serial1': '00000000000000',
        'caps': bytes([0x01, 0x02, 0x1f, 0x01]),
        'hw_id': bytes.fromhex('000000000000000000000000'),
        # Real VGS emits 3 7c:23 page frames on connect (see
        # connect-wheel-start-game.pcapng). Different byte layout than CSP.
        'emits_7c23': True,
        '_7c23_frames_name': 'VGS',
        'session_layout': 'vgs_combined',
        # Factory configJson state file (session 0x09 device→host push).
        # VGS uses W17 RGB factory file. Verified 2026-04-25 against
        # `usb-capture/latestcaps/automobilista2-wheel-connect-dash-change.pcapng`
        # blob00 from the user's real VGS — productType="W17 Display",
        # configJsonList=[Core, Grids, Mono, ..., Rally V6] (11 entries).
        # Earlier swap to W08 SM broke compat: w08_sm.json declares
        # productType="Display" + 12 different dash names (Formula 1, JDM
        # Gauge Style, etc.) which the user's VGS+display does not advertise.
        'factory_state_file': _FACTORY_STATE_FILE_W17_RGB,
        # Replay real-hardware session 1/2 frames from this capture instead of
        # synthesizing. Real VGS session 2 has more than the 5 description
        # chunks — it continues with model-specific TLVs that PitHouse needs
        # before it will send the full tier definition on session 1.
        'catalog_pcapng': 'usb-capture/connect-wheel-start-game.pcapng',
        # Device description blob — split into 5 TLV-aligned sub-messages by
        # build_device_catalog's vgs_combined layout (chunk sizes 26/5/2/9/2).
        # Byte-for-byte match with connect-wheel-start-game.pcapng session 2
        # seq 5..9 data.
        'session1_desc': bytes.fromhex(
            '0701000000000c0669420714e806e0df1099ff3404100105'  # 24B
            '0a06'                                               # last 2B of chunk 1 (→26)
            '0164000000'                                         # chunk 2 (5B)
            '0500'                                               # chunk 3 (2B)
            '040000000000000000'                                 # chunk 4 (9B)
            '0600'                                               # chunk 5 (2B)
        ),
        'display': {
            'name': 'Display',
            'sw_version': 'RS21-W08-HW SM-D',
            'hw_version': 'RS21-W08-HW SM-D',
            'hw_sub': 'U-V14',
            # Serials redacted. Display hw_id extracted from connect-wheel-start-game.pcapng
            # (real VGS + PitHouse) — needed for PitHouse to correctly identify the display.
            'serial0': 'VGSDISPLAY000000',
            'serial1': 'VGSDISPLAY000001',
            'dev_type': bytes([0x01, 0x02, 0x08, 0x06]),
            'caps': bytes([0x01, 0x02, 0x00, 0x00]),
            'hw_id': bytes.fromhex('694207 14e8 06e0 df10 99ff 34'.replace(' ', '')),
        },
}

PROFILE = DeviceProfile.from_legacy('vgs', LEGACY)

# Proactive 7c:23 dashboard-activate page payloads (10B each), byte-exact from
# usb-capture/connect-wheel-start-game.pcapng. VGS emits 3 pages, `fe 01`
# trailer, page-1 selector byte 0x32. Framed at send time by
# wheel_sim.build_7c23_frames().
PROFILE.blocks[0].extras['_7c23_payloads'] = [
    b'\x7c\x23\x32\x80\x03\x00\x01\x00\xfe\x01',  # VGS page 1
    b'\x7c\x23\x3c\x80\x04\x00\x02\x00\xfe\x01',  # VGS page 2
    b'\x7c\x23\x50\x80\x05\x00\x03\x00\xfe\x01',  # VGS page 3
]
