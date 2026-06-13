"""csp wheel profile — verbatim legacy WHEEL_MODELS['csp'] entry plus its
structured DeviceProfile view. Do not edit the LEGACY bytes by hand; they are
golden-gated (tools/sim_golden.py)."""
from .._const import (  # noqa: F401  (referenced inside LEGACY for some models)
    _FACTORY_STATE_FILE_W17_RGB,
    _FACTORY_STATE_FILE_W08_SM,
    _FACTORY_STATE_FILE_KSPRO,
)
from ..schema import DeviceProfile

LEGACY = {
        'name': 'W17',
        'friendly': 'CS Pro',
        'rpm_led_count': 18,
        'button_led_count': 14,
        'sw_version': 'RS21-W17-MC SW',
        'hw_version': 'RS21-W17-HW SM-C',
        'hw_sub': 'U-V12',
        # Real values from usb-capture/latestcaps/pithouse-switch-list-
        # delete-upload-reupload.pcapng. Byte-exact match so PitHouse's
        # cache key aligns with the real CSP wheel identity.
        'serial0': 'CSP000000000000',
        'serial1': 'CSP000000000001',
        'caps': bytes([0x01, 0x02, 0x3f, 0x01]),
        # hw_id from cmd 0x06 response (12B): 80 31 3b c0 00 20 30 04 4a 36 30 34 ("J604" tail)
        'hw_id': bytes.fromhex('000000000000000000000000'),
        # dev_type from cmd 0x04 response (4B): 01 02 06 06 — differs from
        # sim default 01 02 04 06 in position 2 (06 not 04).
        'dev_type': bytes([0x01, 0x02, 0x06, 0x06]),
        'emits_7c23': True,
        '_7c23_frames_name': 'CSP',
        # Hub (0x12) + base (0x13) + wheel (0x17) identity cascade plus all
        # session-port reads extracted from a CSP-on-R9 capture. PitHouse
        # probes hub/base with the same identity cmd set as the wheel.
        'replay_tables': [
            'sim/replay/csp_r9_wheel_17.json',
            'sim/replay/csp_r9_base_13.json',
            'sim/replay/csp_r9_hub_12.json',
        ],
        # Factory configJson state file. CSP shares the W17/RGB-DU-V11
        # display module with VGS — same 11-dashboard set. Extracted from
        # latestcaps/pithouse-switch-list-delete-upload-reupload.pcapng.
        'factory_state_file': _FACTORY_STATE_FILE_W17_RGB,
        # Hub (0x12) + base (0x13) identity — PitHouse probes both addresses
        # with the same identity cascade (02/04/05/06/07/08/09/0F/10/11). Real
        # wheelbase returns identical values on both. Extracted byte-exact from
        # csp_r9_hub_12.json / csp_r9_base_13.json.
        'base_identity': {
            # 20-char name — splits across 07:01 ("R9 Black # MOT-1") and 07:02 ("-V01").
            'name': 'R9 Black # MOT-1-V01',
            'hw_version': 'RS21-D01-HW BM-C',
            'hw_sub': 'U-V40',
            'sw_version': 'RS21-D01-MC WB',
            'serial0': 'R9BASE0000000000',
            'serial1': 'R9BASE0000000001',
            'hw_id': bytes.fromhex('000000000000000000000000'),
            'caps': bytes([0x01, 0x02, 0x50, 0x00]),
            'dev_type': bytes([0x01, 0x02, 0x0e, 0x09]),
        },
        'session1_desc': bytes.fromhex(
            '0701000000000c048ae5d086b2fcad7486dbe208041001'
            '0a0164000000050004020000000000000006 00'
            .replace(' ', '')),
        'display': {
            'name': 'W17 Display',
            'sw_version': 'RS21-W17-HW RGB-',
            'hw_version': 'RS21-W17-HW RGB-',
            'hw_sub': 'DU-V11',
            # Real display serials from same capture (cmd 0x10 via grp 0x43).
            'serial0': 'CSPDISPLAY000000',
            'serial1': 'CSPDISPLAY000001',
            # dev_type from cmd 0x04 response: 01 02 11 06 (position 2 = 0x11,
            # not sim default 0x0d). Capture-verified.
            'dev_type': bytes([0x01, 0x02, 0x11, 0x06]),
            'caps': bytes([0x01, 0x02, 0x00, 0x00]),
            'hw_id': bytes.fromhex('8ae5d086b2fcad7486dbe208'),
        },
}

PROFILE = DeviceProfile.from_legacy('csp', LEGACY)

# Proactive 7c:23 dashboard-activate page payloads (10B each), byte-exact from
# the CSP capture. CSP emits 2 pages, `fe 01` trailer, page-1 selector 0x3c.
PROFILE.blocks[0].extras['_7c23_payloads'] = [
    b'\x7c\x23\x3c\x80\x03\x00\x01\x00\xfe\x01',  # CSP page 1
    b'\x7c\x23\x32\x80\x04\x00\x02\x00\xfe\x01',  # CSP page 2
]
