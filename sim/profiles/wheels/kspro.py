"""kspro wheel profile — verbatim legacy WHEEL_MODELS['kspro'] entry plus its
structured DeviceProfile view. Do not edit the LEGACY bytes by hand; they are
golden-gated (tools/sim_golden.py)."""
from .._const import (  # noqa: F401  (referenced inside LEGACY for some models)
    _FACTORY_STATE_FILE_W17_RGB,
    _FACTORY_STATE_FILE_W08_SM,
    _FACTORY_STATE_FILE_KSPRO,
)
from ..schema import DeviceProfile

LEGACY = {
        # MOZA KS Pro race wheel (RS21-W18). Shares the W17-HW RGB display
        # module with CSP (same 12B display hw_id). Identity strings + session
        # description chunks extracted from
        # usb-capture/ksp/putOnWheelAndOpenPitHouse.pcapng (frames ~19500–19700,
        # full PitHouse handshake). Wheel-head dev_type byte-exact from
        # capture grp=0x84 reply (`01 02 07 07`); the session2 catalog
        # carries a separate model byte (0x05 at desc position 7).
        'name': 'W18',
        'friendly': 'KS Pro',
        # LED counts from probe enumeration in capture: page 0 sub=0 reads
        # cover ff00..ff11 (18 entries), page 1 sub=1 reads cover ff00..ff09
        # (10 entries). Verify against real wheel.
        'rpm_led_count': 18,
        'button_led_count': 10,
        'sw_version': 'RS21-W18-MC SW',
        'hw_version': 'RS21-W18-HW SM-C',
        'hw_sub': 'U-V10',
        # Serials redacted.
        'serial0': 'KSP0000000000000',
        'serial1': 'KSP0000000000001',
        # Wheel-head caps + hw_id + dev_type byte-exact from
        # putOnWheelAndOpenPitHouse.pcapng grp=0x85/0x86/0x84 replies. Earlier
        # values were stale CSP-display copies; PitHouse classifies the wheel
        # off these bytes and demotes from "KS Pro" to a generic model when
        # they don't match. Verified 2026-04-26.
        'caps': bytes([0x01, 0x02, 0x41, 0x01]),
        'hw_id': bytes.fromhex('000000000000000000000000'),
        'dev_type': bytes([0x01, 0x02, 0x07, 0x07]),
        'emits_7c23': True,
        # KS Pro page-activate frames (3 variants, `fc 03` trailer) byte-exact
        # from putOnWheelAndOpenPitHouse.pcapng. Differ from CSP's 2-variant
        # `fe 01` frames; PitHouse appears to gate dashboard detection on
        # the wheel-specific trailer.
        '_7c23_frames_name': 'KSPRO',
        'session_layout': 'vgs_combined',
        'catalog_pcapng': 'usb-capture/ksp/putOnWheelAndOpenPitHouse.pcapng',
        # KS Pro pcap (putOnWheelAndOpenPitHouse.pcapng) only captures the
        # first 12s and shows the device-side OPEN with no state push, but
        # PitHouse won't detect the wheel display without the state push —
        # the real wheel must emit it later in the session. Sim pushes
        # eagerly to keep the dashboard manager UI populated.
        'proactive_session09': True,
        # KS Pro / 2026-04 firmware moves configJson state push from
        # session 0x09 to 0x0a (verified in
        # `usb-capture/ksp/mozahubstartup.pcapng` — session 0x09 carries
        # only zero-payload heartbeats, session 0x0a carries the 14.6 KB
        # Schema A snapshot at connect, Schema B deltas during uploads,
        # and the host's `{"configJson()":{...}, "id":11}` reply).
        # Tile-server also relocated: host→dev push moved from 0x03 to
        # 0x04 (12-byte envelope, sizes 775/3041/6301), and the wheel
        # now emits a dev→host mirror on 0x0b (12-byte envelope,
        # `root: "/home/moza/resource/tile_map/"`). Pushing configJson
        # on 0x09 leaves PitHouse with no parsed state → dashboard
        # manager UI shows wheel as empty.
        'configjson_session': 0x0a,
        # KS Pro shares the W17/RGB-DU-V11 display PCB with CSP but
        # firmware ships a different factory dashboard set: 10 entries
        # (Rally V1..V6 + Core/Mono/Pulse/Grids), NO Nebula. Captured
        # byte-exact 2026-04-26 from
        # `usb-capture/ksp/mozahubstartup.pcapng` seq 11..69.
        'factory_state_file': _FACTORY_STATE_FILE_KSPRO,
        # Per-device replay tables (JSON) layered over the default replay
        # source. Earlier tables win when keys collide. Pedal table is loaded
        # because real KS Pro captures include pedal traffic on 0x19 that
        # PitHouse expects a response to.
        'replay_tables': [
            'sim/replay/kspro_wheel_17.json',
            'sim/replay/kspro_base_13.json',
            'sim/replay/kspro_hub_12.json',
            'sim/replay/kspro_pedal_19.json',
        ],
        # Hub (0x12) + base (0x13) identity — R12 wheelbase. Byte-exact from
        # kspro_hub_12.json (identical to kspro_base_13.json).
        'base_identity': {
            'name': 'R12 Black # MOT-1-V01',
            'hw_version': 'RS21-D07-HW BM-C',
            'hw_sub': 'U-V10',
            'sw_version': 'RS21-D07-MC WB',
            'serial0': 'R12BASE000000000',
            'serial1': 'R12BASE000000001',
            'hw_id': bytes.fromhex('000000000000000000000000'),
            'caps': bytes([0x01, 0x02, 0x4b, 0x00]),
            'dev_type': bytes([0x01, 0x02, 0x0e, 0x09]),
        },
        # Pedal (0x19) identity — SRP pedals (only device answering 0x19 in
        # the KS Pro capture). Byte-exact from kspro_pedal_19.json.
        'pedal_identity': {
            'name': 'SRP',
            'hw_version': 'RS21-D01-HW PM-C',
            'hw_sub': 'U-V11',
            'sw_version': 'RS21-D01-MC PB',
            'serial0': 'SRPPEDAL00000000',
            'serial1': 'SRPPEDAL00000001',
            'hw_id': bytes.fromhex('000000000000000000000000'),
            'caps': bytes([0x01, 0x02, 0x18, 0x00]),
            'dev_type': bytes([0x01, 0x02, 0x02, 0x05]),
            # Pedal returns 00:04 on cmd 09, while hub/base return 00:01.
            'identity_09': bytes([0x00, 0x04]),
        },
        # Byte-for-byte from capture session 0/port 2 frags 6..10
        # (chunk sizes 26/5/2/9/2 → 'vgs_combined' layout).
        'session1_desc': bytes.fromhex(
            '0701000000000c058ae5d086b2fcad7486dbe2080410120 10a00'  # 26B
            '0164000000'                                              # 5B
            '0500'                                                    # 2B
            '040000000000000000'                                      # 9B
            '0600'                                                    # 2B
            .replace(' ', '')),
        'display': {
            'name': 'W18 Display',
            # KS Pro display reports the same RGB-I/RGB-B board strings as CSP.
            'sw_version': 'RS21-W17-HW RGB-',
            'hw_version': 'RS21-W17-HW RGB-',
            'hw_sub': 'DU-V11',
            # Serials redacted.
            'serial0': 'KSPDISPLAY000000',
            'serial1': 'KSPDISPLAY000001',
            # Display dev_type byte-exact from
            # putOnWheelAndOpenPitHouse.pcapng grp=0xC3 wrapper grp=0x84 reply.
            'dev_type': bytes([0x01, 0x02, 0x11, 0x06]),
            'caps': bytes([0x01, 0x02, 0x00, 0x00]),
            'hw_id': bytes.fromhex('8ae5d086b2fcad7486dbe208'),
        },
}

PROFILE = DeviceProfile.from_legacy('kspro', LEGACY)

# Proactive 7c:23 dashboard-activate page payloads (10B each), byte-exact from
# usb-capture/ksp/putOnWheelAndOpenPitHouse.pcapng. KS Pro emits 3 pages with
# the `fc 03` trailer (vs CSP/VGS `fe 01`) — PitHouse gates dashboard detection
# on the wheel-specific trailer.
PROFILE.blocks[0].extras['_7c23_payloads'] = [
    b'\x7c\x23\x32\x80\x04\x00\x01\x00\xfc\x03',  # KS Pro page 1
    b'\x7c\x23\x3c\x80\x05\x00\x02\x00\xfc\x03',  # KS Pro page 2
    b'\x7c\x23\x50\x80\x06\x00\x03\x00\xfc\x03',  # KS Pro page 3
]
