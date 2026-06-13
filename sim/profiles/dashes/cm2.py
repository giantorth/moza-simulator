"""CM2 Racing Dash profile — standalone USB dashboard (PID 0x0025).

The CM2 IS a tier-def device: PitHouse drives it with the same group-0x43 session
pipeline as a wheel (tier defs on session 0x01, value frames on 0x02, fc:00 acks),
so it reuses the wheel engine (engine=unified) at the standalone CM2 bridge/main
device 0x12. On top of that it ABSORBS the per-frame RPM/flag LED bitmask (group
0x41 cmd FD:DE) and ECHOES the one-time group-0x32 colour/threshold config.
Identity from docs/protocol/devices/dash-0x14.md § "CM2 Racing Dash": model
"S09 Display", hw/sw RS21-W08, dev_type 01-02-08-06.

CAVEAT: a standalone CM2 has no wheelbase, but WheelSimulator's simulated-device
baseline always includes 0x13 (base). That's harmless here — the plugin's CM2
path targets dev 0x12 and does not probe 0x13 — but if a future capture shows the
plugin probing 0x13 on a CM2 connection, the baseline needs a per-profile
override. The base-bridged CM2 (dash sub-device at 0x14 on a wheel rig) is a
separate, not-yet-modelled topology.
"""
from ..schema import DeviceProfile, GadgetSpec, PID_DASH_CM2

LEGACY = {
    'name': 'S09 Display',
    'friendly': 'CM2 Racing Dash',
    # Standalone CM2 bridge/main device byte (vs 0x14 when base-bridged).
    'wheel_device': 0x12,
    'rpm_led_count': 16,        # CM2 has 16 RPM LEDs, no buttons / flag strip
    'button_led_count': 0,
    'sw_version': 'RS21-W08',
    'hw_version': 'RS21-W08',
    'serial0': 'CM2000000000000',
    'serial1': 'CM2000000000001',
    'hw_id': bytes.fromhex('000000000000000000000000'),
    'dev_type': bytes([0x01, 0x02, 0x08, 0x06]),
    'caps': bytes([0x01, 0x02, 0x00, 0x00]),   # TODO: confirm from cm2.pcapng
    'emits_7c23': False,
    'proactive_session09': False,
    'session_layout': 'legacy',
}

PROFILE = DeviceProfile.from_legacy('cm2', LEGACY)
# Standalone CM2 enumerates as its own USB device, PID 0x0025 (not the wheelbase
# 0x0006 from_legacy defaults to).
PROFILE.gadgets = [GadgetSpec(pid=PID_DASH_CM2,
                              product_str='MOZA CM2 Racing Dash', engine='unified')]
# Per-frame LED on/off bitmask (group 0x41 FD:DE) -> absorb; one-time colour /
# threshold config (group 0x32) -> echo ack.
PROFILE.blocks[0].absorb_groups = (0x41,)
PROFILE.blocks[0].echo_write_groups = (0x32,)
