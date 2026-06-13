"""FSR V1 (FSR1) display-wheel profile — device 0x17, group 0x42 transport.

The FSR V1 is a wheel (model "FSR", hw RS21-D03-HW FW-C, sw RS21-D03-MC FW) that
does NOT use tier-def: PitHouse pushes pre-computed display field values as
fixed-layout group-0x42 records at ~28 Hz; there are no sessions, no channel
catalog, no 0x43/7D:23 value stream (only a 1-byte 0x43 keepalive poll). See
docs/protocol/devices/wheel-0x17.md § "Group 0x42". Distinct from FSR V2 (W13),
which is a standard tier-def wheel.

So this is a wheel profile on the wheelbase gadget (engine=unified, PID 0x0006),
but with the tier-def pipeline effectively idle: it ANSWERS identity + the 0x43
keepalive + the 0x40/0x3F config echoes (handled by WheelSimulator), ABSORBS the
group-0x42 display push, and ECHOES the group-0x32 cmd-0x81 dashboard switch as a
0xB2 ack. emits_7c23 / proactive_session09 are off — FSR1 emits neither.
"""
from ..schema import DeviceProfile

LEGACY = {
    'name': 'FSR',
    'friendly': 'FSR V1',
    'rpm_led_count': 10,
    'button_led_count': 10,
    'sw_version': 'RS21-D03-MC FW',
    'hw_version': 'RS21-D03-HW FW-C',
    'hw_sub': 'U-V04',
    'serial0': 'FSR10000000000',
    'serial1': 'FSR10000000001',
    # caps / dev_type not captured for FSR1 -> tolerant zero defaults. FSR1 has
    # NO detachable RGB display (the 0x42 push IS the screen), so no 0x20 caps
    # bit is correct in spirit. TODO: confirm exact bytes from usb-capture/fsr1/.
    'hw_id': bytes.fromhex('000000000000000000000000'),
    'emits_7c23': False,
    'proactive_session09': False,
    'session_layout': 'legacy',
}

PROFILE = DeviceProfile.from_legacy('fsr1', LEGACY)

# Group 0x42 = host->wheel display push (~28 Hz) — swallow it so it doesn't
# inflate the unhandled counter. Group 0x32 cmd 0x81 = dashboard-switch index
# write; the wheel echoes it as a 0xB2 ack (group 0x32 | 0x80), so route it
# through the generic settings-write echo.
PROFILE.blocks[0].absorb_groups = (0x42,)
PROFILE.blocks[0].echo_write_groups = (0x32,)
