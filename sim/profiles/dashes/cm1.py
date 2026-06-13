"""CM1 Racing Dash profile — base-bridged dash, device byte 0x14.

Driven by sim/engines/standalone.py::Cm1Simulator. The CM1 does NOT speak
tier-def (group 0x35 keyed float32 stream + group 0x0E register bank instead);
see docs/protocol/devices/dash-0x14.md § "CM1 Racing Dash".

Detection is by tier-def ABSENCE (the plugin's discriminator), so the dash
carries no identity cascade — answers_identity is False, matching the real device
which the plugin never name-probes. It ACKs the keepalive, absorbs the 0x35/0x36
stream, echoes the 0x32 cmd 0x81 switch as a 0xB2 ack, and answers the 0x0E param
reads (values in Cm1Simulator.PARAM_TABLE).

A real CM1 rides the wheelbase bus at 0x14 (no own USB). The gadget here uses the
wheelbase PID so the plugin enumerates it; the standalone engine is for isolated
testing of the plugin's CM1 driver.
"""
from ..schema import DeviceProfile, DeviceBlock, GadgetSpec, DEV_DASH, PID_WHEELBASE_R12

PROFILE = DeviceProfile(
    key="cm1",
    friendly="CM1 Racing Dash",
    gadgets=[GadgetSpec(pid=PID_WHEELBASE_R12, product_str="MOZA CM1 Racing Dash",
                        engine="cm1")],
    blocks=[
        DeviceBlock(
            role="dash-cm1",
            address=DEV_DASH,            # 0x14
            ident={},                    # detection is by tier-def absence, not name
            present=True,                # ACK heartbeat (0x00) + keepalive (0x43)
            answers_identity=False,
            echo_write_groups=(0x32,),   # dashboard switch cmd 0x81 -> 0xB2 ack
            absorb_groups=(0x35, 0x36),  # keyed value stream -> swallow
        ),
    ],
)
