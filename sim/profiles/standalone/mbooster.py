"""mBooster vibration-pedal profile (PID 0x0008, device byte 0x12).

Wire reference: docs/protocol/devices/mbooster.md. Driven by
sim/engines/standalone.py::MBoosterSimulator, NOT the wheel engine (no wheelbase
sessions). The plugin detects mBooster purely by USB PID (registry walk) and
sends no identity cascade — so the block carries NO identity (answers_identity
False): inventing identity strings would be fabricating hardware data we've never
captured. The simulated behaviour is: ACK the ~500 ms keepalive, absorb the
~50 Hz motor writes (group 0x24 cmd 0xb1), and echo the experimental settings
surface (group 0x23 read / 0x24 write).
"""
from ..schema import DeviceProfile, DeviceBlock, GadgetSpec, PID_MBOOSTER

# mBooster's internal bus device byte is 0x12 ("DeviceMotor" in the plugin) on
# its own CDC port — same numeric value as the wheelbase hub, but a different
# physical device on a separate gadget, so there is no collision.
DEV_MBOOSTER = 0x12

PROFILE = DeviceProfile(
    key="mbooster",
    friendly="mBooster Pedal",
    gadgets=[GadgetSpec(pid=PID_MBOOSTER, product_str="MOZA mBooster",
                        engine="mbooster")],
    blocks=[
        DeviceBlock(
            role="mbooster",
            address=DEV_MBOOSTER,
            ident={},                    # no captured identity — detection is by PID
            present=True,                # ACK keepalive (group 0x00) presence
            answers_identity=False,
            # Settings write group 0x24 (cmds 1-29). The motor cmd 0xb1 also rides
            # 0x24 but is intercepted as absorb by MBoosterSimulator before the
            # generic settings echo. Reads ride 0x23 (echo_write_group - 1).
            echo_write_groups=(0x24,),
        ),
    ],
)
