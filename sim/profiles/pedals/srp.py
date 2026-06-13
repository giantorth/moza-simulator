"""Standalone SRP pedal profile (device byte 0x19, PID 0x0003).

Identity captured byte-exact from usb-capture/ksp/putOnWheelAndOpenPitHouse.pcapng
(sim/replay/kspro_pedal_19.json) — same SRP pedals, there bus-attached behind the
KS Pro base. Driven by sim/engines/standalone.py::StandaloneSimulator: identity
cascade + settings (group 0x23 read / 0x24 write) + calibration (0x26) absorb.
Live axis positions come from HID, not serial, so group 0x25 output reads are
deliberately left unanswered.

OPEN QUESTION (flagged in the plan): when a pedal set is standalone on its own
USB port (not bus-attached behind a base/hub), it may answer as root device 0x12
rather than 0x19. KS Pro data is bus-attached (0x19) only. Shipped at 0x19; flip
DeviceBlock.address to 0x12 once a standalone-pedal capture confirms.
"""
from ..schema import DeviceProfile, DeviceBlock, GadgetSpec, DEV_PEDAL, PID_PEDALS_SRP

PROFILE = DeviceProfile(
    key="srp",
    friendly="SRP Pedals",
    gadgets=[GadgetSpec(pid=PID_PEDALS_SRP, product_str="MOZA SRP Pedals",
                        engine="standalone")],
    blocks=[
        DeviceBlock(
            role="pedal",
            address=DEV_PEDAL,
            ident={
                "name": "SRP",
                "hw_version": "RS21-D01-HW PM-C",
                "hw_sub": "U-V11",
                "sw_version": "RS21-D01-MC PB",
                "serial0": "SRPPEDAL00000000",
                "serial1": "SRPPEDAL00000001",
                "hw_id": bytes(12),
                "caps": bytes([0x01, 0x02, 0x18, 0x00]),
                "dev_type": bytes([0x01, 0x02, 0x02, 0x05]),
                "identity_09": bytes([0x00, 0x04]),
            },
            present=True,
            answers_identity=True,
            echo_write_groups=(0x24,),   # settings write; reads ride 0x23
            absorb_groups=(0x26,),       # calibration start/stop — swallow
        ),
    ],
)
