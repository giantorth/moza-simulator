"""Handbrake profile (device byte 0x1B, PID 0x001F HBP).

Identity from docs/protocol/devices/handbrake-0x1B.md (live probe 2026-06-12,
R5 base): the handbrake is a separate MCU at 0x1B (its own UID + sw-version).
Only name/hw/sw/dev_type were captured; caps/hw_sub/serials/hw_id are unknown and
left out — _build_device_identity zero-defaults them rather than fabricating
values. Driven by sim/engines/standalone.py::StandaloneSimulator: identity
cascade + settings echo (group 0x5B read / 0x5C write, output 0x5D, calibration
0x5E per the doc).
"""
from ..schema import DeviceProfile, DeviceBlock, GadgetSpec, DEV_HANDBRAKE

PID_HANDBRAKE_HBP = 0x001F

PROFILE = DeviceProfile(
    key="handbrake",
    friendly="Handbrake (HBP)",
    gadgets=[GadgetSpec(pid=PID_HANDBRAKE_HBP, product_str="MOZA HBP Handbrake",
                        engine="standalone")],
    blocks=[
        DeviceBlock(
            role="handbrake",
            address=DEV_HANDBRAKE,
            ident={
                "name": "HB # S01",
                "hw_version": "RS21-S01-HW HB-C",
                "sw_version": "RS21-S01-MC HB",
                "dev_type": bytes([0x01, 0x02, 0x03, 0x01]),
                # caps / hw_sub / serials / hw_id not captured — TODO if a real
                # handbrake bundle becomes available.
            },
            present=True,
            answers_identity=True,
            echo_write_groups=(0x5C,),   # settings write; reads ride 0x5B
        ),
    ],
)
