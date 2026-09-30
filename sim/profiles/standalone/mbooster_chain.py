"""mBooster lane with a chained second unit (PID 0x0008), as Pit House sees it.

Host unit (0x12) drives the Brake, a chained unit (0x1d) drives the Throttle,
a passive clutch is wired to the host. Both units' identity, registers,
parameter table and firmware text come from Pit House's own 2026-09-08
captures of that rig ("Brake pedal travel calibration", "Brake motor
calibration"; serials/UIDs synthetic). The chained unit's slot registers
0x21/0x22/0x23 read 2/1/3 there, and Pit House assigns it the Throttle from
them. 0x1e is on the bus map but never answers, as on the real lane.
"""
from ..schema import DeviceProfile, DeviceBlock, GadgetSpec, PID_MBOOSTER

DEV_HOST = 0x12
DEV_CHAINED = 0x1D

PROFILE = DeviceProfile(
    key="mbooster_chain",
    friendly="mBooster chain (brake + throttle)",
    gadgets=[GadgetSpec(pid=PID_MBOOSTER, product_str="MOZA mBooster",
                        engine="mbooster")],
    blocks=[
        DeviceBlock(
            role="mbooster",
            address=DEV_HOST,
            present=True,
            answers_identity=False,
            extras={
                "seed": "mbooster_chain_pithouse_0908.json",
                "host_dev": DEV_HOST,
                "units": [{"dev": DEV_HOST, "role": 1},        # Brake on the host
                          {"dev": DEV_CHAINED, "role": 0}],    # Throttle chained
                "passive": [2],                                # clutch
            },
        ),
    ],
)
