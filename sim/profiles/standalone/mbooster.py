"""mBooster pedal lane, single unit (PID 0x0008, host device byte 0x12).

Wire reference: the AZOM plugin's docs/protocol/devices/mbooster.md. Driven by
sim/engines/mbooster.py::MBoosterSimulator, NOT the wheel engine (no wheelbase
sessions). Everything the unit answers — identity, register values,
parameter table, firmware heartbeat — comes from a seed built from real
traffic (tools/mbooster_seed_from_bundle.py; serials and MCU UIDs synthetic).

Topology: one motor unit with its pedal as the Brake, passive throttle and
clutch wired to it — the common one-mBooster setup (bundles 6SWSMJX0,
EAQZ3AH9). The unit's data is the host unit of Pit House's 2026-09-08
captures (seed mbooster_chain_pithouse_0908.json).
"""
from ..schema import DeviceProfile, DeviceBlock, GadgetSpec, PID_MBOOSTER

# mBooster's internal bus device byte is 0x12 on its own CDC port — same
# numeric value as the wheelbase hub, but a different physical device on a
# separate gadget, so there is no collision.
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
            present=True,
            answers_identity=False,      # the engine answers identity from the seed
            extras={
                "seed": "mbooster_chain_pithouse_0908.json",
                "host_dev": DEV_MBOOSTER,
                "units": [{"dev": DEV_MBOOSTER, "role": 1}],   # motor pedal = Brake
                "passive": [0, 2],                              # throttle, clutch
            },
        ),
    ],
)
