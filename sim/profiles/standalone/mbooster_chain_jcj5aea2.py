"""mBooster chain in the state bundle JCJ5AEA2 found it: pedal roles swapped.

Same lane as mbooster_chain, seeded from that bundle's AZOM-era traffic. The
chained unit's pedal-role map 0x21/0x22/0x23 reads 1/2/3 (it did from the
start of that session; what set it is unknown), so Pit House assigns it the
Brake, the same role as the host — two brakes, no throttle — and a throttle
travel calibration sent to it fails (the throttle role maps to its channel T,
which has no motor). It also carries that unit's active error 50 (Brake Encoder Abnormal
Reset), which AZOM never acked. No parameter table (AZOM never reads it).
"""
from ..schema import DeviceProfile, DeviceBlock, GadgetSpec, PID_MBOOSTER

PROFILE = DeviceProfile(
    key="mbooster_chain_jcj5aea2",
    friendly="mBooster chain, roles swapped (JCJ5AEA2)",
    gadgets=[GadgetSpec(pid=PID_MBOOSTER, product_str="MOZA mBooster",
                        engine="mbooster")],
    blocks=[
        DeviceBlock(
            role="mbooster",
            address=0x12,
            present=True,
            answers_identity=False,
            extras={
                "seed": "mbooster_chain_jcj5aea2.json",
                "host_dev": 0x12,
                "units": [{"dev": 0x12, "role": 1}, {"dev": 0x1D, "role": 0}],
                "passive": [2],
                "errors": {0x1D: [50]},
            },
        ),
    ],
)
