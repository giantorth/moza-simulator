"""MOZA Farming Control System profile (PID 0x0030, Pit House name "S14").

Own USB device: CDC ACM (MOZA bus, root device 0x12) + a HID joystick interface
(29-byte report, 6 axes + 128 buttons). Identity, settings protocol (group
0x4E) and HID layout from usb-capture/fcs/ (Pit House 1.4.2.7 beta, fw
1.2.0.10); reference: docs/protocol/devices/fcs.md in moza-simhub-plugin.

The MCU UID (group 0x06), the matching USB serial string and the group-0x10
serial halves are synthetic placeholders — the captured values belong to a
real unit. Driven by sim/engines/fcs.py::FcsSimulator.
"""
from ..schema import DeviceProfile, DeviceBlock, GadgetSpec, DEV_HUB

PID_FCS = 0x0030

# 12-byte MCU UID; the real device's USB serial string is this as upper hex.
_HW_ID = bytes.fromhex("464353494d000000000000a1")

# HID report descriptor, byte-exact from the GET_DESCRIPTOR(Report) reply in
# usb-capture/fcs/pcap/fcs attempt 2.pcapng: joystick, report ID 1, six u16
# axes X Y Rx Ry Rz Z (0..65535), 128 buttons.
HID_REPORT_DESCRIPTOR = bytes.fromhex(
    "05010904a10185010501093009310933093409350932150027ffff00007510"
    "9506810205091901298015002501958075018102c0")
HID_REPORT_LEN = 29

PROFILE = DeviceProfile(
    key="fcs",
    friendly="Farming Control System",
    gadgets=[GadgetSpec(pid=PID_FCS,
                        product_str="MOZA Farming Control System",
                        manufacturer_str="Gudsen",
                        serial_str=_HW_ID.hex().upper(),
                        functions=("acm", "hid"),
                        hid_report_desc=HID_REPORT_DESCRIPTOR,
                        hid_report_len=HID_REPORT_LEN,
                        engine="fcs")],
    blocks=[
        DeviceBlock(
            role="fcs",
            address=DEV_HUB,              # 0x12, replies from 0x21
            ident={
                "name": "FCS # S14",
                "hw_version": "RS21-S14-HW TP-C",
                "hw_sub": "U-V10",
                "sw_version": "RS21-S14-MC FCS",
                "serial0": "FCSSIM0000000000",
                "serial1": "FCSSIM0000000001",
                "hw_id": _HW_ID,
                "caps": bytes([0x01, 0x02, 0x00, 0x04]),
                "dev_type": bytes([0x01, 0x02, 0x0A, 0x00]),   # fw 1.2.0.10
                "identity_09": bytes([0x00, 0x0B]),
            },
            present=True,
            answers_identity=True,
            extras={"firmware_log": True},
        ),
    ],
)
