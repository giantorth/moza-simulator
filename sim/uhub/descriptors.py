"""USB descriptors for the emulated MOZA Universal Hub (VID 0x346E PID 0x0020).

Provenance (usb-capture/ksp/mozahubstartup.pcapng, frames 38/40):
  - DEVICE_DESCRIPTOR and the configuration descriptor are byte-exact, except
    the two HID descriptors' wDescriptorLength, which are patched to the
    lengths of the report descriptors authored below.
  - The real report descriptors (1315 B on interface 2, 37 B on interface 3)
    were NOT in the capture (USBPcap started after enumeration). The joystick
    descriptor here is authored to reproduce the captured 42-byte report-ID-1
    input report layout; interface 3's is a vendor-defined placeholder.
  - String descriptors (indices 1..6) were NOT captured. STRINGS below are
    unverified placeholders.

Configuration layout (full-speed, self-powered, 100 mA):
  IAD  -> interfaces 0-1 (CDC ACM)
  if0  CDC comm   EP 0x81 interrupt IN  (8 B, notifications — never sent)
  if1  CDC data   EP 0x02 bulk OUT / EP 0x82 bulk IN (64 B) — the MOZA bus
  if2  HID        EP 0x03 interrupt OUT / EP 0x83 interrupt IN (64 B) — joystick
  if3  HID        EP 0x84 interrupt IN (64 B) — purpose unknown, idle
"""
from __future__ import annotations

import struct

VID = 0x346E
PID = 0x0020

EP_CDC_NOTIFY = 0x81
EP_CDC_OUT = 0x02
EP_CDC_IN = 0x82
EP_HID_OUT = 0x03
EP_HID_IN = 0x83
EP_HID2_IN = 0x84

IF_CDC_COMM = 0
IF_CDC_DATA = 1
IF_HID = 2
IF_HID2 = 3

DEVICE_DESCRIPTOR = bytes.fromhex('12010002ef0201406e342000000101020301')

# HID report descriptor, interface 2 — report ID 1, 42 bytes on the wire:
#   [0]      report id 0x01
#   [1..16]  8 x u16 LE axes  (X Y Z Rx Ry Rz Slider Dial), 0..65535
#   [17]     hat (low nibble, 0-7 = N..NW, 8 = centred/null) + 4 pad bits
#   [18..33] 128 buttons, bit i of byte 18 + i//8
#   [34..41] 8 constant pad bytes (real hub reports carry 24 button-region
#            bytes; only 18..22 ever change in the capture)
HID_REPORT_DESCRIPTOR = bytes([
    0x05, 0x01,              # Usage Page (Generic Desktop)
    0x09, 0x04,              # Usage (Joystick)
    0xA1, 0x01,              # Collection (Application)
    0x85, 0x01,              #   Report ID (1)
    0x05, 0x01,              #   Usage Page (Generic Desktop)
    0x09, 0x30, 0x09, 0x31, 0x09, 0x32,          # X Y Z
    0x09, 0x33, 0x09, 0x34, 0x09, 0x35,          # Rx Ry Rz
    0x09, 0x36, 0x09, 0x37,                      # Slider Dial
    0x15, 0x00,              #   Logical Minimum (0)
    0x27, 0xFF, 0xFF, 0x00, 0x00,  # Logical Maximum (65535)
    0x75, 0x10,              #   Report Size (16)
    0x95, 0x08,              #   Report Count (8)
    0x81, 0x02,              #   Input (Data,Var,Abs)
    0x09, 0x39,              #   Usage (Hat switch)
    0x15, 0x00,              #   Logical Minimum (0)
    0x25, 0x07,              #   Logical Maximum (7)
    0x35, 0x00,              #   Physical Minimum (0)
    0x46, 0x3B, 0x01,        #   Physical Maximum (315)
    0x65, 0x14,              #   Unit (Eng Rot: Degrees)
    0x75, 0x04,              #   Report Size (4)
    0x95, 0x01,              #   Report Count (1)
    0x81, 0x42,              #   Input (Data,Var,Abs,Null)
    0x65, 0x00,              #   Unit (None)
    0x45, 0x00,              #   Physical Maximum (0)
    0x75, 0x04, 0x95, 0x01,  #   4-bit pad
    0x81, 0x03,              #   Input (Const)
    0x05, 0x09,              #   Usage Page (Button)
    0x19, 0x01,              #   Usage Minimum (1)
    0x29, 0x80,              #   Usage Maximum (128)
    0x15, 0x00,              #   Logical Minimum (0)
    0x25, 0x01,              #   Logical Maximum (1)
    0x75, 0x01,              #   Report Size (1)
    0x95, 0x80,              #   Report Count (128)
    0x81, 0x02,              #   Input (Data,Var,Abs)
    0x75, 0x08, 0x95, 0x08,  #   8 bytes pad
    0x81, 0x03,              #   Input (Const)
    0xC0,                    # End Collection
])

# Interface 3 — placeholder vendor-defined collection (real 37 B descriptor
# unknown; no traffic on EP 0x84 in the capture). Never produces a report.
HID2_REPORT_DESCRIPTOR = bytes([
    0x06, 0x00, 0xFF,        # Usage Page (Vendor 0xFF00)
    0x09, 0x01,              # Usage (1)
    0xA1, 0x01,              # Collection (Application)
    0x15, 0x00,              #   Logical Minimum (0)
    0x26, 0xFF, 0x00,        #   Logical Maximum (255)
    0x75, 0x08,              #   Report Size (8)
    0x95, 0x08,              #   Report Count (8)
    0x09, 0x01,              #   Usage (1)
    0x81, 0x02,              #   Input (Data,Var,Abs)
    0xC0,                    # End Collection
])

_CONFIG_TEMPLATE = bytes.fromhex(
    '090284000401 00c032'            # config: 132 B, 4 ifaces, self-powered, 100 mA
    '080b000202020000'               # IAD: if0-1, CDC/ACM
    '090400000102020004'             # if0 CDC comm, iInterface 4
    '0524002001' '0524010001' '04240202' '0524060001'
    '0705810308 0001'                # EP 0x81 int IN 8 B
    '09040100020a000000'             # if1 CDC data
    '0705020240 0000' '0705820240 0000'
    '090402000203000005'             # if2 HID, iInterface 5
    '0921110100012223 05'            # HID desc (len patched)
    '0705030340 0001' '0705830340 0001'
    '090403000103000006'             # if3 HID, iInterface 6
    '0921110100012225 00'            # HID desc (len patched)
    '0705840340 0001'
    .replace(' ', ''))
assert len(_CONFIG_TEMPLATE) == 132

# Offsets of the HID descriptors (bDescriptorType 0x21 at +1) in the template.
_HID_DESC_OFFSETS = [i for i in range(len(_CONFIG_TEMPLATE) - 1)
                     if _CONFIG_TEMPLATE[i] == 0x09 and _CONFIG_TEMPLATE[i + 1] == 0x21]
assert len(_HID_DESC_OFFSETS) == 2


def _patch_hid_lengths(cfg: bytes) -> bytes:
    out = bytearray(cfg)
    for off, desc in zip(_HID_DESC_OFFSETS, (HID_REPORT_DESCRIPTOR, HID2_REPORT_DESCRIPTOR)):
        struct.pack_into('<H', out, off + 7, len(desc))
    return bytes(out)


CONFIG_DESCRIPTOR = _patch_hid_lengths(_CONFIG_TEMPLATE)

# HID class descriptors per interface, as returned for GET_DESCRIPTOR(0x21).
HID_CLASS_DESCRIPTORS = {
    IF_HID: CONFIG_DESCRIPTOR[_HID_DESC_OFFSETS[0]:_HID_DESC_OFFSETS[0] + 9],
    IF_HID2: CONFIG_DESCRIPTOR[_HID_DESC_OFFSETS[1]:_HID_DESC_OFFSETS[1] + 9],
}
HID_REPORT_DESCRIPTORS = {
    IF_HID: HID_REPORT_DESCRIPTOR,
    IF_HID2: HID2_REPORT_DESCRIPTOR,
}

# UNVERIFIED placeholders — the real hub's strings were not captured.
STRINGS = {
    1: 'MOZA Racing',
    2: 'MOZA Universal Hub',
    3: 'UHUB000000000000',
    4: 'MOZA Universal Hub CDC',
    5: 'MOZA Universal Hub HID',
    6: 'MOZA Universal Hub HID2',
}


def string_descriptor(index: int) -> bytes | None:
    if index == 0:
        return bytes([4, 3, 0x09, 0x04])           # LANGID en-US
    s = STRINGS.get(index)
    if s is None:
        return None
    body = s.encode('utf-16-le')
    return bytes([2 + len(body), 3]) + body


# (bInterfaceClass, bInterfaceSubClass, bInterfaceProtocol) per interface — for
# the USB/IP device-list reply.
INTERFACE_CLASSES = [(0x02, 0x02, 0x00), (0x0A, 0x00, 0x00),
                     (0x03, 0x00, 0x00), (0x03, 0x00, 0x00)]
