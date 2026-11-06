"""The emulated Universal Hub as a USB/IP `UsbDevice`.

  - EP0: standard requests + CDC ACM (line coding / control line state) + HID
    class requests (SET_IDLE, GET_REPORT, ...).
  - CDC data (EP 0x02 OUT / EP 0x82 IN): raw MOZA-bus bytes, relayed to and
    from the wheel_sim engine through `cdc_out` / `cdc_from_engine`.
  - HID (EP 0x83 IN): the merged KS Pro joystick report; an IN URB completes
    immediately on first poll and afterwards only when the report changes
    (idle rate 0 semantics). EP 0x03 OUT is accepted and ignored.
  - EP 0x81 (CDC notify) and EP 0x84 (HID2) never complete — like a device
    with nothing to say.
"""
from __future__ import annotations

import logging
import struct
import time
from typing import Callable, Optional

from . import descriptors as D
from .usbip import STALL, UsbDevice, parse_setup

log = logging.getLogger('uhub.device')

# bmRequestType values
_STD_DEV_IN, _STD_DEV_OUT = 0x80, 0x00
_STD_IF_IN, _STD_IF_OUT = 0x81, 0x01
_STD_EP_IN, _STD_EP_OUT = 0x82, 0x02
_CLASS_IF_OUT, _CLASS_IF_IN = 0x21, 0xA1

CDC_IN_BUFFER_CAP = 256 * 1024
# DTR must have been low at least this long for a rising edge to count as "an
# app (re)opened the COM port". Apps toggle DTR within milliseconds while
# opening (SimHub under Wine: 1,1,0,1 inside one second), which must not count.
PORT_REOPEN_MIN_LOW_S = 0.5


class UhubDevice(UsbDevice):
    busid = '1-1'
    device_descriptor = D.DEVICE_DESCRIPTOR
    config_descriptor = D.CONFIG_DESCRIPTOR
    interface_classes = tuple(D.INTERFACE_CLASSES)

    def __init__(self, initial_report: bytes,
                 cdc_out: Optional[Callable[[bytes], None]] = None,
                 on_attach: Optional[Callable[[], None]] = None,
                 on_detach: Optional[Callable[[], None]] = None,
                 on_port_reopen: Optional[Callable[[], None]] = None):
        super().__init__()
        self._report = initial_report
        self._report_sent: Optional[bytes] = None
        self._cdc_out = cdc_out
        self._attach_cb = on_attach
        self._detach_cb = on_detach
        self._reopen_cb = on_port_reopen
        self._dtr_low_since: Optional[float] = None
        self._cdc_in = bytearray()
        self._cdc_dropped = 0
        self.line_coding = struct.pack('<IBBB', 115200, 0, 0, 8)
        self.dtr = False
        self.stats = {'cdc_out_bytes': 0, 'cdc_in_bytes': 0, 'hid_reports': 0}

    # ── attach lifecycle ────────────────────────────────────────────────
    def on_attach(self) -> None:
        self._cdc_in.clear()
        self._report_sent = None
        self.dtr = False
        # Port is closed at attach: the first open that comes later than the
        # blip threshold re-plugs the wheel too, so an app that opens the port
        # minutes after attach still sees a freshly announced wheel.
        self._dtr_low_since = time.monotonic()
        if self._attach_cb:
            self._attach_cb()

    def on_detach(self) -> None:
        self._cdc_in.clear()
        if self._detach_cb:
            self._detach_cb()

    # ── HID ─────────────────────────────────────────────────────────────
    def set_report(self, report: bytes) -> None:
        self._report = report
        self._pump_hid()

    def _pump_hid(self) -> None:
        if self._report != self._report_sent and self.pending_in(D.EP_HID_IN):
            if self.complete_in(D.EP_HID_IN, self._report):
                self._report_sent = self._report
                self.stats['hid_reports'] += 1

    # ── CDC ─────────────────────────────────────────────────────────────
    def cdc_from_engine(self, data: bytes) -> None:
        """Bytes the wheel_sim engine wrote — queue for the host's bulk IN."""
        if not self.attached:
            return
        self._cdc_in += data
        overflow = len(self._cdc_in) - CDC_IN_BUFFER_CAP
        if overflow > 0:
            del self._cdc_in[:overflow]
            self._cdc_dropped += overflow
            log.warning('CDC IN buffer full — dropped %d bytes (host not reading)', overflow)
        self._pump_cdc()

    def _pump_cdc(self) -> None:
        while self._cdc_in and self.pending_in(D.EP_CDC_IN):
            n = self.complete_in(D.EP_CDC_IN, bytes(self._cdc_in))
            if n <= 0:
                break
            del self._cdc_in[:n]
            self.stats['cdc_in_bytes'] += n

    def _set_dtr(self, dtr: bool, now: Optional[float] = None) -> None:
        now = time.monotonic() if now is None else now
        if not dtr:
            if self.dtr or self._dtr_low_since is None:
                self._dtr_low_since = now
        elif not self.dtr and self._dtr_low_since is not None:
            low_for = now - self._dtr_low_since
            self._dtr_low_since = None
            if low_for >= PORT_REOPEN_MIN_LOW_S:
                log.info('COM port re-opened (DTR low %.1f s) — re-plugging the wheel', low_for)
                self._cdc_in.clear()
                if self._reopen_cb:
                    self._reopen_cb()
        self.dtr = dtr

    # ── USB/IP hooks ────────────────────────────────────────────────────
    def on_in_ready(self, ep: int) -> None:
        if ep == D.EP_CDC_IN:
            self._pump_cdc()
        elif ep == D.EP_HID_IN:
            self._pump_hid()
        # EP 0x81 / 0x84: stay pending.

    def on_out(self, ep: int, data: bytes) -> None:
        if ep == (D.EP_CDC_OUT & 0x0F):
            self.stats['cdc_out_bytes'] += len(data)
            if self._cdc_out:
                self._cdc_out(data)
        elif ep == (D.EP_HID_OUT & 0x0F):
            log.debug('HID OUT (ignored): %s', data.hex())

    def control(self, setup: bytes, data: bytes):
        rt, req, wvalue, windex, _wlength = parse_setup(setup)
        dtype, dindex = wvalue >> 8, wvalue & 0xFF

        if rt == _STD_DEV_IN:
            if req == 0x06:                                  # GET_DESCRIPTOR
                if dtype == 0x01:
                    return self.device_descriptor
                if dtype == 0x02:
                    return self.config_descriptor
                if dtype == 0x03:
                    s = D.string_descriptor(dindex)
                    return STALL if s is None else s
                return STALL                                 # qualifier/BOS: FS-only device
            if req == 0x00:                                  # GET_STATUS
                return b'\x01\x00'                           # self-powered
            if req == 0x08:                                  # GET_CONFIGURATION
                return bytes([self.config_value() if self.configured else 0])
            return STALL
        if rt == _STD_DEV_OUT:
            if req == 0x09:                                  # SET_CONFIGURATION
                self.configured = wvalue != 0
                return b''
            if req in (0x01, 0x03, 0x05):                    # CLEAR/SET_FEATURE, SET_ADDRESS
                return b''
            return STALL
        if rt == _STD_IF_IN:
            if req == 0x06:                                  # GET_DESCRIPTOR (class)
                if dtype == 0x21 and windex in D.HID_CLASS_DESCRIPTORS:
                    return D.HID_CLASS_DESCRIPTORS[windex]
                if dtype == 0x22 and windex in D.HID_REPORT_DESCRIPTORS:
                    return D.HID_REPORT_DESCRIPTORS[windex]
                return STALL
            if req == 0x00:
                return b'\x00\x00'
            if req == 0x0A:                                  # GET_INTERFACE
                return b'\x00'
            return STALL
        if rt == _STD_IF_OUT:
            return b'' if req in (0x0B, 0x01, 0x03) else STALL   # SET_INTERFACE, features
        if rt == _STD_EP_IN and req == 0x00:
            return b'\x00\x00'
        if rt == _STD_EP_OUT and req in (0x01, 0x03):            # CLEAR/SET_FEATURE (halt)
            return b''

        iface = windex & 0xFF
        if iface == D.IF_CDC_COMM:
            if rt == _CLASS_IF_OUT:
                if req == 0x20 and len(data) >= 7:           # SET_LINE_CODING
                    self.line_coding = bytes(data[:7])
                    return b''
                if req == 0x22:                              # SET_CONTROL_LINE_STATE
                    self._set_dtr(bool(wvalue & 1))
                    log.info('CDC control line state: DTR=%d RTS=%d', wvalue & 1, (wvalue >> 1) & 1)
                    return b''
                if req == 0x23:                              # SEND_BREAK
                    return b''
            if rt == _CLASS_IF_IN and req == 0x21:           # GET_LINE_CODING
                return self.line_coding
            return STALL
        if iface in (D.IF_HID, D.IF_HID2):
            if rt == _CLASS_IF_OUT and req in (0x09, 0x0A, 0x0B):  # SET_REPORT/IDLE/PROTOCOL
                return b''
            if rt == _CLASS_IF_IN:
                if req == 0x01:                              # GET_REPORT
                    if iface == D.IF_HID and dindex in (0, 1):
                        return self._report
                    return bytes(8)
                if req == 0x02:                              # GET_IDLE
                    return b'\x00'
                if req == 0x03:                              # GET_PROTOCOL
                    return b'\x01'
            return STALL
        return STALL
