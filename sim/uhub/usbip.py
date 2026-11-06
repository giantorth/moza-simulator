"""Userspace USB/IP server exporting one emulated USB device (asyncio, pure
Python, no kernel gadget support needed — runs on Windows and Linux).

Clients:
  Windows : usbip-win2   ->  usbip attach -r 127.0.0.1 -b 1-1
  Linux   : usbip tools  ->  sudo modprobe vhci-hcd
                             sudo usbip attach -r 127.0.0.1 -b 1-1

Protocol (USB/IP v1.1.1, all header fields big-endian):
  OP_REQ_DEVLIST / OP_REP_DEVLIST   device listing (`usbip list -r`)
  OP_REQ_IMPORT  / OP_REP_IMPORT    attach; the connection then carries URBs
  USBIP_CMD_SUBMIT / USBIP_RET_SUBMIT
  USBIP_CMD_UNLINK / USBIP_RET_UNLINK

The device model is `UsbDevice`: control requests on EP0 are answered
synchronously; non-control IN endpoints hold submitted URBs in a FIFO until the
device has data (`complete_in`), exactly like a real device NAKing until ready.
Isochronous transfers are not supported (the hub has none).
"""
from __future__ import annotations

import asyncio
import logging
import struct
from collections import deque
from dataclasses import dataclass
from typing import Callable, Deque, Dict, Optional, Tuple

log = logging.getLogger('uhub.usbip')

USBIP_VERSION = 0x0111
OP_REQ_DEVLIST = 0x8005
OP_REP_DEVLIST = 0x0005
OP_REQ_IMPORT = 0x8003
OP_REP_IMPORT = 0x0003

CMD_SUBMIT = 1
CMD_UNLINK = 2
RET_SUBMIT = 3
RET_UNLINK = 4

DIR_OUT = 0
DIR_IN = 1

SPEED_FULL = 2

EPIPE = 32          # stall
ECONNRESET = 104    # unlinked

STALL = object()    # sentinel a control handler returns to stall EP0


@dataclass
class Urb:
    seqnum: int
    devid: int
    direction: int
    ep: int
    length: int
    setup: bytes
    data: bytes
    # Echoed back in RET_SUBMIT like the Linux usbip_host stub does (clients
    # send 0 or -1/0xffffffff for non-isochronous transfers).
    npackets: int = 0


class UsbDevice:
    """Base device model. Subclasses implement `control()` and the per-endpoint
    hooks; the server owns URB queueing and the wire protocol."""

    busid = '1-1'
    busnum = 1
    devnum = 1
    speed = SPEED_FULL

    device_descriptor: bytes = b''
    config_descriptor: bytes = b''
    interface_classes: Tuple[Tuple[int, int, int], ...] = ()

    def __init__(self) -> None:
        self._conn: Optional['_Connection'] = None
        self.configured = False

    # ── hooks for subclasses ────────────────────────────────────────────
    def control(self, setup: bytes, data: bytes):
        """Handle a control transfer. Return bytes (IN data / empty OUT ack)
        or STALL."""
        return STALL

    def on_out(self, ep: int, data: bytes) -> None:
        """Bulk/interrupt OUT data from the host."""

    def on_in_ready(self, ep: int) -> None:
        """A new IN URB was queued on `ep` — device may complete it now."""

    def on_attach(self) -> None:
        pass

    def on_detach(self) -> None:
        pass

    # ── device -> host completion ───────────────────────────────────────
    @property
    def attached(self) -> bool:
        return self._conn is not None

    def pending_in(self, ep: int) -> int:
        return self._conn.pending_in(ep) if self._conn else 0

    def complete_in(self, ep: int, data: bytes) -> int:
        """Complete the oldest pending IN URB on `ep` with up to its buffer
        length of `data`. Returns bytes consumed (0 if nothing pending)."""
        if self._conn is None:
            return 0
        return self._conn.complete_in(ep, data)

    # ── standard descriptor helpers ─────────────────────────────────────
    def num_interfaces(self) -> int:
        return self.config_descriptor[4] if len(self.config_descriptor) > 4 else 0

    def config_value(self) -> int:
        return self.config_descriptor[5] if len(self.config_descriptor) > 5 else 1

    def device_struct(self) -> bytes:
        """usbip_usb_device (312 bytes)."""
        dd = self.device_descriptor
        path = f'/sys/devices/uhub/{self.busid}'.encode()
        return struct.pack(
            '>256s32sIII HHH BBBBBB',
            path, self.busid.encode(), self.busnum, self.devnum, self.speed,
            struct.unpack_from('<H', dd, 8)[0],     # idVendor
            struct.unpack_from('<H', dd, 10)[0],    # idProduct
            struct.unpack_from('<H', dd, 12)[0],    # bcdDevice
            dd[4], dd[5], dd[6],                    # class / subclass / protocol
            self.config_value() if self.configured else 0,
            dd[17],                                 # bNumConfigurations
            self.num_interfaces(),
        )


class _Connection:
    def __init__(self, device: UsbDevice, writer: asyncio.StreamWriter):
        self.device = device
        self.writer = writer
        self._in_queues: Dict[int, Deque[Urb]] = {}

    def pending_in(self, ep: int) -> int:
        return len(self._in_queues.get(ep, ()))

    def _send(self, data: bytes) -> None:
        if not self.writer.is_closing():
            self.writer.write(data)

    def ret_submit(self, urb: Urb, status: int, data: bytes = b'',
                   actual: Optional[int] = None) -> None:
        if actual is None:
            actual = len(data)
        hdr = struct.pack('>IIIII iiiii 8x', RET_SUBMIT, urb.seqnum, 0, 0, 0,
                          status, actual, 0, urb.npackets, 0)
        self._send(hdr + (data if urb.direction == DIR_IN else b''))

    def complete_in(self, ep: int, data: bytes) -> int:
        q = self._in_queues.get(ep)
        if not q:
            return 0
        urb = q.popleft()
        chunk = data[:urb.length]
        self.ret_submit(urb, 0, chunk)
        return len(chunk)

    def handle_submit(self, urb: Urb) -> None:
        epnum = urb.ep & 0x0F
        if epnum == 0:
            self._handle_control(urb)
            return
        if urb.direction == DIR_OUT:
            self.device.on_out(epnum, urb.data)
            self.ret_submit(urb, 0, actual=len(urb.data))
            return
        ep = 0x80 | epnum
        self._in_queues.setdefault(ep, deque()).append(urb)
        self.device.on_in_ready(ep)

    def _handle_control(self, urb: Urb) -> None:
        try:
            rsp = self.device.control(urb.setup, urb.data)
        except Exception:
            log.exception('control handler failed for setup %s', urb.setup.hex())
            rsp = STALL
        if rsp is STALL:
            log.debug('EP0 stall: setup=%s', urb.setup.hex())
            self.ret_submit(urb, -EPIPE)
            return
        if urb.direction == DIR_IN:
            wlength = struct.unpack_from('<H', urb.setup, 6)[0]
            data = bytes(rsp)[:min(wlength, urb.length)]
            self.ret_submit(urb, 0, data)
        else:
            self.ret_submit(urb, 0, actual=len(urb.data))

    def handle_unlink(self, seqnum: int, unlink_seq: int) -> None:
        status = 0
        for q in self._in_queues.values():
            for urb in q:
                if urb.seqnum == unlink_seq:
                    q.remove(urb)
                    status = -ECONNRESET
                    break
            if status:
                break
        self._send(struct.pack('>IIIII i 24x', RET_UNLINK, seqnum, 0, 0, 0, status))


class UsbIpServer:
    def __init__(self, device: UsbDevice, host: str = '127.0.0.1', port: int = 3240):
        self.device = device
        self.host = host
        self.port = port
        self._server: Optional[asyncio.base_events.Server] = None
        self._writers: set = set()

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._client, self.host, self.port)
        sock = self._server.sockets[0].getsockname()
        self.port = sock[1]
        log.info('USB/IP server listening on %s:%d (busid %s)', sock[0], sock[1],
                 self.device.busid)

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            # Server.wait_closed() (3.12+) waits for every client connection —
            # an attached host would block shutdown forever, so drop them first.
            for w in list(self._writers):
                w.close()
            try:
                await asyncio.wait_for(self._server.wait_closed(), 2.0)
            except asyncio.TimeoutError:
                log.warning('USB/IP server close timed out')

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info('peername')
        self._writers.add(writer)
        try:
            hdr = await reader.readexactly(8)
            version, code, _status = struct.unpack('>HHI', hdr)
            if code == OP_REQ_DEVLIST:
                writer.write(self._devlist_reply())
                await writer.drain()
            elif code == OP_REQ_IMPORT:
                busid = (await reader.readexactly(32)).split(b'\0', 1)[0].decode()
                await self._import(busid, reader, writer, peer)
            else:
                log.warning('%s: unknown op 0x%04x (version 0x%04x)', peer, code, version)
        except asyncio.IncompleteReadError:
            pass
        except (ConnectionError, OSError) as e:
            log.info('%s: connection error: %s', peer, e)
        finally:
            self._writers.discard(writer)
            writer.close()

    def _devlist_reply(self) -> bytes:
        dev = self.device
        out = struct.pack('>HHII', USBIP_VERSION, OP_REP_DEVLIST, 0, 1)
        out += dev.device_struct()
        for cls, sub, proto in dev.interface_classes:
            out += struct.pack('>BBBx', cls, sub, proto)
        return out

    async def _import(self, busid: str, reader, writer, peer) -> None:
        dev = self.device
        if busid != dev.busid or dev._conn is not None:
            reason = 'busy' if dev._conn is not None else f'unknown busid {busid!r}'
            log.warning('%s: import refused (%s)', peer, reason)
            writer.write(struct.pack('>HHI', USBIP_VERSION, OP_REP_IMPORT, 1))
            await writer.drain()
            return
        writer.write(struct.pack('>HHI', USBIP_VERSION, OP_REP_IMPORT, 0) + dev.device_struct())
        await writer.drain()
        conn = _Connection(dev, writer)
        dev._conn = conn
        log.info('%s: attached %s', peer, busid)
        dev.on_attach()
        try:
            while True:
                base = await reader.readexactly(48)
                command, seqnum, devid, direction, ep = struct.unpack_from('>IIIII', base, 0)
                if command == CMD_SUBMIT:
                    (_flags, length, _start, npackets, _interval) = struct.unpack_from('>Iiiii', base, 20)
                    setup = base[40:48]
                    data = b''
                    if direction == DIR_OUT and length > 0:
                        data = await reader.readexactly(length)
                    urb = Urb(seqnum, devid, direction, ep, max(0, length), setup, data, npackets)
                    if npackets > 0:                  # isochronous: unsupported
                        await reader.readexactly(16 * npackets)
                        conn.ret_submit(urb, -EPIPE)
                        continue
                    conn.handle_submit(urb)
                elif command == CMD_UNLINK:
                    unlink_seq = struct.unpack_from('>I', base, 20)[0]
                    conn.handle_unlink(seqnum, unlink_seq)
                else:
                    log.warning('%s: unknown URB command %d — dropping connection', peer, command)
                    break
                await writer.drain()
        finally:
            dev._conn = None
            dev.configured = False
            log.info('%s: detached %s', peer, busid)
            dev.on_detach()


# ── Standard request helpers usable by device subclasses ────────────────────
def parse_setup(setup: bytes) -> Tuple[int, int, int, int, int]:
    """(bmRequestType, bRequest, wValue, wIndex, wLength)."""
    return struct.unpack('<BBHHH', setup)


CallbackIn = Callable[[bytes], None]
