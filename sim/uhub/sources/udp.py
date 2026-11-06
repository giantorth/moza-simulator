"""Network button source — the wire protocol the ESP32 firmware speaks
(firmware/esp32_wheel_buttons/). One UDP datagram = the sender's FULL current
state, so a lost packet is healed by the next one; senders transmit on every
change plus a heartbeat (firmware default 50 ms). A sender silent for
`timeout_ms` is dropped and all its buttons released — a Wi-Fi drop can't
leave a button stuck down.

Packet v1, little-endian, 36 + 2*axis_count bytes:
    off size field
     0   4   magic       b'MZBR'
     4   1   version     1
     5   1   flags       reserved, 0
     6   1   hat         0-7 = N, NE, E, SE, S, SW, W, NW; 8 = centred
     7   1   axis_count  0..8
     8   4   device_id   sender id (firmware: low 32 bits of the Wi-Fi MAC)
    12   4   session     random per sender boot; a change resets seq tracking
    16   4   seq         +1 per packet; older/duplicate packets are dropped
    20  16   buttons     128-bit bitmask, bit i = byte 20 + i//8, bit i%8
    36  2*n  axes        u16 0..65535, the sender's axes 0..n-1
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import struct
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from ..mapping import DeviceMapping
from ..state import HAT_CENTRED, SourceState

log = logging.getLogger('uhub.udp')

MAGIC = b'MZBR'
VERSION = 1
HEADER = struct.Struct('<4sBBBBIII16s')
assert HEADER.size == 36
DEFAULT_PORT = 34200
MAX_AXES = 8


@dataclass
class Packet:
    device_id: int
    session: int
    seq: int
    buttons: int
    hat: int
    axes: List[int]

    def pressed(self) -> List[int]:
        b, out, i = self.buttons, [], 0
        while b:
            if b & 1:
                out.append(i)
            b >>= 1
            i += 1
        return out


def encode(device_id: int, session: int, seq: int, buttons: int = 0,
           hat: int = HAT_CENTRED, axes: Optional[List[int]] = None) -> bytes:
    axes = list(axes or [])[:MAX_AXES]
    return (HEADER.pack(MAGIC, VERSION, 0, hat, len(axes), device_id & 0xFFFFFFFF,
                        session & 0xFFFFFFFF, seq & 0xFFFFFFFF,
                        (buttons & ((1 << 128) - 1)).to_bytes(16, 'little'))
            + struct.pack(f'<{len(axes)}H', *axes))


def decode(data: bytes) -> Optional[Packet]:
    if len(data) < HEADER.size:
        return None
    magic, ver, _flags, hat, n, dev, sess, seq, btn = HEADER.unpack_from(data)
    if magic != MAGIC or ver != VERSION or n > MAX_AXES or len(data) < HEADER.size + 2 * n:
        return None
    axes = list(struct.unpack_from(f'<{n}H', data, HEADER.size))
    return Packet(dev, sess, seq, int.from_bytes(btn, 'little'),
                  hat if hat <= 8 else HAT_CENTRED, axes)


@dataclass
class _Peer:
    session: int
    seq: int
    last_seen: float
    addr: str


class UdpSource(asyncio.DatagramProtocol):
    def __init__(self, sink: Callable[[str, SourceState], None],
                 sink_remove: Callable[[str], None], cfg: Optional[dict] = None):
        cfg = cfg or {}
        self.bind = cfg.get('bind', '0.0.0.0')
        self.port = int(cfg.get('port', DEFAULT_PORT))
        self.timeout = float(cfg.get('timeout_ms', 500)) / 1000.0
        allow = cfg.get('allow') or []
        self._allow = [ipaddress.ip_network(a, strict=False) for a in allow]
        devs = cfg.get('devices') or {}
        self._default_map = DeviceMapping.from_json(devs.get('*'))
        self._maps: Dict[int, DeviceMapping] = {
            int(k, 0): DeviceMapping.from_json(v) for k, v in devs.items() if k != '*'}
        self._sink = sink
        self._sink_remove = sink_remove
        self._peers: Dict[int, _Peer] = {}
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._reaper: Optional[asyncio.Task] = None
        self.stats = {'rx': 0, 'bad': 0, 'stale': 0, 'denied': 0}

    @staticmethod
    def source_id(device_id: int) -> str:
        return f'udp:{device_id:08x}'

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: self, local_addr=(self.bind, self.port))
        self.port = self._transport.get_extra_info('sockname')[1]
        self._reaper = asyncio.create_task(self._reap())
        log.info('UDP button source listening on %s:%d', self.bind, self.port)

    def close(self) -> None:
        if self._reaper:
            self._reaper.cancel()
        if self._transport:
            self._transport.close()

    def _allowed(self, ip: str) -> bool:
        if not self._allow:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._allow)

    def datagram_received(self, data: bytes, addr: Tuple) -> None:
        ip = addr[0]
        if not self._allowed(ip):
            self.stats['denied'] += 1
            return
        pkt = decode(data)
        if pkt is None:
            self.stats['bad'] += 1
            return
        now = time.monotonic()
        peer = self._peers.get(pkt.device_id)
        if peer is not None and peer.session == pkt.session:
            if not 0 < ((pkt.seq - peer.seq) & 0xFFFFFFFF) < 0x80000000:   # dup or older
                self.stats['stale'] += 1
                return
        if peer is None or peer.session != pkt.session:
            log.info('UDP sender %08x connected from %s (session %08x)',
                     pkt.device_id, ip, pkt.session)
        self._peers[pkt.device_id] = _Peer(pkt.session, pkt.seq, now, ip)
        self.stats['rx'] += 1
        m = self._maps.get(pkt.device_id, self._default_map)
        self._sink(self.source_id(pkt.device_id),
                   m.translate(pkt.pressed(), dict(enumerate(pkt.axes)), pkt.hat))

    async def _reap(self) -> None:
        while True:
            await asyncio.sleep(min(0.1, self.timeout / 2))
            now = time.monotonic()
            for dev, peer in list(self._peers.items()):
                if now - peer.last_seen > self.timeout:
                    del self._peers[dev]
                    log.info('UDP sender %08x timed out — releasing its inputs', dev)
                    self._sink_remove(self.source_id(dev))

    def peers(self) -> Dict[int, _Peer]:
        return dict(self._peers)
