"""Tests for the Universal Hub bridge (sim/uhub, sim/hub_bridge.py).

    .venv/bin/python -m unittest tests.test_uhub -v
"""
from __future__ import annotations

import asyncio
import struct
import sys
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / 'sim'))

from uhub import descriptors as D  # noqa: E402
from uhub.device import UhubDevice  # noqa: E402
from uhub.engine_link import EngineLink  # noqa: E402
from uhub.mapping import DeviceMapping  # noqa: E402
from uhub.state import IDLE_AXES, InputMerger, SourceState, build_report, parse_report  # noqa: E402
from uhub.usbip import (CMD_SUBMIT, CMD_UNLINK, ECONNRESET, EPIPE, OP_REP_DEVLIST,  # noqa: E402
                        OP_REP_IMPORT, OP_REQ_DEVLIST, OP_REQ_IMPORT, RET_SUBMIT,
                        RET_UNLINK, USBIP_VERSION, UsbIpServer)
from uhub.sources import udp  # noqa: E402
import wheel_sim as ws  # noqa: E402

# Most common report in usb-capture/ksp/mozahubstartup.pcapng (4348 of 6919):
# the real hub idle with nothing pressed.
CAPTURED_IDLE = bytes.fromhex('010000018000800180018000800000008008' + '00' * 24)
# A captured report with one button held (byte 19 bit 6).
CAPTURED_BTN = bytes.fromhex('010000018000800180018000800000008008004000' + '00' * 21)


class ReportTests(unittest.TestCase):
    def test_idle_report_matches_real_hub(self):
        self.assertEqual(build_report(0, 8, list(IDLE_AXES)), CAPTURED_IDLE)
        self.assertEqual(len(CAPTURED_IDLE), 42)

    def test_button_bit_layout_matches_capture(self):
        # byte 19 bit 6 -> button (19-18)*8 + 6 = 14
        self.assertEqual(build_report(1 << 14, 8, list(IDLE_AXES)), CAPTURED_BTN)
        self.assertEqual(parse_report(CAPTURED_BTN).buttons, 1 << 14)

    def test_report_descriptor_input_size(self):
        """Walk the authored descriptor and sum Input bits for report ID 1."""
        desc, i, size, count, rid, bits = D.HID_REPORT_DESCRIPTOR, 0, 0, 0, 0, 0
        while i < len(desc):
            prefix = desc[i]
            n = {0: 0, 1: 1, 2: 2, 3: 4}[prefix & 3]
            val = int.from_bytes(desc[i + 1:i + 1 + n], 'little')
            tag = prefix & 0xFC
            if tag == 0x74:
                size = val
            elif tag == 0x94:
                count = val
            elif tag == 0x84:
                rid = val
            elif tag == 0x80 and rid == 1:
                bits += size * count
            i += 1 + n
        self.assertEqual(rid, 1)
        self.assertEqual(bits, 41 * 8)        # 42-byte report incl. report id

    def test_config_descriptor_is_capture_except_hid_lengths(self):
        self.assertEqual(len(D.CONFIG_DESCRIPTOR), 132)
        lens = [struct.unpack_from('<H', D.CONFIG_DESCRIPTOR, off + 7)[0]
                for off in D._HID_DESC_OFFSETS]
        self.assertEqual(lens, [len(D.HID_REPORT_DESCRIPTOR), len(D.HID2_REPORT_DESCRIPTOR)])


class MergerTests(unittest.TestCase):
    def test_or_buttons_and_release_on_remove(self):
        seen = []
        m = InputMerger(on_change=seen.append)
        m.update('a', SourceState(buttons=0b01))
        m.update('b', SourceState(buttons=0b10))
        self.assertEqual(parse_report(m.report).buttons, 0b11)
        m.remove('a')
        self.assertEqual(parse_report(m.report).buttons, 0b10)
        m.remove('b')
        self.assertEqual(m.report, CAPTURED_IDLE)
        self.assertEqual(len(seen), 4)

    def test_axis_last_changed_wins_and_falls_back(self):
        m = InputMerger()
        m.update('a', SourceState(axes={2: 100}))
        m.update('b', SourceState(axes={2: 200}))
        self.assertEqual(parse_report(m.report).axes[2], 200)
        m.update('a', SourceState(axes={2: 150}))
        self.assertEqual(parse_report(m.report).axes[2], 150)
        m.remove('a')
        self.assertEqual(parse_report(m.report).axes[2], 200)
        m.remove('b')
        self.assertEqual(parse_report(m.report).axes[2], IDLE_AXES[2])

    def test_no_callback_when_unchanged(self):
        seen = []
        m = InputMerger(on_change=seen.append)
        m.update('a', SourceState(buttons=1))
        m.update('a', SourceState(buttons=1))
        self.assertEqual(len(seen), 1)


class MappingTests(unittest.TestCase):
    def test_offset_explicit_drop_and_axes(self):
        m = DeviceMapping.from_json({'button_offset': 10, 'buttons': {'2': 0, '3': None},
                                     'axes': {'0': {'to': 6, 'invert': True}}})
        st = m.translate([1, 2, 3], {0: 1000, 1: 5})
        self.assertEqual(st.buttons, (1 << 11) | (1 << 0))
        self.assertEqual(st.axes, {6: 65535 - 1000})

    def test_out_of_range_buttons_dropped(self):
        st = DeviceMapping.from_json({'button_offset': 127}).translate([0, 1], {})
        self.assertEqual(st.buttons, 1 << 127)


class UdpTests(unittest.TestCase):
    def test_roundtrip(self):
        raw = udp.encode(0xDEADBEEF, 7, 42, buttons=(1 << 0) | (1 << 127), hat=3, axes=[1, 65535])
        self.assertEqual(len(raw), 36 + 4)
        p = udp.decode(raw)
        self.assertEqual((p.device_id, p.session, p.seq, p.hat, p.axes),
                         (0xDEADBEEF, 7, 42, 3, [1, 65535]))
        self.assertEqual(p.pressed(), [0, 127])

    def test_rejects_garbage(self):
        self.assertIsNone(udp.decode(b'nope'))
        self.assertIsNone(udp.decode(b'XXXX' + bytes(40)))

    def test_seq_session_and_timeout(self):
        async def go():
            m = InputMerger()
            src = udp.UdpSource(m.update, m.remove,
                                {'bind': '127.0.0.1', 'port': 0, 'timeout_ms': 200})
            await src.start()
            loop = asyncio.get_running_loop()
            tr, _ = await loop.create_datagram_endpoint(
                asyncio.DatagramProtocol, remote_addr=('127.0.0.1', src.port))
            try:
                async def send(seq, buttons, session=1):
                    tr.sendto(udp.encode(1, session, seq, buttons))
                    await asyncio.sleep(0.03)
                await send(5, 0b1)
                self.assertEqual(parse_report(m.report).buttons, 0b1)
                await send(5, 0b11)                 # duplicate seq: dropped
                await send(4, 0b111)                # older: dropped
                self.assertEqual(parse_report(m.report).buttons, 0b1)
                await send(0, 0b100, session=2)     # sender rebooted: accepted
                self.assertEqual(parse_report(m.report).buttons, 0b100)
                self.assertEqual(src.stats['stale'], 2)
                await asyncio.sleep(0.4)            # silence > timeout: released
                self.assertEqual(m.report, CAPTURED_IDLE)
            finally:
                tr.close()
                src.close()
        asyncio.run(go())


class PortReopenTests(unittest.TestCase):
    """DTR edge handling that re-plugs the wheel when an app opens the port."""

    def _dev(self):
        calls = []
        return UhubDevice(CAPTURED_IDLE, on_port_reopen=lambda: calls.append(1)), calls

    def test_open_toggle_blip_is_ignored(self):
        dev, calls = self._dev()
        # SimHub/Wine open sequence observed live: 1, 1, 0, 1 within milliseconds
        for i, dtr in enumerate((True, True, False, True)):
            dev._set_dtr(dtr, now=100.0 + i * 0.001)
        self.assertEqual(calls, [])

    def test_reopen_after_close_replugs(self):
        dev, calls = self._dev()
        dev._set_dtr(True, now=0.0)
        dev._set_dtr(False, now=10.0)        # SimHub closes (observed 06:29:25)
        dev._set_dtr(True, now=26.0)         # PitHouse opens (observed 06:29:41)
        self.assertEqual(calls, [1])
        dev._set_dtr(True, now=27.0)         # repeated high: no new edge
        self.assertEqual(calls, [1])

    def test_open_right_after_attach_does_not_replug(self):
        dev, calls = self._dev()
        dev.on_attach()                      # engine started on attach
        dev._set_dtr(True, now=time.monotonic() + 0.1)
        self.assertEqual(calls, [])

    def test_late_first_open_after_attach_replugs(self):
        dev, calls = self._dev()             # the original live failure:
        dev.on_attach()                      # PitHouse opened 7.5 min after attach
        dev._set_dtr(True, now=time.monotonic() + 450)
        self.assertEqual(calls, [1])


class UsbIpClient:
    """Minimal USB/IP client for driving the server in tests."""

    def __init__(self, reader, writer):
        self.r, self.w = reader, writer
        self.seq = 0
        self._is_in = {}        # seqnum -> False for OUT submits (no data in reply)

    @classmethod
    async def attach(cls, port, busid='1-1'):
        r, w = await asyncio.open_connection('127.0.0.1', port)
        w.write(struct.pack('>HHI', USBIP_VERSION, OP_REQ_IMPORT, 0) + busid.encode().ljust(32, b'\0'))
        ver, code, status = struct.unpack('>HHI', await r.readexactly(8))
        assert code == OP_REP_IMPORT, code
        if status != 0:
            w.close()
            return None, status
        await r.readexactly(312)
        return cls(r, w), 0

    def submit(self, ep, direction, length, setup=bytes(8), data=b''):
        self.seq += 1
        self.w.write(struct.pack('>IIIII Iiiii', CMD_SUBMIT, self.seq, 0x10002, direction, ep,
                                 0, length, 0, 0, 0) + setup + data)
        return self.seq

    def unlink(self, target):
        self.seq += 1
        self.w.write(struct.pack('>IIIII I 24x', CMD_UNLINK, self.seq, 0x10002, 0, 0, target))
        return self.seq

    async def recv(self, timeout=2.0):
        hdr = await asyncio.wait_for(self.r.readexactly(48), timeout)
        cmd, seq = struct.unpack_from('>II', hdr)
        status, actual = struct.unpack_from('>ii', hdr, 20)
        data = b''
        if cmd == RET_SUBMIT and actual > 0 and self._is_in.get(seq, True):
            data = await self.r.readexactly(actual)
        return cmd, seq, status, data

    async def control_in(self, setup):
        wlen = struct.unpack_from('<H', setup, 6)[0]
        s = self.submit(0, 1, wlen, setup)
        cmd, seq, status, data = await self.recv()
        assert (cmd, seq) == (RET_SUBMIT, s)
        return status, data

    async def control_out(self, setup, data=b''):
        s = self.submit(0, 0, len(data), setup, data)
        self._is_in[s] = False
        return await self.recv()


def _setup(rt, req, value, index, length):
    return struct.pack('<BBHHH', rt, req, value, index, length)


class UsbIpTests(unittest.TestCase):
    def test_devlist(self):
        async def go():
            srv = UsbIpServer(UhubDevice(CAPTURED_IDLE), port=0)
            await srv.start()
            try:
                r, w = await asyncio.open_connection('127.0.0.1', srv.port)
                w.write(struct.pack('>HHI', USBIP_VERSION, OP_REQ_DEVLIST, 0))
                ver, code, status, n = struct.unpack('>HHII', await r.readexactly(12))
                dev = await r.readexactly(312)
                ifs = await r.readexactly(4 * 4)
                w.close()
                self.assertEqual((code, status, n), (OP_REP_DEVLIST, 0, 1))
                busid = dev[256:288].rstrip(b'\0')
                vid, pid = struct.unpack_from('>HH', dev, 300)
                self.assertEqual((busid, vid, pid), (b'1-1', 0x346E, 0x0020))
                self.assertEqual(ifs[0:3], bytes([2, 2, 0]))
                self.assertEqual(ifs[8:11], bytes([3, 0, 0]))
            finally:
                await srv.close()
        asyncio.run(go())

    def test_enumeration_hid_cdc_and_unlink(self):
        async def go():
            m = InputMerger()
            cdc_out = []
            dev = UhubDevice(m.report, cdc_out=cdc_out.append)
            m._on_change = dev.set_report
            srv = UsbIpServer(dev, port=0)
            await srv.start()
            try:
                c, st = await UsbIpClient.attach(srv.port)
                self.assertEqual(st, 0)
                # second importer refused while attached
                _, st2 = await UsbIpClient.attach(srv.port)
                self.assertNotEqual(st2, 0)

                st, dd = await c.control_in(_setup(0x80, 6, 0x0100, 0, 18))
                self.assertEqual((st, dd), (0, D.DEVICE_DESCRIPTOR))
                st, cfg9 = await c.control_in(_setup(0x80, 6, 0x0200, 0, 9))
                self.assertEqual(cfg9, D.CONFIG_DESCRIPTOR[:9])
                st, cfg = await c.control_in(_setup(0x80, 6, 0x0200, 0, 0xFFFF))
                self.assertEqual(cfg, D.CONFIG_DESCRIPTOR)
                st, s2 = await c.control_in(_setup(0x80, 6, 0x0302, 0x0409, 255))
                self.assertEqual(s2[2:].decode('utf-16-le'), D.STRINGS[2])
                st, _ = await c.control_in(_setup(0x80, 6, 0x0600, 0, 10))
                self.assertEqual(st, -EPIPE)                     # no qualifier on FS
                cmd, _, st, _ = await c.control_out(_setup(0x00, 9, 1, 0, 0))
                self.assertEqual(st, 0)
                self.assertTrue(dev.configured)
                st, rd = await c.control_in(_setup(0x81, 6, 0x2200, 2, len(D.HID_REPORT_DESCRIPTOR)))
                self.assertEqual(rd, D.HID_REPORT_DESCRIPTOR)
                cmd, _, st, _ = await c.control_out(_setup(0x21, 0x22, 0x0003, 0, 0))
                self.assertTrue(dev.dtr)

                # HID: first IN completes immediately with current report...
                s = c.submit(0x03, 1, 64)
                cmd, seq, st, data = await c.recv()
                self.assertEqual((seq, data), (s, CAPTURED_IDLE))
                # ...the next one waits for a change.
                s = c.submit(0x03, 1, 64)
                with self.assertRaises(asyncio.TimeoutError):
                    await c.recv(timeout=0.2)
                m.update('t', SourceState(buttons=1 << 14))
                cmd, seq, st, data = await c.recv()
                self.assertEqual((seq, data), (s, CAPTURED_BTN))

                # CDC OUT reaches the engine sink; engine bytes come back on IN.
                frame = ws.build_frame(0x07, 0x12, b'\x01')
                s = c.submit(0x02, 0, len(frame), data=frame)
                c._is_in[s] = False
                cmd, seq, st, _ = await c.recv()
                self.assertEqual((seq, st), (s, 0))
                self.assertEqual(b''.join(cdc_out), frame)
                s = c.submit(0x02, 1, 64)
                dev.cdc_from_engine(b'\x7e' * 100)
                cmd, seq, st, data = await c.recv()
                self.assertEqual((seq, len(data)), (s, 64))
                s = c.submit(0x02, 1, 64)
                cmd, seq, st, data = await c.recv()
                self.assertEqual((seq, len(data)), (s, 36))

                # UNLINK a pending URB (CDC notify never completes)
                pend = c.submit(0x01, 1, 8)
                u = c.unlink(pend)
                cmd, seq, st, _ = await c.recv()
                self.assertEqual((cmd, seq, st), (RET_UNLINK, u, -ECONNRESET))
                u = c.unlink(pend)                                 # already gone
                cmd, seq, st, _ = await c.recv()
                self.assertEqual((cmd, st), (RET_UNLINK, 0))
                c.w.close()
                await asyncio.sleep(0.05)
                self.assertFalse(dev.attached)
            finally:
                await srv.close()
        asyncio.run(go())


class EngineTests(unittest.TestCase):
    """Full path through the real wheel_sim engine over socket:// — the same
    route PitHouse traffic takes on Windows."""

    def test_hub_identity_probe_through_engine(self):
        async def go():
            dev_holder = {}
            link = EngineLink('kspro_uhub', on_data=lambda d: dev_holder['dev'].cdc_from_engine(d),
                              log_path=REPO / 'sim' / 'logs' / 'test_uhub_engine.log')
            dev = UhubDevice(CAPTURED_IDLE, cdc_out=link.write,
                             on_attach=link.start_engine, on_detach=link.stop_engine)
            dev_holder['dev'] = dev
            await link.start()
            srv = UsbIpServer(dev, port=0)
            await srv.start()
            try:
                c, _ = await UsbIpClient.attach(srv.port)
                probe = ws.build_frame(0x07, 0x12, b'\x01') + ws.build_frame(0x00, 0x13, b'')
                s = c.submit(0x02, 0, len(probe), data=probe)
                c._is_in[s] = False
                await c.recv()
                got = b''
                deadline = asyncio.get_running_loop().time() + 60
                while b'S03 HUB' not in got and asyncio.get_running_loop().time() < deadline:
                    c.submit(0x02, 1, 4096)
                    try:
                        _, _, _, data = await c.recv(timeout=5)
                        got += data
                    except asyncio.TimeoutError:
                        pass
                frames = ws.parse_frames(got)
                ident = [f for f in frames if f[2] == 0x87 and f[3] == 0x21]
                self.assertTrue(ident, f'no hub identity reply in {got.hex()}')
                self.assertEqual(bytes(ws.frame_payload(ident[0]))[1:8], b'S03 HUB')
                # no wheelbase behind a Universal Hub: 0x13 heartbeat unanswered
                self.assertFalse([f for f in frames if f[3] == 0x31])
                c.w.close()
                await asyncio.sleep(0.2)
                self.assertFalse(link.running)
            finally:
                await srv.close()
                await link.close()
        asyncio.run(go())


if __name__ == '__main__':
    unittest.main()
