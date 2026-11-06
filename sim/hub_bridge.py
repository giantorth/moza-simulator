#!/usr/bin/env python3
"""MOZA Universal Hub bridge — present ESP32 / SDL / evdev inputs as a KS Pro
wheel behind an emulated MOZA Universal Hub (VID 0x346E PID 0x0020).

Runs on Windows and Linux. The hub is a userspace USB/IP device:

    python sim/hub_bridge.py --config sim/uhub_bridge.example.json

    Windows (usbip-win2 installed):  usbip attach -r 127.0.0.1 -b 1-1
    Linux / Wine on Linux:           sudo modprobe vhci-hcd
                                     sudo usbip attach -r 127.0.0.1 -b 1-1

Once attached the host sees the hub's CDC COM port (PitHouse talks to the
wheel_sim `kspro_uhub` engine through it) and a HID joystick whose 42-byte
reports carry the merged buttons/axes of every input source.

    python sim/hub_bridge.py --list-devices   # SDL (+ evdev) devices for config

See docs/hub-bridge.md.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import signal
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from uhub.device import UhubDevice  # noqa: E402
from uhub.engine_link import EngineLink  # noqa: E402
from uhub.state import InputMerger, parse_report  # noqa: E402
from uhub.usbip import UsbIpServer  # noqa: E402
from uhub.sources.udp import DEFAULT_PORT, UdpSource  # noqa: E402

log = logging.getLogger('uhub')

DEFAULT_MODEL = 'kspro_uhub'


def _load_config(path: str | None) -> dict:
    if not path:
        return {}
    with open(path, encoding='utf-8') as fh:
        return json.load(fh)


def cmd_list_devices() -> int:
    from uhub.sources import sdl
    try:
        devs = sdl.list_devices()
        print('SDL joysticks:')
        for d in devs or []:
            print(f"  [{d['index']}] {d['name']!r}  guid={d['guid']}  "
                  f"vid:pid={d['vid']:04x}:{d['pid']:04x}  "
                  f"buttons={d['buttons']} axes={d['axes']} hats={d['hats']}")
        if not devs:
            print('  (none)')
    except RuntimeError as e:
        print(f'SDL: {e}')
    if sys.platform.startswith('linux'):
        try:
            from uhub.sources import evdev_src
            print('evdev devices:')
            for d in evdev_src.list_devices():
                print(f"  {d['path']}  {d['name']!r}  vid:pid={d['vid']:04x}:{d['pid']:04x}  "
                      f"keys={d['keys']} abs={d['abs']}")
        except RuntimeError as e:
            print(f'evdev: {e}')
    return 0


def _describe(report: bytes) -> str:
    st = parse_report(report)
    held = [i for i in range(128) if st.buttons >> i & 1]
    return f'buttons={held} hat={st.hat}'


async def run(args, cfg: dict) -> int:
    loop = asyncio.get_running_loop()
    device: UhubDevice

    def on_report(report: bytes) -> None:
        log.debug('report %s', _describe(report))
        device.set_report(report)

    merger = InputMerger(on_change=on_report)

    engine = None
    if not args.no_engine:
        engine = EngineLink(args.model, on_data=lambda d: device.cdc_from_engine(d),
                            log_path=Path(args.engine_log))

    def on_attach() -> None:
        log.info('host attached — starting %s engine', args.model)
        if engine:
            engine.start_engine()

    def on_detach() -> None:
        log.info('host detached')
        if engine:
            engine.stop_engine()

    def on_port_reopen() -> None:
        # PitHouse only opens its wheel sessions right after the wheel's 7c:23
        # "page activate" announcement, which the engine sends once at startup.
        # An app that opens the COM port later (e.g. PitHouse started after
        # SimHub, or restarted) needs a freshly plugged-in wheel to see it.
        if engine:
            engine.start_engine()

    device = UhubDevice(merger.report,
                        cdc_out=(engine.write if engine else None),
                        on_attach=on_attach, on_detach=on_detach,
                        on_port_reopen=on_port_reopen)

    if engine:
        await engine.start()

    usbip_cfg = cfg.get('usbip') or {}
    server = UsbIpServer(device, host=args.usbip_host or usbip_cfg.get('host', '127.0.0.1'),
                         port=args.usbip_port or int(usbip_cfg.get('port', 3240)))
    await server.start()

    closers = []
    udp_cfg = dict(cfg.get('udp') or {})
    if args.udp_port is not None:
        udp_cfg['port'] = args.udp_port
    if udp_cfg.get('enabled', True) and not args.no_udp:
        udp = UdpSource(merger.update, merger.remove, udp_cfg)
        await udp.start()
        closers.append(udp.close)

    sdl_cfg = cfg.get('sdl') or {}
    if sdl_cfg.get('enabled', bool(sdl_cfg.get('devices'))) and not args.no_sdl:
        from uhub.sources.sdl import SdlSource
        try:
            src = SdlSource(loop, merger.update, merger.remove, sdl_cfg)
            src.start()
            closers.append(src.close)
        except RuntimeError as e:
            log.error('%s', e)

    ev_cfg = cfg.get('evdev') or {}
    if ev_cfg.get('devices'):
        if not sys.platform.startswith('linux'):
            log.warning('evdev source configured but this is not Linux — ignoring')
        else:
            from uhub.sources.evdev_src import EvdevSource
            ev = EvdevSource(merger.update, merger.remove, ev_cfg)
            await ev.start()
            closers.append(ev.close)

    print(f'\nMOZA Universal Hub bridge ready — USB/IP {server.host}:{server.port} busid {device.busid}')
    print(f'  Windows:  usbip attach -r {server.host if server.host != "0.0.0.0" else "<this-pc>"} -b {device.busid}')
    print(f'  Linux:    sudo modprobe vhci-hcd && sudo usbip attach -r 127.0.0.1 -b {device.busid}')
    print('Ctrl+C to stop.\n', flush=True)

    stop = asyncio.Event()
    if sys.platform != 'win32':
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
    try:
        if sys.platform == 'win32':
            while not stop.is_set():          # let Ctrl+C reach us on Windows
                await asyncio.sleep(0.5)
        else:
            await stop.wait()
    finally:
        for c in closers:
            c()
        await server.close()
        if engine:
            await engine.close()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog=__doc__)
    ap.add_argument('--config', help='bridge config JSON (see sim/uhub_bridge.example.json)')
    ap.add_argument('--list-devices', action='store_true',
                    help='list SDL (and on Linux evdev) input devices and exit')
    ap.add_argument('--model', default=DEFAULT_MODEL,
                    help=f'wheel_sim model for the CDC engine (default {DEFAULT_MODEL})')
    ap.add_argument('--usbip-host', help='USB/IP listen address (default 127.0.0.1; '
                    '0.0.0.0 to let another PC attach)')
    ap.add_argument('--usbip-port', type=int, help='USB/IP listen port (default 3240)')
    ap.add_argument('--udp-port', type=int, help=f'ESP32 UDP port (default {DEFAULT_PORT})')
    ap.add_argument('--no-udp', action='store_true', help='disable the UDP/ESP32 source')
    ap.add_argument('--no-sdl', action='store_true', help='disable the SDL joystick source')
    ap.add_argument('--no-engine', action='store_true',
                    help='HID only: do not run wheel_sim on the CDC interface')
    ap.add_argument('--engine-log', default=str(HERE / 'logs' / 'hub_bridge_engine.log'),
                    help='where the wheel_sim engine output goes')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format='%(asctime)s %(name)-12s %(levelname)-7s %(message)s',
                        datefmt='%H:%M:%S')
    if args.list_devices:
        return cmd_list_devices()
    cfg = _load_config(args.config)
    try:
        return asyncio.run(run(args, cfg))
    except KeyboardInterrupt:
        return 0


if __name__ == '__main__':
    raise SystemExit(main())
