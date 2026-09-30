#!/usr/bin/env python3
"""Make MOZA Pit House, running in a local Wine prefix, see a MOZA serial port.

Pit House enumerates ports with Qt's QSerialPortInfo and keeps only those whose
device instance ID carries VID_346E. Under Wine a serial port is just a
dosdevices/comN symlink with no USB identity, so Pit House logs
`serialCount= 0` even with a real base plugged in. This script adds the missing
identity: a Ports-class device under HKLM\\System\\CurrentControlSet\\Enum\\USB
with the MOZA VID/PID and a `Device Parameters\\PortName`, plus the Wine port
mapping (HKLM\\Software\\Wine\\Ports + the dosdevices link) that points that COM
name at a Linux tty.

The tty can be a real device (/dev/ttyACMx) or one end of a tty0tty pair
(/dev/tntN) whose other end is served by bridge.py or a sim engine. Wine rejects
/dev/pts/* at CreateFile time (no serial ioctls), so socat ptys don't work.

Usage:
    python3 sim/pithouse_wine.py register --dev /dev/ttyACM1 --com COM40 --pid 0x0000
    python3 sim/pithouse_wine.py launch
    python3 sim/pithouse_wine.py status
    python3 sim/pithouse_wine.py unregister --com COM40

--prefix defaults to $PITHOUSE_PREFIX or ~/Games/lsu-pfx-winetest; --wine to
$PITHOUSE_WINE or ~/linux-simracing-utils/bin/wine.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional

PORTS_CLASS_GUID = "{4D36E978-E325-11CE-BFC1-08002BE10318}"
MOZA_VID = 0x346E
PITHOUSE_EXE = r"C:\Program Files (x86)\MOZA Pit House\MOZA Pit House.exe"
ENUM_ROOT = r"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\USB"
WINE_PORTS = r"HKEY_LOCAL_MACHINE\Software\Wine\Ports"


def default_prefix() -> Path:
    return Path(os.environ.get("PITHOUSE_PREFIX", Path.home() / "Games" / "lsu-pfx-winetest"))


def default_wine() -> Path:
    return Path(os.environ.get("PITHOUSE_WINE", Path.home() / "linux-simracing-utils" / "bin" / "wine"))


def _multi_sz_hex(values: List[str]) -> str:
    """REG_MULTI_SZ as a regedit 5.00 hex(7) literal (UTF-16LE, double-NUL end)."""
    raw = ("\0".join(values) + "\0\0").encode("utf-16-le")
    return "hex(7):" + ",".join(f"{b:02x}" for b in raw)


def _reg_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _device_key(vid: int, pid: int, serial: str) -> str:
    return f"{ENUM_ROOT}\\VID_{vid:04X}&PID_{pid:04X}\\{serial}"


def _import_reg(args, text: str) -> None:
    # regedit 5.00 files are UTF-16LE with a BOM.
    with tempfile.NamedTemporaryFile("wb", suffix=".reg", delete=False) as fh:
        fh.write(b"\xff\xfe" + text.encode("utf-16-le"))
        path = fh.name
    try:
        _wine(args, ["regedit", "/S", _winpath(args, path)], check=True)
    finally:
        os.unlink(path)


def _winpath(args, unix_path: str) -> str:
    # Z: maps to / in every default prefix.
    return "Z:" + unix_path.replace("/", "\\")


def _wine(args, argv: List[str], check: bool = False, detach: bool = False,
          log: Optional[Path] = None) -> subprocess.CompletedProcess | subprocess.Popen:
    env = dict(os.environ, WINEPREFIX=str(args.prefix), WINEDEBUG=os.environ.get("WINEDEBUG", "-all"))
    cmd = [str(args.wine)] + argv
    if detach:
        out = open(log, "ab") if log else subprocess.DEVNULL
        return subprocess.Popen(cmd, env=env, stdout=out, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, start_new_session=True)
    return subprocess.run(cmd, env=env, check=check, capture_output=True)


def _com_link(args, com: str) -> Path:
    return Path(args.prefix) / "dosdevices" / com.lower()


def cmd_register(args) -> int:
    com = args.com.upper()
    if not re.fullmatch(r"COM\d+", com):
        sys.exit(f"--com must look like COM40, got {args.com}")
    if not Path(args.dev).exists():
        print(f"warning: {args.dev} does not exist yet", file=sys.stderr)
    key = _device_key(args.vid, args.pid, args.serial)
    hwids = [f"USB\\VID_{args.vid:04X}&PID_{args.pid:04X}&REV_0100",
             f"USB\\VID_{args.vid:04X}&PID_{args.pid:04X}"]
    name = f"{args.desc} ({com})"
    text = "\r\n".join([
        "Windows Registry Editor Version 5.00", "",
        f"[{key}]",
        f'"ClassGUID"={_reg_str(PORTS_CLASS_GUID)}',
        '"Class"="Ports"',
        f'"DeviceDesc"={_reg_str(args.desc)}',
        f'"FriendlyName"={_reg_str(name)}',
        '"Mfg"="MOZA"',
        '"Service"="usbser"',
        f'"HardwareID"={_multi_sz_hex(hwids)}',
        '"ConfigFlags"=dword:00000000', "",
        f"[{key}\\Device Parameters]",
        f'"PortName"={_reg_str(com)}', "",
        f"[{WINE_PORTS}]",
        f'"{com}"={_reg_str(args.dev)}', "", ""])
    _import_reg(args, text)
    # mountmgr rebuilds the link from Wine\Ports on the next wineboot; set it
    # now too so a running prefix sees it immediately.
    link = _com_link(args, com)
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(args.dev)
    print(f"registered {key}\n  PortName={com} -> {args.dev}")
    return 0


def cmd_unregister(args) -> int:
    com = args.com.upper()
    text = "\r\n".join([
        "Windows Registry Editor Version 5.00", "",
        f"[-{_device_key(args.vid, args.pid, args.serial)}]", "",
        f"[{WINE_PORTS}]", f'"{com}"=-', "", ""])
    _import_reg(args, text)
    link = _com_link(args, com)
    if link.is_symlink():
        link.unlink()
    print(f"unregistered {com}")
    return 0


def _latest_common_log(args) -> Optional[Path]:
    logs = Path(args.prefix) / "drive_c" / "users" / os.environ.get("USER", "rorth") / \
        "AppData" / "Local" / "MOZA Pit House" / "Logs"
    found = sorted(logs.glob("*-Common.log"), key=lambda p: p.stat().st_mtime)
    return found[-1] if found else None


def cmd_launch(args) -> int:
    log = Path(tempfile.gettempdir()) / "pithouse-wine.log"
    proc = _wine(args, [PITHOUSE_EXE], detach=True, log=log)
    print(f"Pit House started (pid {proc.pid}); wine output -> {log}")
    return 0


def cmd_status(args) -> int:
    log = _latest_common_log(args)
    if not log:
        print("no Pit House Common.log yet")
        return 1
    print(log.name)
    pat = re.compile(r"serialCount|device target|串口|COM\d+|VID_346E|mboost", re.IGNORECASE)
    for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
        if pat.search(line):
            print(line[:240])
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--prefix", type=Path, default=default_prefix())
    ap.add_argument("--wine", type=Path, default=default_wine())
    sub = ap.add_subparsers(dest="cmd", required=True)

    def ident(p):
        p.add_argument("--com", default="COM40")
        p.add_argument("--vid", type=lambda s: int(s, 0), default=MOZA_VID)
        p.add_argument("--pid", type=lambda s: int(s, 0), default=0x0006,
                       help="0x0000 R16 base, 0x0006 base, 0x0008 mBooster")
        p.add_argument("--serial", default="AZOMHARNESS0001")

    p = sub.add_parser("register"); ident(p)
    p.add_argument("--dev", required=True, help="/dev/ttyACMx or /dev/tntN")
    p.add_argument("--desc", default="MOZA USB Serial Device")
    p.set_defaults(func=cmd_register)
    p = sub.add_parser("unregister"); ident(p); p.set_defaults(func=cmd_unregister)
    sub.add_parser("launch").set_defaults(func=cmd_launch)
    sub.add_parser("status").set_defaults(func=cmd_status)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
