# MOZA Simulator

A Python simulator for **MOZA Racing** sim-racing hardware. It speaks MOZA's
reverse-engineered serial protocol convincingly enough that the official **MOZA
Pit House** app and **SimHub** plugins talk to it as if it were real hardware —
over a Linux USB gadget — so you can develop, regression-test, and capture
protocol traffic without owning every wheel, dash, pedal set, and shifter.

It was extracted from the [AZOM](https://github.com/giantorth/AZOM) MOZA SimHub
plugin project, where it grew into a full multi-device rig.

## What it simulates

13 device profiles across every MOZA transport, driven by a data-driven profile
registry (`sim/profiles/`) and a small set of sim engines:

| Category | Devices |
|---|---|
| **Tier-def wheels** | Vision GS, CS Pro (W17), KS, KS Pro (W18), FSR V2 (W13), GS V2 Pro, ES |
| **Display wheel** | FSR V1 (group `0x42` push) |
| **Standalone dash** | CM2 Racing Dash (PID `0x0025`, tier-def + LED bitmask) |
| **Bus dash** | CM1 Racing Dash (group `0x35` keyed-float stream + `0x0E` param bank) |
| **Peripherals** | AB9 active shifter (incl. HID gear-state reports), mBooster pedal, SRP pedals, HBP handbrake |
| **Base / hub** | R5 / R9 / R12 wheelbase + Universal Hub identity cascades |

Each device's identity, capabilities, and wire behaviour come from real
hardware captures and the protocol reference under `docs/protocol/`.

## Quick start (Linux)

```bash
# 1. Python deps
python3 -m venv .venv
.venv/bin/pip install pyserial mcp

# 2. Local (SimHub / Pit House under Wine on this machine): tty0tty pair, no root
#    once the module is loaded. Map the prefix's COM40 to /dev/tnt1 (with the
#    MOZA USB identity Pit House filters on) and run the engine on /dev/tnt0.
python3 sim/pithouse_wine.py register --dev /dev/tnt1 --com COM40 --pid 0x0008
python3 sim/gadget_manager.py run mbooster /dev/tnt0     # mBooster lane (brake + chained throttle)
python3 sim/wheel_sim.py --model kspro /dev/tnt0         # or a wheel

# 2a. SimHub in the linux-simracing-utils prefix (the /deploy target): pass
#     --prefix, since the default is the Pit House test prefix.
P=~/linux-simracing-utils/pfx
python3 sim/pithouse_wine.py --prefix $P register --dev /dev/tnt1 --com COM40 --pid 0x0008
.venv/bin/python3 sim/gadget_manager.py run mbooster /dev/tnt0 &
#     Wine builds HARDWARE\DEVICEMAP\SERIALCOMM only at wineserver start, and
#     the plugin drops COM ports missing from it. After registering, quit
#     SimHub, restart the Wine session, then relaunch:
WINEPREFIX=$P ~/linux-simracing-utils/bin/wineserver -k
setsid ~/linux-simracing-utils/bin/lsu-launch-wrapper \
  'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\SimHub\SimHub.lnk' &
#     Check: SimHub.txt logs "Wine registry declares COM40 as MOZA PID 0x0008".
#     When done: stop the engine and `pithouse_wine.py --prefix $P unregister
#     --com COM40 --pid 0x0008`. A registered COM40 with no engine behind it crashes
#     Pit House on launch.

# 3. Remote Windows over usbip: USB gadget per device (needs root: configfs +
#    dummy_hcd + usbipd). Gadgets are bound to usbipd for export, so they do
#    NOT show up as a local ttyACM.
sudo bash sim/setup_rig.sh kspro mbooster handbrake     # multi-device rig
sudo bash sim/setup_usbip_gadget.sh                     # or a single wheelbase gadget
python3 sim/gadget_manager.py run mbooster /dev/ttyGS1   # engines on the printed ttyGS ports
```

tty0tty setup and troubleshooting: [`sim/README.md`](sim/README.md); usbip:
[`sim/USBIP_SETUP.md`](sim/USBIP_SETUP.md).

mBooster profiles: `mbooster` (host brake + chained throttle + passive clutch),
`mbooster_single` (one unit, passive throttle and clutch),
`mbooster_chain_jcj5aea2` (chain with swapped pedal roles).

## Highlights

- **Profile registry** (`sim/profiles/`) — adding a model is a new file, not new
  dispatch code. `tools/extract_profile.py` turns a SimHub diagnostics bundle
  into a profile stub automatically.
- **Byte-exact regression gate** (`tools/sim_golden.py --check`) — replays real
  Pit House captures through every wheel and asserts the responses are identical
  to committed baselines.
- **Multi-device gadget manager** (`sim/gadget_manager.py`, `sim/setup_rig.sh`) —
  several USB gadgets at once with automatic `dummy_hcd` UDC scaling.
- **Unified rig MCP server** (`sim/rig_mcp_server.py`, registered in `.mcp.json`)
  — start / stop / inspect a whole rig from one place.
- **AB9 HID gear reports** — byte-exact gear-state reports decoded from real
  captures (`tools/ab9-hid-decode`), emitted over an `f_hid` gadget function.

## Layout

```
sim/            simulator engines, profiles, gadget scripts, MCP servers
  profiles/       per-device DeviceProfile registry (wheels/dashes/pedals/standalone)
  engines/        standalone device engines (mBooster, CM1, pedals/handbrake)
  golden/         byte-exact regression baselines
  replay/         captured request→response tables per device
tools/          wire-trace / capture analysis + decoders + the golden harness
docs/protocol/  the reverse-engineered MOZA wire-protocol reference
usb-capture/    capture parsers + RE notes (the raw captures themselves are
                gitignored — see below)
Data/           Telemetry.json — the MOZA channel catalog the sim serves
```

## Captures

The raw Wireshark/USB captures are **not** committed (they total multiple GB and
contain real device traffic). The parsers and RE notes under `usb-capture/`
*are* tracked. The simulator, the golden harness (`--check`), and the AB9 HID
decoder read captures from `usb-capture/` **when present locally** — keep your
captures there to use those features. The committed `sim/replay/*.json` tables
and `sim/golden/*.jsonl` baselines let most of the simulator run without them.

## Status & origin

Extracted from the [AZOM](https://github.com/giantorth/AZOM) SimHub plugin. The MOZA serial protocol was
reverse-engineered with reference to the
[boxflat](https://github.com/Lawstorant/boxflat) project; the wire-level
findings live under `docs/protocol/`.
