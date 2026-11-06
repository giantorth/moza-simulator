# MOZA Universal Hub bridge

`sim/hub_bridge.py` emulates a **MOZA Universal Hub** (VID `0x346E`, PID `0x0020`)
with a **KS Pro** wheel attached, and turns any number of input devices into
that KS Pro's buttons, hat and axes:

| Source | Platforms | Transport |
|---|---|---|
| ESP32 button box (`firmware/esp32_wheel_buttons/`) | any | Wi-Fi UDP |
| SDL2 joysticks (rims, button boxes, pads) | Windows, Linux | pysdl2 |
| evdev devices (keyboards, macro pads, exclusive grab) | Linux | python-evdev |

All sources merge into **one** KS Pro (buttons OR'd, axes last-writer-wins).

```
ESP32 ──UDP──┐
SDL2 ────────┼─► InputMerger ─► HID joystick (EP 0x83, 42-byte reports) ─┐
evdev ───────┘                                                           ├─► USB/IP ─► host
         wheel_sim --model kspro_uhub ◄─socket://─► CDC serial (EP 0x02/0x82) ─┘
```

The hub is a **userspace USB/IP device** (`sim/uhub/usbip.py`), not a kernel
gadget, so the bridge itself runs on Windows or Linux. The host that should
*see* the hub attaches it with a USB/IP client:

| Host | Client | Attach |
|---|---|---|
| Windows 10/11 | [usbip-win2](https://github.com/vadimgrn/usbip-win2) | `usbip attach -r 127.0.0.1 -b 1-1` |
| Linux, incl. PitHouse/games under **Wine/Proton** | kernel `vhci-hcd` + `usbip` tools | `sudo modprobe vhci-hcd && sudo usbip attach -r 127.0.0.1 -b 1-1` |
| Another PC | either of the above | run the bridge with `--usbip-host 0.0.0.0`, attach to its IP |

Once attached the host enumerates a real USB device: a COM port (Linux:
`/dev/ttyACM*`, which Wine maps to a COM port) that PitHouse/SimHub talk to,
and a HID game controller that games and `joy.cpl` see.

## Quick start

**Windows users starting from scratch:** follow
[windows-setup.md](windows-setup.md). It goes step by step from installing
Python to ESP32 wiring, pin-to-button mapping, flashing, and attaching the hub.

```bash
pip install pyserial pysdl2          # Windows: also  pip install pysdl2-dll
python sim/hub_bridge.py --list-devices          # find SDL/evdev device names
cp sim/uhub_bridge.example.json my_bridge.json   # edit mappings
python sim/hub_bridge.py --config my_bridge.json
# then attach from the host (table above)
```

Detach: Windows `usbip detach -p <port>`; Linux `sudo usbip port` then
`sudo usbip detach -p <port>`. Each attach starts a fresh `wheel_sim` engine
(attach == plugging the hub in), each detach stops it. Engine output goes to
`sim/logs/hub_bridge_engine.log`.

Options: `--no-engine` (HID only, CDC silent), `--no-udp`, `--no-sdl`,
`--udp-port`, `--usbip-host/--usbip-port`, `-v` (logs every report change).

## Mapping config

All button and axis numbers are **0-based**; KS Pro button *N* shows as button
*N+1* in Windows "Game Controllers". Axis slots: 0 X, 1 Y, 2 Z, 3 Rx, 4 Ry,
5 Rz, 6 Slider, 7 Dial. Per-device mapping keys (`sim/uhub/mapping.py`):

| Key | Meaning |
|---|---|
| `button_offset` | unmapped source button *i* → KS Pro button *i + offset* |
| `buttons` | explicit `{"src": dst}`; `null` drops a button |
| `only_mapped_buttons` | drop everything not listed in `buttons` |
| `axes` | `{"src": {"to": slot, "invert": bool}}`; omitted = source axis *i* → slot *i* |
| `hat` | forward the source's hat (default true) |

* **UDP** devices are keyed by the ESP32's `device_id` (printed on its serial
  console), `"*"` is the default. `allow` restricts senders to CIDR ranges —
  the UDP port is unauthenticated, so anyone who can reach it can press buttons.
* **SDL** devices match by case-insensitive name substring or exact GUID.
  Unmatched devices are ignored unless `map_unconfigured` is true. The hub's
  own joystick (346E:0020) is always skipped so an attached bridge can't loop
  back into itself.
* **evdev** devices are listed by path with explicit `keys`/`abs` maps; set
  `grab` to stop the device's events also reaching other programs.

See `sim/uhub_bridge.example.json`.

## ESP32 wire protocol (UDP, little-endian)

Every datagram is the sender's **full** state; senders transmit on change and
every 50 ms. The bridge drops a sender after `timeout_ms` (500) of silence and
releases its buttons, so packet loss or a Wi-Fi drop can't leave a button held.

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `MZBR` |
| 4 | 1 | version `1` |
| 5 | 1 | flags (0) |
| 6 | 1 | hat: 0–7 = N…NW clockwise, 8 = centred |
| 7 | 1 | axis count *n* (0–8) |
| 8 | 4 | device_id (firmware: low 32 bits of the Wi-Fi MAC) |
| 12 | 4 | session (random per boot; a change resets sequence tracking) |
| 16 | 4 | seq (+1 per packet; duplicates and older packets dropped) |
| 20 | 16 | 128-button bitmask, button *i* = byte 20 + *i*/8, bit *i*%8 |
| 36 | 2*n* | axes, u16 0–65535 |

Reference implementations: `sim/uhub/sources/udp.py` (encode/decode) and
`firmware/esp32_wheel_buttons/src/main.cpp`.

## What is captured vs. authored

Verified against `usb-capture/ksp/mozahubstartup.pcapng` (real hub + KS Pro)
and cross-checked against seven further Universal Hub captures:

* **Byte-exact from captures:** device descriptor; the 132-byte configuration
  (CDC IAD + 2 HID interfaces) except the two HID `wDescriptorLength` fields;
  the hub's identity cascade on bus device `0x12` (`S03 HUB`,
  `RS21-S03-HW HUB-`, `CU-V04`, `RS21-S03-MC HUB`); group `0x64` port-state and
  status replies; the hub's group `0x0E` parameter table
  (`sim/replay/param_0e_uhub_dev12.json`, from `tools/extract_uhub_tables.py`).
  The idle HID report the bridge emits equals the real hub's idle report.
* **Topology:** behind a Universal Hub only `0x12` (hub) and `0x17` (wheel)
  answer. Nothing answers `0x13` — PitHouse never asks, and the SimHub plugin's
  base polls go unanswered on real hardware — so `kspro_uhub` drops all `0x13`
  traffic.
* **Authored (real bytes never captured):** the HID report descriptors (USBPcap
  started after Windows had read them). The joystick descriptor reproduces the
  captured 42-byte report layout — report ID 1, 8 × u16 axes, hat nibble, 128
  buttons, 8 pad bytes. Interface 3's descriptor is a vendor-defined
  placeholder; its endpoint never carried traffic in any capture.
  The string descriptors are placeholders too.
* **Redacted:** the hub's MCU id (group `0x06`) and serials (group `0x10`).

`tools/sim_golden.py` gates `kspro_uhub` byte-for-byte like the other wheels.

## Verified live (Linux, Wine)

Bridge on Linux, hub attached via `vhci-hcd`, PitHouse and SimHub under Wine,
ESP32 on Wi-Fi (2026-11-06):

* Kernel enumerates `346e:0020 MOZA Racing MOZA Universal Hub` (full speed):
  `cdc_acm` → `/dev/ttyACM*`, `usbhid` on both HID interfaces, joystick on
  `/dev/input/event*` (kernel accepts the authored report descriptor).
* ESP32 BOOT button → Wi-Fi UDP → bridge → hub joystick `BTN_TRIGGER`: 8/8
  presses with matching releases, no sender timeouts over 2 min.
* SimHub (with a real R16 base also connected) opens the hub port and polls
  only the hub's group `0x64` status — expected: the plugin keeps the base as
  primary and treats a hub port as peripherals-only.
* PitHouse shows a **KS Pro with its dashboard list**; zero unhandled frames.

Session-start behaviour seen in that run:

* A PitHouse that had **never seen** the device identified hub + wheel but
  opened no wheel sessions for 5 min — the engine's one-shot `7c:23` page
  announcement had gone out at USB attach, minutes before PitHouse opened the
  port. After a re-plug (fresh engine → fresh `7c:23`) it opened sessions
  within 0.1 s, as in both real KS Pro captures.
* A **restarted** PitHouse opened sessions 12 ms after connecting, with no new
  announcement, and re-ran identity afterwards.
* Hence the bridge restarts the engine ("re-plugs the wheel") when DTR rises
  after ≥ 0.5 s low, counting attach as low. Caveat: PitHouse closing under Wine
  did **not** lower DTR, so this fires on attach / SimHub→PitHouse hand-overs,
  not on a PitHouse restart (which didn't need it). If PitHouse ever sits on a
  detected-but-sessionless wheel, detach + re-attach the hub.

## Limitations / open items

* PitHouse's handling of the authored HID descriptor (e.g. its button-test
  page) is unverified until the real descriptor is dumped from hardware
  (`/sys/kernel/debug/hid/*/rdesc` or `usbhid-dump` on Linux).
* The KS Pro wheel identity and session catalog come from a KS Pro-on-R12
  capture. The engine replays the catalog from
  `usb-capture/ksp/putOnWheelAndOpenPitHouse.pcapng` when that file is present.
  Otherwise it uses the committed extract `sim/replay/kspro_catalog.json`
  (byte-identical, from `tools/extract_catalog_json.py`). It never falls back
  to the synthesised catalog, which differs substantially from the real one.
* The engine child runs with `PYTHONUTF8=1`. `wheel_sim` writes non-ASCII to
  logs opened with the platform default encoding, which is cp1252 on Windows
  before Python 3.15 and would make it fail on the first `→`.
* No feedback path yet: LED colours / telemetry PitHouse or SimHub send to the
  wheel are handled by `wheel_sim`, not forwarded to input devices.
* USB/IP clients other than Linux `vhci-hcd` and usbip-win2 are untested.
