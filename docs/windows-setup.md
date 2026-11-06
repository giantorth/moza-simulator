# Windows setup from scratch: ESP32 buttons as a MOZA KS Pro

This guide takes a Windows PC with nothing installed to a working setup where
buttons wired to an ESP32 show up on Windows, in games and in MOZA Pit House
as the buttons of a **KS Pro wheel on a MOZA Universal Hub**.

How it fits together:

```
 buttons ─ ESP32 ──Wi-Fi (UDP)──► hub_bridge.py ──USB/IP──► usbip-win2 ──► Windows
                                  (on this PC)               (driver)       │
                                                                            ├─ COM port  → Pit House / SimHub
                                                                            └─ joystick  → games, joy.cpl
```

`hub_bridge.py` emulates the hub and wheel in software. **usbip-win2** turns it
into what Windows sees as a real USB device plugged into this PC.

> **Status.** Every piece was verified end to end on Linux, with Pit House and
> SimHub running under Wine and an ESP32 on Wi-Fi. Pit House showed a KS Pro
> with its dashboard. The Windows path (usbip-win2 attaching to the bridge on
> the same PC) has **not been tested yet**. If a step below fails, the
> troubleshooting table at the end says what to check, and a report helps.

---

## What you need

| Item | Notes |
|---|---|
| Windows 10 x64 (version 1903 or later) or Windows 11 | the usbip-win2 requirement |
| ESP32 development board | a **classic ESP32** (ESP32-WROOM-32 / "ESP32 DevKit") is what the firmware targets. Tested: ESP32-D0WDQ6 with a CP2102 USB chip |
| USB **data** cable for the ESP32 | charge-only cables are a common cause of "no COM port" |
| Momentary push buttons and wire | each button connects one ESP32 pin to GND, no resistors needed |
| 2.4 GHz Wi-Fi | the ESP32 has no 5 GHz radio. The PC can be wired, as long as the ESP32 can reach it over the network |
| MOZA Pit House (optional) | only needed to see the wheel in Pit House. Games just need the joystick |

All commands below are typed into **PowerShell** (Start menu → "PowerShell").

---

## 1. Install Python and Git

1. Install Python 3.12 or newer from <https://www.python.org/downloads/windows/>.
   On the installer's first page, **tick "Add python.exe to PATH"**.
   You can use `winget install Python.Python.3.13` instead.
2. Install Git: `winget install Git.Git`, or the installer from <https://git-scm.com>.
3. Close PowerShell and open a new one so both are on the PATH. Then check:

   ```powershell
   py --version
   git --version
   ```

## 2. Get the code and its Python packages

```powershell
cd $HOME
git clone https://github.com/giantorth/moza-simulator.git
cd moza-simulator
py -m venv .venv
.venv\Scripts\python -m pip install pyserial pysdl2 pysdl2-dll platformio
```

* `.venv` is a private Python environment for this project. Every command
  below calls `.venv\Scripts\python` (or `pio`) directly, so you never need to
  "activate" it.
* `pyserial` is for the KS Pro protocol engine, `pysdl2` and `pysdl2-dll` are
  for optional USB controllers, and `platformio` builds and flashes the ESP32.

> All later commands assume you are in the `moza-simulator` folder
> (`cd $HOME\moza-simulator`).

## 3. Install usbip-win2 (the virtual USB driver)

1. Go to <https://github.com/vadimgrn/usbip-win2/releases/latest> and download
   the installer from **Assets**. At the time of writing the latest release is
   0.9.8.1.
2. The usbip-win2 README recommends **creating a System Restore point** first.
   During installation **all USB 3.0 hubs restart**, so USB devices
   (including keyboard and mouse) drop out for a moment.
3. Run the installer. Current releases ship Microsoft-signed (WHLK or
   attestation) x64 drivers, so test-signing mode should **not** be needed.
   Their README says to enable it only *"if drivers are not signed by
   Microsoft"*. If the installer warns about it, follow the usbip-win2 README.
4. The command-line tool is `usbip.exe`. Open a new PowerShell and check
   that it's on the PATH:

   ```powershell
   Get-Command usbip.exe
   ```

   If PowerShell can't find it, use the full path to `usbip.exe` in the
   installer's install folder in the commands below.

## 4. Find this PC's IP address

```powershell
ipconfig
```

Write down the **IPv4 Address** of the adapter that connects to your network
(e.g. `10.0.1.48` or `192.168.1.20`). The ESP32 sends its button presses to
this address.

> If your router can, give the PC a fixed (reserved) address. If it changes,
> the ESP32 must be re-flashed with the new one.

## 5. Let the ESP32's packets through Windows Firewall

The bridge listens for the ESP32 on **UDP port 34200**. Open an
**Administrator** PowerShell (right-click PowerShell → *Run as administrator*)
and run:

```powershell
netsh advfirewall firewall add rule name="MOZA hub bridge (ESP32 UDP 34200)" dir=in action=allow protocol=UDP localport=34200 profile=private
```

This allows the port on **Private** networks only. Check under *Settings →
Network & internet → (your connection) → Network profile type* that your
network is **Private**.
Alternatively, accept the "Allow access" prompt for `python.exe` (Private
networks) that Windows may show the first time the bridge runs.

The USB/IP connection only uses `127.0.0.1` (this PC), so it needs no firewall rule.

---

## 6. Wire the buttons to the ESP32

Wire each button **between one GPIO pin and GND**. The firmware turns on the
ESP32's internal pull-up, so the pin reads "pressed" when the button connects it
to ground. No resistors and no 3.3 V wire are needed for buttons.

```
 ESP32 GPIO13 ──────┤ button ├────── ESP32 GND
 ESP32 GPIO14 ──────┤ button ├────── ESP32 GND     (all buttons can share one GND wire)
```

### Which pins to use (classic ESP32)

| Pins | Use for buttons? |
|---|---|
| **4, 13, 14, 16, 17, 18, 19, 21, 22, 23, 25, 26, 27, 32, 33** | ✅ Yes, recommended (15 pins). On ESP32-**WROVER** boards, 16 and 17 are used by PSRAM, so skip them |
| 0 | Only as the on-board **BOOT** button, which is already wired. Don't hold it while the board resets |
| 2, 5, 12, 15 | ⚠️ Avoid. These are boot-strapping pins and can stop the board booting or flashing |
| 34, 35, 36 (VP), 39 (VN) | Input-only with **no internal pull-up**. Usable only with an external 10 kΩ resistor from the pin to **3V3** |
| 1, 3 | ❌ No. USB serial (programming and log output) |
| 6 – 11 | ❌ Never. Connected to the board's flash chip |

The pin labels on the board (`D13`, `IO13`, `G13`, `13`) all mean GPIO13.

### Optional: hat switch (D-pad)

Four buttons (up, right, down, left), wired like any other button, become one
**hat switch** (POV) in Windows. Assign their pins with `HAT_UP_PIN` …
`HAT_LEFT_PIN` in step 7.

### Optional: analog axes (potentiometers, clutch paddles)

Wire a potentiometer's outer legs to **3V3** and **GND** (never 5 V) and its
middle leg (wiper) to an **ADC1 pin: 32, 33, 34, 35, 36 or 39**.
ADC2 pins (e.g. 25, 26, 27) **don't work while Wi-Fi is on**.

---

## 7. Configure the firmware: which pin is which button

The firmware config is a small text file, `config.h`. Create it from the example:

```powershell
cd firmware\esp32_wheel_buttons
copy include\config.example.h include\config.h
notepad include\config.h
```

`config.h` is ignored by git, so your Wi-Fi password is never committed.
Set these values:

```c
#define WIFI_SSID      "your-2.4GHz-network"
#define WIFI_PASSWORD  "your-password"
#define BRIDGE_HOST    "10.0.1.48"     // the PC's IPv4 address from step 4
#define BRIDGE_PORT    34200

// The POSITION in this list is the ESP32 button number: first entry = button 0.
static const int BUTTON_PINS[] = {0, 13, 14, 16, 17};

#define HAT_UP_PIN     -1              // -1 = not used
#define HAT_RIGHT_PIN  -1
#define HAT_DOWN_PIN   -1
#define HAT_LEFT_PIN   -1

static const int AXIS_PINS[] = {-1};   // e.g. {34, 35, -1}; keep the trailing -1
```

**The one rule to remember:** a button's number is its **position in
`BUTTON_PINS`**, starting at 0. The GPIO number doesn't decide it. With
`{0, 13, 14, 16, 17}`:

| `BUTTON_PINS` position | GPIO | ESP32 button | KS Pro button (default) | Windows shows |
|---|---|---|---|---|
| 1st | 0 (BOOT) | 0 | 0 | Button **1** |
| 2nd | 13 | 1 | 1 | Button **2** |
| 3rd | 14 | 2 | 2 | Button **3** |
| 4th | 16 | 3 | 3 | Button **4** |
| 5th | 17 | 4 | 4 | Button **5** |

Keeping GPIO0 (BOOT) as the first entry is handy: the board's own BOOT button
gives you a test button before anything is wired.

By default ESP32 button *N* becomes KS Pro button *N*, which Windows shows as
button *N + 1* (Windows counts from 1). Step 10 shows how to renumber buttons
without re-flashing.

Limits: up to **128 buttons** and **8 axes** per ESP32. The firmware reads one
pin per button (no matrix), so one classic ESP32 handles about 15 buttons with
internal pull-ups. For more, use a second ESP32 (step 10) or the 34–39 pins with
external resistors.

## 8. Flash the ESP32

1. Plug in the ESP32. In **Device Manager → Ports (COM & LPT)** it appears as
   e.g. *Silicon Labs CP210x USB to UART Bridge (COM5)* or *USB-SERIAL CH340
   (COM5)*. Note the **COM number**.
   * If it appears as an unknown device instead, install the USB driver for the
     chip printed on the board: **CP210x** (Silicon Labs) or **CH340/CH341** (WCH).
   * If nothing appears at all, try another cable. It may be charge-only.
2. Build and upload. You should still be in `firmware\esp32_wheel_buttons`.
   The first build downloads the ESP32 toolchain and takes a few minutes.

   ```powershell
   ..\..\.venv\Scripts\pio run -t upload --upload-port COM5
   ```

   It ends with `Hash of data verified.` and `[SUCCESS]`. If it stalls at
   `Connecting....`, hold the board's **BOOT** button until writing starts.
3. Watch the board start up:

   ```powershell
   ..\..\.venv\Scripts\pio device monitor -p COM5 -b 115200
   ```

   Press the board's **EN/RST** button. You should see:

   ```
   device_id=0xd815b80c session=0x42f423ce buttons=5 axes=0
   Wi-Fi: connecting to your-2.4GHz-network.....
   Wi-Fi: 10.9.1.134
   ```

   **Write down the `device_id`.** It identifies this ESP32 in the bridge
   config. Exit the monitor with `Ctrl+C`.
   If it prints dots forever, the SSID or password is wrong, or the network is
   5 GHz only.

Return to the project folder: `cd ..\..`

## 9. Start the bridge

```powershell
copy sim\uhub_bridge.example.json my_bridge.json
.venv\Scripts\python sim\hub_bridge.py --config my_bridge.json -v
```

The example config already accepts any ESP32 with the default numbering. Step
10 explains how to change it. Within a second of starting you should see:

```
MOZA Universal Hub bridge ready — USB/IP 127.0.0.1:3240 busid 1-1
… uhub.udp  INFO  UDP sender d815b80c connected from 10.9.1.134 (session …)
```

With `-v`, every press is logged, e.g. `report buttons=[0] hat=8`. That's the
quickest way to check wiring and numbering, before Windows is involved at all.

Leave this window open. The bridge runs until you press `Ctrl+C`.

## 10. Map ESP32 buttons to KS Pro buttons (bridge config)

Renumbering happens in `my_bridge.json`, so you **don't re-flash** to change
it. Restart the bridge after editing.

The `udp.devices` section has one entry per ESP32 `device_id`, plus `"*"`, the
default for any ESP32 not listed. All numbers are **0-based KS Pro buttons**.
Windows shows button *N* as *N + 1*.

```json
"udp": {
  "enabled": true,
  "bind": "0.0.0.0",
  "port": 34200,
  "timeout_ms": 500,
  "allow": [],
  "devices": {
    "*": {},
    "0xd815b80c": {
      "button_offset": 0,
      "buttons": {"0": 10, "3": 20, "4": null},
      "hat": true
    }
  }
}
```

| Key | What it does | Example |
|---|---|---|
| `button_offset` | Every ESP32 button *i* not listed in `buttons` becomes KS Pro button *i + offset* | `32`: ESP32 button 0 → KS Pro 32 (Windows 33) |
| `buttons` | Explicit `"esp32 button": ks_pro_button` pairs. `null` disables that button | `{"0": 10}`: BOOT/first pin → KS Pro 10 (Windows 11) |
| `only_mapped_buttons` | `true` = ignore every button not listed in `buttons` | |
| `hat` | `false` = ignore this ESP32's hat switch | |
| `axes` | `{"esp32 axis": {"to": slot, "invert": false}}`. Slots: 0 X, 1 Y, 2 Z, 3 Rx, 4 Ry, 5 Rz, 6 Slider, 7 Dial. If omitted, axis *i* → slot *i* | `{"0": {"to": 6}}` |

With the example above and `BUTTON_PINS = {0, 13, 14, 16, 17}`:

| Pin | ESP32 button | Rule applied | KS Pro button | Windows |
|---|---|---|---|---|
| GPIO0 (BOOT) | 0 | `buttons` 0 → 10 | 10 | 11 |
| GPIO13 | 1 | offset 0 | 1 | 2 |
| GPIO14 | 2 | offset 0 | 2 | 3 |
| GPIO16 | 3 | `buttons` 3 → 20 | 20 | 21 |
| GPIO17 | 4 | `null` | — (disabled) | — |

**Several ESP32s** all merge into the **same** KS Pro, so give each its own
range with `button_offset`. Otherwise the same numbers overlap, and both
devices press the same buttons.

```json
"devices": {
  "0xd815b80c": {"button_offset": 0},
  "0x4a7c2e11": {"button_offset": 32}
}
```

**`allow`** optionally limits which senders are accepted, as a list of network
ranges, e.g. `["10.9.1.0/24"]`. Leave it `[]` to accept any sender. Anything
that can reach UDP port 34200 can press buttons, so restrict it if your network
isn't private. If you set it, it must include the ESP32's address from step 8,
or its packets are silently ignored.

Which KS Pro number matches which physical control on a *real* KS Pro rim isn't
known. Games bind buttons by number, so this only matters if you want a
layout identical to a real KS Pro.

## 11. Attach the virtual hub to Windows

Open a **second** PowerShell, leaving the bridge running in the first. Run it
as Administrator if the command below reports an access error; the usbip-win2
docs don't say whether attach needs it.

```powershell
usbip.exe attach -r 127.0.0.1 -b 1-1
```

The expected reply is `successfully attached to port 1` (the port number may
differ). The bridge window logs `attached 1-1` and
`host attached — starting kspro_uhub engine`, and Windows plays its
device-connected sound.

## 12. Check it in Windows

1. **Device Manager**:
   * *Ports (COM & LPT)* shows a new **USB Serial Device (COMx)**. That's the
     hub's MOZA serial port.
   * *Human Interface Devices* / *Game controllers* show the HID game controller.
2. **Game Controllers test**: press `Win+R`, type `joy.cpl`, Enter. Select the
   MOZA hub's controller → *Properties*, then press the ESP32 buttons. It should
   be named **MOZA Universal Hub**: that's the bridge's product string. The real
   hub's string was never captured, so this one is a placeholder. The
   numbered lights should match the table from step 10.
   This page only displays the first 32 buttons. For higher numbers, watch the
   bridge's `-v` log instead.
3. If the controller shows but buttons don't light, check the bridge window for
   `UDP sender … connected`. If that line is missing, see "troubleshooting".

## 13. Pit House (optional)

Start Pit House. It should list a **KS Pro** with its dashboard, behind a
Universal Hub.

* If Pit House shows the wheel but no dashboards for more than a few seconds,
  re-plug the virtual hub. Run `usbip.exe detach -p 1`, then the attach command
  from step 11 again. A Pit House that has never seen this device before needed
  that once in testing.
* **Decline any firmware update** Pit House offers for the hub or wheel. The
  devices are emulated, and nobody has tested what an update attempt would do.
* The SimHub MOZA plugin (AZOM) also finds the hub. If a real MOZA wheelbase is
  connected too, the plugin keeps the base as its main device and only polls
  the hub for peripherals.

## 14. Stopping, and starting again next time

Stop: detach first, then stop the bridge.

```powershell
usbip.exe detach -p 1        # or: usbip.exe detach -all
```

Then press `Ctrl+C` in the bridge window.

usbip-win2 retries attachments in the background after a disconnect. If it
keeps re-attaching after you've stopped, run
`usbip.exe attach --remote 127.0.0.1 --bus-id 1-1 --stop`.

**Every session after the first:**

1. `cd $HOME\moza-simulator`
2. `.venv\Scripts\python sim\hub_bridge.py --config my_bridge.json`
3. In a second window: `usbip.exe attach -r 127.0.0.1 -b 1-1`
4. Power the ESP32 (USB charger or PC port). It reconnects by itself.
5. Start Pit House / your game.

---

## Troubleshooting

| Symptom | Check |
|---|---|
| ESP32 not in Device Manager | data cable; CP210x/CH340 driver (step 8) |
| Upload stalls at `Connecting....` | hold **BOOT** until writing starts; close any open serial monitor using the COM port |
| Monitor prints `Wi-Fi: connecting....` forever | SSID/password in `config.h`; the network must be 2.4 GHz |
| Bridge never logs `UDP sender … connected` | `BRIDGE_HOST` is the PC's current IPv4 (step 4)? firewall rule and *Private* network profile (step 5)? `allow` list includes the ESP32's address? guest/IoT Wi-Fi with "client isolation" can block traffic to the PC |
| `connected` then `timed out — releasing its inputs` repeatedly | weak Wi-Fi; the bridge releases buttons after 500 ms of silence. Move closer or raise `timeout_ms` |
| Wrong button numbers | the first `BUTTON_PINS` entry is button 0; Windows counts from 1; check `button_offset`/`buttons` for this `device_id` |
| Button stuck in Windows | can't come from a dropped packet: every packet carries full state and silence releases everything. Check the bridge `-v` log to see whether the ESP32 is still reporting it pressed (wiring short to GND?) |
| `usbip.exe attach` fails | is the bridge running and showing `bridge ready`? retry from an Administrator PowerShell; with a non-default `--usbip-port`, pass it to usbip.exe too |
| `address already in use` on start | another program is using port 34200 (ESP32) or 3240 (USB/IP). For 34200: start with `--udp-port 34201` and set `BRIDGE_PORT` in `config.h` to match. 3240 is the standard USB/IP port: stop whatever else is using it. These docs don't cover pointing usbip-win2 at a different port |
| Pit House sees the wheel but no dashboards | detach and re-attach (step 13) |
| Wheel protocol problems | `sim\logs\hub_bridge_engine.log` and `sim\logs\wheel_sim.log` |

Background and technical details are in [hub-bridge.md](hub-bridge.md).
