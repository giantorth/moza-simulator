# ESP32 wireless button box for the MOZA Universal Hub bridge

Turns buttons wired to an ESP32 into KS Pro buttons through
`sim/hub_bridge.py`. It sends Wi-Fi UDP packets carrying its full state on
every change and every 50 ms.

* **Step-by-step setup** (wiring, safe pins, `config.h`, flashing, mapping pins
  to KS Pro buttons): [docs/windows-setup.md](../../docs/windows-setup.md),
  steps 6–10. The pin and mapping parts apply on Linux too. There, run `pio`
  from the project venv and use `/dev/ttyUSB0` instead of `COM5`.
* **Wire protocol and bridge config reference:**
  [docs/hub-bridge.md](../../docs/hub-bridge.md).

Quick version:

```sh
cp include/config.example.h include/config.h   # Wi-Fi, bridge IP, BUTTON_PINS (git-ignored)
pio run -t upload --upload-port <port>
pio device monitor -p <port> -b 115200          # shows device_id + Wi-Fi IP
```

A button's number is its **position in `BUTTON_PINS`** (first entry = button 0
= Windows button 1, before any remapping in the bridge config). Each button is
wired between its GPIO and GND.

Tested: classic ESP32 (ESP32-D0WDQ6, CP2102) on PlatformIO `espressif32` /
Arduino.
