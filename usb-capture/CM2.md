# 2026-05-21 - CM2 Dashboard And LED Learnings


## CM2 Device Model

- CM2 is a standalone USB dashboard, not a wheel-integrated display. The Windows COM device is claimed directly from the MOZA USB inventory.
- SimHub needs a dedicated deployed device profile: `DeviceTemplates/MozaDashCm2/`.
- The telemetry stream target is `0x12` (`CM2 bridge/main`). Some configuration writes are broadcast to `0x14 + 0x12` as a fallback because older dashboard paths target the meter/display id `0x14`.
- A standalone CM2 should report `DisplayDetected: True` with model `S09 Display`; integrated wheel display probing is not applicable.

## Dashboard Management

- CM2 exposes its installed dashboard list through the session `0x09` `configJson` state. This provides `configJsonList`, root paths, image maps, and dashboard metadata.
- Selecting an installed dashboard can activate the corresponding device slot and restart the telemetry stream on `0x12`.
- The dropdown is intentionally a merged local library view: Pit House `_dashes`, a user-selected folder, built-in plugin profiles, and installed CM2 entries.
- Device storage upload is not implemented. Uploading new `.mzdash` files still requires capturing the standalone CM2 file-transfer protocol from Pit House.
- The test pattern proves that dashboard telemetry channels are independent from the physical LED strip: screen RPM/speed widgets can update even when LEDs do not.

## LED Protocol Findings

Legacy dashboard LED commands are not enough for CM2. Captures showed old group `0x32` writes could be echoed/accepted while producing no visible LED effect. The 2026-05-21 01:59 bundle also showed `0x20/0x12` base-ambient live frames being sent repeatedly with no matching `0xA0`/`0xA2` acknowledgments, so that path is now diagnostics-only for CM2.

Current SimHub-mode handling uses the CM2 firmware telemetry path first:

- Set meter normal mode (`0x32/18 00`) to `1` for telemetry mode, `2` for forced-on mode, `0` for off.
- Set RPM group mode (`0x32/11 00`) and flag group mode (`0x32/11 02`) to `1` for telemetry/SimHub mode.
- Set RPM regulation mode (`0x32/0D`) to percent mode and write percentage thresholds with `0x32/05`.
- Also write absolute RPM thresholds with `0x32/0E <index>`, derived from `MaxRpm` or an 8000 RPM fallback, because CM2 percent-vs-absolute mode semantics are not independently verified yet.
- Send the active 16-bit LED mask through the legacy dashboard `dash-send-telemetry` (`0x41 FD DE`) path.
- The CM2 SimHub preset and test-pattern button explicitly enable/restart screen telemetry so the LED tick path is active even if screen telemetry was previously off.

Experimental probes still available from diagnostics:

- CM2 meter config commands from the Pit House parameter database, exposed as `dash-cm2-*` commands in `MozaCommandDatabase`.
- Telemetry-channel override probes for RPM, max RPM, RPM percent, and flags.
- Legacy dashboard telemetry bitmask (`0x41`) for compatibility.
- Experimental live LED color/bitmask probes on `0x20/0x12` (not acknowledged in current CM2 captures).
- Experimental session `0x02` kind `9` color probes.

Pit House database entries that look most relevant are meter write group `50`/`0x32` commands:

| Command intent | Prefix bytes |
| --- | --- |
| Indicator brightness | `17 00 FF` |
| Normal mode | `18 00` |
| Standby mode | `19 00` |
| Standby cycles | `1A 00 <mode>` |
| Standby colors 1-16 | `1B 00 FF <index>` |
| Sleep mode / timeout / breath | `1C` through `20` |
| Startup color | `21` |

Confirmed with the standalone lab on CM2 COM6:

- `dash-cm2-standby-color1..16` (`0x32 / 1B 00 FF <index> + RGB`) sent to bridge/main `0x12` visibly updates all 16 physical LEDs.
- `dash-cm2-indicator-brightness` (`0x32 / 17 00 FF + value`) sent to bridge/main `0x12` visibly changes LED brightness.
- Physical order is logical 1-3 left side bottom-to-top, logical 4-13 top row left-to-right, logical 14-16 right side top-to-bottom.
- Stored color writes persist across CM2 replug/power cycle, so they should be treated as persistent device settings and not used as a high-rate live LED frame transport.
- `dash-cm2-indicator-normal-mode` is accepted; modes `1` and `2` looked visually similar in lab testing without a proven live telemetry LED path.
- Legacy live on/off controls (`0x41 FD DE` bitmask via the lab `mask`/`off` commands) did not visibly affect the LEDs.
- This proves stored color control, brightness, and physical ordering. It strongly suggests CM2 physical LEDs are firmware/stored-register driven rather than host-driven by the legacy bitmask path.

Older-looking CM2 meter entries are also important:

| Command intent | Prefix bytes |
| --- | --- |
| RPM percentage thresholds | `05` (10 bytes) |
| Color-flow/display mode | `07` |
| Burst interval | `0C` |
| RPM regulation mode | `0D` |
| Absolute RPM thresholds | `0E <index>` |
| RPM/flag group mode | `11 00` / `11 02` |
