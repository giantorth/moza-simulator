# USB Capture Inventory

All non-text pcapng captures are from **VGS** or **CS** wheels (not CSP). The CSP captures are Wireshark text exports from a different contributor.

**Note:** SimHub plugin captures are from older builds and may be missing features implemented since.

## Root-level (`usb-capture/`)

| File | Software | Wheel | Session opens | Telem flags | Tier config | 28:xx | Keepalives | FD:DE enables |
|------|----------|-------|---------------|-------------|-------------|-------|------------|---------------|
| `cs-to-vgs.pcapng` | PitHouse | CS→VGS swap | none | none | none | 28:00 ×1, 28:01 ×1, 28:02 ×11 | 0x14,0x15,0x17 | 0 |
| `vgs-to-cs.pcapng` | PitHouse | VGS→CS swap | none | none | none | 28:02 ×19 | 0x14,0x15,0x17 | 0 |
| `connect-wheel-start-game.pcapng` | PitHouse | ? | 0x01,0x02,0x03 | 0x02(16B), 0x03(2B), 0x04(13B) | s=0x01: VERSION v=2, TIER 0x00/0x01, END total=0, ENABLE 0 | 28:00 ×1, 28:01 ×1, 28:02 ×204 | 0x14,0x15,0x17 | 1940 |

### Observations
- **cs-to-vgs**: No session opens, no telemetry, no enables — capture starts mid-swap, only config/keepalive traffic
- **vgs-to-cs**: Same — mid-swap, no telemetry flowing
- **connect-wheel-start-game**: Full startup with tier config on session 0x01 (not 0x02). Version 2 tier defs, flags 0x02-0x04

## `09-04-26/` — PitHouse mid-session captures

All mid-session — no session opens, no tier definitions.

| File | Dashboard | Telem flags | 28:xx | FD:DE |
|------|-----------|-------------|-------|-------|
| `burn-tyres.pcapng` | F1 | 0x0a(16B), 0x0b(2B), 0x0c(13B) | 28:02 ×253 | N/A* |
| `0-100redline-0-main-dash.pcapng` | F1 | 0x13(16B), 0x14(2B), 0x15(13B) | 28:02 ×46 | N/A* |
| `0-100redline-0-other-dash.pcapng` | "other" | 0x02(6B), 0x03(3B) | 28:02 ×33 | 504 |
| `0-100redline-0-simple-rpm-dash.pcapng` | simple RPM | 0x07(2B) | 28:02 ×35 | N/A* |
| `0-6thgear-0-main-dash.pcapng` | F1 | 0x0a(16B), 0x0b(2B), 0x0c(13B) | 28:02 ×129 | N/A* |
| `0-6thgear-0-simple-rpm-dash.pcapng` | simple RPM | 0x10(2B) | 28:02 ×131 | 1937 |
| `dash-upload.pcapng` | (upload) | none | 28:00 ×3, 28:01 ×3, 28:02 ×30 | N/A* |

*N/A = analyzed in earlier pass, enable count not re-extracted here

### Observations
- **"other" dashboard** has only 2 tiers: 0x02(6B) and 0x03(3B) — smaller channel set
- **Simple RPM** has only 1 tier (2B) — just RPM value
- Flag bytes are all over the map (0x02, 0x07, 0x0a, 0x10, 0x13) — monotonic counter per session

## `12-04-26/` — First comparative capture set

| File | Software | Session opens | Telem flags | Tier config | Keepalives |
|------|----------|---------------|-------------|-------------|------------|
| `moza-startup.pcapng` | PitHouse | 0x01,0x02,0x03 | 0x00(6B), 0x02(16B), 0x03(2B), 0x04(13B) | s=0x02: VERSION v=2, flags 0x00-0x04 | 0x14,0x15,0x17 |
| `simhub-startup.pcapng` | SimHub (old build) | none | 0x01(16B), 0x02(13B) | none | 0x14,0x15 only |

### Observations
- **simhub-startup**: No session opens detected — old build may not have had port probing. Only 2 tiers, flags 0x01-0x02. **Missing 0x17 keepalive.**

## `12-04-26-2/` — Second comparative capture set

Game: Assetto Corsa. See `readme.txt` for exact test steps per capture.

| File | Software | Session opens | Telem flags | Tier config | Keepalives |
|------|----------|---------------|-------------|-------------|------------|
| `moza-startup-1.pcapng` | PitHouse | 0x01,0x02,0x03 | 0x00(11B), 0x03(16B), 0x04(2B), 0x05(13B) | s=0x02: VERSION v=2, CRC all valid, flags 0x00-0x05 | 0x14,0x15,0x17 |
| `moza-startup-2.pcapng` | PitHouse | 0x01,0x02,0x03 | 0x00(16B), 0x03(16B), 0x04(2B), 0x05(13B) | s=0x02: VERSION v=2, CRC all valid, flags 0x00-0x05 | 0x14,0x15,0x17 |
| `moza-unplug-plug-wheel-to-base.pcapng` | PitHouse | 0x01,0x02,0x03 | 0x00(2B), 0x02(16B), 0x03(16B), 0x04(2B), 0x05(13B) | s=0x01: sentinels (dashboard re-upload) | 0x14,0x15,0x17 |
| `simhub-startup-1.pcapng` | SimHub (old build) | 0x01-0x09 | 0x09(16B), 0x0a(2B), 0x0b(13B) | s=0x09: tag 0x00 enables, tag 0x01 tier defs (flags 0x09+) | 0x14,0x15,0x17 |
| `simhub-startup-2.pcapng` | SimHub (old build) | 0x01-0x0a | 0x0a(16B), 0x0b(2B), 0x0c(13B) | not found (CRC invalid?) | 0x14,0x15 only (0x17 ×3) |
| `simhub-enable-disable-dash-telemetry.pcapng` | SimHub (old build) | none | 0x0a(16B), 0x0b(2B), 0x0c(13B) | none | 0x14,0x15 only |
| `simhub-test-pattern.pcapng` | SimHub (old build) | none | 0x08(16B), 0x09(2B), 0x0a(13B) | none | 0x14,0x15 only |

### Observations
- **SimHub captures are from an older build** and may be missing features since implemented (CRC on all chunks, sub-message 1 preamble, 0x17 keepalive, etc.)
- **simhub-startup-1**: Probed ports 0x01-0x09 (9 probes), landed on port 0x09. Tier config used flags 0x09+ (session-port-based, the old behavior before the flag byte fix)
- **simhub-startup-2**: Probed ports 0x01-0x0a (10 probes), landed on port 0x0a. Tier config CRC may have been invalid (old build without CRC-on-all-chunks fix)
- **simhub-enable-disable / test-pattern**: Mid-session, no startups. Different flag bytes between captures (0x0a vs 0x08) because they were separate sessions

## `CSP captures/` — CSP wheel (Wireshark text exports)

Different wheel model, different contributor. All files are Wireshark verbose text exports.

| File | Size | Software | Scenario | Analyzed? |
|------|------|----------|----------|-----------|
| `pithouse-complete.txt` | 189M | PitHouse | Full session | Yes — v0 URL tier defs, flags 0x00/0x02/0x04/0x05 |
| `disp-start.txt` | 50M | ? | Display startup | Device not found in first 5000 frames |
| `disp0.txt` | 47M | ? | Display related | Device not found in first 5000 frames |
| `moza-init.txt` | 486M | PitHouse? | Full initialization | Not analyzed (very large) |
| `automobilista-full.txt` | 289M | PitHouse | Full game session | Not analyzed |
| `automobilista-full-pitlane-pithouse-start.txt` | 446M | PitHouse | Game + PitHouse start | Not analyzed |
| `automobilista-pitlane.txt` | 142M | PitHouse | Pitlane session | Not analyzed |
| `automobilista-sleep-resume.txt` | 106M | PitHouse | Sleep/resume | Not analyzed |
| `pithouse-dash-brightness.txt` | 35M | PitHouse | Brightness adjustment | Not analyzed |
| `pithouse-dash-switch-display.txt` | 72M | PitHouse | Dashboard switch | Device not found in first 5000 frames |
| `pithouse-gear-speed-rpm.txt` | 194M | PitHouse | Telemetry active | Not analyzed |

### Observations
- **pithouse-complete**: Uses protocol version 0 (URL-based tier definitions, tag 0x04 with channel URLs). 20 channels subscribed. Tag 0x03 value=1 (vs value=0 in VGS version 2).
- **disp-start, disp0, dash-switch-display**: Device detection failed in initial scan — may need full-file scan or different USB topology

## `startupchime/` — R25 base chime & LED settings

PitHouse adjusting startup chime selection, volume, enable/disable, and base ambient LED effects.

| File | Scenario | Key commands |
|------|----------|--------------|
| `Wheel Base Chimes part 1.pcapng` | Cycling chimes 1–5 (set + preview each) | `0x2A` music-index-set, music-preview |
| `Wheel Base Chimes Part 2.pcapng` | Cycling chimes 6–10 | `0x2A` music-index-set, music-preview |
| `Wheel Base Chimes Settings.pcapng` | Enable/disable toggle + volume 0↔255 | `0x2A` music-enabled-set, music-volume-set |
| `Moza R25 Wheel Base Settings Part 1.pcapng` | Full LED read + standby mode cycling 0–4 | `0x22` read all, `0x20` standby-mode writes |
| `Wheel Base Settings Part 2.pcapng` | Standby mode 5 (flow) + back to 0 | `0x20` standby-mode writes |

| `R25 LED Telemetry.pcapng` | Base LEDs driven as RPM bar during game | `0x20` live-color (1A), live-bitmask (1B); `0x1F` status polls |

### Observations
- **10 built-in chimes** indexed 1–10 (0x01–0x0A). Default volume 0x17 (23).
- **PitHouse workflow:** `music-index-set(N)` → `music-preview(N)` on each selection change.
- **6 standby LED modes** (0–5): constant, ?, breath, cycle, rainbow, flow. Mode 1 name unknown.
- **Per-mode interval registers** written independently of mode selection (`1E [mode] [u16be ms]`).
- **Dual write response:** group `0x20` writes get both `0xA0` ACK and `0xA2` read-notify.
- **Brightness cmd discrepancy:** DB says `1F 02`, PitHouse uses `1F FF` on wire.
- **Live RPM indicator:** cmd `0x1A` sends color chunks (up to 5 LEDs per chunk, green→yellow→red→magenta gradient), cmd `0x1B` sends LE u32 bitmask (bits 0–8 for 9 LEDs). Bitmask every frame, colors only on change. Each strip independently addressable (PitHouse mirrors both).
- **Group `0x1F`** polled at ~10 Hz: status registers `4F 08/09/0A/0B` (all return `FF 00`), brightness readback `4D` → `64`.

## Cross-capture summary

### PitHouse tier config patterns (all captures with session opens)

| Capture | Config session | Protocol version | First batch flags | Second batch flags | Telem flags |
|---------|---------------|------------------|-------------------|--------------------|----|
| moza-startup-1 | 0x02 | v2 | 0x00,0x01,0x02 | 0x03,0x04,0x05 | 0x00,0x03,0x04,0x05 |
| moza-startup-2 | 0x02 | v2 | 0x00,0x01 | 0x03,0x04,0x05 | 0x00,0x03,0x04,0x05 |
| moza-startup (12-04-26) | 0x02 | v2 | 0x00,0x01 | 0x02,0x03,0x04 | 0x00,0x02,0x03,0x04 |
| connect-wheel-start-game | 0x01 | v2 | 0x00,0x01 | 0x02,0x03,0x04 | 0x02,0x03,0x04 |
| CSP pithouse-complete | 0x02 | v0 (URLs) | N/A | N/A | 0x00,0x02,0x04,0x05 |

### Key differences: PitHouse vs SimHub plugin (old build)

| Aspect | PitHouse | SimHub (old build) |
|--------|----------|--------------------|
| Session opens | 2-3 ports (0x01,0x02,0x03) | 9-10 ports (0x01-0x0a) |
| Flag bytes | Monotonic from 0x00 (two batches) | Session-port-based (0x09+) |
| Tier config CRC | All chunks have CRC (verified) | Final chunk may lack CRC (old bug) |
| Sub-message 1 | Always present (tag 0x07 v=2, tag 0x03 v=0) | Not sent (old build) |
| 0x17 keepalive | Always present | Often missing |
| 28:00/28:01 | Sent at startup | Not sent (old build) |

## `fsr1/` — FSR / RS21-D03 display wheel (firmware variant)

USBPcap captures of a Moza **`FSR`** display wheel (hw `RS21-D03-HW FW-C`, sw
`RS21-D03-MC FW`, box name "FSR1"), hub-attached (`0x12`/`0x21`, hub model `S03 HUB`).
Software is PitHouse. This firmware uses a **fundamentally different display-telemetry
path** from the VGS/CS/CSP/Type02 eras: no session opens, no tier-definition / channel
catalog advertisement (v0 or v2), no `0x41` `FD DE` enable, no `0x43`/`7D 23` value
stream. Live display values are pushed via the otherwise-undocumented **group `0x42`**
(see [`../docs/protocol/devices/wheel-0x17.md`](../docs/protocol/devices/wheel-0x17.md)
§ Group 0x42). Group `0x43` carries only a 1-byte cmdid-`00` keepalive poll.

| File | MOZA frames | Duration | Scenario | Session opens | Catalog advert | FD:DE | Group 0x42 |
|------|-------------|----------|----------|---------------|----------------|-------|------------|
| `FSR1 with game.pcapng` | 20658 | 310.5 s | live gameplay + startup identity probe | none | none | 0 | 8828 (type `02` hot) |
| `FS1 multiple changes.pcapng` | 28884 | 445.9 s | brightness / dashboard / multiple settings changes | none | none | 0 | 10585 (types `06`/`0e` hot) |
| `Moza FSR1 dashboard change.pcapng` | 5030 | 84.6 s | dashboard-switch scenario | none | none | 0 | 24 (startup type enumeration) |
| `dashboard change through pithouse, connected to base..pcapng` | 1273 | 22.0 s | PitHouse dashboard switch, **base-attached** | none | none | 0 | 8 (enumeration only — no gameplay) |
| `Manual dashboard change - Pithouse opened.pcapng` | 621 | 22.4 s | **wheel-initiated** dash switch, PitHouse open | none | none | 0 | 7 (enumeration only) |
| `Basic settings change with pithouse opened connected to hub.pcapng` | 1110 | 25.6 s | settings change via PitHouse (hub) | none | none | 0 | 0 (no gameplay → no push) |
| `manual settings change with pithouse opened, CONNECTED TO BASE.pcapng` | 1017 | 15.1 s | settings change via PitHouse (base) | none | none | 0 | 0 (no gameplay → no push) |
| `Manual dashboard change - Pithouse closed.pcapng` | 0 | — | **wheel-initiated** dash switch, **PitHouse closed** | — | — | — | 0 — HID-only (no bulk serial) |
| `manual change connected to BASE - PITHOUSE CLOSED.pcapng` | 0 | — | wheel-side changes, PitHouse closed (base) | — | — | — | 0 — HID-only |
| `manual dashboard change and setting change from wheel while connected to base..pcapng` | 0 | — | wheel-side dash + settings, PitHouse closed (base) | — | — | — | 0 — HID-only |
| `Basic settings change (WITHOUT pithouse) connected to hub.pcapng` | 0 | — | wheel-side settings, no PitHouse (hub) | — | — | — | 0 — HID-only |

### Observations
- **No catalog advertisement of any version.** 0 wheel→host `0xC3` frames, 0 `7C 00`
  session opens across all captures — the wheel never negotiates a channel catalog.
- **Group `0x41` absent** in all captures (the documented `FD DE` enable is never sent).
- **Group `0x3F`** live LED telemetry is exercised (`1A` RPM/button/knob bitmasks +
  `19` live colors); **group `0x40`** carries a full config sweep (reply `0xC0`).
- **`0x42` hot-streaming requires active gameplay.** Only `FSR1 with game` and
  `FS1 multiple changes` (running game) stream live values; the dashboard-switch and
  settings-change captures show at most the startup type *enumeration* (declaration
  frames), and the settings-only captures show no `0x42` at all.
- **PitHouse owns the bulk-serial push — wheel-side input is USB HID.** Every
  *PitHouse-closed* capture (`manual …`/`WITHOUT pithouse`) contains **0 bulk-serial
  MOZA frames**: a wheel-initiated dashboard/settings change produces no serial traffic
  at all, only HID (not extracted here). With PitHouse open, a wheel-initiated switch
  (`Manual dashboard change - Pithouse opened`) is reflected only as a host→wheel `0x42`
  type re-enumeration — there is **no wheel→host switch frame on the serial bus**. This
  confirms the wheel signals dashboard switches over HID and PitHouse (the host) reacts;
  see [`../docs/protocol/devices/wheel-0x17.md`](../docs/protocol/devices/wheel-0x17.md)
  § Group 0x42.
- Both **hub-attached** (`0x12`/`0x21`, `S03 HUB`) and **base-attached** topologies are
  represented.
- Identity probe (model `FSR`, hw `RS21-D03-HW FW-C`, sw `RS21-D03-MC FW`, rev `U-V04`,
  serial present) appears only in `FSR1 with game.pcapng`. Decode tooling:
  `tools/pcap_to_jsonl.py`, `tools/fsr1-inventory`, `tools/fsr1-0x42-extract`,
  `tools/fsr1-field-decode`.
