# Session 0x02 UTF-16 dictionary blobs — reverse engineering targets

Status: **not started**. Format is partially visible in sim previews but exact binary layout is unverified. Plugin-side stub not written.

PitHouse pushes two zlib-compressed UTF-16LE dictionary blobs on session 0x02 (in addition to the tier-definition data SimHub already sends):

1. Channel-name dictionary — ~7.2 KB uncompressed
2. Input-action-name dictionary — ~9.9 KB uncompressed

These populate the wheel's dashboard UI lookup tables (so the wheel can render "RpmAbsolute1" instead of a raw channel index, and label pickable wheel actions like "decrementEqualizerGain1"). SimHub does not currently push either — telemetry works without them; only the wheel's native UI loses user-facing names.

## What's known

- Both blobs are zlib-wrapped (standard `78 9C` magic + Deflate + Adler-32).
- Content is UTF-16LE text, strings appear alphabetically ordered within each dictionary.
- Each entry is tagged / length-prefixed (non-zero u16 bytes between strings indicate structure).
- Blob 1 content starts: `RpmAbsolute1`, `RpmAbsolute10`, `RpmAbsolute2`, …, `RpmPercent1`, … → telemetry-channel display names.
- Blob 2 content starts: `decrementEqualizerGain1..6`, `decrementGameForceFeedbackFilter`, … → wheel-action command names.

## What's unknown

### Entry layout

From `sim/logs/uploads/sess02_off<offset>_sz7183.utf16.txt` raw preview:

```
Ȁ\0᠀[UTF-16LE "RpmAbsolute1"]\0\0\0[UTF-16LE "RpmAbsolute10"]\0
ĀЀ\0᠀[UTF-16LE "RpmAbsolute2"]\0\0\0[UTF-16LE "RpmAbsolute3"]\0
```

Interpreting as raw bytes (each \0 = 1 null byte, Ȁ = U+0200 → `00 02` LE, ᠀ = U+1800 → `00 18` LE):

```
02 00 00 00 | 18 00 | R 00 p 00 m 00 A 00 b 00 s 00 o 00 l 00 u 00 t 00 e 00 1 00 00 00
01 00 03 00 | 1A 00 | R 00 p 00 m 00 A 00 b 00 s 00 o 00 l 00 u 00 t 00 e 00 1 00 0 00 00 00
```

Hypothesis:

| Bytes | Field | Notes |
|-------|-------|-------|
| `02 00` | tag or entry-id | u16 LE, increments? |
| `00 00` | reserved / separator | always zero across observed entries |
| `18 00` | byte length of UTF-16 string (not char count) | `"RpmAbsolute1"` = 12 chars × 2 = 24 = 0x18 ✓ |
| `…utf16_bytes…` | string body | no null terminator within the length |
| `00 00` | trailing null (u16) | separator before next entry |

Next entry:

| Bytes | Field | Notes |
|-------|-------|-------|
| `01 00 03 00` | double-tag? `0x0001` + `0x0003`? | Two u16s — maybe `(version, id)` or `(entry_type, entry_id)` |
| `1A 00` | byte length | `"RpmAbsolute10"` = 13 chars × 2 = 26 = 0x1A ✓ |
| `…utf16_bytes…` | string body |
| `00 00` | trailing null |

**Action items**:
1. Extract 30–50 consecutive entries from a clean session 0x02 reassembly and tabulate (tag1, tag2, length, string) — confirm whether the `0x02 00 00 00` / `0x01 00 03 00` pattern is a state machine or an entry-type code.
2. Check if the dictionary has a top-level header (count prefix, version byte) before the first entry.
3. Check for a tail / terminator marker after the last entry.

### Entry ordering

Alphabetical observed on a small sample. Confirm this holds for the full 7.2 KB and 9.9 KB blobs — if not, ordering might encode something else (e.g. display priority).

### Duplication rules

Does the wheel treat repeated pushes of the same dictionary as idempotent, or does it accumulate? Matters because PitHouse might re-push on every connect; SimHub would want the same behaviour.

## Research inputs

| File | Contents | Relevant range |
|------|----------|---------------|
| `usb-capture/latestcaps/automobilista2-wheel-connect-dash-change.pcapng` | 2025-11 firmware, fresh connect | Session 0x02 writes after tier-definition |
| `sim/logs/uploads/sess02_raw.bin` | Reassembled session 0x02 byte stream from last test run | zlib magic locations at start of blob 1 + blob 2 |
| `sim/logs/uploads/sess02_off<offset>_sz7183.utf16.txt` | Decoded channel-name dictionary (UTF-16LE) | Full entry list |
| `sim/logs/uploads/sess02_off<offset>_sz9874.utf16.txt` | Decoded action-name dictionary (UTF-16LE) | Full entry list |

Data sources for building the dictionaries from scratch:

- Channel names: `Telemetry.json` (RS21 parameter DB) has the full channel enumeration. See § Telemetry channel census in `docs/moza-protocol.md`.
- Action names: `usb-capture/rs21_parameter.db` / `rs21_parameter.json` — the `ServiceParameter` table contains action identifiers that match the observed blob 2 content (`decrementEqualizerGain*`, `decrementGameForceFeedbackFilter`, etc.).

## Minimum viable implementation path

1. Write `DictionaryBlobBuilder.cs`:
   - Enumerate channel names from a static list (sourced from `Telemetry.json` census)
   - Sort alphabetically
   - Emit `[tag1 u16][tag2 u16][len u16][utf16le_bytes][null u16]` per entry (format pending confirmation)
2. Write equivalent for action names (source: rs21_parameter.db action enum).
3. Wrap in zlib (same as `TileServerStateBuilder.Compress`).
4. Prepend session 0x02 envelope (separate envelope from session 0x03 — still unverified; extract from pcapng).
5. Chunk via `TierDefinitionBuilder.ChunkMessage(msg, session=0x02, ref seq)` AFTER `SendTierDefinition()` completes.
6. Gate behind `MozaPluginSettings.UploadDictionaryBlobs`, default OFF.

## Priority

**Low**. Wheels work fine for telemetry without the dictionaries — they just display raw channel indices or fallback labels in the wheel's built-in UI. SimHub's typical use case (external dashboard rendered by SimHub's dashboard stack, not the wheel's native UI) is unaffected.

Revisit if:
- Users report the wheel's integrated UI showing blank/generic channel labels when driven from SimHub
- Pithouse-compatible dashboard authoring tools need SimHub to act as a drop-in replacement
