# Tile-server JSON upload — reverse engineering targets

Status: **envelope decoded 2026-04-21**. JSON content known, zlib framing known, 12-byte envelope **reversed from live Pithouse capture**. Ready to implement.

Session number depends on firmware (verified 2026-04-26 against `ksp/mozahubstartup.pcapng`):

| Firmware | Host → Wheel push | Wheel → Host mirror | PitHouse exposes? |
|---|---|---|---|
| 2025-11 (VGS, CSP, older displays) | session **0x03** | session 0x0a (small JSON, wheel-side `root: "/home/moza/resource/tile_map/"`) | yes — Map area in PitHouse UI |
| 2026-04+ (KS Pro) | session **0x04** | session **0x0b** (12-byte envelope, sizes 398/718/727 in mozahubstartup capture; wheel-side path `/home/moza/resource/tile_map//`) | **no — KS Pro display does not support map UI in PitHouse**; data observed in pcap is mozahub's startup-time push that the wheel echoes but never renders |

Same 12-byte envelope shape on both directions on both firmwares.

**KS Pro implication (user-confirmed 2026-04-27):** PitHouse does not give the user a "send map data" option for KS Pro wheels — the display module doesn't render a tile-server map area. The session 0x04 host→dev tile-server push observed in `mozahubstartup.pcapng` is mozahub pushing its own client-side state to the wheel as part of every connect cycle (regardless of whether the wheel can use it), and the wheel emits a corresponding 0x0b mirror as a no-op. Plugin should NOT send tile-server data on KS Pro. Sim's `TileServerStateBuilder` should skip emission when `_configjson_session == 0x0a` (KS Pro sentinel).

Plugin-side stub: `Telemetry/TileServerStateBuilder.cs` produces the empty-state JSON and zlib-wraps it. Envelope builder + transport wiring is the remaining work for older-firmware support. **For 2025-11 firmware**, plugin must target session 0x03. **For KS Pro**, skip the push entirely.

## What's known

- Session 0x03 is opened by the host (SimHub already does this at `TelemetrySender.cs:242`). PitHouse opens it too.
- After opening, PitHouse pushes zlib-compressed blobs on session 0x03. Three blobs observed in the VGS capture currently retained in `sim/logs/uploads/`:
  - offset `0x00c` (12) — empty-state map JSON, 775 bytes uncompressed
  - offset `0x124` (292) — populated ATS/ETS2 map JSON, 3041 bytes uncompressed
  - offset `0x448` (1096) — populated map JSON variant, 6301 bytes uncompressed
- Each blob decompresses to `{"map":{"ats":"<escaped JSON>","ets2":"<escaped JSON>"},"root":"...","version":N}`. See the preview in `sim/logs/uploads/sess03_off0000c_sz775.json`.
- zlib stream is standard Deflate + zlib wrapper (magic `78 9C` for default compression).

## What's unknown

### 12-byte envelope before each zlib stream — **DECODED**

Two captures from live Pithouse pushes (sim MCP `sim_uploads` field `envelope_hex`):

| Sample | Uncompressed | Compressed | Envelope bytes |
|--------|-------------|------------|---------------|
| Empty-state | 775 B | ~247 B | `FF 01 00 FB 00 00 00 FF 00 00 03 07` |
| Populated ATS/ETS2 (map_version=153) | 6301 B | 1165 B | `FF 01 00 91 04 00 00 FF 00 00 18 9D` |

Field decode:

| Offset | Size | Field | Empty | Populated | Notes |
|--------|------|-------|-------|-----------|-------|
| 0 | 1 | `0xFF` marker | `FF` | `FF` | Constant. Same sentinel used for session 0x01/0x04 FF-prefixed fields |
| 1 | 1 | sub-msg index / field count | `01` | `01` | Constant |
| 2 | 1 | tag | `00` | `00` | Constant |
| 3..6 | 4 | compressed_size + 4 (u32 LE) | `FB 00 00 00` → 251 | `91 04 00 00` → 1169 | 251 = 247+4 ; 1169 = 1165+4 ✓ (extra 4 bytes likely per-chunk CRC overhead) |
| 7 | 1 | `0xFF` separator | `FF` | `FF` | Constant |
| 8 | 1 | tag | `00` | `00` | Constant |
| 9..11 | 3 | uncompressed_size (u24 BE) | `00 03 07` → 0x000307 = 775 | `00 18 9D` → 0x00189D = 6301 | Big-endian; exact match to decompressed sizes ✓ |

**So the envelope is:**

```
FF 01 00 [compressed_size+4 u32 LE] FF 00 [uncompressed_size u24 BE]
```

The "+4" on compressed_size almost certainly accounts for the Adler-32 trailer inside the zlib stream (zlib = 2-byte header + Deflate + 4-byte Adler-32). Compressed_size here counts the Deflate payload; adding 4 gets the total zlib stream size. Worth verifying by checking whether the value equals `len(zlib_bytes)` or `len(zlib_bytes) - 2` on a third sample.

### Per-blob pacing

- Is there an ack frame between blobs (like session 0x04 sub-msg 1/2 ack)?
- Or are they pushed back-to-back on the same session?

Check `sim/logs/uploads/sess03_frames.log` timestamps to see if PitHouse paces the three blobs with a gap.

### When exactly does PitHouse send the empty-state blob?

Observed relative to connect — but before or after tier definition? Matters because SimHub's tier definition is on session 0x02 (`TelemetrySender.SendTierDefinition`) and opening / pushing on 0x03 concurrent with 0x02 may hit the same write-queue pacing window.

### Are populated blobs required?

The 3041- and 6301-byte blobs carry real map metadata. Likely only pushed when PitHouse has populated tile-server directories. If SimHub never pushes populated blobs, does the wheel still render the map area? Probably shows blank — acceptable for telemetry-feeder role.

## Research inputs

Captures to inspect:

| File | Contents | Relevant range |
|------|----------|---------------|
| `usb-capture/latestcaps/automobilista2-wheel-connect-dash-change.pcapng` | 2025-11 firmware, fresh connect + dash change | Full connect sequence, includes session 0x03 opens |
| `usb-capture/latestcaps/automobilista2-dash-change.pcapng` | 2025-11 firmware, mid-session dash change | Session 0x03 activity without the fresh-connect noise |
| `sim/logs/uploads/sess03_raw.bin` | Reassembled session 0x03 byte stream from last test run | Start of file for header bytes |
| `sim/logs/uploads/sess03_off0000c_sz775.json` | Decoded empty-state JSON | Confirms JSON schema |
| `sim/logs/uploads/sess03_off00124_sz3041.json` | Decoded populated map JSON (ATS data) | Confirms populated schema |

Extraction script pattern:

```bash
# In usb-capture/, reassemble host→device session 0x03 writes from the pcapng.
# Filter USB bulk-out packets; strip 7E length group device 7C 00 [sess=03]
# [type] [seq] framing; concat payloads.
tshark -r latestcaps/automobilista2-wheel-connect-dash-change.pcapng \
  -Y 'usb.dst == "1.1.0" and usb.transfer_type == 0x03' \
  -T fields -e usb.capdata \
  | xxd -r -p > /tmp/session03_raw.bin
```

(Adjust USB address filter per the capture's device assignment.)

## Minimum viable implementation path — envelope now known

1. Add `BuildEnvelope(int compressedSize, int uncompressedSize)` to `TileServerStateBuilder` that emits the 12-byte envelope per decoded table above.
2. Concat envelope + zlib stream → full blob payload for session 0x03.
3. Chunk with `TierDefinitionBuilder.ChunkMessage(msg, session=0x03, ref seq)` — same SerialStream 7c:00 + CRC-32 chunking used for tier definitions.
4. Call from `TelemetrySender.Start()` after `SendSessionOpen(0x03, 0x03)`.
5. Gate behind `MozaPluginSettings.UploadTileServerState`, default OFF until verified on real hardware.

Open question before shipping: confirm the `compressed_size + 4` formula on a third sample (different uncompressed size) to rule out coincidence. Easiest path: toggle Pithouse's tile_server state to a third variant (e.g. delete cached maps then push), capture envelope, confirm byte 3..6 LE u32 = `len(zlib_stream)`.

## Stretch goal — populated map JSON

Defer. Requires:
- Enumerating host-side tile_server directory contents
- Computing per-zoom-level `compressed_size`, `file_count`, `x`, `y` for each layer
- Deciding whether to ship ATS/ETS2 tile assets with the plugin (size concern) or leave empty

Only worth pursuing if users ask for the wheel's native map display to work via SimHub.
