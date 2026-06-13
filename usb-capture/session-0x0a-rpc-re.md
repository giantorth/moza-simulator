# Session 0x0a — JSON-RPC call format + KS Pro state push

Status: **format documented; semantics partial**. Captured 2026-04-21 using sim MCP research fields (S1/S3/S4) against live Pithouse.

**KS Pro firmware (2026-04+) makes session 0x0a multi-purpose:**

| Direction | Payload class | Envelope | Trigger |
|---|---|---|---|
| dev → host | configJson **Schema A** snapshot | 9-byte (`00 [comp_size+0 LE u32] [uncomp_size LE u32]`) | Once at connect |
| dev → host | configJson **Schema B** delta | Same 9-byte | After FS mutations (upload, delete) |
| dev → host | RPC reply | Same 9-byte | After host RPC call |
| host → dev | RPC call (this document) | Same 9-byte | UI events (Reset, completelyRemove, configJson echo) |

Verified 2026-04-26 against `ksp/mozahubstartup.pcapng` per
[ksp-deep-investigation-plan.md § Findings](ksp-deep-investigation-plan.md).
Older firmware (VGS/CSP) split these: state push on 0x09 (Schema A), delta on
0x03 (Schema B), RPC on 0x0a. KS Pro consolidated everything onto 0x0a — see
[payload-09-state-re.md § Session number depends on firmware](payload-09-state-re.md).

## Envelope

9 bytes before zlib magic. Same shape as session 0x09 (configJson state push), different from session 0x03 tile-server.

```
[tag:1B = 0x00] [comp_size+4 u32 LE] [uncomp_size u32 LE] [zlib stream]
```

Confirmed on 5 captured reset-RPC blobs — envelope is byte-identical across all: `00 1d 00 00 00 11 00 00 00`. Decoded per blob:

| Field | Bytes | Value |
|-------|-------|-------|
| tag | `00` | 0 |
| comp_size+4 (u32 LE) | `1d 00 00 00` | 29 (= 25 + 4) |
| uncomp_size (u32 LE) | `11 00 00 00` | 17 |

All 5 blobs carried identical 25-byte zlib payload decoding to 17-byte JSON: `{"()":"","id":N}`.

## RPC body shape

```
{"<method_name>()": <args>, "id": <integer>}
```

- **Key** = `<method_name>()` — method name followed by literal `()`. Empty method name is possible (observed as just `()`).
- **Value** = args, usually string or object. Observed `""` for empty args.
- **Id** = integer correlation id.

### Regex for method name extraction

Sim's `UploadTracker._extract_dashboard_metadata` currently requires `^[A-Za-z_][A-Za-z_0-9]*\(\)$`. This drops the empty-method `()` case (observed with reset). Relax to `^[A-Za-z_0-9]*\(\)$` (or split empty-method path separately) so reset RPCs land in `rpc_log`.

## Observed RPC: reset (empty method)

User action: click "Reset Dashboard" button in PitHouse.

- 5 captures across 3 separate user click events
- All sent on session 0x0a via host→wheel chunk
- Id behaviour:
  - Session A (first sim connect): id=15 on one click
  - Session B (after sim cycle): id=13 on 4 clicks (rapid triple-click + earlier single click)
  - **Id is static per-session, NOT an incrementing counter**
  - Hypothesis: id is a session-scoped target reference — Pithouse assigns it at connect, reuses for every reset targeting the same item

### Plain-english semantic

`{"()": "", "id": N}` = "null-method acting on ref N" = reset-to-empty signal.

## Other RPCs to look for on session 0x0a

Not yet captured but likely exist (PitHouse UI features suggest them):

| Action | Captured RPC | Status |
|--------|-------------|--------|
| Click "Reset" | `{"()": "", "id": <session-scoped>}` | ✓ confirmed |
| Delete dashboard | `{"completelyRemove()": "{<uuid>}", "id": N}` | ✓ confirmed — UUID in Microsoft GUID format, e.g. `{7c218515-6ec6-4e5f-9820-ba030b14c43d}` |
| Upload dashboard | unknown — does NOT fire on session 0x0a | ✗ — user clicked Upload with brand-new dashboard but no RPC on 0x0a AND no file-transfer traffic on session 0x04. Root cause: Pithouse likely expects specific state/capability signal from sim before initiating upload. See `empty-fs-signalling.md` + `main-mcu-uid-re.md` |
| Use dashboard (select) | likely `{"setDashboard()": ..., "id": N}` | ✗ not yet triggered without upload succeeding first |
| Rename / metadata edit | unknown | ✗ |

To capture the upload / select / delete RPCs: (1) implement S7 empty-FS signalling so PitHouse issues fresh upload traffic, OR (2) manually wipe PitHouse's cached wheel state via its "Delete cached wheel data" option if it exists.

## Plugin-side implications

SimHub does not currently need to send or receive these RPCs — plugin role is telemetry feeder, not dashboard manager. If a future plugin feature adds wheel-dashboard management parity with PitHouse:

- **Outbound**: plugin would need to discover a valid `id` for the target. Probably learned from configJson state push (session 0x09) where the wheel tells PitHouse which slots exist. Plugin would receive the same state on its side of session 0x09 and read slot ids from `enableManager.dashboards[].id`.
- **Inbound**: wheel ACKs RPCs back via session 0x0a wheel→host; plugin would need to parse `{"<method>()": <response>, "id": <matching_id>}` replies.

Until plugin has a reset/clear feature, skip.

## Research inputs

- `sim/logs/uploads/sess0a_frames.log` — all session 0x0a host→wheel chunks (mostly 4-byte `00 00 00 00` keepalives + occasional 38-byte content frames)
- `sim/logs/uploads/sess0a_off*_sz17.json` — decoded RPC JSON (once sim parses + dumps)
- `usb-capture/latestcaps/automobilista2-wheel-connect-dash-change.pcapng` — may contain additional RPC variants (dash upload captured here)
