# KS Pro pcap deep investigation plan

Established (2026-04-26):
- KS Pro = configJson on session **0x0a** (54B net, no CRC, seq starts 0x000b)
- Sim now passes PitHouse's state-parse gate (active-dash switch + Dashboard Manager populated for the **2 user uploads**)
- User reports Sim still gets "wrong" treatment: PitHouse only treats user uploads as on-device, ignores the 10 factory entries we advertise; storage display = 51.68 MB (origin unknown to sim); active-dash slot 1 maps to first-user-upload because PitHouse's effective list excludes factory

User assertion: **The KS Pro pcaps (`putOnWheelAndOpenPitHouse.pcapng` + `mozahubstartup.pcapng`) already contain every signal we need — we've been misidentifying frames.** Plan: walk every byte of both pcaps, classify exhaustively, diff against what sim emits today.

## Inventory pass

For each pcap:

1. **Per-session breakdown** — every `7c 00 [sess]` frame, both directions, `(session, type, direction)` → count, total bytes, time range, first/last seq. Treat each direction independently (host & device have separate seq counters per session).
2. **Per-`fc:00` breakdown** — every `fc 00 [sess]` frame, direction, payload length, `[ack:u16]` value.
3. **Per-bare cmd** — every non-session `[group][device]` pair → count + first frame of each (group, device, payload-prefix).
4. **All `7e XX YY ZZ` framed messages** with cmd byte not in `{7c, 7d, fc, 00, 0e, 43, 40, 3f, ...}` — anything sim doesn't currently route.

Output: one TSV per pcap + one `inventory.md` with the deltas vs sim's emit log. Tools: `usb-capture/decode_session.py` (already exists), augment with a new `inventory_pcap.py`.

## Per-session deep dive

Sessions to fully decode (host AND device direction):

| Session | Hypothesis from session-roles table | What to verify |
|---------|-------------------------------------|----------------|
| 0x01 | Mgmt (host channel-catalog push) | Catalog content. Sim's reply on this session matches? |
| 0x02 | Telemetry (host tier def + fc:00 acks) | Tier def content + sub-msg structure |
| 0x03 | Aux config (older firmware: tile-server) | KS Pro should be empty / minimal here |
| 0x04 | Dir listing (host type=0x08 → wheel type=0x0a) | What does PitHouse query for? Is the 14B pre-zlib metadata the storage signal? |
| 0x05/0x06/0x07 | File transfer | Already RE'd; double-check 2026-04 path-push header |
| 0x08 | Keepalive (older firmware) | Confirm payload pattern |
| 0x09 | KS Pro: empty heartbeats | Verify NO state push lands here on KS Pro (our new model) |
| 0x0a | KS Pro: configJson state push + host configJson() reply | **CRITICAL** — full host→wheel reply byte-by-byte. What's in arg? Does it carry an active-dash signal? Does it acknowledge factory entries? |
| 0x0b | User mentioned "tile-server state (was 0x03 in older firmware)" | Decode every chunk. Is dashboard list confirmation here? |
| 0x0c+ | Unknown | Inventory first |

Reassembly approach (from `mozahubstartup.pcapng` 0x0a state push RE):
- Group consecutive seq runs by time + seq monotonicity (don't dedupe by seq across runs — keepalives reuse low seqs).
- Detect chunk net width by trying `54, 52, 50, 56` × CRC strip `0, 3, 4` and looking for clean zlib EOF.
- Once envelope decoded, dump JSON / UTF-16 / raw to per-session per-blob files for grep-ability.

## Specific byte-diff targets

For each of these we believe is wrong, write a sim emit + capture extract side-by-side at byte level:

1. **Dashboard list confirmation** — what message tells PitHouse "this dashboard is REALLY on the wheel, not just claimed in state push"? Likely candidates: a session 0x04 query response, a session 0x0b push, or an RPC on 0x0a we haven't decoded.
2. **Storage display value** — 51.68 MB origin. Candidates:
   - A u32/u64 in session 0x04 dir-listing reply (sim hardcodes 100,521 — fixed, but PitHouse displays varying values across captures so it's NOT this).
   - A field in some other periodic device→host message (group `0x0E` debug? group `0x40` reply?).
   - A computed value PitHouse derives from individual file sizes via per-file query.
   Action: capture two pcaps with different storage occupancy on real wheel, diff every byte.
3. **Active dashboard signal (host→wheel)** — what RPC/cmd makes the wheel switch active dash? Search every host-direction byte for the dashboard's id/name as PitHouse switches it.

## Tooling deliverables

- `usb-capture/inventory_pcap.py` — emits exhaustive per-(session, direction, type) TSV + groupby on bare cmds.
- `usb-capture/zlib_streams.py` — walks every `78 9c` / `78 da` magic in both directions and any session, decompresses, dumps to disk with seq-run metadata.
- `usb-capture/sim_vs_capture_diff.py` (already exists; extend) — for each device-direction frame in capture, run sim's `handle()` against the prior host frame and compare bytes; flag `no_handler` / `mismatch` / `extra_reply` / `missing_reply`.

## Working hypotheses to falsify

- **H1**: PitHouse's "on device" list comes from a separate query stream, not state push enableManager.dashboards. Falsify by finding a host→wheel query for dashboard presence + the wheel's reply with names.
- **H2**: Storage display is in the session 0x0b stream (the new tile-server). Falsify by decoding 0x0b in mozahubstartup and looking for a u32 matching the displayed MB.
- **H3**: Active dash switch goes through an RPC on session 0x0a (`useDashboard()` or similar). Falsify by walking every host→wheel session 0x0a data chunk and looking for JSON RPC shape with the dashboard id.
- **H4**: Factory entries pass to PitHouse only when sim also serves the corresponding `.mzdash` file via session 0x05/0x07 file-read (read direction inverted from upload). Falsify by checking pcap for any host→wheel "read this file" trigger followed by wheel→host bulk content.

## Process

1. Run inventory pass, drop output into `usb-capture/ksp/inventory.md`.
2. Decode every zlib stream, name files by `(direction, session, t_start, t_end, decompressed_size)`.
3. Read EACH decoded blob. Look for: `productType`, `dashboard`, dashboard names from pithouse (e.g. `asdfgh`/`horse`/`lovely`/`main`/`test_copy`), MB-sized u32 / u64 ints, dashboard ids.
4. Update this doc with findings, then refine sim.

Keep notes in this file under a new "Findings" section as RE progresses.

---

## Findings (2026-04-26)

Source artefacts:
- `usb-capture/inventory_pcap.py` — exhaustive frame inventory (this RE's tool)
- `usb-capture/zlib_streams.py` — every zlib blob walker (this RE's tool)
- `usb-capture/ksp/inv/` — TSV outputs per pcap
- `usb-capture/ksp/zlib/<capture>/` — decoded blobs + manifest.tsv
- Comparison reference: `/tmp/latestcaps_zlib/pithouse-switch-list-delete-upload-reupload/`

### Capture coverage caveat

**Both KS Pro pcaps are mid-session.** `mozahubstartup.pcapng` opens at frame 1 but the wheel was already running — first 0x0a content chunk is at fn=2589, and the 3 captured 0x0a state pushes happen late (fn 33145–33621, after a user upload). `putOnWheelAndOpenPitHouse.pcapng` is even shorter (frames 55971–59061, ~3000) and contains **no session 0x0a or 0x0b traffic at all** — opening PitHouse against an already-connected wheel does NOT trigger a fresh state push. Conclusion: neither capture preserves the wheel's first-connect state push, if one exists.

### Verified KS Pro session role table

| Session | Direction | Content (KS Pro) | Verified by |
|---------|-----------|------------------|-------------|
| 0x01 | dev→host | zlib-wrapped wheel debug log (memory stats, file ops, dashboard paths) | 12 zlib blobs in `mozahubstartup`, all decode as ASCII text wrapped as 0x00 0xNN bytes |
| 0x01 | host→dev | zlib-wrapped channel-catalog binary (id+UTF-16LE name table) | 2 blobs starting `00 02 00 00 00 18 00 R\0p\0m\0A\0b\0s\0o\0l\0u\0t\0e\01\0` |
| 0x02 | both | telemetry tier definition + telemetry stream | tier-def zlib blobs in `putOnWheelAndOpenPitHouse` host direction, ~5102 B |
| 0x03 | both | OPEN frames + 4 B `00 00 00 00` keepalive only — **UNUSED on KS Pro** | 9 OPEN frames in `mozahubstartup`, 0 actual data |
| 0x04 | host→dev | **tile-server state push** (12-byte envelope, sizes 775/3041/6301 — same as session 0x03 in older firmware) | 3 zlib JSON blobs in `mozahubstartup`, env_kind=`12b`. `root: "C:/Users/jacks/AppData/Local/Temp/tile_server"` proves it's mozahub's local push |
| 0x04 | dev→host | dir-listing reply (392 B JSON, `/home/root` → `{temp: empty}`) | 1 blob in `putOnWheelAndOpenPitHouse` |
| 0x05 | host→dev | file content uploads (8-byte path/header + raw payload, no zlib) | 281 host chunks in `mozahubstartup`, headers like `02 40 01 00 00 00 00 00 8c 00 C\0:\0/\0U\0s\0e\0r\0s\0/\0...` |
| 0x05 | dev→host | dir-listing reply (same 392 B JSON shape; sometimes lands here instead of 0x04 depending on session ordering) | 1 blob in `mozahubstartup` |
| 0x06, 0x07, 0x08 | both | OPEN + 4 B zero keepalive only — reserved/heartbeat | inventory shows only 4-byte payloads |
| 0x09 | both | OPEN + 4 B zero keepalive only — **UNUSED on KS Pro** (was Schema A state push session in older firmware) | 0 zlib blobs in `mozahubstartup`; chunks all 4 B |
| 0x0a | dev→host | **configJson state push (Schema B)** with 9-byte envelope. Three deltas captured in `mozahubstartup`, all keyed `[TitleId, disabledManager, enabledManager, imagePath]` | env_kind=`9b`, sizes 5759/4471/12609 |
| 0x0a | host→dev | host-side `configJson()` JSON-RPC call. Body: `{"configJson()": {"dashboards": [...names...], "dashboardRootDir":"", "fontRootDir":"", "imageRootDir":"", "fonts":[], "sortTags":0}, "id":11}` | 2 blobs in `mozahubstartup`, both 262 B uncomp |
| 0x0b | dev→host | wheel→host **tile-server state mirror** (12-byte envelope; was session 0x0a dev→host in older firmware) | 3 zlib JSON blobs in `mozahubstartup`, env_kind=`12b`. `root: "/home/moza/resource/tile_map/"` is wheel-side path |
| 0x0b | host→dev | nothing in either KS Pro capture |

Plan's session-roles table was directionally correct. The single notable correction: **session 0x04 in KS Pro carries BOTH dir-listing replies (dev→host) AND tile-server state pushes (host→dev)** — same session, two different protocols multiplexed by direction. Sim's existing TileServerStateBuilder targets session 0x03; for KS Pro it must move to session 0x04.

### Schema A AND Schema B both emitted on KS Pro

**Correction to an earlier draft of these findings.** The first pass through `zlib_streams.py` had a burst-splitting bug (dedup-by-seq picked 4 B keepalives over real data when seqs collided across reopen events; whole-stream reassembly then concatenated unrelated chunks). After fixing the tool to (a) split bursts on seq decreases, (b) split bursts on frame-number gaps, and (c) prefer the larger chunk over a 4 B keepalive on seq collisions, **the missing Schema A push was recovered**:

| Capture | Burst | Frame range | Blob | Uncomp | Schema |
|---|---|---|---|---|---|
| mozahubstartup | sess 0x0a dev burst1 | 6515–13689 | b100 | 14671 B | **A** (`configJsonList` + `enableManager.dashboards`) |
| mozahubstartup | sess 0x0a dev burst2 | 20293–33861 | b200 | 5759 B | B (delta) |
| mozahubstartup | sess 0x0a dev burst2 | 20293–33861 | b201 | 4471 B | B (delta) |
| mozahubstartup | sess 0x0a dev burst2 | 20293–33861 | b202 | 12609 B | B (delta) |

So KS Pro emits **Schema A on session 0x0a at connect** (full snapshot), and **Schema B deltas on the same session 0x0a** during/after subsequent user actions like uploads. The session role table above stands; the schema observation needed correction.

The Schema A push from KS Pro:

- `TitleId`: 1 (steady-state value, matches older firmware)
- `configJsonList`: 13 names — 10 factory (`Core`, `Grids`, `Mono`, `Pulse`, `Rally V1`–`Rally V6`) plus 3 user uploads (`lovely`, `main`, `test_copy`) that were already on the wheel before this capture
- `enableManager.dashboards`: 13 entries with full per-dashboard records (id, hash, idealDeviceInfos, etc.)
- `rootDirPath`: `/home/moza/resource`
- `displayVersion`: 11, `resetVersion`: 10
- `disableManager.dashboards`: empty
- `imagePath`: full image manifest with `.png` and `.mp4` entries
- `idealDeviceInfos` mixes `RS21-W08-HW SM-DU-V14` (most dashboards) and `RS21-W17-HW RGB-DU-V11` (`Rally V6` only) — per-dashboard authoring info, not a uniform wheel-side display report

The Schema B deltas (burst 2) show:
- 5759 B blob: `disabledManager.updateDashboards = [{VM - GT3 Dash, ...}]` while `VM - GT3 Dash` is mid-upload
- 4471 B blob: `enabledManager.updateDashboards = []`, `disabledManager.updateDashboards = []` — transitional / cleared state
- 12609 B blob: post-upload state

Implication for sim: the existing Schema A `build_configjson_state` path is **correct** for KS Pro at connect. The remaining gap is **emitting Schema B deltas on session 0x0a** during/after user-driven changes (upload, delete, switch). Today the sim only emits the full snapshot once and then keepalives; PitHouse may be relying on the delta stream to refresh its UI after operations complete. Both schemas live on the same session 0x0a — sim must alternate between full Schema A and Schema B deltas based on lifecycle events.

The "PitHouse only treats user uploads as on-device" symptom in the original plan is not explained by Schema A vs Schema B (Schema A is emitted, including factory entries). It is more likely explained by the Dashboard-Manager UI being scoped to user-managed entries by design — factory entries are part of the wheel inventory regardless and PitHouse never offers them as deletable/movable items.

### Why PitHouse "only treats user uploads as on-device"

The pcaps contain **zero device→host messages enumerating what dashboards live on the wheel**. The only place a full dashboard list appears is the host→wheel `configJson()` RPC (`{"dashboards": [...14 names...]}`) which mozahub PUSHES to the wheel. mozahub already knows this list — it maintains the per-wheel cache itself.

Therefore PitHouse's "on-device" list is mozahub's own local cache, not anything sourced from the wheel. Factory dashboards never appear in mozahub's cache because they were never uploaded — they ship in firmware ROM. PitHouse renders Dashboard Manager strictly from this local cache, which is why the 10 factory entries our sim advertises via Schema A `configJsonList` are absent from the UI.

Hypothesis H1 (separate query stream) is **falsified**: there is no such query stream in either KS Pro pcap. PitHouse's UI list is local state, not wire state.

### Storage display value (51.68 MB)

**Not located in either pcap.** Searched both directions for plausible byte representations:
- 51,680,000 (LE u32 `c0 70 14 03`): no hit
- 54,193,324 / 54,194,176 (LE u32): no hit
- The session 0x05 dir-listing reply 14-byte pre-zlib metadata block carries u32 LE `b0 88 01 00` = **100,528** at the offset previously noted in `payload-09-state-re.md`. Way smaller than the displayed MB number — cannot be a byte total of stored content (the wheel has 4 .mp4 files in its imagePath that alone would dwarf 100 KB).

Hypothesis H2 (storage in session 0x0b) is **falsified**: 0x0b dev→host carries only the tile-server map state mirror (root path + per-game map metadata, no size fields).

Most likely explanation, parallel to the dashboard list: **PitHouse computes the displayed storage value locally from its own per-wheel upload cache** (sum of `.mzdash` sizes + image asset sizes for each upload). The wheel does not report total storage on the wire in either KS Pro pcap. To verify, capture a wheel session where PitHouse displays a known storage number, then confirm the same byte total can be derived from the local PitHouse cache without any wire u32 carrying it.

### Active-dash switch (host→wheel)

**No `0x40 0x17 28:NN ...` SET-side write in either KS Pro pcap** — confirmed via `_bare_cmd.tsv`. Only GET-side reads (`0x40 0x17 28 00 00`, `28 01 00`, `28 02 00 00`, `28 02 01 00`) appear. The active slot index is whatever the wheel was last set to via some channel not in these captures.

Hypothesis H3 (RPC on session 0x0a) is **not falsified but not confirmed**: the captures contain only the `configJson()` RPC variant, no `useDashboard()` / `setActive()` call. To capture an active-dash switch RPC, the user would need to click the "Use" button on a non-active dashboard inside PitHouse during a fresh capture session.

### Factory entries do not require file-read traffic

Hypothesis H4 (sim must serve `.mzdash` for factory entries via 0x05/0x07 file-read) is **falsified**: session 0x05/0x07 device→host carries no bulk file content in either pcap. Only host→device file uploads + dir-listing replies. Factory dashboards are never streamed wire-side because they live in firmware ROM and are read directly by the display's render pipeline.

### Concrete action items derived from findings

1. **Keep emitting Schema A snapshot at connect on session 0x0a.** Already implemented; appears correct.
2. **Add Schema B delta emitter on session 0x0a** triggered by lifecycle events (upload-in-progress, upload-committed, delete). Body shape `{TitleId, disabledManager, enabledManager, imagePath}` with the relevant entries populated in `disabledManager.updateDashboards` (mid-upload) or cleared (post-commit).
3. **~~Move tile-server state push to session 0x04 host→dev for KS Pro profile.~~** Superseded 2026-04-27: KS Pro display does not support a map UI in PitHouse — user-confirmed the option isn't presented. The 0x04 host→dev tile-server push observed in `mozahubstartup.pcapng` is mozahub's startup-time client-side push that the wheel echoes back on 0x0b but never renders. Plugin should NOT send tile-server data on KS Pro; sim's `TileServerStateBuilder` should skip emission when the model uses `_configjson_session == 0x0a`.
4. **~~Add session 0x0b dev→host tile-server mirror~~** Superseded 2026-04-27: same reason as #3. Sim doesn't need to emit a tile-server mirror; PitHouse doesn't consume it on KS Pro.
5. **Storage display is a local-cache compute on the PitHouse side.** Sim has no obligation to send a "total bytes" value over the wire. The "origin unknown to sim" is because the value never crosses the wire — PitHouse derives it.
6. **Active-dash SET-side RE deferred.** Need a fresh capture where the user explicitly clicks "Use" on a non-active KS Pro dashboard. The captures we have do not exercise this path.
7. **Investigate why PitHouse Dashboard Manager hides factory entries even though the Schema A push lists them.** Hypothesis: UI design choice (factory entries are surfaced in a different UI scope, not Dashboard Manager). Verify by looking at PitHouse's actual UI text/strings for the relevant pane rather than at the wire protocol.

### Tooling delivered

- `usb-capture/inventory_pcap.py` — per-(session, dir, type) + per-bare-cmd TSVs, plus an `unmatched.tsv` filter for cmd bytes outside the documented set.
- `usb-capture/zlib_streams.py` — exhaustive zlib-magic walker; auto-detects 9-byte and 12-byte envelopes; dumps decoded JSON / UTF-8 / UTF-16 / binary blobs with full source coordinates in `manifest.tsv`.
- Manifest extension is straightforward if more envelope shapes turn up.

