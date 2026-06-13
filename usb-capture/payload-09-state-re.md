# Session 0x09 configJson state RE

Reverse-engineering of the wheel→host state push on session 0x09 (older
firmware) / 0x0a (KS Pro 2026-04+). Goal: understand each field well enough
that the sim can synthesise a believable state push for any configured
wheel model rather than blind-replaying a captured blob.

Source: [analyze_session09.py](analyze_session09.py) decoded blobs from every
pcapng with non-trivial 0x09 traffic. JSON dumps under `/tmp/sess09_blobs/` (regenerate
on demand). Captures cited:

| Capture | Wheel | Display module | Schema | Blob count |
|---|---|---|---|---|
| `latestcaps/automobilista2-wheel-connect-dash-change.pcapng` | VGS | W17 / RGB-DU-V11 | new (2025-11) | 1 |
| `latestcaps/pithouse-switch-list-delete-upload-reupload.pcapng` | CSP on R9 | W17 / RGB-DU-V11 | new (2025-11) | 1 (truncated) |
| `connect-wheel-start-game.pcapng` | unspecified | Display / SM-DU-V14 | new (2025-11) | 1 |
| `12-04-26/moza-startup.pcapng`, `12-04-26-2/moza-startup-1.pcapng`, `moza-unplug-plug-wheel-to-base.pcapng` | unspecified | Display / SM-DU-V14 | new (2025-11) | 1 each |
| `09-04-26/dash-upload.pcapng` | unspecified | (same display, different blob shape) | **old (pre-2025-11)** | 2 |
| `ksp/mozahubstartup.pcapng` | KS Pro | W08 / SM-DU-V14 | A snapshot + B deltas, **session 0x0a** | 1 A + 3 B |

Captures with 0 chunks (cs-to-vgs, vgs-to-cs, putOnWheelAndOpenPitHouse, etc.) start
mid-session after the device 0x09 push has already completed.

---

## Session number depends on firmware

| Firmware | Schema A snapshot session | Schema B delta session |
|---|---|---|
| 2025-11 (VGS, CSP, older displays) | 0x09 dev→host | 0x03 dev→host |
| 2026-04+ (KS Pro) | **0x0a dev→host** (session 0x09 is keepalive-only) | **0x0a dev→host** — same session as snapshot |

Verified 2026-04-26 against `ksp/mozahubstartup.pcapng` per
[ksp-deep-investigation-plan.md § Findings](ksp-deep-investigation-plan.md):
KS Pro emits Schema A once at connect (14671 B uncomp blob, seq 0x000b–0x004x)
and Schema B deltas afterward on lifecycle events (5759/4471/12609 B uncomp,
later seqs in the same session). Sim's `_configjson_session` setting toggles
this per-model; KS Pro profile uses 0x0a, others 0x09.

---

## Two firmware schemas

The wheel's session 0x09 state JSON has been observed in two incompatible schemas. The plugin already accepts both via [Telemetry/WheelStateParser.cs](../Telemetry/WheelStateParser.cs); the sim must produce one or the other based on the wheel model it is impersonating.

### Schema A — current (2025-11 firmware)

Top-level keys (11 total, alphabetised by the wheel):

| Key | Type | Purpose |
|---|---|---|
| `TitleId` | int | Always 1 in observed steady-state. Likely a **schema/profile selector** rather than active-dashboard. NOT the active-dash indicator (see § Active dashboard). |
| `configJsonList` | string[] | Names of factory dashboards baked into firmware. Wheel reports this list immutably regardless of FS contents. PitHouse uses it as the canonical "supported by this display" set. **Empty list breaks display detection** ([usb-capture/empty-fs-signalling.md](empty-fs-signalling.md)). |
| `disableManager` | object | Mirror of `enableManager`. `dashboards` empty in factory state — populated when user marks dashboards as "disabled" in PitHouse. `imageRefMap` and `rootPath` always populated, identical to enableManager's. |
| `displayVersion` | int | Display module firmware version. `11` across all observed Set-A captures. |
| `enableManager` | `{dashboards, imageRefMap, rootPath}` | The list of "available / installed" dashboards plus image refcount + path root. |
| `fontRefMap` | object | Always `{}` in observed factory state. Reserved for user-installed fonts. |
| `imagePath` | object[] | Manifest of actual image files stored on the wheel: `{md5, modify, url}`. The `url` is relative to `rootPath` (or absolute under `/MD5/` namespace). `modify` is **always negative** in observed factory data — pre-1970 Unix ms timestamps are firmware bake-time markers, not real modification times. |
| `imageRefMap` | `{path: refcount}` | How many dashboards reference each image. Top-level = global view; per-manager copies are scoped. |
| `resetVersion` | int | `10` across all observed captures. Possibly bumped when factory-reset happens. |
| `rootDirPath` | str | Wheel's resource root. **Always `/home/moza/resource`** — the sim previously wrote `/home/root/resource` which is a different (mostly empty) tree. |
| `sortTag` | int | `0` across all observed captures. Possibly a UI tab/category selector. |

`enableManager.dashboards[]` per-entry shape:

| Field | Notes |
|---|---|
| `createTime` | Always empty string `""` in factory entries. Set on user-uploaded dashboards. |
| `dirName` | Subdirectory under `rootPath`. e.g. `Rally V1`. |
| `hash` | **Hex-encoded ASCII of the actual MD5 hex string**: `bytes.fromhex(field).decode("ascii")` recovers the canonical MD5. e.g. `"6237346230306537..."` → ASCII `"b74b00e723d42eee..."` (32-char MD5 hex). |
| `id` | Stable identifier. Two formats observed: 32-char alnum (`0ZPoaC0XdTHawiWIvXEq8wjDYjGenlMz`) for some factory entries, Microsoft GUID (`{23f611f4-5660-454b-808b-f19728f64d48}`) for others. **PitHouse's `completelyRemove` RPC uses its OWN per-install cache key, NOT this id** (see [docs/moza-protocol.md § Session 0x0a RPC](../docs/moza-protocol.md)). |
| `idealDeviceInfos` | List of compatible display modules. Each entry: `{deviceId, hardwareVersion, networkId, productType}`. **Per-dashboard list — the same wheel reports a MIX of `RS21-W08-HW SM-DU-V14` and `RS21-W17-HW RGB-DU-V11` across its dashboards.** Inferred meaning: each dashboard was authored against a specific display revision; PitHouse uses this to gate "compatible / not compatible" badges in the UI. |
| `lastModified` | ISO-8601 UTC, e.g. `"2025-11-21T07:45:36Z"`. Real timestamps for factory entries (firmware bake time). |
| `previewImageFilePaths` | List of absolute paths under `rootPath` to the dashboard's preview PNG. Conventional name: `<dirName>.mzdash_v2_10_3_05.png`. |
| `resouceImageFilePaths` | (sic — `resouce`, missing `r`) Always empty in factory state. Populated for user uploads that include extra image assets. |
| `title` | Human-readable name. Usually equals `dirName` for factory entries. |

### Schema B — lifecycle delta (older firmware AND KS Pro)

Different shape entirely:

| Key | Notes |
|---|---|
| `TitleId` | `4` in delta pushes (vs `1` in steady-state Schema A snapshot). May indicate "currently focused on transaction N" or be a delta-marker. |
| `disabledManager` | (note `d` suffix) `{deletedDashboards, updateDashboards}`. Wheel populates `updateDashboards` while a dashboard upload is in-flight. |
| `enabledManager` | (note `d` suffix) `{deletedDashboards, updateDashboards}`. After upload commits, full per-dashboard records land in `updateDashboards` and any replaced id appears in `deletedDashboards`. |
| `imagePath` | List of `{md5, modify, url}` — same shape as Schema A but only includes entries relevant to the delta. |

Schema B is missing: `configJsonList`, `displayVersion`, `resetVersion`, `rootDirPath`, `sortTag`, `imageRefMap`, `fontRefMap`. Those are Schema-A-only fields.

The plugin already tolerates both via `WheelStateParser`.

**Sim emission rules** (post-2026-04-26):

- Sim emits a Schema A snapshot once at device init on the configured
  `_configjson_session` (0x09 for older firmware profiles, 0x0a for KS Pro).
- For KS Pro, sim's `_fire_state_refresh` emits Schema B deltas on the same
  session 0x0a after FS mutations (uploads, deletes). Delete RPCs surface the
  removed id via `enabledManager.deletedDashboards`.
- For older-firmware profiles, sim's `_fire_state_refresh` re-emits Schema A
  on session 0x09 (matches captured behavior in latestcaps).
- Schema B Phase 1 (mid-upload) fires from `_maybe_fire_schema_b_phase1` as
  soon as chunk-0's bundle file table is parseable — `disabledManager.updateDashboards`
  carries the in-flight dashboard. Phase 2 (transitional, both managers
  empty) fires post-commit before Phase 3 (re-enumerate via `_fire_state_refresh`).

---

## Two factory dashboard sets — keyed on display module, not wheel chassis

The factory dashboard list ships baked into the **display module's firmware**, not the wheel chassis. A VGS and a CSP wheel both connected to a `RS21-W17-HW RGB-DU-V11` display report the **same** factory list. A wheel paired with the older `RS21-W08-HW SM-DU-V14` display reports a **different** list.

### Set A — W17 / RGB-DU-V11 display (current 2025-11 firmware)

11 dashboards, observed in `latestcaps/automobilista2-wheel-connect-dash-change.pcapng` (VGS) and `latestcaps/pithouse-switch-list-delete-upload-reupload.pcapng` (CSP on R9):

```
Rally V1, Rally V2, Rally V3, Rally V4, Rally V5, Rally V6,
Core, Mono, Pulse, Nebula, Grids
```

- `idealDeviceInfos` mixes `W17 Display`/`RGB-DU-V11` (Rally V6 + Core/Mono/Pulse/Nebula/Grids) with `W17 Display`/`SM-DU-V14` (Rally V1-V5).
- Top-level `imageRefMap` has 7 entries, all `MD5/<hash>.png` form. `imagePath` lists 5 of them — the other 2 are referenced but not in the file manifest (probably built-in to firmware ROM).

Saved as [sim/factory_state_w17_rgb.json](../sim/factory_state_w17_rgb.json).

### Set B — W08 / SM-DU-V14 display (older firmware in 12-04-26 captures)

12 dashboards:

```
Formula 1, GT V01, GT V02, GT V03,
JDM Gauge Style 01, JDM Gauge Style 02, JDM Gauge Style 03,
Rally V01, DNR endurance, m Formula 1,
Lovely Dashboard for Vision GS, rpm-only
```

- 2 of the 12 are user-uploaded (alphanumeric ids): `m Formula 1`, `Lovely Dashboard for Vision GS`. Removing those leaves 10 firmware-baked dashboards. These ids change across user wheels.
- 8 of the remaining 10 use sequential zero-prefixed GUIDs `{00000000-0000-0000-0000-00000000000N}` — the firmware-baked numbering scheme.
- 2 use random GUIDs (`{0568d52d...}` for DNR endurance, `{bb821501...}` for rpm-only). Possibly newer additions whose ids weren't sequenced.
- `idealDeviceInfos` is uniformly `Display` / `RS21-W08-HW SM-DU-V14`.
- `imageRefMap` has 35 entries, mostly per-dashboard (`Formula 1/bg_3.png` etc.) plus a few `MD5/...` entries. `imagePath` 38 entries.

Saved as [sim/factory_state_w08_sm.json](../sim/factory_state_w08_sm.json).

### Sim implication

Per-wheel-model factory state is **wrong abstraction** — it should be per-display-module. For now the sim only impersonates one display module per wheel profile, so wheel-keyed selection works, but the data model should reflect display-module identity.

---

## What is NOT in the 0x09 state

Things the plugin or sim might be tempted to look for here, but aren't:

### Active / currently-displaying dashboard

`TitleId` is `1` in **every** steady-state capture across multiple distinct test sequences (connect, dash-change, switch, unplug-plug). It is NOT updated when the user switches the active dashboard via PitHouse.

The pithouse-switch capture explicitly contains 4 user actions (switch + list + delete + upload + reupload). Only one configJson state push was decoded; the rest of the device→host 0x09 traffic is keepalive-only short chunks. **Active-dashboard switching does not trigger a 0x09 state re-push.**

The active-dashboard channel is elsewhere on group 0x40:

- `28:00` (`WheelGetCfg_GetMultiFunctionSwitch`) — host reads, wheel replies with active-dash slot index in the 3rd byte. Captured replies: `28 00 01` everywhere (user happened to leave dash 1 active in every capture — value never observed at non-`01`).
- `28:01` (`WheelGetCfg_GetMultiFunctionNum`) — host reads, wheel replies `28 01 00 <page_count>`. Captured: always `28 01 00 01` (single page).

**SET-side wire signals — TWO MECHANISMS IDENTIFIED (2026-04-30, updated 2026-05-01):**

**(1) Primary: FF-record on session 0x02.** 25-byte payload. Slot = **0-based** index into `configJsonList` (alphabetical dashboard name list from session 0x09), NOT `enableManager.dashboards`. Verified against live wheel: slot mapping confirmed correct. PitHouse sends tier-def ~800ms later (no tag 0x07/0x03 preamble on re-sends). See [`../docs/protocol/findings/2026-04-30-dashboard-switch-3f27.md`](../docs/protocol/findings/2026-04-30-dashboard-switch-3f27.md) for full wire format + implementation details.

**(2) Secondary: Group `0x3F` cmd `27:NN`** — per-page 4-byte fingerprint write. Wire format:

```
write : 7e 06 3f 17 27 [page] [flag:1] [fingerprint:3] [csum]    host→wheel
read  : 7e 03 40 17 27 [page] 00                                  host→wheel
reply : 7e 06 c0 71 27 [page] [flag:1] [fingerprint:3] [csum]    wheel→host
```

`page` = 0..3 (per-page binding). Fingerprint is opaque wheel-assigned value, NOT derivable from dashboard metadata. This appears to be state sync / per-page binding, not the primary switch trigger.

**Older candidates (now ruled out):**
1. Session 0x0a RPC — no `useDashboard()` / `setActive()` method observed in any capture
2. `7c:23` page-activate frames — periodic 1Hz page-activate cycles, not switch trigger
3. `3F:28` — cmd `28` never written; real activity is cmd `27`

**Post-switch catalog format:** wheel re-pushes channel catalog on session 0x01 using `\x01` prefix shorthand (e.g. `\x01Rpm` = `v1/gameData/Rpm`). Parser must accept both forms.

Sim impl note: `WheelSimulator.set_active_dashboard(target, pages)` updates internal `active_dash_index` + `active_dash_pages`. Sim needs to handle FF-record on session 0x02 and the `3F 27:NN` fingerprint writes to fully replicate PitHouse-driven switches.

### Free / used storage space — NOT in 0x09 state, but signalled elsewhere

**Correction (2026-04-25):** PitHouse's Dashboard Manager UI displays
occupied/free storage; the previous claim that the wheel never reports
this was incomplete. Storage info is NOT in the session 0x09 configJson
state JSON (verified — no `size`/`free`/`capacity` field at any depth) but
IS conveyed elsewhere on the wire. Top RE candidate:

**Session 0x04 dir-listing reply 14-byte pre-zlib metadata block.** The
type=0x0a reply for `/home/root` carries 14 bytes between the path/sentinel
header and the zlib stream that wasn't decoded by earlier work:

| Capture | 14B metadata | LE u32 at offset 10 |
|---|---|---|
| `latestcaps/automobilista2-wheel-connect-dash-change.pcapng` (VGS) | `c3 90 00 00 00 00 00 00 00 a9 88 01 00 00` | **100,521** |
| `latestcaps/pithouse-switch-...pcapng` (CSP) | `c7 80 00 00 00 00 00 00 00 a9 88 01 00 00` | **100,521** |
| `connect-wheel-start-game.pcapng` (older VGS firmware) | `c9 80 00 00 00 00 00 00 01 2e 2c 04 00 00` | **273,966** |
| `12-04-26-2/moza-startup-1.pcapng` (older firmware) | `c7 40 00 00 00 00 00 00 01 2e 2c 04 00 00` | **273,966** |

The first 2 bytes vary per capture (likely session/request nonce); the
4-byte LE u32 at offset 10 of the metadata is constant within a firmware
generation and changes between firmware revisions. Hypotheses:

1. **Total used storage in bytes.** 100,521 and 273,966 fit if the wheel
   counts only mzdash binary sizes (factory images live in firmware ROM,
   not user storage).
2. **Storage capacity total in bytes.** Less likely — values seem too small
   for a typical embedded display module.
3. **An entry count × structure size** for some internal table.

The 1-byte field at offset 8 also varies (`00` in latestcaps, `01` in
older captures) — possibly a "storage version" or "format" indicator.

**Verification path:** capture a fresh session with PitHouse's Dashboard
Manager visible (storage display present) and correlate the on-screen
byte/KB number against the metadata block's u32. If they match, sim's
session 0x04 reply ([sim/wheel_sim.py:851](../sim/wheel_sim.py#L851)
`_DIR_LISTING_REPLY_TAIL`) needs to compute this dynamically from FS state
instead of replaying the captured constant.

Sim today replays the latestcaps tail bytes verbatim — so PitHouse will
show whatever 100,521 bytes evaluates to (≈98 KB). If a user uploads new
dashboards the displayed value won't change. Phase 4 follow-up.

### Dashboard upload progress

Old schema (B) uses `disabledManager.updateDashboards[]` to surface which dashboard is being uploaded, with `TitleId` apparently encoding the active update index. New schema (A) does NOT — uploads are tracked only via session 0x04 file transfer + per-round acks. The new wheel emits a fresh 0x09 state push only **after** the upload is committed to FS (observed in earlier work, [docs/handoff-upload-stall-2026-04-24.md](../docs/handoff-upload-stall-2026-04-24.md)).

---

## Wire format reminders

For implementers writing their own decoder, not just calling `analyze_session09.py`:

1. **Per-chunk 4-byte CRC trailer** — `7c:00 [sess] [type=0x01] [seq:2] [body...] [CRC32-LE:4]`. Strip the CRC before reassembly. ([docs/moza-protocol.md § CRC algorithm](../docs/moza-protocol.md))
2. **0x7E byte stuffing** — every `0x7E` byte in the frame body (group/device/payload/checksum) is doubled on the wire. Use `wheel_sim.parse_frames` or equivalent for de-stuffing.
3. **9-byte envelope before zlib** — `[flag:1=0x00] [comp_size:u32 LE] [uncomp_size:u32 LE] [zlib stream]`. Multiple back-to-back envelopes can appear in a single session bytestream.
4. **Validate envelope** — only accept `flag==0x00`, sane `comp_size`/`uncomp_size`, AND `data[i+9..i+11]` matches zlib magic (`78 [01|5e|9c|da]`). Otherwise advance one byte and retry — captures with dropped chunks have garbage between blob boundaries.

Reassembly heuristic for incomplete captures: try (a) first-occurrence-per-seq, (b) last-occurrence-per-seq, (c) burst-split by frame-number gap. Pick the strategy that produces the most successful zlib decompressions. The analyzer does this automatically.

---

## Sim behaviour required (informs Phase 2 + 3)

1. **Default schema is A.** Only emit B for older-firmware compatibility tests.
2. **Default factory state matches display module.** Sim profiles for VGS + CSP both use Set A (matches user's hardware per latestcaps captures). KSPro (older display) would use Set B.
3. **`enableManager.dashboards` must list factory entries even when the FS has no `.mzdash` files.** Real wheel reports them; they live in firmware ROM, not in queryable filesystem paths. Sim's previous behaviour (gate on FS contents) makes the wheel look factory-wiped, which causes PitHouse cache-skip logic to misbehave.
4. **`rootDirPath` / `rootPath` is `/home/moza/resource[/dashes]`** — not `/home/root/...`. Session 0x04 root listing of `/home/root` is a *separate tree* and only contains `/temp` on the real wheel.
5. **Top-level `imageRefMap`, `imagePath`, and per-manager `imageRefMap`** must be populated to match the factory set. PitHouse uses these to track image dedup; an empty manifest tells PitHouse "nothing is shared" and triggers per-dashboard re-uploads of duplicated assets.
6. **User uploads register in `enableManager.dashboards[]`** with PitHouse-supplied id (or an alnum cache key). Per-upload `idealDeviceInfos` should match the active wheel's display module.
7. **Hash field is hex-encoded ASCII** of the canonical MD5 hex string. Sim must encode `bytes(md5_hex, 'ascii').hex()` on write, decode `bytes.fromhex(field).decode('ascii')` on read.
8. **Active-dash indicator NOT in 0x09 state.** Future RE work needed on group 0x40 cmd 28:xx.
