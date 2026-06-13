# Sim empty-filesystem signalling — research + plan

Status: **hypothesis revised 2026-04-21**. Initial guess (configJsonList should track FS state) was wrong — zeroing the canonical list broke PitHouse display detection. The canonical list is **firmware-baked and immutable** (factory catalog of supported dashboard names); it is NOT derived from FS. PitHouse UI cache-skip is keyed on something else — likely MD5/hash match in `enableManager.dashboards`, or on separate session-0x04 directory listing state.

## Observed symptom

User clicks Upload 2x + Use Dashboard 2x in PitHouse on a fresh sim (FS empty, count=0). Zero host→wheel RPC content frames appear on session 0x0a during those clicks. All UI actions absorbed by PitHouse's cache check.

## What we tried (and why it failed)

**Hypothesis H1 (wrong)**: `configJsonList` being pre-populated with 11 canonical names on an empty FS tricks PitHouse into cache-skipping uploads.

**Fix attempted (reverted)**: gate `configJsonList` on FS state — emit `[]` when FS empty.

**Result**: PitHouse stopped fully detecting the wheel's display. `configJsonList` is firmware-baked immutable data — the wheel's integrated UI needs the canonical list to be present regardless of FS state to enable display-feature routing. Setting it empty made PitHouse downgrade the wheel to "no display" mode.

Lesson: canonical list = firmware catalog, not FS mirror. Do not gate it.

## Revised hypothesis (partially tested 2026-04-21)

Post-revert test: fresh sim + sim_reset_fs + fresh Pithouse connect → user clicks Upload on a "test" dashboard → **zero content frames on sessions 0x01 or 0x04 for 3+ minutes**. Only keepalives. Pithouse did not transmit the upload at all.

Candidate cause ranking:

1. **mcUid caching (most likely)** — per `docs/moza-protocol.md:1375`, PitHouse's `Sync_DashboardManager` uses `mcUid` (STM32 MCU hardware UID via `MainMcuUidCommand`) as a per-device routing key. Sim does NOT implement `MainMcuUidCommand` response. Two sub-cases:
   - a) Pithouse can't get mcUid → treats wheel as "unknown, skip sync" → no upload
   - b) Pithouse gets a default/zero mcUid → caches under that key → thinks same wheel as previous tests → cache-skips
   - Verification path: implement a `MainMcuUidCommand` response with a randomised UID on each sim start. See `usb-capture/main-mcu-uid-re.md` (to be written).

2. **Hardcoded sim serial** — `wheel_sim.py:144` uses `serial0: 'VGS00000000000'` unchanged across runs. Even if mcUid isn't the key, Pithouse may cache by serial. Randomising the serial on start could disambiguate.

3. **Session 0x04 directory listing** — `build_session04_dir_listing(self.fs.list_children('/'))` should emit empty `children` when FS empty. Not confirmed on wire yet.

4. **Pithouse local cache file on PC** — `%APPDATA%/PitHouse/` likely holds "last-synced" dashboard state per wheel. Clearing that dir (or running Pithouse as a different user) would force fresh uploads.

## Next experiments

- Implement dummy `MainMcuUidCommand` response (needs wire format RE first)
- Randomise serial on each sim start via `--randomize-serial` flag
- Inspect `usb-capture/latestcaps/automobilista2-wheel-connect-dash-change.pcapng` for the mcUid query frame — expected somewhere in the first 500 ms of connect
- Ask user to clear PitHouse's `%APPDATA%` data folder and retry upload

## Plan — Phase S7 (revised)

1. ~~**Gate canonical list on FS state**~~ — reverted; do NOT change.
2. **Expose `sim_reset_fs` MCP tool** — clears FS + stored dashboards + upload tracker state (implemented, works).
3. **Verify session 0x04 root directory listing mirrors FS** — `build_session04_dir_listing(self.fs.list_children('/'))` already walks FS. Confirm it emits empty `children` when FS has no `/home/moza/resource/dashes/*` entries.
4. **Capture a PitHouse "fresh upload" flow from a known-empty state** — either (a) use PitHouse's own "Delete cached wheel data" option if it exists, or (b) change sim's reported serial/MCU UID so PitHouse treats it as a new wheel, or (c) start PitHouse with a clean `%APPDATA%` profile.
5. **Add session 0x0a RPC handler for uploads** — parse `{"completelyAdd()":{name,...}, id}` etc., write payload to FS, re-emit configJson state so new dashboard surfaces in UI.
6. **Expose `sim_reported_state` MCP tool** — done.
7. **Relax RPC regex** — done; empty-method `()` now captured.

## Success criteria

- User clicks Upload on a dashboard → session 0x0a RPC blob arrives on the wheel
- Sim `sim_rpc_log` shows the RPC with method name + args
- Sim writes to FS, re-emits state, PitHouse UI reflects the change

## Research inputs

- `sim/wheel_sim.py:1207` — `_CONFIGJSON_CANONICAL_LIST` definition
- `sim/wheel_sim.py:1213` — `build_configjson_state()` composer
- `sim/wheel_sim.py:1498` — `_extract_dashboard_metadata` (RPC parser, regex needs relaxing)
- `sim/logs/uploads/sess0a_frames.log` — observed RPC traffic (only reset RPCs captured so far)
- `usb-capture/latestcaps/automobilista2-wheel-connect-dash-change.pcapng` — should contain `completelyAdd` RPCs from the dash-change sequence
