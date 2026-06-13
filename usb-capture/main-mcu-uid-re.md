# MainMcuUidCommand — research target

Status: **not reversed**. Wire format, group/device/cmd IDs, response shape all unknown.

## Why it matters

From `docs/moza-protocol.md:1375` (RESOLVED 2026-04-14 on other context):

> PitHouse's `Sync_DashboardManager` uses `mcUid` (STM32 MCU hardware UID, read via `MainMcuUidCommand`) as a per-device routing key

`mcUid` = the cache key PitHouse uses to decide "have I already uploaded dashboard X to this specific physical wheel?". Without a unique per-instance UID, PitHouse appears to either:

- Refuse to sync (wheel treated as unknown), or
- Treat all sims as the same "wheel" because the default/missing UID collapses them into one cache bucket

Observed symptom 2026-04-21: user clicks Upload in PitHouse on a fresh sim with empty FS → zero bytes of file-transfer traffic arrives on session 0x04. Clearing the FS via `sim_reset_fs` does not help.

## What we know

- `MainMcuUidCommand` is a method/command name mentioned by the RS21 parameter DB or PitHouse internals
- mcUid is distinct from:
  - Wheel serial number (read via group 0x10 / dev 0x17 / cmd `00` and `01` — ~16-byte strings)
  - Upload token 1/2 (session 0x04 sub-msg 1 correlation IDs — CSPRNG random, not derived from mcUid)
- mcUid is **NOT** encoded in the upload tokens (tested exhaustively in 2026-04-14 investigation)
- Probably fetched by PitHouse during connect preamble, before any upload decision

## What we don't know

- Which group/device the command targets (likely dev 0x12 "main hub" or 0x13 "base")
- Command ID byte(s)
- Response payload size — STM32 UIDs are typically 96 bits (12 bytes) stored at `0x1FFF7A10`. Response might be exactly that.
- Wire-level frame structure

## Research path

### 1. Extract from captured pcapng

`usb-capture/latestcaps/automobilista2-wheel-connect-dash-change.pcapng` captures a fresh PitHouse connect. Expected mcUid query somewhere in the first ~500 ms. Approach:

1. Filter to host→device writes in that window
2. Look for a short query (4–8 bytes) with no known group match in `docs/moza-protocol.md § Device and command reference`
3. Check the wheel's response — if it's a 12-byte binary blob that looks random (not ASCII, not mirroring the request), that's the mcUid
4. Cross-reference wire bytes against unknown-opcode lists in `_GROUP_LABELS` at `sim/wheel_sim.py:341` — any command the sim currently tags as unknown and that appears early in the connect flow is a candidate

### 2. Search PitHouse PE binary

Open `SimplePitHouse.exe` or equivalent in a disassembler. Search strings for:
- `MainMcuUidCommand`
- `mcUid`
- `Sync_DashboardManager`

Cross-reference to the SerialStream layer. Should give the exact group+cmd bytes.

### 3. Look at shipped MOZA firmware

`usb-capture/rs21_parameter.db` is a SQLite of RS21 parameters. Open and search for `mcuid`, `main_mcu_uid`, or parameter names containing `uid`. If found, the parameter's group+id tells us the wire format.

```bash
sqlite3 usb-capture/rs21_parameter.db 'SELECT * FROM Parameter WHERE name LIKE "%Uid%" OR name LIKE "%MCU%" OR name LIKE "%mcu%";'
```

## Minimum viable sim response

Once group+cmd known:

1. Add to sim `pithouse_rsp` table: `(group, cmd_payload): 12-byte-UID`
2. Generate UID at sim start from hash of (hostname, timestamp) or pure random — ensures cross-run uniqueness so PitHouse treats each run as a new wheel
3. Add `--stable-mcuid` flag for researchers who want reproducible testing

## Expected outcome

With a unique mcUid per sim run, PitHouse should:

- Treat the sim as a new wheel after every `sim_start`
- Send the full upload sequence on session 0x04 when user clicks Upload
- Populate `sim_uploads` with session 0x04 sub-msg 1 (path registration) + sub-msg 2 (file content) blobs
- Let the sim capture and parse the actual mzdash upload
