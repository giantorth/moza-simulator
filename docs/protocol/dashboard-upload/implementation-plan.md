# Dashboard upload — implementation plan

Ordered checklist of plugin gaps against the protocol as currently
decoded. Severity tags reflect user-visible impact at the time of
writing.

| Order | Gap | Severity | Status |
|------:|-----|---------|--------|
| 1 | Wheel acks land on `sess=0x04` not the host upload session | Critical | Decoded; coordinator change pending |
| 2 | Multi-file bundle (PNG dependencies) not built — plugin hardcodes `file_count=1` | Critical | Bundle layout verified byte-exact (`sess05-bundle-contents.md`); implementation pending |
| 3 | No type=0x03 chunking; `BuildFileContentChunked` returns a single sub-msg | High | Per-chunk envelope verified byte-exact (`per-chunk-trailer.md`); implementation pending. Code has explicit TODO at [`FileTransferBuilder.cs:175-194`](../../../Telemetry/Dashboard/FileTransferBuilder.cs) |
| 4 | Wheel staging path: `/_moza_filetransfer_md5_<hex>` vs observed `/tmp/_moza_filetransfer_md5_<hex>` | Unknown | Wheel may ignore — verify by changing path and watching for ack-byte-status differences |
| 5 | `BuildCompressedHeaderType02` emits a 12-byte `[uncomp BE][comp BE][CRC LE]` block; verified bundle preamble has an 8-byte `[total_compressed BE][total_uncompressed LE]` block (no CRC) — current code's structure is wrong for current PitHouse | Medium | Subsumed by Gap 2 rewrite — `BuildCompressedHeaderType02` should be replaced, not patched |
| 6 | `BuildMetadataBodyType02` writes `[(uint)0 LE = reserved][token LE]`; verified wire layout has `[bytes_written:u32 BE = 0][total_size:u32 BE]`. Current "token" field is mis-named and emitted with wrong byte order; the value should be the bundle's `total_compressed_size` (same as the per-chunk envelope's `total_compressed_size` at body[283:287]) written BE | Medium | One-line fix: replace `w.Write(token)` with `WriteUInt32BE(w, totalCompressedSize)`. Also rename `token` parameter throughout the call chain → `totalCompressedSize` |

## Gap 1 — cross-session ack handling (verified 2026-05-15)

### Problem

`WheelUploadCoordinator.NoteInboundChunk` early-returns when
`session != ActiveSession`:

```csharp
if (session != ActiveSession) return false;
```

But for current PitHouse, the wheel acks the upload on **`sess=0x04`**
regardless of which session (0x05, 0x07, 0x09…) the host opened for the
upload. Verified 2026-05-15 via time-correlation against
`sim/logs/bridge-20260514-170002.jsonl` (two consecutive PitHouse
uploads, ETS2-ATS + Simple Rally Mini Dash):

- 5 b2h sess=0x04 sub-msgs per upload (`type=0x01` × N progress acks +
  `type=0x11` × 1 complete-ack), 292 B each.
- Body echoes `0x70` REMOTE TLV `/_moza_filetransfer_md5_<md5hex>` (UTF-16LE)
  even though the host's outbound metadata carried no `0x70` TLV — the
  wheel derives this from the host-declared MD5.
- fc:00 chunk-level acks also flow on sess=0x04 (39 in upload #2's
  5-window aggregation).
- Acks emit ~25–28 s after each host `type=0x03` content sub-msg ends;
  final `type=0x11` arrives ~4 s after the last `type=0x01`.

The existing `_inboundMsgCount >= 5` heuristic worked accidentally for
upload #1 (sess=0x05 saw 25 b2h frames there) but fails for upload #2
(zero b2h frames on sess=0x05). The wire-format fallback (Legacy ↔ New)
mis-fires when the new format actually works because the coordinator
times out on the wrong session.

### Fix outline

1. Add a constant for the linked ack session: `private const byte UploadAckSession = 0x04;`
2. Plumb b2h sess=0x04 chunks into the coordinator alongside the upload
   session. `TelemetrySender`'s b2h chunk handler currently only forwards
   to the coordinator when `session == coordinator.ActiveSession` — add
   the OR branch for `0x04` during an active upload (gated by an
   `IsUploadInFlight` flag set by `SendDashboardUpload` and cleared on
   completion / abort).
3. Reassemble the b2h sess=0x04 stream and walk it with the 6-byte
   sub-msg parser (`[type:1][size_LE u16][pad:3][body:size]`). The
   walker is already proven correct on bridge captures.
4. Replace the `_inboundMsgCount >= 5` threshold:
   - On first observed `type=0x01` sub-msg → set `_subMsg1Response`.
   - On observed `type=0x11` sub-msg → set `_subMsg2Response`.
   - On observed type=0x01 with `bytes_written == total_size` → also
     valid trigger for `_subMsg2Response` (firmware variant).
5. Decode each ack's body to extract `bytes_written` and `status_byte`
   so the coordinator can surface upload progress + per-chunk failure
   detection (status byte ≠ XOR of body bytes ⇒ wheel rejected the
   round).
6. Keep `ActiveSession` semantics for outbound chunks (`SendAndTrackChunk`
   still routes to the host upload session). Only the inbound path
   changes.

### Risks

- **Cross-talk with `ConfigJsonClient`** which also listens on sess=0x04
  for dir-listing reassembly. The 6-byte sub-msg parse will see the
  type=0x0a dir-listing replies and skip them (different type byte) —
  but verify by running an upload + sess=0x09 schema push concurrently.
- **fc:00 ack consumption.** sess=0x04 fc:00 acks shouldn't be routed
  to the coordinator's `_subMsg*Response` events — fc:00 is the chunk-
  level ack for the bytes the wheel received, not a sub-msg progress
  signal.

### Verification

After implementing:

1. Capture a bridge JSONL during a fresh dashboard upload from the
   plugin (not PitHouse).
2. Verify the coordinator's `_subMsg1Response` fires after the wheel's
   first b2h sess=0x04 `type=0x01`, not after the 5-chunk heuristic.
3. Verify the wire-format-fallback branch (`upload = DashboardUploader.BuildUpload(..., Legacy)`)
   does NOT fire when the `New2026_04_Type02` format succeeded — i.e.
   the coordinator's `Wait(timeout)` returns true before timeout.

## Gap 2 — multi-file PNG bundle (layout decoded 2026-05-15)

### Problem

`BuildFileContentBodyType02` hardcodes:

```csharp
WriteUInt32BE(w, 1);  // file_count = 1
byte[] destBytes = Encoding.BigEndianUnicode.GetBytes(destPath);
WriteUInt32BE(w, (uint)destBytes.Length);
w.Write(destBytes);
w.Write(cmpHdr);
w.Write(zlib);  // single zlib stream of the mzdash
```

So every plugin-side upload sends ONE file (the mzdash). PitHouse
captures show real dashboards bundling the mzdash + every PNG resource
referenced by widgets, e.g.:

- ETS2-ATS: 1 mzdash + 8+ PNGs at `/home/moza/resource/images/MD5/<md5>.png`
- Simple Rally Mini Dash: 1 mzdash + 1 PNG

Widgets bound to image refs in the mzdash render blank when the host
uploads only the mzdash and the wheel can't find the image at its
content-addressed path.

### Decoded bundle layout (Simple Rally Mini Dash, upload #2)

Full byte-exact decode in [`sess05-bundle-contents.md`](sess05-bundle-contents.md).
The **compressed payload** (the byte stream split across type=0x03
chunks at `body[291 : 291 + this_chunk_deflate_size]`) starts with the
uncompressed bundle preamble, immediately followed by the zlib stream:

```
[file_count: u32 BE = N]
for each file i in 0..N-1:
    [dest_path[i]_byte_len: u32 BE]
    [dest_path[i]: UTF-16BE, no NUL terminator]
    [file[i]_uncompressed_size: u32 BE]
[total_compressed_size: u32 BE]     — byte count of the zlib stream
[total_uncompressed_size: u32 LE]   — Σ file_uncompressed_sizes (note: LE)
[zlib stream: 78 9c + raw deflate of (file[0]_bytes ‖ file[1]_bytes ‖ …) + adler32]
```

Verified math for upload #2 (file_count=2, dest_paths 158 B + 134 B,
preamble = 320 bytes, zlib stream = 14949 bytes, total payload =
15,269 bytes — equal to the per-chunk envelope's `total_compressed_size`
at body[283:287]):

- `file[0]_size + file[1]_size = 340342 + 747 = 341089` matches
  `total_uncompressed_size` exactly. The deflate stream is ONE zlib
  of all files concatenated in `dest_path` order; the wheel slices
  the decompressed output by per-file size — no internal separators
  inside the deflate stream.
- The preamble's `total_compressed_size` (14953 in upload #2) is
  4 bytes larger than the actual zlib stream length (14949). The
  field appears to be informational; the wheel reassembles using the
  per-chunk envelope's `total_compressed_size` (15269) which IS the
  full preamble + zlib stream length. Emit either value; verify by
  capture if the plugin's choice matters.

### Fix outline

1. Change `BuildFileContent` / `BuildFileContentBodyType02` to accept
   `List<(string destPath, byte[] content)>` instead of single
   `(destPath, mzdashContent)`.
2. **Normalise mzdash JSON line endings to CRLF before bundling**
   (verified 2026-05-15: bundle `file[0]_uncompressed_size` = on-disk
   byte count after `\n`→`\r\n` conversion, e.g. 332,404-byte LF mzdash
   → 340,342-byte CRLF-normalised). Other file types (PNGs) are binary
   and pass through unchanged. The conversion is
   `bytes.Replace(b"\r\n", b"\n").Replace(b"\n", b"\r\n")` (first
   strip any existing `\r\n` to avoid double-conversion).
3. Build the **uncompressed bundle preamble**:
   ```
   [file_count: u32 BE]
   for each file i:
       [dest_path[i]_byte_len: u32 BE]
       [dest_path[i]: UTF-16BE, no NUL]
       [file[i]_uncompressed_size: u32 BE]
   [total_compressed_size: u32 BE]    (= byte count of the zlib stream produced in step 4)
   [total_uncompressed_size: u32 LE]  (= Σ file[i]_uncompressed_size)
   ```
4. Concatenate all (CRLF-normalised) file bytes in `dest_path` order,
   run `CompressZlib` to produce one zlib stream (`78 9c …adler32`).
   Append zlib stream bytes after the preamble. This concatenation
   `[preamble] + [zlib]` is the **compressed payload** that gets split
   across type=0x03 sub-msgs (see Gap 3).
5. Plugin caller needs to walk the mzdash JSON to find every PNG the
   widgets reference, then resolve each PNG's bytes from a content
   store. PitHouse maintains one at
   `%LOCALAPPDATA%\MOZA Pit House\_dashes\<hash>\images\MD5\<md5>.png`;
   the plugin would either (a) read from the same path if PitHouse
   created it, or (b) maintain its own content store from the mzdash
   bundle file the user originally loaded. The user's on-wheel
   reference copies under `~/dashes/<DashName>/Resource/MD5/<md5>.png`
   share the same content-addressed layout. **Walk strategy**: search
   the mzdash JSON text for `MD5/<32-hex>.png` substrings (matches
   both `imageRefMap` keys and bare `src=` references); for each
   distinct hex, look up the file bytes from the content store and
   emit a `(/home/moza/resource/images/MD5/<hex>.png, content_bytes)`
   entry alongside the mzdash entry.
6. dest_path order should be **mzdash first, PNGs in any stable order
   afterwards** (matches PitHouse upload #2's ordering and is what the
   wheel's `imageRefMap` resolver expects — the mzdash is parsed first
   so the wheel knows which images to look for).
7. **Compute `md5 = MD5(compressed_payload)` AFTER building the full
   payload.** Verified 2026-05-15: the metadata's 16-byte MD5 field
   (at body[263:279] of every type=0x03 chunk; also emitted in the
   type=0x02 metadata) is `md5(preamble ‖ zlib_stream)` — i.e. of the
   full 15,269-byte compressed payload that gets split into chunks for
   upload #2. **Not** a content fingerprint of the original file
   bytes; **not** of the zlib stream alone; **not** of the
   decompressed concatenation. The same input files compressed at a
   different zlib level produce a different md5 — md5 is a signature
   of *this upload's compressed bytes*, used by the wheel as the
   staging-path filename (`/_moza_filetransfer_md5_<md5hex>`) so two
   uploads of the same content don't collide if one re-bundles with
   different compression. Order: (a) build preamble, (b) zlib-compress
   concatenated files, (c) concat preamble + zlib stream = payload,
   (d) md5(payload), (e) chunk payload + emit metadata using this md5.

### Verification

After implementing, upload a dashboard with a custom PNG referenced from
a widget. The widget should render the image on the wheel display.

## Gap 3 — type=0x03 chunking (decoded 2026-05-15)

### Problem

`BuildFileContentChunked` returns a single-element list. For mzdash
files compressing to > ~65 KB (the `u16` size cap on the 6-byte sub-msg
header), `BuildSubMsgHeader` throws. Real-world dashboards regularly
compress to > 4 KB, requiring at least 2-3 type=0x03 sub-msgs.

### Fix outline (decoded layout)

Per [`per-chunk-trailer.md`](per-chunk-trailer.md):

- Build the FULL compressed payload once = `[uncompressed bundle preamble]` (file table) + `[zlib stream]` (78 9c header + deflate of the concatenated file contents + adler32).
- Each type=0x03 sub-msg body is **`291 + this_chunk_deflate_size + 1` bytes** (1 trailing wire-pad byte) with the layout:
  - bytes 0-278 (279 B): shared TLV envelope (byte-identical across all chunks of one upload — LOCAL/REMOTE path TLVs + flag `0x10` + 16-byte MD5).
  - bytes 279-290 (12 B): **per-chunk position envelope** `[chunk_offset:u32 BE][total_compressed_size:u32 BE][this_chunk_deflate_size:u32 BE]`.
  - bytes 291 onwards: deflate slice. Chunk 0 includes the uncompressed bundle preamble (file table) + zlib magic `78 9c` + start of the deflate stream. Chunks 1+ are raw continuation bytes of the deflate stream.
  - body_len for upload #2 = `291 + 4092 + 1 = 4384` for chunks 0-2 and `291 + 2993 + 1 = 3285` for chunk 3.
- For chunk i ≥ 1: `chunk_offset = i × chunkStride` (chunkStride = 4092 = `0x0FFC`).
- For the last chunk: `this_chunk_deflate_size = remaining_bytes` (less than chunkStride).
- For non-last chunks: `this_chunk_deflate_size = chunkStride`.

`total_compressed_size` is the SAME across all chunks (matches the
type=0x02 metadata's `total_size_BE` and equals the total byte count
of `[bundle preamble] + [zlib stream]`).

**Decode-side verification (2026-05-15).** Reassembling the 4 chunks
of upload #2 with this exact slicing decompresses byte-exact to the
on-disk bundle content (modulo PitHouse re-generating `lastModified`
and `window.GUID` between save events).

Gated on Gap 1 verification (need clean ack flow to test).

## Gap 4 — wheel staging path mismatch

### Problem

Plugin emits `/_moza_filetransfer_md5_<hex>` (Type02) or
`/home/root/_moza_filetransfer_md5_<hex>` (legacy).

PitHouse 2026-05+ emits `/tmp/_moza_filetransfer_md5_<hex>`.

### Investigation

This may not matter — the wheel echoes whatever the host claims as the
staging path in its ack. The wheel likely uses the MD5 (not the
declared path) to look up the staging file internally. To verify:

1. Capture an upload from the plugin with the current
   `/_moza_filetransfer_md5_<hex>` path.
2. Check whether the wheel's ack echoes back the same path or rewrites
   it to `/tmp/...`.
3. If the wheel rewrites, the host's declared path is decorative; if
   the wheel echoes verbatim, we should match PitHouse for safety
   (matches "Replicate PitHouse fully" memory).

## Gap 5 — `BuildCompressedHeaderType02` is wrong for current PitHouse

Current code's 12-byte `[uncomp BE][comp BE][CRC32 LE]` block does NOT
appear anywhere in the verified upload #2 wire bytes. The verified
preamble has an 8-byte block at preamble[312:320]:

```
[total_compressed_size:u32 BE]   — byte count of the zlib stream
[total_uncompressed_size:u32 LE] — Σ file[i]_uncompressed_size (note: LE)
```

No 4-byte CRC anywhere in the bundle preamble — the wheel relies on
per-chunk CRC32-LE (in the session-data chunk framing) for integrity,
not a bundle-level CRC.

`BuildCompressedHeaderType02` should be **deleted** as part of the
Gap 2 rewrite — the multi-file bundle builder emits the verified 8-byte
block directly, no separate helper needed. Keep the legacy
`BuildCompressedHeader` for `FileTransferWireFormat.Legacy` callers if
those are still required by older firmware testing.

## Gap 6 — `BuildMetadataBodyType02` byte order + field naming

Current code emits at the end of the metadata body:

```csharp
w.Write((uint)0);     // "reserved"   — emits 00 00 00 00 (LE/BE indistinguishable for 0)
w.Write(token);       // "4B token (LE)"
```

Verified wire bytes (upload #2's type=0x02 metadata, body[307:319]):

```
body[307:311] = 00 00 00 00         — bytes_written:u32 BE = 0
body[311:315] = 00 00 3b a5         — total_size:u32 BE = 15269
body[315:319] = ff ff ff ff         — sentinel
```

So:
- `(uint)0` happens to be correct for `bytes_written_BE` (zero on host-
  emit) by coincidence (LE vs BE both serialize zero identically).
- `token` parameter is **misnamed**: the field is `total_size_BE`, not
  a token. Current code writes it LE; verified wire is BE. Same
  observation applies to `BuildFileContentBody` (legacy format) which
  also writes `w.Write(token)`.

Fix outline:

1. Rename `token` → `totalCompressedSize` throughout `FileTransferBuilder`
   and its call sites (`DashboardUploader`, `WheelUploadCoordinator`).
2. Replace `w.Write(token)` with `WriteUInt32BE(w, totalCompressedSize)`
   in `BuildMetadataBodyType02` and `BuildFileContentBody`.
3. Caller computes `totalCompressedSize` as the byte count of the full
   compressed payload (preamble + zlib stream — see Gap 2 step 4).
4. Verify by capture that the wheel's type=0x01 ready-ack echoes the
   same `total_size_BE` value the host emitted.

## Implementation order

Recommended sequence:

1. **Gap 1** (cross-session ack handling) — un-stalls every other
   verification, since without correct ack detection we can't tell
   whether subsequent changes succeeded.
2. **Gap 6** (rename `token` → `totalCompressedSize`, fix BE writer) —
   trivial one-line code fix; do it alongside Gap 1's coordinator work
   so the renamed parameter flows through cleanly.
3. **Gap 2** (multi-file bundle, including `BuildCompressedHeaderType02`
   replacement = Gap 5) — biggest user-visible payoff (PNG resources
   finally upload). Subsumes Gap 5.
4. **Gap 3** (chunking) — un-blocks larger dashboards. Builds on
   Gap 2's bundle structure.
5. **Gap 4** (staging path) — cosmetic; defer unless wheel proves it
   cares.

Each gap closure should land with a fresh bridge capture verifying the
plugin's outbound bytes match PitHouse's bytes byte-exact. If a delta
appears, decode it before declaring the gap closed — half-understood
deltas have produced the wrong-claim debris this doc trail had to
scrub once already.
