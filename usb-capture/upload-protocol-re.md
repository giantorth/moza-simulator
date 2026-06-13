# Dashboard upload protocol — RE notes (2026-04-27)

Status: **partial — small single-chunk uploads work, multi-chunk uploads stall**.
Sim's existing logic completes uploads when total byte count is small (verified
via captures + live tests) but PitHouse stops streaming mid-upload at random
chunk counts on KS Pro for large dashboards. Root cause not yet identified.

## Wire format — what's known

Each upload session goes:

```
host → wheel:  type=0x02 metadata sub-msg (declares total_size + md5 + paths)
host → wheel:  type=0x03 content sub-msg(s) (zlib-compressed mzdash bundle)
wheel → host:  type=0x01 ready-ack (bytes_written=0)         [right after type=0x02]
wheel → host:  type=0x01 progress-ack (bytes_written=N)      [per round, optional]
wheel → host:  type=0x11 done-ack (bytes_written=total_size) [after content fully received]
host → wheel:  SESSION_END
wheel → host:  SESSION_END (ack)
```

### Sub-msg structure

Each sub-msg in the host buffer:

```
[type:1] [size_LE:u16] [pad:3=00 00 00] [body:size]
```

Type bytes observed:
- `0x02` — metadata. Body carries LOCAL path TLV + REMOTE path TLV + md5 + bytes_written(BE u32) + total_size(BE u32) + 0xff*4 sentinel + 1B XOR status.
- `0x03` — content. Body[0..280] = TLV envelope (paths + md5 + tokens), body[281..283] = LE u24 chunk counter, body[284..289] = constant `03 92 16 00 00 0f fc`, body[290..1267) = chunk-0 only carries dest_path TLV + compressed_header, body[1267:] = chunk-0 zlib stream OR body[291:] = continuation deflate slice.
- `0x11` — wheel's done-ack reply (NOT a host content type — wheel emits this).
- `0x01` — wheel's ready/progress-ack reply.

### Wheel reply body

Both type=0x01 and type=0x11 from the wheel use identical body shape (verified
2026-04-26 against `latestcaps/pithouse-switch-list-delete-upload-reupload.pcapng`
upload #1 wheel reply stream):

```
[role:1=0x01|0x11] [size_LE:u16=body_len] [pad:3=00 00 00]
[00 00]                                              ← 2B preamble (real wheel)
[0x70 0x00] [UTF-16LE remote path] [0x00 0x00]
[0x8C 0x00] [UTF-16LE local path]  [0x00 0x00]
[0x10] [md5:16]
[bytes_written:u32 BE] [total_size:u32 BE]
[0xFF 0xFF 0xFF 0xFF]                                ← sentinel
[status:1]                                           ← 8-bit XOR over the body
```

Sim emits this via `build_file_transfer_response()` in `wheel_sim.py:1229`.
Sim uses an 8-byte header internally (`role + size_LE_u32 + pad*3`) but sets
`size = body_len + 2` so PitHouse's 6B-header parser lands on the correct
boundary. **Direct 6B-header emission was tried 2026-04-26 and stalled
PitHouse uploads at chunk 1** — revert kept the 8B trick.

## What works

- Single-chunk uploads (e.g. `latestcaps/pithouse-switch-list-delete-upload-reupload.pcapng`
  upload #1 + #2: 1 type=0x03 chunk each, 1902 / 3158 bytes, both completed).
- VM-GT3-Dash upload in `ksp/mozahubstartup.pcapng`: 4 type=0x03 chunks,
  total_size=13204, completed (FS shows file written + Schema B delta pushes
  on session 0x0a immediately after).

## What's broken

- Live KS Pro PitHouse uploading a 234006-byte dashboard against sim:
  PitHouse stops streaming after chunk 16 (65488 bytes received, 28% of total).
- Live KS Pro PitHouse uploading after sim restart with progress-ack
  suppression: PitHouse stops at chunk 1.
- Random "finishes at random point" UI symptom — partial files were being
  written to FS on `SESSION_END` regardless of whether content was complete
  (mitigated 2026-04-26 via `_ft_rounds_acked == 0xFFFF` gate).

## Hypotheses still on the table

1. **PitHouse expects something specific in the per-round progress ack body
   that sim's `bytes_written = bytes_received` doesn't satisfy.** Real wheel's
   progress acks (if it sends them at all) might carry uncompressed-byte
   count rather than compressed, or some other derived value. Multi-chunk
   real-wheel captures haven't been found that show explicit progress acks
   between READY and DONE — both observed multi-chunk captures
   (`mozahubstartup` VM-GT3-Dash + `latestcaps` upload #2) had the wheel
   send only 2 acks total per upload, suggesting NEW firmware doesn't use
   per-round progress acks at all and PitHouse may interpret extras as
   "wait, wheel is busy" → flow-control back off.
2. **Sim's 8B header trick + `size_LE = body_len + 2`** could land the body
   at wrong offset for PitHouse's per-round ack parsing. PitHouse parses
   the first ack OK (sees ready-ack, sends content) but subsequent acks
   may fail validation and PitHouse aborts. Real wheel uses 6B header but
   direct 6B emission also stalled — so the 8B/6B detail isn't the only
   factor.
3. **`type=0x03` body offset assumptions are wrong for KS Pro firmware.**
   Sim uses `body[291:]` for content (per existing comment line 4555).
   For KS Pro mozahubstartup VM upload, summing `body[291:]` slices yields
   13208 bytes vs declared total_size=13204 — close match. For latestcaps
   upload #1, zlib magic lives at body[411] not body[291] — older firmware
   different layout. KS Pro firmware might have a different chunk-0 vs
   continuation offset that sim isn't tracking.
4. **PitHouse times out per-chunk based on USB latency** and sim's reply
   chain (8B reply gets chunked to multiple session-mux frames + per-frame
   `fc:00` acks consume USB bandwidth) is too slow under high-throughput
   load. Different chunk pacing on the sim side might unstick it.

## Next debugging steps

- Capture a fresh pcap of a live KS Pro real wheel doing a large
  (200+ KB) dashboard upload. Isolate the wheel's actual ack pattern —
  per-round or 2-total. Decode body layout offsets for the type=0x03 chunk
  content slice on KS Pro firmware specifically.
- Check whether real wheel ever emits a progress ack in the captures we
  already have. `usb-capture/AB9/`, `09-04-26/burn-tyres.pcapng`,
  `usb-capture/connect-wheel-start-game.pcapng` may contain large uploads.
  `usb-capture/analyze_upload_end.py` can locate them.
- If real wheel does use 2-acks-only on KS Pro, restore ack-suppression in
  sim AND solve the chunk-1 stall some other way (maybe READY-ACK timing
  is off — try emitting it BEFORE content arrives, on type=0x02 metadata
  receipt, instead of from the chunk-debounced timer).

## Tooling

- `usb-capture/analyze_upload_end.py` — walks per-session host + device
  buffers, identifies upload sessions (≥3 type=0x03 chunks), prints last
  3 type=0x03 chunks + first 2 wheel type=0x11 acks side-by-side, and
  finds the exact host frame immediately preceding the wheel's first
  type=0x11. Use for verifying wheel's actual completion signal.
- `sim/logs/ft_echo_sess<NN>.log` — per-call diagnostic from
  `_queue_file_transfer_echo`. Tracks rounds, bytes_received, total_size,
  decoded_size, decoded_complete per ack tick.
- `sim/logs/parse_upload.log` + `parse_upload_sess<NN>_buf.bin` /
  `_decoded.bin` — full captured upload buffer + decoded bundle, dumped on
  every parse attempt. Survives sim restart so the next debugging session
  can replay.

## Related docs

- [docs/moza-protocol.md § Dashboard upload protocol](../docs/moza-protocol.md)
- [usb-capture/payload-09-state-re.md](payload-09-state-re.md) — Schema B
  delta emission on session 0x0a follows upload completion.
- [usb-capture/ksp-deep-investigation-plan.md](ksp-deep-investigation-plan.md)
  — overall KS Pro firmware findings.
