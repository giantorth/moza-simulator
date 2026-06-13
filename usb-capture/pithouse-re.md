# Pithouse binary reverse engineering

Reverse engineering notes for `bin/MOZA Pit House.exe` (PE32, 31MB, MSVC C++/Qt 5).
Binary location: `<pithouse>/bin/MOZA Pit House.exe`.

---

## Goal

Determine how Pithouse packs game telemetry into the bit stream sent over serial to the wheel/dash, specifically:
1. Exact bit width per compression type
2. Channel ordering in the bit stream
3. The full assemble-and-send chain
4. The meaning of the flag byte in the telemetry header

---

## Tools and approach

- **Ghidra 12.0.4** headless mode (`analyzeHeadless`) for decompilation
- `strings -t x` + Python for string/xref searches
- `objdump -d -M intel` for targeted disassembly
- Python scripts for RTTI vtable tracing and capture data correlation

The binary is not obfuscated. MSVC RTTI is intact, giving full class names. No PDB available.

---

## Key addresses

All addresses are virtual addresses (VAs) in the loaded PE.

### String references

| VA | String | Context |
|----|--------|---------|
| `0x01b69684` | `TelemetryBitFormat::assemble::` | Error logging in assemble function |
| `0x01b69718` | `MOZA::Telemetry::TelemetryServer::reconfigClientField [TelemetryBitPackage::addTelemetry] error:` | Error in channel addition |
| `0x01b69780` | `TelemetryBitFormat::disassemble::` | Error logging in disassemble function |
| `0x01b69ca4` | `[LOCK_ACQUIRE] TelemetryServer::updateTelemetry` | Lock tracing in update loop |
| `0x01b6a3ec` | `[LOCK_ACQUIRE] TelemetryServer::worker` | Lock tracing in send worker |
| `0x01b6a46c` | `TelemetryServer:: telemetry send error:` | Serial send error |
| `0x0176aaa0` | `[Sync_DashboardManager::getMcUid] start` | MCU UID retrieval for dashboard routing |
| `0x0176bf10` | `_t1.toHex() != m_mcUid` | Upload device verification |
| `0x017dbb28` | `Protocol - MainMcuUidCommand -` | MCU UID command definition |
| `0x017d4198` | `slot updateMainMcuUid enter this=` | MCU UID update handler |
| `0x0176b3e8` | `mcUid->getTargetDevice() != m_deviceInfo->getTargetDevice()` | Dashboard upload device check |
| `0x018cc7b8` | `requestUploadTitanToken` | Cloud upload auth (not serial) |
| `0x018cc960` | `moza::usrsvc::GetTitanTokenResp` | Cloud token response type |

### Compression type string table

Clustered at file offset ~`0x17669d8`. These are the keys in the factory lookup table built by `FUN_0042fc00`.

| VA | String | Factory ID |
|----|--------|-----------|
| `0x01b679c8` | `bool` | 0 |
| `0x01b679d0` | `int8_t` | 1 |
| `0x01b679d8` | `uint8_t` | 2 |
| `0x01b679e0` | `int16_t` | 3 |
| `0x01b679e8` | `uint16_t` | 4 |
| `0x01b679f4` | `uint24_t` | 24 |
| `0x01b67a00` | `int32_t` | 5 |
| `0x01b67a08` | `uint32_t` | 6 |
| `0x01b67a14` | `float` | 7 |
| `0x01b67a1c` | `int64_t` | 8 |
| `0x01b67a24` | `uint64_t` | 9 |
| `0x01b67a30` | `double` | 10 |
| `0x01b67a38` | `string` | 11 |
| `0x01b67a40` | `int30` | 13 |
| `0x01b67a48` | `uint30` | 19 |
| `0x01b67a50` | `uint31` | 19 |
| `0x01b67a58` | `location_t` | 9 |
| `0x01b67a64` | `percent_1` | 14 |
| `0x01b67a70` | `float_6000_1` | 15 |
| `0x01b67a80` | `float_600_2` | 16 |
| `0x01b67a8c` | `tyre_temp_1` | 17 |
| `0x01b67a98` | `brake_temp_1` | 18 |
| `0x01b67aa8` | `uint8` | 20 |
| `0x01b67ab0` | `uint3` | 20 |
| `0x01b67ab8` | `uint15` | 20 |
| `0x01b67ac0` | `track_temp_1` | 17 |
| `0x01b67ad0` | `tyre_pressure_1` | 22 |
| `0x01b67ae0` | `oil_pressure_1` | 17 |

Note: factory IDs are NOT bit widths. They're enum values selecting which interface constructor to call. Multiple compression types can share the same ID (e.g. `uint30`/`uint31` both map to 19; `uint8`/`uint3`/`uint15` all map to 20).

### RTTI type descriptors (MOZA::Telemetry namespace)

Found via `strings -t x | grep "Interface@Telemetry@MOZA"`:

| File offset | Class name |
|-------------|-----------|
| `0x1cdbb3c` | `Interface` (base) |
| `0x1cdbb64` | `BoolInterface` |
| `0x1cdbb90` | `IsUnsignedInterface` (abstract) |
| `0x1cdbbc4` | `Int8Interface` |
| `0x1cdbbf0` | `Int16Interface` |
| `0x1cdbc1c` | `Int32Interface` |
| `0x1cdbc48` | `Int64Interface` |
| `0x1cdbc74` | `DoubleInterface` |
| `0x1cdbca4` | `Int1000Interface` |
| `0x1cdbcd4` | `UInt24Interface` |
| `0x1cdbd04` | `Int30Interface` |
| `0x1cdbd30` | `Int15Interface` |
| `0x1cdbd5c` | `PercentInterface` |
| `0x1cdbd8c` | `NormalizedInterface` |
| `0x1cdbdc0` | `UFloatInterface` |
| `0x1cdbdf0` | `TyreTempInterface` |
| `0x1cdbe20` | `TyrePressureInterface` |
| `0x1cdbe54` | `BrakeTempInterface` |

### Interface vtables

Traced from RTTI Type Descriptors → Complete Object Locators → vtable pointers. Each vtable has 4+ entries.

| Class | vtable VA | vtable[0] (bitCount) | vtable[1] (decode) | vtable[2] (encode) | vtable[3] (convert) |
|-------|-----------|---------------------|--------------------|--------------------|---------------------|
| `BoolInterface` | `0x01b68304` | `0x00800780` | `0x00804240` | `0x008041e0` | `0x007fe860` |
| `Int8Interface` | `0x01b68334` | `0x00800890` | `0x00804340` | `0x008042e0` | `0x007fe860` |
| `Int15Interface` | `0x01b683f4` | `0x008007f0` | `0x00804f40` | `0x00804ed0` | `0x007fe860` |
| `Int16Interface` | `0x01b6834c` | `0x00800810` | `0x008044d0` | `0x00804470` | `0x007fe860` |
| `Int30Interface` | `0x01b683dc` | `0x00800830` | `0x00804df0` | `0x00804d80` | `0x007fe860` |
| `Int32Interface` | `0x01b68364` | `0x00800850` | `0x00804660` | `0x00804600` | `0x007fe860` |
| `Int64Interface` | `0x01b6837c` | `0x00800870` | `0x00804800` | `0x00804790` | `0x007fe860` |
| `DoubleInterface` | `0x01b68394` | `0x008007a0` | `0x008049e0` | `0x00804920` | `0x007fe860` |
| `Int1000Interface` | `0x01b683ac` | `0x008007d0` | `0x00804ba0` | `0x00804b20` | `0x007fe860` |
| `UInt24Interface` | `0x01b683c4` | `0x008008f0` | `0x00804cd0` | `0x00804c70` | `0x007fe860` |
| `PercentInterface` | `0x01b6840c` | `0x008007d0` | `0x00804ba0` | `0x00804b20` | `0x00805020` |
| `NormalizedInterface` | `0x01b68424` | `0x008007d0` | `0x00804ba0` | `0x00804b20` | `0x00805170` |
| `UFloatInterface` | `0x01b6843c` | `0x00800810` | `0x008044d0` | `0x00804470` | `0x008052c0` |
| `TyreTempInterface` | `0x01b68454` | `0x008008d0` | `0x008054e0` | `0x00805440` | `0x007fe860` |
| `TyrePressureInterface` | `0x01b6846c` | `0x008008b0` | `0x00805620` | `0x00805580` | `0x007fe860` |
| `BrakeTempInterface` | `0x01b68484` | `0x00800810` | `0x008044d0` | `0x00804470` | `0x008056c0` |

Key observations:
- `Int1000Interface`, `PercentInterface`, and `NormalizedInterface` share the same `bitCount` (10 bits), `decode`, and `encode` functions — they differ only in the conversion function (`vtable[3]`)
- `Int16Interface`, `UFloatInterface`, and `BrakeTempInterface` share the same `bitCount` (16 bits), `decode`, and `encode` — differ only in conversion
- `IsUnsignedInterface` vtable entries point to `_purecall` (abstract class)

### Key functions

| VA | Name/purpose | Size | Notes |
|----|-------------|------|-------|
| `0x0042fc00` | Compression type factory table builder | 1717 | Builds `{string → factory_ID}` lookup table |
| `0x0080c1b0` | `TelemetryBitFormat::assemble` | 832 | Packs channel values into bit stream |
| `0x0080c630` | `TelemetryBitFormat::disassemble` | 514 | Unpacks bit stream into channel values |
| `0x0080dfc0` | `TelemetryBitPackage::addTelemetry` | 2608 | Builds channel list from dashboard config |
| `0x0080d4e0` | `TelemetryServer::updateTelemetry` | 2418 | Updates channel values from game data |
| `0x00814610` | `TelemetryServer::worker` | 5512 | Main send loop — assembles and sends serial frames |
| `0x00811260` | `TelemetryServer::newConnectionRequest` | 2772 | Handles new wheel/dash connections |
| `0x008128c0` | `TelemetryServer::readReady` | 5244 | Processes incoming data from wheel |
| `0x0080c940` | Header builder | 383 | Prepends `[flag] [0x20]` to assembled data |
| `0x0080c0f0` | Byte count calculator | 182 | Returns `ceil(total_bits / 8.0)` |
| `0x00822240` | `MOZA::Telemetry::UrlSimplifier` constructor | — | Calls `FUN_00832160(this, descriptor_buf, 3)` |
| `0x00832160` | UrlSimplifier core | — | Loops 3 streams; processes 16-byte descriptor entries via `FUN_00778280` (×2 per entry), then calls `FUN_008238c0` to push 48-byte routing entry |
| `0x00778280` | UrlSimplifier string builder | 189 | `__thiscall`: zeroes 24 bytes at `this`, then calls `FUN_005b4490(ptr, len)` — constructs a `std::string` from an 8-byte `{char*, size_t}` descriptor half |
| `0x008238c0` | UrlSimplifier routing table push_back | 126 | Appends a 48-byte entry to the routing table vector; calls `FUN_008242b0` if capacity full, else calls `FUN_00821760` and advances write pointer by `0x30` |
| `0x00838940` | UrlSimplifier routing table init | 68 | Zeroes 3 DWORDs (data/begin/end) — standard vector default-init |
| `0x0081eb30` | Stream descriptor builder | — | Constructs `MOZA::Telemetry::UrlSimplifier` shared_ptr; `*param_1 = vftable`; calls `FUN_00822240` |
| `0x00836930` | UrlSimplifier factory entry point | — | Called from `newConnectionRequest` as `FUN_00836930(output, local_118)` with the 48-byte stream descriptor buffer |
| `0x00806d30` | Channel value reader (typed) | 206 | Switch on type-id (0–4): 0→`FUN_008089d0`, 1/2→`*(byte*)param_3`, 3→`*(int*)param_3 & 0xff`, 4→`FUN_00806540(param_2,param_3,5)` |
| `0x00805820` | Interface lookup | 291 | Looks up interface by compression ID in global singleton map |
| `0x0080be20` | Channel vector add/update | 352 | Adds or updates a channel in the packing vector |
| `0x00806900` | Global interface map lookup | 77 | Searches `std::map<int, Interface*>` at `DAT_02157ca8` |

### Bit read/write functions

| VA | Purpose | Bit count | Notes |
|----|---------|-----------|-------|
| `0x00808d30` | Read N bits (1-bit variant) | 1 | LSB-first within each byte |
| `0x00809e60` | Write N bits (1-bit variant) | 1 | LSB-first, clears then sets |
| `0x00808a00` | Read N bits (4-bit variant) | 4 | Same algorithm, hardcoded loop count |
| `0x00809a70` | Write N bits (4-bit variant) | 4 | |
| `0x00808f50` | Read N bits (10-bit variant) | 10 | Returns `ushort` |
| `0x00809fb0` | Write N bits (10-bit variant) | 10 | |
| `0x008094f0` | Read 32-bit float | 32 | Returns `uint` (reinterpreted as IEEE float) |
| `0x0080a4f0` | Write 32-bit float | 32 | |
| `0x00809820` | Read 64-bit double | 64 | Returns `uint64` |
| `0x0080a790` | Write 64-bit double | 64 | |

All use the same algorithm: `byte_offset = bit_position / 8`, `bit_offset = bit_position % 8`, then loop byte-by-byte extracting/inserting bits with masks. **LSB-first within each byte.**

---

## Findings

### 1. Bit widths (verified from vtable[0])

Each interface's `bitCount()` (`vtable[0]`) is a trivial function returning a constant:

```c
// BoolInterface::bitCount — returns 1
undefined8 FUN_00800780(void) { return 1; }

// Int30Interface::bitCount — returns 5
undefined8 FUN_00800830(void) { return 5; }

// PercentInterface/NormalizedInterface/Int1000Interface::bitCount — returns 10
undefined8 FUN_008007d0(void) { return 10; }

// Int16Interface/UFloatInterface/BrakeTempInterface::bitCount — returns 16
undefined8 FUN_00800810(void) { return 0x10; }

// DoubleInterface::bitCount — conditional on flag byte at this+4
undefined4 FUN_008007a0(int param_1) {
    if (*(char *)(param_1 + 4) == '\0') return 0x40;  // 64 bits (double)
    else return 0x20;                                   // 32 bits (float)
}
```

Complete bit width table:

| Compression | Bits | Interface | Evidence |
|-------------|------|-----------|----------|
| `bool` | 1 | `BoolInterface` | `return 1` |
| `uint3`, `uint8`, `uint15` | 4 | `Int15Interface` | `return 4` |
| `int30`, `uint30`, `uint31` | 5 | `Int30Interface` | `return 5` |
| `int8_t`, `uint8_t` | 8 | `Int8Interface` | `return 8` |
| `float_001` | 10 | `NormalizedInterface` | `return 10` |
| `percent_1` | 10 | `PercentInterface` | `return 10` |
| `tyre_pressure_1` | 12 | `TyrePressureInterface` | `return 0xc` |
| `tyre_temp_1`, `track_temp_1`, `oil_pressure_1` | 14 | `TyreTempInterface` | `return 0xe` |
| `uint16_t`, `int16_t` | 16 | `Int16Interface` | `return 0x10` |
| `float_6000_1` | 16 | `UFloatInterface` | `return 0x10` |
| `float_600_2` | 16 | (factory ID 16) | `return 0x10` |
| `brake_temp_1` | 16 | `BrakeTempInterface` | `return 0x10` |
| `uint24_t` | 24 | `UInt24Interface` | `return 0x18` |
| `float` | 32 | `DoubleInterface(flag=1)` | `return 0x20` |
| `int32_t`, `uint32_t` | 32 | `Int32Interface` | `return 0x20` |
| `double`, `int64_t`, `uint64_t`, `location_t` | 64 | `DoubleInterface(flag=0)` / `Int64Interface` | `return 0x40` |

Surprise: `uint3` uses 4 bits (same as `uint15`), NOT 3. All three types with factory ID 20 (`uint3`, `uint8`, `uint15`) map through abstract `IsUnsignedInterface` to `Int15Interface`. The type name's number does NOT determine the bit width.

### 2. Channel ordering — alphabetical by URL, within each `package_level`

`TelemetryServer::updateTelemetry` (`FUN_0080d4e0`) iterates a `std::map<QString, ...>` keyed by channel URL. The tree comparison function (`FUN_008273d0` at `0x008273d0`) uses `FUN_005bb180` (Qt string comparison) to traverse nodes.

Since `std::map` in-order traversal yields sorted keys, channels within each stream are packed **alphabetically by their URL suffix** (the part after the last `/`). Channels from different `package_level` tiers go to different streams and are packed independently.

This was confirmed by:
1. Brute-force searching capture data for the 5-bit Gear field — found at bit 79
2. Under level-30-only ordering: Brake(10)+CurrentLapTime(32)+DrsState(1)+ErsState(4)+GAP(32) = **79 bits** before Gear ✓
3. Decoding all 9 level-30 channels from captures produces plausible values (gear {0-6}, brake 26-87%, monotonic lap times, etc.)

### 3. Size limit and channel dropping

`FUN_0080c0f0` (ByteCountCalculator) iterates the channel vector (stride 0x10), sums the bit count at entry offset +8, and returns `ceil(total_bits / 8.0)` using constant `DAT_01b6a8b8 = 8.0`.

In the worker function, before adding each channel, the current byte count is compared against a per-dashboard limit (stored at config offset `+0x30`). The comparison determines whether to add or skip each channel. Channels that would push the total beyond the limit are skipped, but the loop continues trying subsequent (smaller) channels.

**The comparison is inclusive: a channel is added if `ceil((current_bits + channel_bits) / 8) <= limit`.**

The F1 dashboard (current install, no FuelRemainder) has 9 level-30 channels totalling 126 bits = 16 bytes — hitting the 16-byte limit exactly with 2 padding bits. All 9 fit; none are dropped.

### 4. Telemetry send chain

Traced from game data to serial wire:

```
Game (SimHub/AC/LMU)
  → Telemetry.json defines channel compression types
  → Dashboard .mzdash defines which channels to display

TelemetryServer::updateTelemetry (FUN_0080d4e0)
  → iterates std::map<QString, ChannelInfo> in alphabetical order
  → for each channel, looks up in active client's channel tree
  → calls FUN_0083d670 to assign sequential channel index
  → updates channel values from game data

TelemetryServer::worker (FUN_00814610) — main send loop
  → for each connected client (in client tree):
      → FUN_008295b0: set up channel data
      → FUN_0080c1b0 (assemble): pack all channels into bit stream
          → iterates channel vector (16-byte entries, stride 0x10)
          → for each channel:
              → FUN_00805820: lookup interface by compression ID
              → vtable[3]: convert game value → raw integer
              → vtable[2]: encode raw integer into bit stream
          → bit offset starts at 0, advances by each channel's bitCount()
      → FUN_0080c940: prepend header [flag_byte] [0x20]
          → flag_byte comes from client tree node key (offset 0x0E)
          → 0x20 is a hardcoded constant
      → FUN_00964f80: wrap in Moza serial frame and send
          → adds 7E, length, group 0x43, device 0x17, cmd 7D 23
          → prepends constant header bytes 32 00 23 32
          → appends checksum
```

### 5. Flag byte

The flag byte (header byte 4) is the **map key** of the client connection in `TelemetryServer`'s client tree. The tree node at offset 0x0E is the start of the key in MSVC's `std::_Tree_node` layout:

```
std::_Tree_node layout (32-bit MSVC):
  +0x00: _Left   (pointer)
  +0x04: _Parent (pointer)
  +0x08: _Right  (pointer)
  +0x0C: _Color  (char, 0=red, 1=black)
  +0x0D: _Isnil  (char, 0=real node, 1=sentinel)
  +0x0E: _Myval  (start of key+value) ← flag byte is here
```

The worker reads it at line 848: `puStack_5e4 = (undefined1 *)(iStack_158 + 0xe)`.

The base flag value is assigned per-session during connection negotiation in `readReady` (`FUN_008128c0`, 5244 bytes). Minority flags (base+1, base+2) are separate client tree entries carrying additional telemetry payloads — see § Multi-stream telemetry below.

Observed flag values across captures (all from the same VGS wheel, W08-V12):

| Session | Dashboard | Payload bytes | Majority flag | Minorities |
|---------|-----------|---------------|---------------|------------|
| dash | unknown | ? | 0x02 | 0x03, 0x04 |
| 0-100redline-other | other | 6 | 0x02 | 0x03 |
| 0-100redline-rpm | simple-rpm | 2 | 0x07 | — |
| 0-6thgear-main | F1 | 16 | 0x0a | 0x0b, 0x0c |
| burn-tyres | F1 | 16 | 0x0a | 0x0b, 0x0c |
| 0-6thgear-rpm | simple-rpm | 2 | 0x10 | — |
| 0-100redline-main | F1 | 16 | 0x13 | 0x14, 0x15 |

The flag is NOT determined by wheel model (all same wheel) or dashboard type (F1 appears with both 0x0a and 0x13). It is per-session, assigned during connection negotiation. Minority flags are always base+1 and base+2.

**Flag assignment mechanism** (from Ghidra decompilation of `readReady` and `newConnectionRequest`):

The flag byte is a **Pit House-internal monotonic counter**. In `readReady`, when the wheel sends a command type 0x04 message during connection:
1. `FUN_00845610` retrieves the current counter value
2. The counter is incremented by 1: `new_flag = *counter + 1`
3. `FUN_0081e6c0` creates a new client entry using the incremented value
4. `FUN_008145b0` inserts the entry into the client tree (with the flag as the map key at offset 0x0E)

In `newConnectionRequest`, the flag value is NOT communicated to the wheel. The function sets up internal Pit House data structures (string templates for `${port_name}`, `${devId}`, `${port}`) but does not send the flag byte over the serial bus. The flag's purpose is purely Pit House-side client multiplexing — it lets the worker thread differentiate between multiple simultaneous dashboard connections.

**Conclusion:** The wheel firmware almost certainly does NOT validate the flag byte in telemetry frames. Any fixed value (e.g., `0x01`) should work. The `newConnectionRequest` function also computes `FUN_00966560(connection) - 2` which may be the telemetry payload byte limit (total buffer minus 2 header bytes).

### 6. Multi-stream telemetry

When a dashboard has more channels than fit in a single telemetry frame, Pit House sends multiple concurrent `0x43/7D:23` frames per tick. Each frame uses a sequential flag value (base, base+1, base+2) and carries a distinct slice of channels.

**Stream assignment — by `package_level`:**

Channels are routed to streams based on their `package_level` in `GameConfigs/Telemetry.json`, not alphabetical position across all channels. Each level gets its own frame sent at that update rate:

| Flag offset | `package_level` | Typical payload size | Update rate |
|-------------|----------------|----------------------|-------------|
| base | 30 | Up to byte limit (fast channels) | ~30 ms |
| base+1 | 500 | Usually small; 2 bytes if no level-500 channels subscribed | ~500 ms |
| base+2 | 2000 | Varies | ~2000 ms |

`package_level=1000` channels are rare (one known: `TimeAbsolute`) and likely fold into the 500 or 2000 stream. Within each stream, channels are sorted **alphabetically by URL suffix** and packed in that order.

This is confirmed by the F1 dashboard captures: Gear was found at bit 79, which is exactly `Brake(10)+CurrentLapTime(32)+DrsState(1)+ErsState(4)+GAP(32) = 79` bits — consistent only with level-30-only sorting, not alphabetical-across-all-channels.

#### UrlSimplifier and stream routing

`newConnectionRequest` creates four stream objects (A, B1, C, B2) and attaches URL filter templates to three of them:

| Stream | Filter template | Malloc size |
|--------|----------------|-------------|
| A | (none) | 44 bytes |
| B1 | `${port_name}` | 44 bytes |
| C | `${devId}` | 32 bytes |
| B2 | `${port}` | 44 bytes |

At connection time the templates are expanded with the connecting device's actual `port_name`, `devId`, and `port` number values. `FUN_00836930` then constructs a `MOZA::Telemetry::UrlSimplifier` from a 48-byte descriptor buffer (`local_118`) that encodes the three filter strings (3 × 16 bytes, each holding two 8-byte `{char*, size_t}` string-view pairs). The UrlSimplifier core (`FUN_00832160`) iterates these three descriptors, calls `FUN_00778280` to build `std::string` objects from each string-view pair, and pushes one 48-byte routing entry per stream into a `std::vector` via `FUN_008238c0`.

During `addTelemetry` (`FUN_0080dfc0`), `FUN_008273d0` (BST lower-bound lookup) and `FUN_008290c0` (skip check) use this routing table to decide which stream each channel belongs to. A channel is skipped for a given stream when the routing node's flag-at-0xd is 0 and `FUN_005bb180(channel_url, node+0x10) == 0` (channel URL ≥ boundary URL), implementing cross-stream deduplication so each channel appears in exactly one frame.

The exact mechanism by which the URL filter templates route channels by `package_level` is not yet fully traced, but the empirical result is consistent: level-30 → base, level-500/empty → base+1, level-2000 → base+2.

Device-specific channels (`v1/preset/CurrentTorque`, `v1/preset/SteeringWheelAngle`) would appear in the stream whose filter matches the device's URL namespace.

#### Channel config file

`GameConfigs/Telemetry.json` (referenced in binary at `0x01b68598`) defines all 410 known telemetry channels. Each entry has:
- `url` — channel URL (e.g. `v1/gameData/Rpm`)
- `compression` — type name (maps to Interface via factory at `0x0042fc00`)
- `package_level` — 30, 500, 1000, or 2000 — determines which stream/frame carries this channel
- `data_type`, `range`, `default_value`

#### Packing algorithm (per stream)

1. For each `package_level` tier, collect the dashboard's subscribed channels at that level.
2. Sort alphabetically by URL suffix (segment after the last `/`).
3. Assign channels to the frame in sorted order using an inclusive byte-limit check: include the channel if `⌈(current_bits + channel_bits) / 8⌉ ≤ limit`. (The limit applies to the level-30 / base frame; level-2000 / base+2 appears unconstrained in practice.)
4. Channels that exceed the limit are dropped (or overflow — not yet confirmed).
5. Use LSB-first bit packing (see § 9).

If a level has no subscribed channels, that stream still registers but sends only the 2-byte header (`[flag] [0x20]`). If a dashboard subscribes to channels from only one level, only one non-trivial stream is sent.

#### Formula 1.mzdash layout (byte limit = 16)

**Base frame — level-30 channels (16 bytes = 128 bits):**

| Bit offset | Channel | Type | Bits |
|------------|---------|------|------|
| 0–9 | Brake | float_001 | 10 |
| 10–41 | CurrentLapTime | float | 32 |
| 42 | DrsState | bool | 1 |
| 43–46 | ErsState | uint3 | 4 |
| 47–78 | GAP | float | 32 |
| 79–83 | Gear | int30 | 5 |
| 84–99 | Rpm | uint16_t | 16 |
| 100–115 | SpeedKmh | float_6000_1 | 16 |
| 116–125 | Throttle | float_001 | 10 |
| 126–127 | (padding, zero) | — | 2 |

All 9 level-30 F1 channels fit in 126 bits = 16 bytes (2 bits padding). Gear at bit 79 is confirmed by capture analysis.

**Base+1 frame — level-500 channels (2 bytes):**

The current F1 dashboard has no level-500 channels, so this stream sends only the 2-byte header `[flag] [0x20]` with no channel payload.

**Base+2 frame — level-2000 channels (13 bytes = 104 bits):**

| Bit offset | Channel | Type | Bits |
|------------|---------|------|------|
| 0–31 | BestLapTime | float | 32 |
| 32–63 | LastLapTime | float | 32 |
| 64–73 | TyreWearFrontLeft | percent_1 | 10 |
| 74–83 | TyreWearFrontRight | percent_1 | 10 |
| 84–93 | TyreWearRearLeft | percent_1 | 10 |
| 94–103 | TyreWearRearRight | percent_1 | 10 |

All 6 level-2000 F1 channels pack exactly into 104 bits = 13 bytes with no padding.

#### Stream registration

Before sending multi-stream telemetry, Pit House sends a `group=0x43, cmd=7c:23` registration frame, then periodic `cmd=7c:27` display config frames (~1/s, cycling through dashboard pages). The `7c:27` payload is page-dependent — see moza-protocol.md § Dashboard upload for the per-page formula and byte layout.

#### Session preamble (sub-message 1)

Pithouse sends a 14-byte preamble as 7c:00 session data before the tier definition. This is serialized by `TelemetryDataOutputBuffer` (RTTI at file offset `0x1d2649c`), defined in `FormulaSteeringTelemetryDataStructres.cc`. Validated by `TelemetryMessageInfo` (string at `0x17684e0`).

```
07 04 00 00 00 02 00 00 00 03 00 00 00 00
```

| Tag | Param (u32 LE) | Value | Meaning |
|-----|----------------|-------|---------|
| 0x07 | 4 | 2 | Protocol version / capability level. Constant across all observed sessions — not a dynamic value. |
| 0x03 | 0 | 0 | Base flag offset. Value 0 = tier flags start at 0x00. |

The same TLV encoding is used for tier enable (tag 0x00), tier definition (tag 0x01), and end marker (tag 0x06). Tags 0x07 and 0x03 are session-level metadata that precede the per-tier configuration.

Every top-level tag follows the generic TLV shape `[tag:1B][param:u32 LE][data:param bytes]`, so a parser that doesn't recognize a tag can safely skip `5 + param` bytes. Tag 0x00 fits the pattern trivially (param=1, data=flag byte); tag 0x01 is the only special case (its data block carries the 1-byte flag followed by a 16-byte-per-channel table).

Related RTTI: `TelemetryDataInputBuffer` at file offset `0x1d26474` (deserialization counterpart on the receiving side).

#### Concatenated probe + real tier def on the same session

The full session buffer assembled from 7c:00 data chunks on the telemetry session can contain **two tier-def messages back-to-back**, each terminated by its own 0x06 end marker:

1. **Probe batch** — a short preview with 1–2 tiers (at flag offsets 0x00, 0x01) and `total_channels=0` in its end marker. Appears to prime the wheel's tier parser.
2. **Real tier def** — enables + the full tier table (flag offsets typically 0x02+). `total_channels` in its end marker is the actual count.

Verified in `usb-capture/12-04-26/moza-startup.pcapng` session 0x02 (394 bytes): the first message ends at offset 90 with `06 04 00 00 00 00 00 00 00` (total=0); the second message starts at offset 99 and ends at offset 385 with `06 04 00 00 00 10 00 00 00` (total=16). Both messages are consumed by the wheel.

A reassembler/parser that hard-breaks on the first 0x06 will miss the real tier def. Treat 0x06 as a generic TLV skip; iterate until the buffer end.

#### Simultaneous multi-flag telemetry

Once the tier def is accepted, Pit House sends `7D:23` telemetry frames on **every declared flag byte**, not just one. Per-flag frequency depends on the tier's package level (see § 6). In the moza-startup capture we observed 614 7D:23 frames split across four flags: `0x00(22)`, `0x02(586)`, `0x03(4)`, `0x04(2)`. Flag 0x02 matches the F1 level-30 base frame (9 channels, 126 bits, 16 bytes) exactly — cross-validates the channel order documented in § 6.

Telemetry on already-defined flags can begin **before** later tier-def chunks for other flags finish buffering. A simulator/decoder that processes frames in capture order must either tolerate early frames decoding against an incomplete tier table, or run a two-pass scheme that builds tier state first and decodes telemetry second (see `usb-capture/wheel_sim.py` `cmd_validate`).

#### CRC-32 on all chunks

**All** 7c:00 session data chunks include a 4-byte CRC-32 trailer, including the final chunk. This was verified by computing CRC-32 (ISO 3309) of every chunk's net data in `moza-startup-1` and `moza-startup-2` captures — all trailing 4 bytes matched. The previous assumption (CRC omitted on last chunk) was incorrect.

#### Flag byte decoupling from session port

The flag byte in tier definitions and telemetry frames is **always 0-based** (0x00, 0x01, 0x02), independent of the session port number used for 7c:00 framing. Confirmed by comparing `moza-startup-1` (session port 0x02, flags 0x00+) and `moza-startup-2` (same). The earlier RE conclusion at § 5 — "The wheel firmware almost certainly does NOT validate the flag byte" — was partially correct: the wheel doesn't require a specific flag value, but the tier definition's enable entries (tag 0x00, offset 0/1/2) must match the tier headers (tag 0x01, flag byte). The firmware maps enable offset N → tier with flag N, so both sides must agree on the numbering.

---

### 7. Dashboard upload (group 0x40)

Observed in `dash-upload.json` capture. Three upload sequences visible:

**Upload sequence structure:**
1. `09 00` — init
2. `1E [enable:0/1] [channel_id] [00 00]` — enable/disable channels per page
3. `1C [page] 00` — page configuration
4. `1D [page] 00` — page finalization
5. Various config commands (`0A`, `21`, `24`, `2A`, `0D`, `03`, `05`, `1B`, `20`, `22`)
6. `28 02 XX 00` — telemetry mode: `01` = multi-channel, `00` = single-channel (RPM only)
7. `0B 00` — finalize upload

The `28 02 XX 00` byte 2 does NOT directly correspond to the telemetry flag byte. Different sessions with the same dashboard produce different flag values.

**Sub-command 0x28 decoded from rs21_parameter.db** (group 64=0x40, sub_cmd 40=0x28):

| Wire | DB key | Name | Purpose |
|------|--------|------|---------|
| `28:00 data=00` | `[64,40,0]` | `WheelGetCfg_GetMultiFunctionSwitch` | Query active dashboard mode |
| `28:01 data=00` | `[64,40,1]` | `WheelGetCfg_GetMultiFunctionNum` | Query active page number |
| `28:02 data=01:00` | `[64,40,2,1]` | `WheelGetCfg_GetMultiFunctionRight` | Set multi-channel mode |
| `28:02 data=00:00` | `[64,40,2,0]` | `WheelGetCfg_GetMultiFunctionLeft` | Set single-channel (RPM only) mode |

SET counterparts live at group 0x3F (`[63,40,...]` = `WheelSetCfg_SetMultiFunction*`).

The "MultiFunction" name refers to the dashboard display system — the wheel retains its last loaded dashboard across disconnections and power cycles. Pithouse reads the current state (28:00, 28:01) before setting the telemetry mode (28:02), a standard read-before-write pattern.

### 8. Interface object model

Inheritance hierarchy (from RTTI and constructor analysis):

```
Interface (abstract base)
  ├── BoolInterface (1 bit)
  ├── IsUnsignedInterface (abstract, flag byte at +4)
  │     ├── Int8Interface (8 bits)
  │     ├── Int16Interface (16 bits)
  │     │     └── BrakeTempInterface (16 bits, different conversion)
  │     ├── Int30Interface (5 bits)
  │     ├── Int15Interface (4 bits)     ← used by uint3, uint8, uint15
  │     ├── Int32Interface (32 bits)
  │     ├── Int64Interface (64 bits)
  │     ├── Int1000Interface (10 bits)
  │     │     ├── PercentInterface (10 bits, percent conversion)
  │     │     └── NormalizedInterface (10 bits, 0-1 conversion)
  │     ├── UInt24Interface (24 bits)
  │     ├── UFloatInterface (16 bits, float scale conversion)
  │     ├── TyreTempInterface (14 bits)
  │     └── TyrePressureInterface (12 bits)
  └── DoubleInterface (32 or 64 bits, flag at +4 selects)
```

All interfaces share a byte at object offset +4. For `DoubleInterface`, this flag selects 32-bit (flag=1, for `float` compression) or 64-bit (flag=0, for `double` compression). For `IsUnsignedInterface` descendants, it appears to encode signed vs unsigned interpretation.

Interface instances are **singletons** stored in a global `std::map<int, shared_ptr<Interface>>` at `DAT_02157ca8`. Created once at startup by the factory, looked up by compression type ID via `FUN_00805820`.

### 9. Bit-packing algorithm

From decompilation of `FUN_00808f50` (10-bit read) and `FUN_00809fb0` (10-bit write):

```c
// Read N bits from byte buffer at given bit position (LSB-first)
ushort read_bits(byte *buffer, uint bit_pos, int count) {
    uint byte_off = bit_pos / 8;
    uint bit_off  = bit_pos % 8;
    ushort result = 0;
    int shift = 0;
    while (count > 0) {
        int take = min(count, 8 - bit_off);
        byte mask = ((1 << take) - 1) << bit_off;
        result |= ((buffer[byte_off] & mask) >> bit_off) << shift;
        shift += take;
        byte_off++;
        bit_off = 0;
        count -= take;
    }
    return result;
}

// Write N bits to byte buffer at given bit position (LSB-first)
void write_bits(byte *buffer, uint bit_pos, ushort value, int count) {
    uint byte_off = bit_pos / 8;
    uint bit_off  = bit_pos % 8;
    while (count > 0) {
        int take = min(count, 8 - bit_off);
        byte mask = ((1 << take) - 1) << bit_off;
        buffer[byte_off] &= ~mask;                    // clear
        buffer[byte_off] |= (value << bit_off) & mask; // set
        value >>= take;
        byte_off++;
        bit_off = 0;
        count -= take;
    }
}
```

### 10. Value encoding details

#### Decode (vtable[1]): raw bits → game value

**PercentInterface / NormalizedInterface / Int1000Interface** (`FUN_00804ba0`):
```c
ushort raw = read_10_bits(buffer, bit_offset);
if (raw > 0x3FE) raw = 0xFFFF;  // 1023 → -1 (N/A sentinel)
result = (int)(short)raw;        // sign-extend
```
Values 0-1022 are valid. Value 1023 maps to -1 (not available).

**Int15Interface** (`FUN_00804f40`):
```c
byte raw = read_4_bits(buffer, bit_offset);
if (raw > 0x0E && !is_unsigned_flag) raw = 0xFF;  // 15 → -1 (N/A)
result = (int)(char)raw;  // sign-extend
```
Values 0-14 valid. Value 15 = N/A for signed types.

**DoubleInterface** (`FUN_008049e0` decode):
```c
if (*(char *)(this + 4) == '\0') {
    // flag=0: 64-bit double
    raw_64 = read_64_bits(buffer, bit_offset);
    bit_offset += 64;
} else {
    // flag=1: 32-bit float
    raw_32 = read_32_bits(buffer, bit_offset);
    value = (double)(float)raw_32;  // reinterpret as IEEE float, widen
    bit_offset += 32;
}
```

**TyreTempInterface** (`FUN_008054e0` decode, 14-bit):
```c
short raw = read_14_bits(buffer, bit_offset);
game_value = (raw - 5000) * 0.1;  // offset + scale
```
Raw 5000 = 0.0°C, raw 0 = -500°C, raw 16383 = 1138.3°C.

**TyrePressureInterface** (`FUN_00805620` decode, 12-bit):
```c
short raw = read_12_bits(buffer, bit_offset);
game_value = raw * 0.1;  // scale only, no offset
```
Raw 0 = 0.0 kPa, raw 4095 = 409.5 kPa.

#### Convert (vtable[3]): game value → intermediate (before encode)

Constants extracted from binary:

| Address | Value | Name |
|---------|-------|------|
| `0x01b643f8` | 10.0 | Scale factor (×10) |
| `0x01b64418` | 100.0 | Normalized→percent scale |
| `0x01b68cc0` | 1000.0 | Percent max raw value |
| `0x01b69460` | 0.1 | Decode scale (÷10) |
| `0x01b69468` | 409.5 | TyrePressure max (kPa) |
| `0x01b69470` | 1138.3 | TyreTemp max (°C) |
| `0x01b69478` | 5000.0 | Temp offset (raw = temp×10 + 5000) |
| `0x01b69480` | 65535.0 | 16-bit max |
| `0x01b69488` | -500.0 | TyreTemp min (°C) |

**PercentInterface** (`FUN_00805020`):
```c
raw = clamp(game_percent * 10.0, 0.0, 1000.0);
// 10-bit field: 0-1000 valid, 1023 = N/A
// game 0% → raw 0, game 100% → raw 1000
```

**NormalizedInterface** (`FUN_00805170`):
```c
// First scales 0-1 → 0-100, then delegates to PercentInterface
raw = clamp(game_value * 100.0 * 10.0, 0.0, 1000.0);
// = clamp(game_value * 1000.0, 0, 1000)
// game 0.0 → raw 0, game 1.0 → raw 1000
```

**UFloatInterface** (`FUN_008052c0`):
```c
// Scale factor comes from object instance: 10^(field at this+8)
// For float_6000_1: exponent=1 → scale=10
// For float_600_2: exponent=2 → scale=100
raw = clamp(game_value * scale, 0.0, 65535.0);
// float_6000_1: game 0.0 → raw 0, game 6553.5 → raw 65535
// float_600_2: game 0.0 → raw 0, game 655.35 → raw 65535
```

**BrakeTempInterface** (`FUN_008056c0`):
```c
raw = clamp(game_temp_C * 10.0 + 5000.0, 0.0, 65535.0);
// 16-bit field: raw 5000 = 0°C, offset allows -500°C to +6053.5°C
```

#### Encode (vtable[2]): intermediate → bit stream

Types with conversion baked into encode (NOT using vtable[3]):

**TyreTempInterface** (`FUN_00805440`, 14-bit):
```c
clamped = clamp(game_temp_C, -500.0, 1138.3);
raw = (int)(clamped * 10.0 + 5000.0) & 0xFFFF;
write_14_bits(buffer, bit_offset, raw);
// game 0°C → raw 5000, game -500°C → raw 0, game 1138.3°C → raw 16383
```

**TyrePressureInterface** (`FUN_00805580`, 12-bit):
```c
clamped = clamp(game_pressure_kPa, 0.0, 409.5);
raw = (int)(clamped * 10.0) & 0xFFFF;
write_12_bits(buffer, bit_offset, raw);
// game 0 kPa → raw 0, game 409.5 kPa → raw 4095
```

**Int1000Interface (shared by Percent/Normalized)** (`FUN_00804b20`, 10-bit):
```c
// value comes from vtable[3] convert (already 0-1000 range)
if (value > 0x3FF) value = 0x3FF;  // cap at 1023
write_10_bits(buffer, bit_offset, value);
```

**Int30Interface** (`FUN_00804d80`, 5-bit):
```c
if (value > 0x1F) value = 0x1F;  // cap at 31
write_5_bits(buffer, bit_offset, value);
```

**Int15Interface** (`FUN_00804ed0`, 4-bit):
```c
if (value > 0x0F) value = 0x0F;  // cap at 15
write_4_bits(buffer, bit_offset, value);
```

**DoubleInterface** (`FUN_00804920`):
```c
if (flag == 0) {
    write_64_bits(buffer, bit_offset, double_value);  // 64-bit
} else {
    write_32_bits(buffer, bit_offset, (float)double_value);  // 32-bit
}
```

#### Complete encode pipeline summary

| Compression | Bits | Encode formula | Range |
|-------------|------|---------------|-------|
| `bool` | 1 | raw = value (0 or 1) | 0-1 |
| `uint3`/`uint8`/`uint15` | 4 | raw = min(value, 15) | 0-15, 15=N/A |
| `int30`/`uint30`/`uint31` | 5 | raw = min(value, 31) | 0-31 |
| `int8_t`/`uint8_t` | 8 | raw = value (byte) | 0-255 |
| `percent_1` | 10 | raw = clamp(game% × 10, 0, 1000), 1023=N/A | 0-100% |
| `float_001` | 10 | raw = clamp(game × 1000, 0, 1000), 1023=N/A | 0.0-1.0 |
| `tyre_pressure_1` | 12 | raw = clamp(kPa × 10, 0, 4095) | 0-409.5 kPa |
| `tyre_temp_1`/`track_temp_1`/`oil_pressure_1` | 14 | raw = clamp(°C × 10 + 5000, 0, 16383) | -500 to 1138.3°C |
| `int16_t`/`uint16_t` | 16 | raw = value | 0-65535 |
| `float_6000_1` | 16 | raw = clamp(game × 10, 0, 65535) | 0-6553.5 |
| `float_600_2` | 16 | raw = clamp(game × 100, 0, 65535) | 0-655.35 |
| `brake_temp_1` | 16 | raw = clamp(°C × 10 + 5000, 0, 65535) | -500 to 6053.5°C |
| `uint24_t` | 24 | raw = value | 0-16777215 |
| `float` | 32 | raw = IEEE 754 single bits | full float range |
| `int32_t`/`uint32_t` | 32 | raw = value | full 32-bit |
| `double`/`location_t` | 64 | raw = IEEE 754 double bits | full double range |
| `int64_t`/`uint64_t` | 64 | raw = value | full 64-bit |

---

## Data files

### Telemetry.json

Location: `<pithouse>/bin/GameConfigs/Telemetry.json`

Contains all telemetry channels in a `sectors` array. Each entry has:
- `name`: display name (e.g. `"Gap"`, `"Drs"`, `"FuelRemain"`)
- `url`: channel URL (e.g. `"v1/gameData/GAP"`, `"v1/gameData/DrsState"`)
- `compression`: encoding type string (e.g. `"float"`, `"bool"`, `"percent_1"`)
- `data_type`: value type (`"int"`, `"float"`, `"string"`, `"array"`)
- `range`: valid range description
- `package_level`: priority/update frequency (30=high, 2000=low)
- `default_value`: zero value
- `is_visible`: whether shown in dashboard editor

22 unique compression types across 400+ channels.

### .mzdash files

Location: `<pithouse>/bin/dashes/<name>/<name>.mzdash`

JSON files defining dashboard layouts. Multi-page, with channel bindings via `METHOD_CHAINING` type:
```json
{
    "type": "METHOD_CHAINING",
    "methods": ["Telemetry.get('v1/gameData/SpeedKmh').value"]
}
```

The `Math.round()` and other JavaScript transforms in methods are executed on the wheel firmware for display — they don't affect the wire encoding.

Top-level `children` array = pages. Channels referenced on any page get registered for packing (not just the currently visible page).

### Dashboard channel layout (m Formula 1.mzdash)

| Page | Channels |
|------|----------|
| 0 | SpeedKmh, Throttle, Brake, Gear, Rpm |
| 1 | CurrentLapTime, LastLapTime, BestLapTime, GAP |
| 2 | FuelRemainder, Gear, ErsState, TyreWear x4, DrsState, SpeedKmh |

16 unique channels across 3 pages. Channel URLs are extracted by regex matching `Telemetry.get('v1/gameData/...')` across all pages, then deduplicated, sorted alphabetically by full URL, and cross-referenced with `Telemetry.json` for compression type and bit width.

Alphabetical sort order of the 16 channels:

| # | URL suffix | Compression | Bits | Cumulative bits | Cumulative bytes |
|---|-----------|-------------|------|-----------------|------------------|
| 1 | BestLapTime | float | 32 | 32 | 4 |
| 2 | Brake | float_001 | 10 | 42 | 6 |
| 3 | CurrentLapTime | float | 32 | 74 | 10 |
| 4 | DrsState | bool | 1 | 75 | 10 |
| 5 | ErsState | uint3 | 4 | 79 | 10 |
| 6 | FuelRemainder | percent_1 | 10 | 89 | 12 |
| 7 | GAP | float | 32 | 121 | 16 |
| 8 | Gear | int30 | 5 | 126 | 16 |
| 9 | LastLapTime | float | 32 | 158 | 20 |
| 10 | Rpm | uint16_t | 16 | 174 | 22 |
| 11 | SpeedKmh | float_6000_1 | 16 | 190 | 24 |
| 12 | Throttle | float_001 | 10 | 200 | 25 |
| 13 | TyreWearFrontLeft | percent_1 | 10 | 210 | 27 |
| 14 | TyreWearFrontRight | percent_1 | 10 | 220 | 28 |
| 15 | TyreWearRearLeft | percent_1 | 10 | 230 | 29 |
| 16 | TyreWearRearRight | percent_1 | 10 | 240 | 30 |

All 16 channels = 240 bits = 30 bytes. Observed live data size in captures = 16 bytes. The per-dashboard byte limit determines how many channels are packed; see § Size limit and channel dropping.

---

## Verification

The bit layout was verified against two USB captures:

**0-6thgear-0-main-dash** (1259 frames, flag=0x0a):
- Gear: values {0,1,2,3,4,5,6} with step transitions — neutral + gears 1-6
- Brake: 5-87% (rest to hard braking)
- CurrentLapTime: 99%+ monotonic
- FuelRemainder: varies over session
- DRS/ERS: all 0 (AC practice)

**0-100redline-0-main-dash** (327 frames, flag=0x13):
- Gear: {0,1} — neutral and 1st gear
- Brake: 26-74%
- CurrentLapTime: monotonic
- BestLapTime: 0 (no completed laps, with some NaN from partially written floats)

---

## Ghidra project

Saved at `/tmp/ghidra_pithouse_project/PitHouse`. Imported with full auto-analysis. No PDB symbols — all function names are `FUN_XXXXXXXX` format.

Ghidra scripts used are in `/tmp/ghidra_*.py`. Note: Jython (Ghidra's Python) requires `# -*- coding: utf-8 -*-` header and does not support `DefinedDataIterator.definedStrings()` in Ghidra 12.x — use address-based decompilation instead.

---

## Pit House installation structure

Location: `<pithouse>` = the installer root (`Program Files (x86)/MOZA Pit House/`).

```
MOZA Pit House/
├── bin/                              # Main application + dependencies
│   ├── MOZA Pit House.exe            # 31MB PE32, MSVC C++/Qt5
│   ├── MOZA Dashboard Studio.exe     # 4.3MB dashboard editor
│   ├── FirmwareManager.exe           # Firmware update tool
│   ├── GameConfigs/
│   │   ├── Telemetry.json            # Master channel list (410 channels, 23 compression types)
│   │   ├── carModels.db              # SQLite: 3370 car models across 60 game IDs
│   │   ├── TrackData/
│   │   └── <Game Name>/              # Per-game configs (plugins, INI presets)
│   ├── dashes/                       # 44 dashboard profiles (.mzdash JSON)
│   ├── fmw_bin/                      # 55 numbered firmware binaries (.bin)
│   ├── rs21_parameter.db             # SQLite: RS21 command database (919 commands)
│   ├── as23_parameter.db             # SQLite: AS23 flight sim commands (1042 commands)
│   ├── ALL_FmwHwCompatTab.json       # 79 products with firmware version/HW compat info
│   ├── AS23_FmwHwCompatTab.json      # AS23 subset
│   ├── rs21_parameter.json           # JSON export of the RS21 parameter DB schema
│   ├── monitor.json                  # Device tree topology for all base models
│   ├── MOZADriverInterface.h         # C++ driver API (game start, key mapping, VMOZA)
│   ├── MOZADriverInstaller.h         # C++ driver installer API
│   ├── MOZADriverInterface.dll/.lib  # Driver implementation
│   ├── DashboardFonts/               # Dashboard display fonts
│   ├── images/
│   └── drivers/{win10,win11}/        # USB driver packages
├── version.json                      # {"json_version":"1.0.1", branch, experimentalFirmwareCommand}
├── InstallationLog.txt
└── MaintenanceTool.exe               # Qt installer framework maintenance tool
```

---

## rs21_parameter.db — authoritative command database

The SQLite database `rs21_parameter.db` is the canonical command reference for all RS21-series (sim racing) peripherals. The Apr 2026 build (528 KB) has **909 commands** across the same group structure as earlier builds; the older Jan 2026 build (458 KB) had 919. See § FormulaSteering pack architecture for the new commands and `>=1.2.4.x` variants.

### Schema

```sql
CommandOperator (
  name TEXT PRIMARY KEY,     -- e.g. "MotGetSteer_FfbStrength"
  description TEXT,          -- Chinese description, e.g. "读取游戏力回馈强度"
  request_group TEXT,        -- e.g. "[40, 2]" — JSON array of group + command ID bytes
  response_group TEXT,       -- e.g. "[40, 2]" — response uses same encoding
  request_bytes INTEGER,     -- payload size (0-64)
  response_bytes INTEGER
)

CommunicationParameter (
  name TEXT PRIMARY KEY,     -- e.g. "BaseFfbStrength"
  type TEXT,                 -- 'int' | 'uint' | 'float' | 'string' | 'hex'
  bits INTEGER,              -- bit width of the value
  range TEXT                 -- e.g. "[0, 100]", "{0, 1}", "{0, 85}"
)

ParameterIndex (
  parameter_name TEXT,       -- FK → CommunicationParameter
  read_or_write TEXT,        -- 'read' | 'write'
  request_begin_bit_index,   -- bit offset within request payload
  response_begin_bit_index,  -- bit offset within response payload
  command_name TEXT           -- FK → CommandOperator
)

EepromParameter (
  table_id INTEGER,          -- EEPROM table (2=Base, 3=Motor, 4=Wheel, 5=Pedals, 11=?)
  address INTEGER,           -- relative address within table
  name TEXT,                 -- e.g. "gpw_rpm_percent[0]", "master->config.load_inertia"
  category_path TEXT,        -- pithouse:// URI
  type TEXT,                 -- 'int' | 'uint' | 'float'
  range TEXT,
  default_value TEXT
)

ServiceParameter (
  name TEXT,                          -- business-level parameter name
  category_path TEXT,                 -- pithouse:// URI with optional version/HW filters
  communication_parameter_name TEXT,  -- FK → CommunicationParameter
  default_value TEXT,
  unit TEXT,                          -- e.g. "%"
  stored INTEGER DEFAULT 1,
  transform_function TEXT,            -- 'multiply' | 'division' | 'softLimitStiffness_conversion'
  transform_params TEXT               -- e.g. "0.01", "65535"
)

-- Joins all tables for a complete view
ParameterView (业务参数名, 分类路径, 数据类型, 数据大小, 单位, 读或写, 指令名称, 请求编号, 响应编号, 指令描述)
```

### Command group summary

The `request_group` field encodes as a JSON array: first element is the protocol group byte, remaining elements are the command ID bytes. Example: `[40, 2]` → group 0x28, command ID 0x02.

| Group | Device | R/W | Purpose | Commands |
|-------|--------|-----|---------|----------|
| 10 | any | RW | EEPROM direct access (table select, address, read/write int/float) | 8 |
| 31 | main | RW | Settings (compat mode, BLE, LED status, work mode, interpolation, FFB effect gains) | 16 |
| 32 | main | W | Ambient LED write (indicator groups, standby/sleep modes, per-LED RGB for 2×9 strips) | ~120 |
| 33 | main | RW | FFB status enable/disable | 2 |
| 34 | main | R | Ambient LED read (mirrors group 32 writes) | ~120 |
| 35 | pedals | R | Settings read (direction, min/max, curves, HID mode, data source) | ~30 |
| 36 | pedals | W | Settings write | ~30 |
| 37 | pedals | R | Output (throttle/brake/clutch theta) | 3 |
| 38 | pedals | W | Calibration start/stop | 6 |
| 40 | base | R | Motor settings read (FFB, equalizer 6-band, angle, damping, torque, curves, gear jolt) | ~40 |
| 41 | base | W | Motor settings write | ~40 |
| 43 | base | R | Status (state, error, MCU/MOSFET/motor temps) | 5 |
| 50 | dash | W | Display settings write (brightness, speed/temp units, UI index, power mode) | 7 |
| 51 | dash | R | Display settings read | 7 |
| 63 | wheel | W | Configuration write — massive: LED groups, modes, colors, sleep, rotary switches, multi-function | ~260 |
| 64 | wheel | R | Configuration read | ~260 |
| 70 | estop | RW | E-stop FFB state | 2 |
| 81 | shifter | R | Settings read (HID mode, apply mode, LED, direction, paddle sync) | 7 |
| 82 | shifter | W | Settings write | 7 |
| 83 | shifter | R | Output (theta) | 1 |
| 91 | handbrake | R | Settings read (direction, min/max, curves, mode, threshold) | ~10 |
| 92 | handbrake | W | Settings write | ~10 |
| 100 | hub | R | Port connection status (5 ports) | 5 |

Not in the database (discovered from binary RE and USB captures only):
- Group 7/8/15/16: Identity queries (model name, HW/SW version, serial) — hardcoded in firmware
- Group 42 subcommands: Music (preview, index, enabled, volume)
- Group 45: Sequence counter (`F5 31`)
- Group 65: Telemetry enable (`FD DE`)
- Group 67 (0x43): Live telemetry stream (`7D 23`)

### EEPROM direct access protocol (group 10)

Low-level read/write to device EEPROM, bypassing the named command interface:

1. Select table ID: `[10, 0, 5]` — 4-byte int payload
2. Read table ID: `[10, 0, 6]`
3. Select address: `[10, 0, 7]` — 4-byte int payload (relative address within table)
4. Read address: `[10, 0, 8]`
5. Write int: `[10, 0, 9]` — 4-byte int
6. Read int: `[10, 0, 10]`
7. Write float: `[10, 0, 11]` — 4-byte IEEE float
8. Read float: `[10, 0, 12]`

### EEPROM tables

| Table | Device | Params | Addr range | Contents |
|-------|--------|--------|------------|----------|
| 2 | Base | 38 | 4–41 | User settings: LED brightness, RPM thresholds, BLE mode, paired mode/channel, USB mode, protect time, startup mode |
| 3 | Motor | 76 | 4–90 | FOC motor control: PID gains (Id/Iq Kp/Ki), encoder calibration (Bk/Ck/bias/omega_k), field weakening (fw_current_max, fw_id0/mtpa PID), dead-time compensation, torque/speed control modes, power limits |
| 4 | Wheel | 123 | 4–126 | LED group colors/modes for all 5 groups, rotary switch configs, paddle thresholds |
| 5 | Pedals | 45 | 4–48 | Calibration offsets, output curves, HID config |
| 11 | Unknown | 8 | 4–11 | Purpose unknown |

### Value transform functions

The ServiceParameter table's `transform_function` + `transform_params` convert raw protocol values to display units:

| Function | Params | Meaning |
|----------|--------|---------|
| `multiply` | `0.01` | Percentage from 0–10000 raw → 0–100% |
| `multiply` | `0.1` | Tenths resolution |
| `multiply` | `0.05` | 5% resolution steps |
| `multiply` | `2` | Double the raw value |
| `division` | `65535` | Normalize 16-bit to 0.0–1.0 |
| `division` | `16384` | Normalize 14-bit to 0.0–1.0 |
| `softLimitStiffness_conversion` | — | Custom non-linear conversion for soft limit stiffness |

---

## Wheel LED group architecture (groups 63/64)

The rs21_parameter.db reveals wheels have **5 independently controlled LED groups**, far richer than what serial.md documents. Each group has its own brightness, color set, normal mode, and standby mode.

### LED groups

| ID | Group | Max LEDs | Purpose |
|----|-------|----------|---------|
| 0 | Shift | 25 | RPM indicator bar (top of wheel) |
| 1 | Button | 16 | Button backlights |
| 2 | Single | 28 | Single-purpose status indicators |
| 3 | Rotary | 56 | Rotary encoder ring LEDs |
| 4 | Ambient | 12 | Ambient / underglow lighting |

### Command structure per group

All use group 63 (write) / 64 (read). `G` = LED group ID (0–4), `N` = LED index.

| Command ID | Bytes | Purpose |
|------------|-------|---------|
| `[27, G, 0xFF]` | 1 | Brightness (0–15) |
| `[28, G]` | 1 | Normal (telemetry active) mode |
| `[29, G]` | 1 | Standby (idle) mode |
| `[30, G, 2]` | 2 | Standby: breathing cycle interval |
| `[30, G, 3]` | 2 | Standby: circular cycle interval |
| `[30, G, 4]` | 2 | Standby: rainbow cycle interval |
| `[30, G, 5]` | 2 | Standby: drift sand cycle interval |
| `[30, G, 6]` | 2 | Standby: breath color cycle interval |
| `[31, G, 0xFF, N]` | 3 | LED N static color (RGB) |

### Additional wheel commands (not in serial.md)

| Command ID | Bytes | Name | Purpose |
|------------|-------|------|---------|
| `[16]` | 1 | MeterAutoRotation | Auto-rotate dashboard display |
| `[32]` | 1 | SleepMode | Sleep enable/disable |
| `[33]` | 2 | SleepTimeout | Sleep timeout (ms or seconds) |
| `[34, 1]` | 2 | SleepBreathCycle | Sleep breathing animation cycle |
| `[35, 0]` | 1 | SleepBreathBrightnessMin | Minimum brightness during sleep breathing |
| `[35, 1]` | 1 | SleepBreathBrightnessMax | Maximum brightness during sleep breathing |
| `[36, 0xFF, 1, 0xFF]` | 3 | SleepBreathColor | Sleep breathing color (RGB) |
| `[37]` | 3 | StartupColor | LED color on power-up (RGB) |
| `[38]` | 24 | PaddleThreshold | Paddle trigger thresholds (12× 2-byte values) |
| `[39, N, 0]` | 3 | RotarySwitchForeground N | Rotary switch N foreground color (RGB), N=0–4 |
| `[39, N, 1]` | 3 | RotarySwitchBackground N | Rotary switch N background color (RGB) |
| `[40, 0]` | 1 | MultiFunctionSwitch | Multi-function switch enable |
| `[40, 1]` | 1 | MultiFunctionNum | Number of multi-function positions |
| `[40, 2, 0]` | 1 | MultiFunctionLeft | Left multi-function assignment |
| `[40, 2, 1]` | 1 | MultiFunctionRight | Right multi-function assignment |
| `[42, N]` | 1 | RotarySignalMode N | Rotary encoder N signal mode, N=0–4 |

---

## Base ambient LED control (groups 32/34)

Completely undocumented in serial.md. Controls 2 LED strips (9 LEDs each) on the wheelbase body. Group 32 = write, group 34 = read.

| Command ID | Bytes | Purpose |
|------------|-------|---------|
| `[28]` | 1 | Indicator group state (on/off) |
| `[29]` | 1 | Standby mode (0=constant, 2=breath, 3=cycle, 4=rainbow, 5=flow) |
| `[30, mode]` | 2 | Standby interval for mode (mode: 2=breath, 3=cycle, 4=rainbow, 5=flow) |
| `[31, 2]` | 1 | Brightness level |
| `[32, strip, mode, led]` | 3 | LED color (RGB). strip=0/1, mode=1(constant)/2(breath), led=0–8 |
| `[33]` | 1 | Sleep mode enable |
| `[34]` | 2 | Sleep timeout |
| `[35, 1]` | 2 | Sleep breathing interval |
| `[36]` | 1 | Sleep brightness |
| `[37, strip, 1, led]` | 3 | Sleep breathing color per LED (RGB) |
| `[38]` | 3 | Startup LED color (RGB) |
| `[39]` | 3 | Shutdown LED color (RGB) |

---

## Device tree topology (monitor.json)

The `monitor.json` file defines the internal bus topology for each wheelbase model. Device IDs here are **bus addresses** (not the serial protocol device IDs from serial.md). The base model is identified by hardware version regex.

### Common topology (single-controller bases: D00, D01, D05, D06, D07)

```
1 (USB host)
└── 2 (Main controller)
    ├── 3 (Motor controller)
    ├── 4 (Wheel) ── 18 (Wheel display)
    ├── 5 (Dashboard) ── 17 (Dash sub-device)
    ├── 6, 7 (Peripherals) ── 16 (child of 7)
    ├── 8, 9 (Peripherals) ── 13, 14 (children of 9)
    ├── 10, 11, 12
    └── (varies by model)
```

### Per-device performance tuning

Some bus nodes have custom timing. Example for dashboard (device 5):
```json
{"current": 5, "parent": 2, "performance": {
  "app":  {"duration": 10, "buffer": 30},
  "boot": {"duration": 10, "buffer": 30}
}}
```

Default: main controller `duration=1, buffer=80` (app) / `128` (boot). Child controllers `duration=4, buffer=220/240`.

### D11 (R21/R25/R27 Ultra) — different topology

Omits device 5 (built-in dashboard port removed). CM2 dashboard (S09) connects as device 19 off device 2.

### S09 CM2 dashboard

```
1 (USB host)
└── 2 (Main controller)
    └── 19 (CM2 sub-device)
```

---

## Product catalog (ALL_FmwHwCompatTab.json)

79 products across all categories. Hardware version format: `[Platform]-[DeviceCode]-HW_[Component]-CU-V[Version]`.

### Platforms

| Platform | Product line |
|----------|-------------|
| RS21 | Sim racing (bases, wheels, pedals, shifters, handbrake, etc.) |
| AS23 | Flight simulation (bases, throttles, rudder, joysticks, instrument panels) |
| MP24 | Motion platform (G-Force G01 AU/SU) |
| GC25 | Gaming chair (C00 GP) |

### RS21 sim racing products

**Wheel Bases (20):**
- R3 (D06), R5 (D05), R5 Pro (D13), R9 (D01, 4 HW revisions), R12 (D07)
- R16 (D00, 2 revisions), R16 Ultra (D12)
- R21 (D00, 2 revisions), R21 Ultra (D11), R25 Ultra (D11), R27 Ultra (D11)

**Steering Wheels (22):**
- D00/D01/D02/D03 (early models)
- W00–W23 (current gen): W04 KS, W05, W06, W08 VGS (with display unit DU), W10 TSW, W11, W13 FSR V2, W14, W17 (with RGB display unit), W18, W20, W23

**Pedals (5):** CRP P00, CRP2 P02, SR-P D01, SR-P Lite D05, mBooster P01

**Meters (3):** D00 RM, D01 CM, S09 CM2

**Other:** HGP shifter S00, SGP shifter S04, HBP handbrake S01, E-Stop S05, Hub S03, Stalk S07

### AS23 flight sim products

**Bases:** BA0, BA1, BA2, BA3
**Throttles:** T00, T01
**Throttle Panel:** T02
**Rudder:** T10
**Joysticks:** J02, J03, J04 (J02 has a display unit sharing W08's DU hardware)
**Instrument Panels:** DDI T20, MCD T20, FPP T20, PFD T22, CDU T23, MCDU T23

### Firmware update parameters

Each product entry includes:
- `maxSectionSize`: 4096 (typical)
- `minimumStorageUnit`: 8
- `compressStrategy`: `"MinilzoCompress"` — firmware binaries use miniLZO compression
- `avoidEscapeCharacters`: false (typical)

---

## Telemetry.json — extended channel analysis

410 channels total. Beyond the 22 compression types documented in the binary RE section, the full channel list reveals:

### Channel URL namespaces

| Prefix | Count | Purpose |
|--------|-------|---------|
| `v1/gameData/` | 275 | Standard game telemetry (speed, RPM, temps, etc.) |
| `v1/gameData/patch/` | 133 | Extended data (track maps, opponent info, display names) |
| `v1/preset/` | 2 | Device presets (CurrentTorque, SteeringWheelAngle) |

### Compression type distribution

| Compression | Count | Bits | Primary use |
|-------------|-------|------|-------------|
| `float` | 73 | 32 | Lap times, delta, torque, fuel |
| `location_t` | 65 | 64 | Track position coordinates (patch/Location_N) |
| `uint32_t` | 65 | 32 | Race info slots (patch/ri_N) |
| `bool` | 51 | 1 | Flags, states, lights |
| `tyre_temp_1` | 43 | 14 | Tyre temperatures (inner/middle/outer × 4 wheels) |
| `percent_1` | 19 | 10 | Throttle, brake, clutch, fuel, ERS, tyre wear |
| `string` | 15 | var | Player/track/game names, car model |
| `brake_temp_1` | 14 | 16 | Brake disc temperatures |
| `tyre_pressure_1` | 12 | 12 | Tyre pressures |
| `float_600_2` | 12 | 16 | Sector times, various |
| `uint8_t` | 12 | 8 | Lap count, position, gear count |
| `uint8` | 5 | 4 | TC/ABS levels, sector index |
| `track_temp_1` | 5 | 14 | Track/air/water temperatures |
| `float_6000_1` | 4 | 16 | RPM-range values |
| `float_001` | 3 | 10 | Normalized 0–1 values |
| `int32_t` | 3 | 32 | Signed 32-bit |
| `uint16_t` | 2 | 16 | MaxRpm, MaxSpeedKmh |
| `uint30` | 2 | 5 | Spotter car proximity |
| `int30` | 1 | 5 | Signed 5-bit |
| `uint15` | 1 | 4 | Boost |
| `uint31` | 1 | 5 | DRS allowed |
| `uint3` | 1 | 4 | ERS state |
| `oil_pressure_1` | 1 | 14 | Oil pressure |

### Notable v1/preset channels

These two channels are NOT game telemetry — they come from the device preset system:
- `v1/preset/CurrentTorque` — compression `float_6000_1` (16 bits) — current FFB torque output
- `v1/preset/SteeringWheelAngle` — compression `float_6000_1` (16 bits) — current wheel angle

---

## MOZADriverInterface.h — driver API

Public C++ API for third-party integration. Namespace `RS21::moza_driver::controller`.

```cpp
class IMOZADriverController {
    virtual void refresh() = 0;
    virtual bool startGame(const std::string& gameName) = 0;
    virtual bool closeGame() = 0;
    virtual std::string deviceVersion() = 0;
    virtual std::string latestVersion() = 0;
    virtual void supportGameNameList(std::map<ProblemType, MOZADriverSupportGameInfo>& _map) = 0;
    virtual bool getKeyInformationByType(KeyMapType type, void* pDevicePosition) = 0;
    virtual bool setKeysBlock(std::vector<int>& _vec) = 0;
    virtual bool setKeysMap(std::map<int, int>& _map) = 0;
    // Virtual MOZA (VMOZA) interface — HID device emulation
    virtual bool setVMOZAsOnOff(bool isSetOn, int pid) = 0;
    virtual std::vector<USHORT> getVMOZAsVersion(int pid) = 0;
    virtual bool initVMOZAsByPID(UINT pid) = 0;
    virtual std::vector<HANDLE> getVMOZAsByPid(int pid) = 0;
    virtual bool getVMOZAOutput(HANDLE handle, std::vector<std::wstring>& vecOutput) = 0;
};

enum KeyMapType { ORIGINAL = 0, MODIFIED, BLOCKED };
```

Driver version at time of install: `MOZA_DRIVER_LATEST_VERSION "1.0.2.4"`.
Vendor ID `0x346E` (Gudsen/Moza), hardware ID format: `VID_346E&PID_0000&MI_1`.

---

## carModels.db — car telemetry name mapping

SQLite database mapping game-specific car identifiers to display names. 3370 entries across 60 game IDs.

```sql
CREATE TABLE CarModels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    gameId TEXT NOT NULL,       -- numeric game identifier
    telemetryName TEXT,         -- internal telemetry ID (e.g. "amr_v12_vantage_gt3")
    name TEXT,                  -- display name (e.g. "Aston Martin Vantage V12 GT3 2013")
    category TEXT               -- e.g. "GT3", "GT4", "LMP2"
);
```

Game IDs correspond to the game folders in GameConfigs/ (e.g. ACC = 2, LMU/rFactor2 = shared memory plugin based).

---

## AS23 flight sim parameter database

The `as23_parameter.db` contains 1042 commands for the flight simulation product line. Uses the same schema as rs21_parameter.db. Command groups:

| Group | Purpose |
|-------|---------|
| 14 | Unknown |
| 17 | Unknown |
| 30 | Device output |
| 31 | Base settings |
| 32/34 | LED control |
| 35/36 | Peripheral settings R/W |
| 37 | Peripheral output |
| 38/39 | Calibration |
| 50/51 | Display settings |
| 52/53 | Additional settings |
| 54/55 | Unknown |

Not investigated in detail — the AS23 line uses the same protocol framing but different device codes and command sets.

---

## File transfer protocol (`MOZA::FileTransfer`)

The dashboard file transfer lives in the `MOZA::FileTransfer` namespace, implemented as a first-party library (log strings reference `3rdparty/file_transfer`). It runs on top of a proprietary TCP-like serial stream managed by `MOZA::Protocol::SerialStreamManager`.

### Architecture

```
  MOZA::FileTransfer::FileTransferClient / FileTransferServer
      │
  MOZA::FileTransfer::SendHandler / GetHandler / CopyHandler / RemoveHandler
      │
  MOZA::Protocol::SerialStreamManager  (TCP-like reliable stream)
      │
  Group 0x43/0xC3, cmd 7c:00 (data) / fc:00 (ack)  (serial framing)
```

CoAP (libcoap 4.3.4, statically linked) is a **separate layer** used for device parameter management over UDP — it does NOT carry file transfers. The `7c:00`/`fc:00` framing is the SerialStream protocol, not CoAP.

### RTTI class hierarchy

| File offset | Class name |
|-------------|-----------|
| — | `MOZA::FileTransfer::FileTransferClient` |
| — | `MOZA::FileTransfer::FileTransferServer` |
| — | `MOZA::FileTransfer::RemoteFileManager` |
| — | `MOZA::FileTransfer::RemoteFileHandler` |
| — | `MOZA::FileTransfer::SendHandler` |
| — | `MOZA::FileTransfer::GetHandler` |
| — | `MOZA::FileTransfer::GetHandlerInMemory` |
| — | `MOZA::FileTransfer::CopyHandler` |
| — | `MOZA::FileTransfer::RemoveHandler` |
| — | `MOZA::FileTransfer::RemoteInfoManager` |
| — | `MOZA::FileTransfer::FileServer` |

### Serial stream packet types

From RTTI at `0x1ce7808` (`SerialStreamManager@Protocol@MOZA`):

| Type | Purpose | Validation |
|------|---------|------------|
| `request_package_t` | Generic data wrapper | Size-validated only |
| `request_syn_t` | SYN (connection initiation) | Size-validated only |
| `request_trans_t` | Data transfer packet | Magic word validated |
| `request_fin_t` | FIN (connection teardown) | Magic word validated |
| `response_t` | Response / acknowledgment | Size-validated only |

### Three-way handshake

Connection establishment follows a TCP-like pattern:

```
Host                        Device
  │  ─── SYN1 (request_syn_t) ──→  │
  │  ←── SYN2 (request_syn_t) ───  │
  │  ─── SYN3 (response_t) ─────→  │
  │         [stream open]           │
  │  ←── FIN (request_fin_t) ────   │   (teardown)
```

Handlers: `_onSyn1()` → `_onSyn2()` → `_onSyn3(response_t)` → `_onFin()`.

### Packet header fields

Strings confirm the following header fields:
- **TCP version** — `"invalid tcp version received"` error
- **CRC** — `"invalid crc detected"`, `"Discard invalid data buffer crc not valid"` (via `SerialTransmitter`)
- **Magic word** — only `request_trans_t` and `request_fin_t` have magic validation

### CRC algorithm

**Standard CRC-32** (ISO 3309 / ITU-T V.42) — same as zlib, Ethernet, gzip, PNG.
- Polynomial: `0x04C11DB7` (reflected)
- Init: `0xFFFFFFFF`, XOR out: `0xFFFFFFFF`
- Stored **little-endian** in the 4-byte chunk trailer
- Covers only the **54-byte payload** (not the session/type/seq header)
- Imported from zlib at offset `0x1c668e0`

Verified: 46/49 chunks in `dash-upload.ndjson` pass CRC validation. The 3 failures are due to `0x7E` byte corruption in the capture tool (the serial frame delimiter was not escaped, causing 1-byte data loss in affected chunks).

### File integrity

End-to-end file integrity uses **MD5** (not CRC). The file's MD5 hash is transmitted alongside the file paths. Temp file naming on the device side: `_moza_filetransfer_md5_{hex_digest}`.

### Compression

`ZLibCompressor2` wraps standard zlib deflate. File content and RPC messages are zlib-compressed with the standard `78 9c` magic.

### File transfer API

`FileTransferClient::initClient()` sets up callbacks for:
- `QByteArray` data chunks
- `int64` progress
- `SerialClientState` state changes
- Completion

`pushFiles()` accepts `QMap<QString, QString>` (local path → remote path) or `QMap<QString, QByteArray>` (remote path → in-memory data).

### Exception types

`FileNotFound`, `OverSizeError`, `ConnectionError`, `TransmitError`.

### Dashboard upload orchestration

`Sync_DashboardManager` coordinates dashboard synchronization:
- `upload` — push .mzdash to device
- `download` — pull .mzdash from device
- `synchronizationModule` — sync logic
- `getMcUid` — retrieves the MCU UID for this manager's device
- `sigUploadFile` — verifies `_t1.toHex() != m_mcUid` before upload
- `sltUploadDashboard` — verifies `mcUid->getTargetDevice() != m_deviceInfo->getTargetDevice()`

`DashboardSerializer::parseMsg` handles `configJsonList` deserialization. `LocalDashboardFactory` compresses/decompresses dashboard directories.

### mcUid (MCU Unique Identifier)

The STM32 MCU's hardware UID, burned at fab (likely the 96-bit silicon UID). **Not** the USB serial number, **not** tag 0x0c data, **not** a CoAP resource.

**Acquisition:** `Protocol::MainMcuUidCommand` (part of `NecessaryInfoGroup` batch during device enumeration) → `UsbDevice::updateMainMcuUid()` slot → emits `mainMcuUidChanged()`.

**Usage:** Per-device dictionary key throughout PitHouse:
- `ResourceManagerProxy::addResourceManager(QByteArray mcUid, Sync_DashboardManager*)` — maps mcUid → dashboard manager
- `ScreenControllerUpgradeProxy::addControllerUpgrade(QByteArray mcUid, ...)` — maps mcUid → upgrade handler
- `MBoostChannelManager` — keyed by mcUid
- CoAP: `createProductDeviceInfoResourceInterface mcuUid:` — registered with `productName`, `productType`, `appVersion`, `hardwareVersion`, `parentId`, `mcuUid`

**Not used in upload tokens:** The FF-prefixed field 0 tokens (correlation IDs) are random nonce + timestamp, not derived from mcUid. PitHouse uses mcUid for internal routing but doesn't encode it in the wire protocol.

### Dashboard upload session 0x01 token structure (from capture analysis)

Field 0 payload (16 bytes LE) across 8 observed sessions (VGS + CSP):

| Offset | Size | Value | Description |
|--------|------|-------|-------------|
| 0 | 4 | varies | Random nonce (CSPRNG — tested CRC-32, FNV-1a, DJB2, MurmurHash3, mt19937, 12 LCG variants, crypto hashes — all negative) |
| 4 | 4 | `0x00000002` | Constant (protocol version or request type) |
| 8 | 4 | varies | Unix timestamp (session start, seconds since epoch) |
| 12 | 4 | `0x00000000` | Zero padding |

Field 0 "remaining" = total bytes of subsequent fields (field1_block + field2_block = 38 + compressed_size). The value 7200 seen in captures matches dashboards like "Formula Racing V1-Mission R" (7170B compressed). Not a hardcoded constant — confirmed by PE .text section search.
Field 1 "remaining" = 3 (constant across all captures). NOT a byte count — semantics unknown.

**Field 1 payload `9e 79 52 7d 07 00 00 00` is NOT a hardcoded constant in the binary.** Searched for the pattern as:
- Raw bytes in `MOZA Pit House.exe` (.text, .rdata, .data)
- `push imm32` instruction (`68 9E 79 52 7D`)
- `mov r32, imm32` instructions (`B8..BF 9E 79 52 7D`)
- Hex string forms (`9e79527d`, `9E79527D`, `7D52799E`)
- Inside `MOZADriverInterface.dll`, `crypt.dll`

No matches. This means the value is computed at runtime or constructed from a higher-level object (e.g., a serialized protobuf-like message, a CRC/hash of session metadata, or an external config). Brute-force CRC-32 of common strings (`dashboard`, `mzdash`, `FileTransfer`, etc.) also produced no match.

### FileTransfer call chain (traced via Ghidra, 5 rounds)

From `Sync_DashboardManager::upload` down toward the FF-prefix construction:

```
Sync_DashboardManager::upload                     (FUN_00849c30)
  └─ Sync_DashboardManager::synchronizationModule
       └─ UploadFilesReply::uploadFile
            └─ RemoteFileManager::pushFiles wrapper  (FUN_00920490)
                 └─ FileTransferClient::pushFiles inner (FUN_0092d630)
                      ├─ FUN_0092eee0 — temp path "_moza_filetransfer_tmp_%1" via QDateTime::currentMSecsSinceEpoch
                      ├─ FUN_00861370 — QMap copy of file list
                      ├─ FUN_0079a5f0 — 8-byte session value via atomic CAS loop (FUN_00798050)
                      ├─ FUN_0093f1c0 — create SendHandler
                      │     ├─ FUN_0092ff50 — struct copy
                      │     ├─ FUN_0093ca70 — allocates task state (0xa8/0xb0 bytes, std::_Deferred_async_state<void> vtable)
                      │     └─ FUN_006434b0
                      ├─ FUN_0093ed20 — insert into session map (red-black tree via FUN_00942c70)
                      ├─ FUN_00941d60 — shared_ptr move
                      └─ FUN_0092ffc0 — cleanup (QString destructor, etc.)
```

`FUN_0093e3e0` references the `FileTransferClient::pushFiles lambda_1` vtable and dispatches the async task that executes the actual transfer. Its inner calls (`FUN_00940f30` → `FUN_00934eb0` / `FUN_0093b140` / `FUN_00943530`) manage SendHandler state but do not contain byte-level FF framing either.

**Conclusion of trace:** Five decompilation rounds (`/tmp/ghidra_decompiled.txt`, `/tmp/ghidra_deep.txt`, `/tmp/ghidra_deeper.txt`, `/tmp/ghidra_round4.txt`, `/tmp/ghidra_round5.txt`) walked through the FileTransferClient / RemoteFileManager / SendHandler infrastructure without reaching the actual byte-level FF-prefix builder. The FF framing, tokens, and CRC are built in a lower layer (likely `MOZA::Protocol::SerialStreamManager` or a deeper SendHandler method reached via vtable / Qt signal indirection). The call graph bottoms out in `std::_Deferred_async_state`, `Concurrency::task`, and `_PPLTaskHandle` plumbing rather than a direct byte-packing routine.

For the field 0 token question this is still a conclusive negative result: the concurrency layer passes the file content as a `QByteArray`/`QMap`, not as a pre-built message — so the field 0 tokens are generated fresh per send at the wire-format layer, consistent with the capture analysis (random nonce + timestamp, no device-state dependency).

### Titan token system (cloud, not serial)

PitHouse has a cloud upload path separate from serial device communication:
- `requestUploadTitanToken` → `UploadTitanTokenReq` → gets `GetTitanTokenResp` with `userId`, `titanUsername`, `titanPassword`, `titanToken`
- Endpoints: `/titan/save`, `/titan/find` on `ace.gudsen.vip`
- OSS storage: Alibaba Cloud at `oss-cn-hongkong.aliyuncs.com`, key pattern `racing-backend/telemetry/%1/%2/.../%9.dat`
- Credentials: `accessKeyId`, `accessKeySecret`, `securityToken`, `endPoint`, `bucketName`, `regionId`

This is unrelated to the serial dashboard upload protocol — it's PitHouse's cloud sync feature.

---

## FormulaSteering pack architecture (Pit House Apr 2026 build)

Reverse-engineered from `MOZA Pit House.exe` md5 `2b9ad3b5cb0d333e4034397be8ee1de0` (39 MB, mtime 2026-04-24) shipped with KS Pro firmware support. New layered telemetry architecture above the bit-packed `7d:23` wire flow documented in §6.

### Class hierarchy

```
Domain layer (UI / business logic)
  ├── FormulaSteeringProgram + FormulaSteeringProgramManager
  ├── DisplayProgram + DisplayProgramManager
  ├── ScreenProgram + ScreenProgramManager        (S09 CM2 dashboard)
  ├── SteeringProgram + SteeringProgramManager
  ├── MotorProgram, PedalProgram, HandbrakeProgram, ...
  └── UiListInfo, WheelLightColorMap_V2, KeyCombinationWrapper, ...

Protocol layer (wire format)
  ├── TelemetryDataSend                           (abstract base)
  ├── TelemetryRpmDataStrategy
  ├── TelemetryCommonDataStrategy
  ├── TelemetryDataContinuousForwardingSwitch     (per-stream on/off)
  ├── TelemetryDataForwarding::ForwardingStrategies
  ├── TelemetryDataFrameDecoder
  ├── TelemetryDataTopicList                      (pub/sub)
  ├── TelemetryDataTopicListManager
  ├── TelemetryUniversalDataPack                  (pack base — fields data + index)
  ├── FormulaSteeringTelemetryDataSend            (concrete sender for formula-style wheels)
  ├── FormulaSteeringTelemetryDataForwarding      (forwarding manager)
  │     └── TelemetryDataTimedForwardingWorker    (timer-driven worker thread)
  └── FormulaSteeringTelemetryDataPack1..18       (18 concrete sub-packs)
```

Source filename `FormulaSteeringTelemetryDataStructres.cc` (sic — typo in MOZA source) appears in error messages tagged `Protocol - FSR - %1 throw: %2`.

### Pack object layout (constructor analysis, MSVC 32-bit)

Each `FormulaSteeringTelemetryDataPackN` constructor stores:

| Offset | Type | Value | Meaning |
|--------|------|-------|---------|
| `+0x00..0x07` | ptrs | (QObject vptr + d-ptr) | QObject base |
| `+0x08` | byte | `0x01` | flag (initialized?) |
| `+0x0c` | uint32 LE | varies (13–20) | payload byte size |
| `+0x10` | byte | `0x42` ('B') | pack type magic |
| `+0x14..` | bytes | (allocated via `malloc(0x20)`) | data buffer |

Pack-by-pack payload sizes (from `mov dword [eax+0x0c], imm32` immediates in the ctor):

| Pack | Size | Pack | Size | Pack | Size |
|------|------|------|------|------|------|
| 1 | 20 | 7 | 20 | 13 | 20 |
| 2 | 13 | 8 | 18 | 14 | 19 |
| 3 | 14 | 9 | 19 | 15 | 19 |
| 4 | 18 | 10 | 20 | 16 | 19 |
| 5 | 20 | 11 | ?  | 17 | 20 |
| 6 | 20 | 12 | 13 | 18 | 20 |

Pack 11's size opcode form differs and was not extracted (likely `mov [esi+0xc], imm32` variant).

### Wire-side observations so far (insufficient to conclude)

Scanning every checksum-valid Moza frame in `usb-capture/ksp/{mozahubstartup,putOnWheelAndOpenPitHouse}.pcapng` (KS Pro / 2026-04 firmware): no frame carries tag `0x42` followed by a plausible u32 length. **This is not authoritative.** Both captures cover power-on / Pit House startup only — no game was running, no tier-def + telemetry burst was observed, and `FormulaSteeringTelemetryDataForwarding::TelemetryDataTimedForwardingWorker` only ticks while a subscriber is registered. Two idle traces from one wheel is too small a sample to rule out 0x42 as a wire tag.

Possibilities still open:
- 0x42 is an internal C++ class discriminator and never hits the wire; the Packs feed into the existing bit-packed `[flag][0x20][bits...]` payload inside `cmd=0x43, dev=0x17, sub=7d:23` documented in §6.
- 0x42 is a TLV tag carried inside a 7c:00 session-data envelope only during active game telemetry (not yet captured).
- 0x42 rides a different wire envelope (a new cmd byte, or a sub-tag inside an existing one) that idle traffic doesn't exercise.

A capture with a running sim and a connected KS Pro is needed to decide between these. Until then, treat the Pack-byte sizes documented below as binary-derived constants only.

### ControllerType routing enum

`Protocol::DisplayProgram::DisplayProgram(shared_ptr<SendMessageQueue>, Domain::DisplayProgram*, Protocol::TelemetryDataTopicList*, Protocol::ControllerType, QObject*)` — a new `ControllerType` enum routes commands to the correct controller queue. Hundreds of `<lambda_N>` types in the binary's RTTI table take `(QByteArray, Protocol::ControllerType)` parameters, indicating fan-out by controller type for every command class (Motor, Pedal, AS23BAX, Steering, Display, etc.). Specific values weren't extracted — they live as integer immediates in the call sites.

### Domain-side telemetry properties

`Protocol::AS23BAXTelemetryForceFeedbackControlStrategy` (flight-sim parallel) reveals the slot/signal vocabulary that the racing equivalent shares. Slot names from RTTI:

```
setCurrentTelemetryMaxRpm, setCurrentTelemetryRpm, setCurrentTelemetryGear,
setCurrentTelemetryClutch, setCurrentLocX, setCurrentLocY,
setGearDamping, setGearNotchiness,
setEngineVibrationForce, setEngineVibrationFrequency, setEngineVibrationTorqueCoef,
setDeviceEffectIndex, setLedTelemetryData,
prepareForceFeedbackParameters, deleteForceFeedbackParameters, setForceFeedback
```

The racing strategy uses `updateLedTelemetryData` and `controlIndicatorLightOff` (per-index), `setIndicatorColors(QList<QColor>)`, `setButtonColors`, `setAtmosphereColors`, `setKnobColors`. RPM data feeds via `Protocol::SteeringRpmPercent` and `Protocol::SteeringLedRGBArray<10>` (10-LED indicator strip).

### KS Pro = W18 (not W04)

`ALL_FmwHwCompatTab.json` distinguishes two KS-tagged steering wheels:

| Product | Hardware regex | Display |
|---------|---------------|---------|
| W04 "KS Wheel" | `^\[RS21-W04-HW_SM-CU-V0\d\w?\]\[KS\]\[[13]\]\[[457]\]` | none |
| W18 "KS Pro Wheel" | `^\[RS21-W18-HW_SM-CU-V1\d\w?\]\[W18\]\[[13]\]\[[7]\]` | shared with W17 RGB-DU |

W18 Display unit: `^\[RS21-W17-HW_RGB-DU-V1\d\w?\]\[W18\]\[[139]\]\[(8|16|17|18|19)\]` — the W18 Steering Wheel's display board reuses W17's RGB-DU hardware. Plugin's references to "KS Pro on RS21-W18-MC SW" are correct.

### Telemetry.json grew 410 → 454 channels

`bin/GameConfigs/Telemetry.json` distribution (count 454, sectors 454):

| package_level | Count | Compression |
|--------------|-------|-------------|
| 30 | 203 | mostly fast bool/uint/percent_1 |
| 500 | 124 | many `location_t` opponent slots |
| 1000 | 1 | `TimeAbsolute` |
| 2000 | 126 | `string`, slow stats |

New channels for race/opponent awareness (also referenced in §10):
- `v1/gameData/patch/Location_0..63` — 64 × `location_t`, lvl=500 (opponent positions)
- `v1/gameData/patch/ri0..63` — 64 × `uint32_t`, lvl=30 (race-info indices)
- `v1/gameData/patch/OnTrack` (bool, lvl=500)
- `v1/gameData/patch/OpponentCount` (uint8, lvl=2000)
- `v1/gameData/patch/PlayerIndex` (uint8, lvl=2000)
- `v1/gameData/patch/TrackPositionPercent` (percent_1, lvl=30)

### rs21_parameter.db delta (Apr 2026 build)

Database now has 909 commands across the same group structure. New for this build:

- **Group 100** (Hub state, RW): `HubGetState_Port1Connect..Port4Connect`, `HubGetState_PedalConnect` — Universal Hub port-connection probes used during device-tree discovery.
- **`>=1.2.4.x` MeterSet/Get variants** in group 50/51: `SetIndicatorNormalMode` (`[50,24,0]`), `SetIndicatorGroupStandbyMode` (`[50,25,0]`), per-cycle setters `SetIndicatorStandbyBreathModeCycle/CircularModeCycle/RainbowModeCycle/DriftSandModeCycle` (`[50,26,0,N]`), `SetIndicatorGroupStandbyModeColor1..16` (`[50,27,0,255,N]`), sleep mode group (`[50,28]..[50,32,...]`), `SetIndicatorStartUpColor` (`[50,33]`).
- **Older `_o` suffixed variants** (`MeterSetCfg_SetIndicatorGroupBrightness_o` etc) marked `<1.2.4.x` and are kept for backwards compatibility.

The `>=1.2.4.x` constraint matches QML config schema entries tagged `S09;ge:1.2.4.0` — all three (DB command, QML schema, S09 dashboard firmware) coordinate around this version cliff.

KS Pro display surface reuses **existing meter group [50/51]** for runtime brightness/UI/units; no dedicated KS-Pro-specific command group exists.

### New wheel UI styles

Strings in the binary register many more dashboard UI variants than older builds: 11× `Formula Style v1..v11`, 4× `GT v1..v4`, 3× `Simple Style v1..v3`, 3× `Simple v1..v3`, plus `Modern Tech`, `Realistic Style v5/v6/v7`, `Truck version v1`, `Config`. Selectable per-controller via `displayUiStyleIndex` (read/write through `[51,1]`/`[50,1]`).

### KS Pro session moves (2026-04+ firmware)

Existing plugin code (`Telemetry/TelemetrySender.cs`) already encodes:
- configJson state push session moved from `0x09` → `0x0a` (KS Pro / 2026-04+)
- Tile-server / dashboard list push: still `0x05`/`0x07` device-init, `0x04` host-upload baseline; uses `7c:23 46` to redirect upload to a different session under the new firmware
- W18 KS Pro / W13 FSR V2 silently drop frames during ~11 s post-connect window — plugin defers tier-def + display config burst until ack idle

Captures `usb-capture/ksp/zlib/mozahubstartup/{device,host}_sess0x0a_*.json` confirm the configJson topology runs over session 0x0a on KS Pro: device push at sequence boundaries (3-piece state blob: 14671 + 5759 + 4471 + 12609 bytes), host reply with dashboard list (262 bytes uncompressed, identical "configJson()" envelope as session 0x09 on older firmware).

---

## SerialStream protocol — wire format (from capture analysis)

### Session type byte mapping

| Value | Meaning | Notes |
|-------|---------|-------|
| `0x00` | Control / end marker | SYN, FIN, session close |
| `0x01` | Data transfer | Normal data chunks |
| `0x81` | Request / channel open | Device-initiated; carries session params |

### Type 0x81 request payload

Observed in session 4: `04 00 fd 02` = two LE uint16:
- `session_id` = 4
- `receive_window` = 765 (0x02FD)

This is the device acknowledging / opening the session channel.

### Session lifecycle (from `dash-upload.ndjson`)

8 concurrent sessions observed during a single dashboard upload:

| Session | Duration | Role | Description |
|---------|----------|------|-------------|
| 0x01 | 8.5s | Management | Bidirectional RPCs with `0xFF`-prefixed CoAP-like messages |
| 0x02 | 6.9s | Keepalive | Dev→host, empty `00 00 00 00` payloads, ~3.4s interval |
| 0x03 | 6.9s | Keepalive | Host→dev, linked to 0x0A via cross-session acks |
| 0x04 | 3.0s | **File transfer** | Path exchange + mzdash file upload (75 data + 28 ack) |
| 0x06 | 6.9s | Keepalive | Alternating directions, ~3.4s |
| 0x08 | 6.9s | Keepalive | Alternating directions, ~3.4s |
| 0x09 | 5.8s | **configJson RPC** | Dev sends dashboard state; host responds with dashboard list |
| 0x0A | 6.9s | Keepalive | Dev→host, linked to 0x03 |

Session IDs appear pre-assigned (not negotiated in-band). Sessions 0x03 and 0x0A are a linked pair — the session ID in `fc:00` ack frames identifies the ack sender's session, not the data sender's.

### Cross-session ack pattern

```
Session 0x03 (host→dev) data seq 0x03AB
Session 0x0A (dev→host) ack  seq 0x03AB   ← ack sender uses its own session ID
```

### Keepalive frames (bare 0x43)

34 bare frames (no cmd bytes, n=1, payload=`0x00`) sent to devices 0x17/0x14/0x15 every ~1.1s. Device 0x71 replies `0x80`. These are connection-level pings, not part of the file transfer sessions.

---

## Session 1 — management messages (0xFF-prefixed)

### Message format

```
FF(1)  inner_len(4 LE)  token(4 LE)  data(inner_len)  CRC32(4)
```

- `FF` = management message marker
- `inner_len` = size of the `data` field only
- `token` = per-message identifier linking requests to responses
- `CRC32` = standard zlib CRC-32 over all bytes from `FF` through end of `data`
- Multi-chunk messages also have per-chunk CRC trailers (same as file transfer)

### Observed messages

| # | Time | Dir | inner_len | Token | Content |
|---|------|-----|-----------|-------|---------|
| 1 | 0.15s | H→D | 8 | `0xC4ECAD0F` | Param query: id=14, value=100 |
| 2 | 2.47s | H→D | 12 | `0xE6D977EC` | Transfer descriptor: resource=10, size=60000 |
| 3 | 2.50s | D→H | 12 | `0xE6D977EC` | Echo/ACK (identical to msg 2) |
| 4 | 5.01s | D→H | 20 | `0x993A3D05` | Extended descriptor |
| 5 | 5.20s | H→D | 8 | `0xC4ECAD0F` | Repeat of msg 1 |
| 6 | 5.21s | D→H | 742 | `0x7FBD1F` | **Zlib device log** (14 chunks, decompresses to 7163 bytes) |
| 7 | 5.24s | H→D | 8 | `0x1C3062FB` | Param query: id=15, value=32 |
| 8 | 8.61s | D→H | — | — | Null completion marker `00 00 00 00` |

Message 6 decompresses to UTF-16BE device log entries containing:
- Firmware process status (`execvp: No such file or directory`)
- Dashboard rendering engine listing 13 .mzdash files
- Preview image generation: `grabfromFbo: Successfully saved preview image to .../rpm-only.mzdash_v2_10_3_05.png (480x480)`

---

## Session 4 — file transfer wire format

### 8-byte transfer header

Each direction's reassembled data starts with an 8-byte header:

```
role(1)  max_chunk(1)  transfer_type(1)  reserved(5)
```

| Byte | Host→dev | Dev→host | Meaning |
|------|----------|----------|---------|
| 0 | `0x02` | `0x01` | Sender role: 0x02=host, 0x01=device |
| 1 | `0x40` (64) | `0x38` (56) | Max chunk payload size |
| 2 | `0x01` | `0x01` | Transfer type (0x01=file transfer) |
| 3–7 | `00 00 00 00 00` | `00 00 00 00 00` | Reserved |

### TLV path structure

After the header, paths are encoded as TLV entries:

| Marker | Meaning |
|--------|---------|
| `0x8C` | Local path (host-side temp file) |
| `0x84` | Remote path (device-side staging or target) |

Each path entry: `marker(1) + padding(1=0x00) + UTF-16LE_path(null-terminated)`.

Path length is implicit (scan to null terminator).

### Sub-message 1: path registration

Host sends 3 path entries:

```
header(8)
  0x8C local:  C:/Users/.../AppData/Local/Temp/_moza_filetransfer_tmp_{timestamp}
  0x8C local:  (same)
  0x84 remote: /home/root/_moza_filetransfer_md5_{md5hex}
  0x84 remote: (same)
  MD5_len(1=0x10)  MD5(16 bytes)
  reserved(4=0x00000000)
  token(4)=0x054B
  sentinel(4)=0xFFFFFFFF  (no content in this sub-message)
```

Device echoes with its own header (`01 38 01 ...`) and paths:
- Remote staging: `/home/root/_moza_filetransfer_md5_{md5hex}`
- Local echo: `C:/Users/.../AppData/Local/Temp/_moza_filetransfer_tmp_{timestamp}`

### Sub-message 2: file content push

```
header(8) = 03 83 06 00 00 00 00 00
  0x8C local path
  0x84 remote staging path
  MD5_len(1=0x10) + MD5(16)
  reserved(4)
  token(4)=0x054B
  token(4)=0x054B
  file_count(4)=0x00000001
  dest_path_byte_len(4)=102
  dest_path: UTF-16BE "/home/moza/resource/dashes/rpm-only/rpm-only.mzdash"
  compressed_header: uncomp_sz + comp_sz (mixed endian)
  zlib_stream (78 9c magic, ~1238 bytes)
```

Note: The destination path in sub-message 2 is **UTF-16BE** (big-endian), unlike the TLV paths which are UTF-16LE. This is likely because the file content sub-message uses a different serialization path within Pithouse.

### Session 4 sequence diagram

```
Device                                     Host
  │                                          │
  │ ──── type=0x81 (session open) ────────→  │  seq=0x0004, payload=04:00:fd:02
  │                                          │
  │ ←─── fc:00 ACK ──────────────────────    │  ack_seq=0x0004
  │                                          │
  │ ←─── Sub-msg 1: path registration ───    │  seqs 0x0007–0x000D (7 chunks)
  │                                          │
  │ ──── fc:00 ACKs ─────────────────────→   │
  │ ──── Sub-msg 1 response (paths) ─────→   │  seqs 0x0005–0x000A (6 chunks)
  │                                          │
  │ ←─── fc:00 ACKs ─────────────────────    │
  │ ←─── Sub-msg 2: file content push ───    │  seqs 0x000E–0x002D (32 chunks)
  │                                          │
  │ ──── fc:00 ACKs ─────────────────────→   │
  │ ──── Sub-msg 2 response ─────────────→   │  seqs 0x000B–0x0010 (6 chunks)
  │                                          │
  │ ←─── type=0x00 end marker ───────────    │  seq=0x002E
  │ ──── type=0x00 end marker ───────────→   │  seq=0x0011
```

---

## Session 9 — configJson RPC

### Device→host (dashboard state query)

Compressed transfer: `flag=0x00, comp_sz=1512, uncomp_sz=4481`.

Could not decompress due to `0x7E` byte corruption in 104 capture frames. Original content includes `TitleId`, `disabledManager`, `deletedDashboards`, `updateDashboards` with per-dashboard `createTime`, `dirName`, `hash`.

### Host→device (dashboard list response)

Compressed transfer: `flag=0x00, comp_sz=194, uncomp_sz=310`. Successfully decompressed:

```json
{
  "configJson()": {
    "dashboardRootDir": "",
    "dashboards": [
      "DNR endurance", "Formula 1", "GT V01", "GT V02", "GT V03",
      "JDM Gauge Style 01", "JDM Gauge Style 02", "JDM Gauge Style 03",
      "Lovely Dashboard for Vision GS", "Rally V01", "m Formula 1", "rpm-only"
    ],
    "fontRootDir": "",
    "fonts": [],
    "imageRootDir": "",
    "sortTags": 0
  },
  "id": 11
}
```

The `id` field is a message counter (not session-related).
