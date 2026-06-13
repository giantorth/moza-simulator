# Plan: Telemetry Sender with Diagnostic Mode

## Context

All protocol research for sending game telemetry to Moza wheel dashboards is complete. We know:
- Frame format: `7E [N] 43 17 7D 23 32 00 23 32 [flag] 20 [data] [checksum]`
- Bit-packing: LSB-first, channels sorted alphabetically by URL
- All 22 compression type encode formulas (from Ghidra RE)
- Flag byte: any fixed value works (Pit House internal counter, wheel doesn't validate)
- Channel layouts: parsed from .mzdash + Telemetry.json
- Enable sequence: likely just the `7D 23` frames are sufficient

Remaining unknowns for users to verify:
- Exact channel count per dashboard (7 vs 8 for F1, depends on byte limit semantics)
- Whether `0x41/FD:DE` enable signal or `0x40/28:02` mode set are required
- Reverse gear encoding

## Architecture

### New files

```
Telemetry/
  TelemetryBitWriter.cs       — LSB-first bit packing into byte buffer
  TelemetryEncoder.cs         — Game value → raw bits per compression type
  DashboardProfile.cs         — Channel layout definition (name, URL, compression, bits)
  DashboardProfileStore.cs    — Bundled profiles + .mzdash parser
  TelemetryFrameBuilder.cs    — Assembles complete 7E frame from game data
  TelemetrySender.cs          — Periodic sender (timer, game data hook, frame dispatch)
  TelemetryDiagnostics.cs     — Diagnostic mode controls and logging
```

### Modified files

```
MozaPlugin.cs                 — Hook TelemetrySender into plugin lifecycle
MozaDeviceManager.cs          — Add SendRawFrame() for pre-built byte arrays
Protocol/MozaProtocol.cs      — Add telemetry constants (group 0x43, cmd 7D 23, header bytes)
UI/SettingsControl.xaml        — Add telemetry section with dashboard selector + diagnostics
UI/SettingsControl.xaml.cs     — Wire up telemetry UI
MozaPluginSettings.cs          — Add telemetry settings (enabled, dashboard, flag byte, etc.)
```

### Data files to bundle

```
Data/
  Telemetry.json               — Copied from Pit House (channel URL → compression type mapping)
  Profiles/                    — Pre-computed channel layouts for common dashboards
    Formula 1.json
    Core.json
    GT V1.json
    ...
```

---

## Implementation steps

### 1. TelemetryBitWriter

Stateless utility. Implements the LSB-first bit-write algorithm from pithouse-re.md § 8.

```csharp
public class TelemetryBitWriter
{
    private readonly byte[] _buffer;
    private int _bitPosition;

    public TelemetryBitWriter(int byteCount);
    public void WriteBits(uint value, int bitCount);
    public void WriteFloat(float value);       // 32-bit IEEE 754
    public void WriteDouble(double value);      // 64-bit IEEE 754
    public byte[] GetBuffer();
    public int BitPosition { get; }
}
```

Algorithm (from pithouse-re.md):
```
byte_off = bit_pos / 8
bit_off  = bit_pos % 8
while count > 0:
    take = min(count, 8 - bit_off)
    mask = ((1 << take) - 1) << bit_off
    buffer[byte_off] &= ~mask
    buffer[byte_off] |= (value << bit_off) & mask
    value >>= take
    byte_off++; bit_off = 0; count -= take
```

### 2. TelemetryEncoder

Converts game values to raw bit values using the formulas from pithouse-re.md § 9.

```csharp
public static class TelemetryEncoder
{
    public static uint Encode(string compression, double gameValue);
}
```

Encoding table (from Ghidra RE):

| Compression | Formula |
|-------------|---------|
| `bool` | `(uint)(gameValue != 0 ? 1 : 0)` |
| `uint3`/`uint8`/`uint15` | `Min((uint)gameValue, 15)` |
| `int30`/`uint30`/`uint31` | `Min((uint)gameValue, 31)` |
| `int8_t`/`uint8_t` | `(uint)(byte)gameValue` |
| `percent_1` | `(uint)Clamp(gameValue * 10.0, 0, 1000)` |
| `float_001` | `(uint)Clamp(gameValue * 1000.0, 0, 1000)` |
| `tyre_pressure_1` | `(uint)Clamp(gameValue * 10.0, 0, 4095)` |
| `tyre_temp_1`/`track_temp_1`/`oil_pressure_1` | `(uint)Clamp(gameValue * 10.0 + 5000.0, 0, 16383)` |
| `int16_t`/`uint16_t` | `(uint)(ushort)gameValue` |
| `float_6000_1` | `(uint)Clamp(gameValue * 10.0, 0, 65535)` |
| `float_600_2` | `(uint)Clamp(gameValue * 100.0, 0, 65535)` |
| `brake_temp_1` | `(uint)Clamp(gameValue * 10.0 + 5000.0, 0, 65535)` |
| `uint24_t` | `(uint)gameValue & 0xFFFFFF` |
| `float` | `BitConverter.SingleToUInt32Bits((float)gameValue)` |
| `int32_t`/`uint32_t` | `(uint)gameValue` |
| `double`/`location_t`/`int64_t`/`uint64_t` | 64-bit — use WriteDouble |

For N/A sentinel: `percent_1` and `float_001` use 1023 when the value is unavailable.

### 3. DashboardProfile

Defines which channels are packed and in what order.

```csharp
public class ChannelDefinition
{
    public string Name;          // e.g. "Brake"
    public string Url;           // e.g. "v1/gameData/Brake"
    public string Compression;   // e.g. "float_001"
    public int BitWidth;         // e.g. 10
    public string SimHubProperty; // e.g. "GameData.Brake" — maps to SimHub's data model
}

public class DashboardProfile
{
    public string Name;                      // e.g. "Formula 1"
    public List<ChannelDefinition> Channels; // Sorted alphabetically by URL, truncated to byte limit
    public int TotalBits;
    public int TotalBytes;                   // ceil(TotalBits / 8)
}
```

### 4. DashboardProfileStore

Loads profiles from bundled JSON or parses .mzdash files.

```csharp
public class DashboardProfileStore
{
    public List<DashboardProfile> BuiltinProfiles { get; }
    
    // Parse a .mzdash file: extract Telemetry.get() URLs, sort, look up compression, apply byte limit
    public DashboardProfile ParseMzdash(string mzdashPath, int byteLimitOverride = 0);
    
    // Load the bundled Telemetry.json for URL → compression mapping
    private Dictionary<string, TelemetryChannelInfo> LoadTelemetryJson();
}
```

**Building a profile from .mzdash:**
1. Regex all `Telemetry.get(['"]v1/gameData/...['"])` references
2. Deduplicate
3. Sort alphabetically by full URL
4. Look up compression type + bit width from Telemetry.json
5. Pack channels in order, stopping when byte limit is reached (configurable)
6. Map each channel URL to a SimHub GameData property name

**SimHub property mapping** (URL suffix → SimHub GameData):

| URL suffix | SimHub property | Notes |
|-----------|-----------------|-------|
| `SpeedKmh` | `SpeedKmh` | |
| `Rpm` | `Rpms` | |
| `Gear` | `Gear` | SimHub: -1=R, 0=N, 1+=gears |
| `Throttle` | `Throttle` | 0-100 |
| `Brake` | `Brake` | 0-100 |
| `BestLapTime` | `BestLapTime.TotalSeconds` | |
| `CurrentLapTime` | `CurrentLapTime.TotalSeconds` | |
| `LastLapTime` | `LastLapTime.TotalSeconds` | |
| `GAP` | `DeltaToSessionBest` | delta in seconds |
| `FuelRemainder` | `FuelPercent` | 0-100% |
| `DrsState` | `DRSEnabled` | bool |
| `ErsState` | `ERSPercent` | 0-100 → mapped to uint3 |
| `TyreWear*` | `TyreWear*` | 0-100%, may need individual tire data |

A full mapping table will be needed. For channels with no direct SimHub equivalent, send 0 or N/A sentinel.

### 5. TelemetryFrameBuilder

Reads game data, encodes channels, builds the complete frame.

```csharp
public class TelemetryFrameBuilder
{
    private readonly DashboardProfile _profile;
    
    public byte[] BuildFrame(GameData gameData, byte flagByte)
    {
        // 1. Create bit writer sized to profile.TotalBytes
        var writer = new TelemetryBitWriter(_profile.TotalBytes);
        
        // 2. For each channel in profile order:
        foreach (var ch in _profile.Channels)
        {
            double value = GetGameValue(gameData, ch);
            if (ch.BitWidth == 32 && ch.Compression == "float")
                writer.WriteFloat((float)value);
            else if (ch.BitWidth == 64)
                writer.WriteDouble(value);
            else
                writer.WriteBits(TelemetryEncoder.Encode(ch.Compression, value), ch.BitWidth);
        }
        
        // 3. Build full frame: 7E [N] 43 17 [7D 23] [32 00 23 32] [flag] [20] [data] [checksum]
        var frame = new List<byte>();
        byte[] data = writer.GetBuffer();
        byte[] cmdId = { 0x7D, 0x23 };
        byte[] header = { 0x32, 0x00, 0x23, 0x32, flagByte, 0x20 };
        int payloadLen = cmdId.Length + header.Length + data.Length;
        
        frame.Add(0x7E);                            // Start
        frame.Add((byte)payloadLen);                 // N
        frame.Add(0x43);                             // Group
        frame.Add(0x17);                             // Device (wheel)
        frame.AddRange(cmdId);                       // Command ID
        frame.AddRange(header);                      // Telemetry header
        frame.AddRange(data);                        // Bit-packed channels
        frame.Add(MozaProtocol.CalculateChecksum(frame.ToArray()));
        return frame.ToArray();
    }
}
```

### 6. TelemetrySender

Periodic sender that hooks into the plugin lifecycle.

```csharp
public class TelemetrySender : IDisposable
{
    private Timer _sendTimer;
    private TelemetryFrameBuilder _frameBuilder;
    private GameData _latestGameData;
    private bool _enabled;
    
    // Settings
    public byte FlagByte { get; set; } = 0x01;
    public int SendRateHz { get; set; } = 20;
    public bool SendEnableSignal { get; set; } = true;
    public bool SendTelemetryMode { get; set; } = true;
    public DashboardProfile Profile { get; set; }
    
    public void Start(MozaSerialConnection connection);
    public void Stop();
    public void UpdateGameData(GameData data);  // Called from DataUpdate
    
    private void OnTimerElapsed(object sender, ElapsedEventArgs e)
    {
        if (!_enabled || _latestGameData == null) return;
        
        // Build and send telemetry frame
        byte[] frame = _frameBuilder.BuildFrame(_latestGameData, FlagByte);
        _connection.Send(frame);
        
        // Optionally send enable signal (0x41/FD:DE)
        if (SendEnableSignal)
            _connection.Send(BuildEnableFrame());
        
        // Optionally send telemetry mode (0x40/28:02 data=01:00)
        if (SendTelemetryMode && _modeCounter++ % 10 == 0)  // Every 10th tick (~2/sec at 20Hz)
            _connection.Send(BuildTelemetryModeFrame());
    }
}
```

**Integration into MozaPlugin.cs:**
- Create `TelemetrySender` in `Init()`
- Call `sender.UpdateGameData(data)` from `MozaDashDeviceExtension.DataUpdate()` (or `MozaPlugin.DataUpdate()`)
- Start/stop based on settings toggle
- Dispose in `End()`

### 7. TelemetryDiagnostics

Logging and diagnostic controls.

```csharp
public class TelemetryDiagnostics
{
    // Log last N sent frames for inspection
    public CircularBuffer<TelemetryLogEntry> SentFrames { get; }
    
    // Log incoming frames from wheel (for serial sniffer)
    public CircularBuffer<byte[]> ReceivedFrames { get; }
    
    // Test pattern: cycles through known values so user can verify channels
    public GameData BuildTestPattern(int frameCounter);
    
    // Export log to file
    public void ExportLog(string path);
}
```

### 8. Settings UI additions

Add a "Telemetry" section to the existing settings panel:

```
┌─ Dashboard Telemetry ─────────────────────────────────────────┐
│                                                                │
│  [✓] Enable dashboard telemetry                                │
│                                                                │
│  Dashboard: [Formula 1          ▼]  [Load .mzdash...]         │
│  Channels:  7 packed (121 bits, 16 bytes)                      │
│                                                                │
│  ─── Diagnostic Mode ──────────────────────────────────────── │
│                                                                │
│  Flag byte: [0x01    ]  (any value should work)                │
│  Send rate: [20] Hz                                            │
│                                                                │
│  [✓] Send enable signal (0x41)                                 │
│  [✓] Send telemetry mode (0x40)                                │
│                                                                │
│  Byte limit override: [16]  (0 = auto from profile)           │
│                                                                │
│  [▶ Send Test Pattern]  [■ Stop]                               │
│  Test pattern: Gear 0→6, Brake 0→100%, Speed 0→200             │
│                                                                │
│  [Export Frame Log...]                                         │
│                                                                │
│  Last frame: 7e 18 43 17 7d 23 32 00 23 32 01 20 ...         │
│  Status: Sending at 20 Hz (1247 frames sent)                   │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

Key diagnostic controls:
- **Dashboard selector**: Dropdown of bundled profiles + "Load .mzdash" button
- **Flag byte**: Editable field (default 0x01, users can try other values)
- **Enable signal toggle**: Test with/without 0x41 frames
- **Telemetry mode toggle**: Test with/without 0x40 frames
- **Byte limit override**: Let users try different limits to find the correct channel count
- **Test pattern**: Sends cycling values so users can visually confirm each channel maps correctly on the wheel display
- **Frame log**: Shows last sent frame hex + running frame count

---

## Implementation order

### Phase 1: Core engine (no UI)

1. `TelemetryBitWriter` — bit packing, unit testable standalone
2. `TelemetryEncoder` — encoding formulas, unit testable
3. `DashboardProfile` + `DashboardProfileStore` — profile loading
4. `TelemetryFrameBuilder` — frame assembly
5. Bundle `Telemetry.json` + F1 profile as embedded resources

### Phase 2: Integration

6. `TelemetrySender` — timer + game data hook
7. Wire into `MozaPlugin` lifecycle (DataUpdate, Init, End)
8. Add `MozaProtocol` constants for telemetry groups/commands
9. Add settings fields to `MozaPluginSettings`

### Phase 3: UI + diagnostics

10. `TelemetryDiagnostics` — frame logging + test pattern
11. Settings UI — dashboard selector, diagnostic controls
12. Parse additional .mzdash profiles from Pit House dashes directory

### Phase 4: User testing + iteration

13. Ship to users with diagnostic mode
14. Collect feedback: which flag byte works, which streams are required, correct channel count
15. Adjust defaults based on results

---

## Verification

### Unit tests

- `TelemetryBitWriter`: round-trip write/read for all bit widths (1, 4, 5, 8, 10, 12, 14, 16, 24, 32, 64)
- `TelemetryEncoder`: validate each compression type against known values from capture data
- `DashboardProfileStore`: parse F1 .mzdash, verify 16 channels extracted, correct alphabetical order
- `TelemetryFrameBuilder`: build frame with known inputs, verify checksum and byte layout

### Integration tests

- Build a frame with F1 profile + test game data, compare hex output against a capture frame
- Verify frame structure: start byte, length, group, device, command ID, header, data, checksum

### User validation

- User loads F1 dashboard, enables telemetry, starts a game
- Dashboard should display recognizable values (gear number, speed, brake %)
- Diagnostic test pattern cycles values so user can confirm each channel
- If display shows garbage: user adjusts byte limit override, tries different channel counts
- User reports which combination works → we update defaults

---

## Key files reference

| File | Purpose |
|------|---------|
| `docs/pithouse-re.md § 8-9` | Bit packing algorithm + encode formulas |
| `docs/moza-protocol.md § Telemetry encode/decode` | Complete formula reference |
| `Protocol/MozaProtocol.cs` | Frame constants, checksum |
| `Protocol/MozaSerialConnection.cs` | Send() method, write queue |
| `MozaPlugin.cs:189` | DataUpdate hook (currently empty) |
| `Devices/MozaLedDeviceManager.cs` | Reference: periodic sending pattern |
| `UI/SettingsControl.xaml.cs` | Reference: settings UI pattern |
| `<pithouse>/bin/GameConfigs/Telemetry.json` | Channel URL → compression mapping |
| `usb-capture/m Formula 1/m Formula 1.mzdash` | Reference dashboard for testing |
