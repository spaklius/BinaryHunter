# BinaryHunter.UI - Agent Guide & Knowledge Base

## Quick Start Checklist
When starting work on this project, ALWAYS:
1. Read this file first
2. Check `TEST/readout.txt` for current test reference data
3. Build core project: `dotnet build BinaryHunter.Core/BinaryHunter.Core.csproj`
4. Review recent detector changes in git: `git log --oneline -10`
5. Check for uncommitted changes: `git status`

---

## Project Structure

```
BinaryHunter.UI/
├── AGENT_GUIDE.md                    ← THIS FILE - Read first!
├── README.md                         ← User-facing documentation
├── BinaryHunter.UI.slnx              ← Solution file
├── .gitignore                        ← Git ignore rules
├── BinaryHunter.Core/                ← Core detection engine
│   ├── BinaryHunter.Core.csproj
│   ├── Enums/                        ← Shared enumerations
│   ├── Identification/               ← Detection system
│   │   ├── Helpers/                  ← IdentifierHelpers, etc.
│   │   ├── Models/                   ← IdentifierMatch, EcuBinaryImage
│   │   └── Detectors/                ← ECU-specific detectors
│   │       ├── Bosch/                ← Bosch detectors
│   │       │   ├── BoschEdc17C42RenaultNissanOpelDetector.cs
│   │       │   └── [other Bosch detectors]
│   │       ├── Continental/          ← Continental/Siemens-VDO
│   │       │   └── ContinentalSiemensVdoSid310Detector.cs
│   │       └── [other manufacturers]
│   ├── Models/                       ← Core models
│   ├── Plugins/                      ← Plugin system
│   ├── Projects/                     ← Project management
│   ├── Properties/                   ← Assembly info
│   └── Services/                     ← Business logic
├── BinaryHunter.UI/                  ← WPF desktop application
│   ├── App.xaml / App.xaml.cs
│   ├── MainWindow.xaml / .cs
│   ├── Assets/                       ← Images, icons
│   ├── Models/                       ← UI models
│   ├── Properties/
│   ├── Services/
│   │   └── SupportedEcuCatalog.cs    ← Supported ECU registry
│   ├── *Window.xaml / .cs           ← Feature windows
│   └── *.cs                          ← Supporting classes
├── test/                             ← Permanent test files (gitignored)
└── TEST/                             ← Temporary test files (gitignored)
    ├── readout.dtf                   ← Current test binary
    ├── readout.txt                   ← Reference metadata
    └── [test projects]               ← Temporary test harnesses
```

---

## Core Concepts

### Detection Flow
```
Raw Binary → EcuBinaryImage → AutomaticDetectorRegistry → [Detector1, Detector2, ...] → IdentifierMatch[]
```

### Key Interfaces & Classes
- **IEcuDetectionModule**: Interface all detectors implement
  - `string Name { get; }` - Detector name for registry
  - `string Manufacturer { get; }` - Manufacturer string
  - `IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)` - Main detection logic
  
- **EcuBinaryImage**: Wrapper for binary data
  - `byte[] Bytes` - Raw binary data
  - `string AsciiText` - ASCII-decoded version (non-ASCII bytes become `?`)
  - `string DisplaySize` - Human-readable size

- **IdentifierMatch**: Detection result
  - `string Type` - e.g., "Software Nr.", "ECU type"
  - `string Value` - Detected value
  - `int Offset` - Byte offset in binary

---

## Critical Rules & Gotchas

### 1. ASCII Encoding in .NET
- **NEVER assume** binary data is pure ASCII
- `EcuBinaryImage.AsciiText` uses ASCII encoding - bytes > 127 become `?`
- **ALWAYS** use `\xNN` hex escapes in regex patterns for control bytes
- **Python equivalent**: Use `latin1` decode to match .NET behavior
  ```python
  text = data.decode('latin1')  # NOT 'ascii' or 'utf-8'
  ```

### 2. Regex Patterns in C#
- Use verbatim strings `@"pattern"` for regex with backslashes
- Non-ASCII bytes: `\x17`, `\x08`, `\x01`, NOT `\u0017` (different!)
- Named groups: `(?<upgrade>[0-9]{4}R)` - accessible via `match.Groups["upgrade"]`
- **NEVER** use `?<` inside character classes `[]` - causes "unknown extension" error

### 3. Detector Size Gates
ALWAYS check size FIRST:
```csharp
if (image.Bytes.Length == PartialImageSize) return DetectPartial(image);
if (image.Bytes.Length != FullImageSize) return [];
```

### 4. Pattern Matching Strategy
- **Multiple independent checks** = high confidence
- **Duplicate fields** (e.g., software number at two offsets) = strong signal
- **Fixed offsets** work across variants - prefer over flexible search
- **Platform paths** in binary are excellent anchors - search for repeated patterns

### 5. Partial vs Full Reads
- Partial reads start at specific addresses (e.g., 0x00180000)
- Software numbers often at same relative offset in both
- Hardware/upgrade records may use DIFFERENT encoding in partial reads
- ALWAYS implement `DetectPartial()` if you support partial reads

### 6. Device-Agnostic Identification
- Binary files can be read using a wide variety of devices/tools
- The relevant sections will still contain identical information
- **ALWAYS** design detectors to be device-agnostic:
  - Do not rely on a single tool's specific marker or offset
  - Provide fallback paths when primary markers are missing
  - Use structural evidence (mirrored records, identification blocks) as fallbacks
  - Prefer flexible patterns over hardcoded device-specific strings
- If a detector only matches files from one specific tool, it is too narrow

---

## Binary Analysis Workflow

### Step 1: Initial Reconnaissance
```bash
# File size
python -c "import os; data=open(r'TEST/readout.dtf','rb').read(); print(len(data), hex(len(data)))"

# Quick ASCII scan
python -c "data=open(r'TEST/readout.dtf','rb').read(); text=data.decode('latin1'); print('TC1767:', 'TC1767' in text); print('EDC17C42:', 'EDC17C42' in text); print('Software:', repr(text[0x18001A:0x18001A+15]))"
```

### Step 2: Find Key Markers
```python
import re
data = open(r'TEST/readout.dtf','rb').read()
text = data.decode('latin1')

# Search for patterns
patterns = ['EDC17C42', 'TC1767', 'ERCOSEK', 'TPROT', 'R[0-9]{4}R']
for pat in patterns:
    matches = list(re.finditer(pat, text))
    print(f"{pat}: {len(matches)} matches")
    if matches:
        print(f"  First: {matches[0].start():08X}: {repr(text[max(0,matches[0].start()-20):matches[0].start()+30])}")
```

### Step 3: Hex Dump Suspect Areas
```python
# Dump hex around offset
OFFSET = 0x18001A
data = open(r'TEST/readout.dtf','rb').read()
for i in range(0, 64, 16):
    print(f'{OFFSET+i:08X}:', ' '.join(f'{b:02X}' for b in data[OFFSET+i:OFFSET+i+16]))
```

### Step 4: Analyze Record Structure
```python
# Find all R-suffixed records
for m in re.finditer(r'[0-9]{4}R', text):
    start = m.start()
    print(f'{start:08X}: {repr(text[start:start+40])}')
```

### Step 5: Test Pattern in Python
```python
import re
pattern = r'(?<upgrade>[0-9]{4}R)\x91[0-9]{3}(?<hardware>[0-9]{4}R)\x17\x08'
match = re.search(pattern, text)
print(f"Match: {match is not None}")
if match:
    print(f"Upgrade: {match.group('upgrade')}")
    print(f"Hardware: {match.group('hardware')}")
```

---

## Detector Implementation Checklist

When creating a new detector:

- [ ] **Size constants**: Define `FullImageSize` and `PartialImageSize` (if applicable)
- [ ] **Size gate**: Check size FIRST in `Detect()`, route to `DetectPartial()` if needed
- [ ] **Platform pattern**: Find repeated platform path in binary (usually 2+ occurrences)
- [ ] **Runtime marker**: ERCOSEK for TriCore, or equivalent for other CPUs
- [ ] **Processor check**: Only if consistently present across variants
- [ ] **Software offset**: Fixed offset is GOLD - use it!
- [ ] **Software validation**: Use prefix pattern if followed by extra digits
- [ ] **Upgrade/Hardware pair**: Find the R-suffixed records with unique terminator
- [ ] **Return matches**: Build `IdentifierMatch` list with correct offsets
- [ ] **Register in AutomaticDetectorRegistry**: Add to `Modules` list in `AutomaticDetectorRegistry.cs` - detectors are NOT auto-discovered!
- [ ] **Register in SupportedEcuCatalog**: Add to `SupportedEcuCatalog.cs` for UI integration
- [ ] **README**: Add documentation
- [ ] **Test**: Verify against multiple variants
- [ ] **AGENT_GUIDE**: Update this file with new patterns/lessons learned

---

## Common Patterns Reference

### Universal Patterns
```csharp
// Platform path with underscore terminator (flexible)
PlatformPattern = new(@"\d{2,3}/1/EDC17_?C42/\d+/P?_?[A-Z0-9]+//[A-Za-z0-9_]+_", RegexOptions.IgnoreCase | RegexOptions.Compiled);

// ERCOSEK runtime for Infineon TriCore
RuntimePattern = new(@"ERCOSEK\s+V\d+(?:\.\d+){1,3}\s+TriCore_g", RegexOptions.IgnoreCase | RegexOptions.Compiled);

// TPROT marker
TprotPattern = new(@"TPROT_V\d+\.\d+\.\d+/1767", RegexOptions.IgnoreCase | RegexOptions.Compiled);

// Software number prefix (10SW###### or 10375#####)
SoftwarePrefixPattern = new(@"^(?:10SW\d{6}|10375\d{4,5})", RegexOptions.Compiled);

// Universal upgrade/hardware pair - matches any 2-byte terminator after 0x17
UpgradeHardwarePattern = new(@"(?<upgrade>[0-9]{4}R).{1}[0-9]{3}(?<hardware>[0-9]{4}R)\x17.{2}", RegexOptions.Compiled);
```

### Specific ECU Patterns

**EDC17C41 (BMW):**
- Full size: 0x400000 (4 MB)
- DDE layout: DDE701/721 marker, TC1766 processor, fixed software offset 0x1001A, upgrade offset 0x10122
- Platform-path/BCD layout: `32/1/EDC17_C41/...` banner, TC1797 processor, BCD records `00 00 08 <4 BCD bytes>` in ID block (0xFE00-0x10100), hardware `0281xxxxxx`
- Customer software numbers are BCD-encoded (e.g. `08574351`), NOT the `1037xxxxxx` calibration number

**EDC17C42:**
- Full size: 0x200000 (2 MB)
- Partial size: 0x80000 (512 KB)
- Software offset: 0x18001A (full), 0x1A (partial)
- Platform: `\d{2,3}/1/EDC17_?C42/...`

**EDC16CP31 (Mercedes) / EDC16C31 (BMW):**
- Full size: 0x200000 (2 MB)
- Mercedes uses `EDC16CP31` in platform marker but may use `EDC16C31` in platform path banner
- BMW uses `EDC16C31` in platform path banner
- Both share 1037xxxxxx software format — ALWAYS use platform path + marker for exclusivity

**EDC16CP42 (Nissan/Renault):**
- Full size: 0x200000 (2 MB)
- Partial size: 0x50000 (320 KB)
- Software offset: 0x10
- Hardware offset: 0x31991
- Upgrade offset: 0x31996
- Platform: `\d{2,3}/1/EDC16CP42/...`

**EDC16U31/U34 (VAG):**
- Partial size: 0x80000 (512 KB)
- Full size: 0x200000 (2 MB)
- Software record: mirrored `1037\d{6}[A-Z0-9]{6,10}` at 0x40000 distance (partial: 2+ repetitions, full: mirrored pair)
- Identification block: 10-11 char hardware, VAG part number `0[A-Z0-9]{8,10}`, 4-digit revision, `R4 d{,.]dL EDC` engine
- No platform marker in many real-world variants — identification block + mirrored software is primary evidence
- Hardware may be generic VAG number (e.g. `0281012469`, `0281012746`, `03G906021AB`), not always containing `9060`
- BMW detector must exclude U31/U34 identification block to prevent false EDC16C35 matches

**EDC16U1 (VAG):**
- Full size: 0x100000 (1 MB)
- Software record: repeated `1037\d{6}` with flexible version `[A-Z0-9]{6,10}` (not always `P\d{3}...`)
- Identification block: hardware `0281\d{6}`, OEM software `[A-Z0-9]{3}9060\d{2}[A-Z]{1,2}`, revision, engine `R[45] d{,.]dL EDC`
- Minimum 3 software repetitions for confirmed profile, 2 for generic evidence

**SIMOS PPD1.x (VAG):**
- Full size: 0x200000 (2 MB)
- Partial size: 0x40000 (256 KB)
- Dataset record: `CASN[A-Z0-9]{2,8}\.DAT`
- Module identifiers: `SN0F[A-Z0-9]{2,4}` (may vary across PPD variants, not required)
- Identification block: VAG part number `[A-Z0-9]{3}\d{6}[A-Z]{0,2}`, engine `R4 d{,.]dl?`, `PPD1.\d+`, 10-digit software number `\d{10}`, version `\d{2}\.\d{2}`
- No Bosch/EDC markers — identified purely by Siemens/Continental dataset records and OEM block

**SID310 Full:**
- Size: 0x300000 (3 MB)
- Hardware: 0x1C05
- Software: 0x1C31 (must match 0x1C3D)
- Code: `^[0-9A-Z]{5}$`

**SID310 Partial:**
- Size: 0xC0000 (768 KB)
- Software: 0x871F, prefix 5 chars
- Upgrade: 0x84CF, prefix 4 chars + "S"

---

## Testing Strategy

### Create Test Harness
```csharp
// TEST/Test.csproj
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <ProjectReference Include="..\BinaryHunter.Core\BinaryHunter.Core.csproj" />
  </ItemGroup>
</Project>
```

```csharp
// TEST/Test.cs
using BinaryHunter.Core.Identification;
using BinaryHunter.Core.Identification.Detectors;

var bytes = File.ReadAllBytes(@"TEST/readout.dtf");
var image = new EcuBinaryImage(bytes);
var detector = AutomaticDetectorRegistry.DetectModules
    .First(m => m.Name == "Detector Name Here");

var matches = detector.Detect(image).ToArray();
Console.WriteLine($"Matches: {matches.Length}");
foreach (var m in matches)
    Console.WriteLine($"  {m.Type}: {m.Value} @ 0x{m.Offset:X8}");
```

### Test Multiple Variants
- Test with 2-3 different readouts of same ECU type
- Test full and partial sizes if applicable
- Test edge cases: missing fields, extra digits, different terminators
- Only declare "universal" after testing multiple variants

---

## Build & Development Commands

```bash
# Build core library
dotnet build BinaryHunter.Core/BinaryHunter.Core.csproj

# Build UI
dotnet build BinaryHunter.UI/BinaryHunter.UI.csproj

# Run UI application
dotnet run --project BinaryHunter.UI/BinaryHunter.UI.csproj

# Run specific test
dotnet run --project TEST/TestProject.csproj

# Check git status
git status
git diff BinaryHunter.Core/Identification/Detectors/

# View recent changes
git log --oneline -10
git show HEAD:BinaryHunter.Core/.../Detector.cs
```

---

## Troubleshooting

### Detector Returns 0 Matches
1. Check file size matches expected
2. Verify patterns in Python first
3. Check if `image.AsciiText` has the expected content
4. Look for non-ASCII bytes breaking patterns
5. Try more flexible patterns (`.{1}` instead of specific byte)

### Python Regex Fails with "unknown extension ?<"
- **Cause**: Named group syntax inside character class `[]`
- **Fix**: Move named groups outside character classes
- **Wrong**: `[(?<name>abc)]`
- **Right**: `(?<name>[abc])`

### .NET Regex Fails but Python Works
- **Cause**: .NET `AsciiText` replaces non-ASCII with `?`, Python `latin1` preserves them
- **Fix**: Use explicit `\xNN` escapes for non-ASCII bytes
- **Check**: `Console.WriteLine(Encoding.ASCII.GetString(bytes, offset, length))`

### Build Succeeds but Detection Fails
- **Cause**: Patterns match Python `latin1` text but not .NET `AsciiText`
- **Fix**: Test with actual C# code, not just Python
- **Debug**: Add `Console.WriteLine(text.Substring(offset, length))` to see actual text

---

## File Management

### TEST/ Directory
- **Purpose**: Temporary test files and harnesses
- **Git**: Should be in `.gitignore`
- **Cleanup**: ALWAYS remove test harnesses after verification
- **Keep**: Reference readout files (readout.dtf, readout.txt)

### Reference Files
- Keep working reference files in `TEST/`
- Name descriptively: `TEST/[ECU]_[Model]_[Variant].dtf`
- Include `.txt` with human-readable metadata

### Git Workflow
```bash
# Before starting work
git status
git pull

# After making changes
git status  # Verify only expected files changed
git diff    # Review changes
git add -A
git commit -m "Description"

# If TEST/ files accidentally staged
git reset HEAD TEST/
git checkout -- TEST/  # Discard changes
```

---

## Common Pitfalls to Avoid

1. **Assuming ASCII**: Always decode as `latin1` in Python to match .NET
2. **Hardcoding terminators**: Use `.` wildcard for variable bytes
3. **Full-match when prefix needed**: Software numbers often have trailing data
4. **Forgetting partial reads**: Always check if partial support is needed
5. **Skipping multiple variants**: Test with 2+ files before declaring pattern "universal"
6. **Leaving test files**: Clean up `TEST/` after verification
7. **Not updating README**: Documentation must match implementation
8. **Forgetting catalog**: Update `SupportedEcuCatalog.cs` for UI integration
9. **Platform path fragment collisions**: EDC16C31 appears in both Mercedes EDC16CP31 and BMW EDC16C31 binaries — always add cross-manufacturer exclusions

---

## Important Reminders

1. **ALWAYS** read `TEST/readout.txt` before analyzing new test files
2. **ALWAYS** build after changes: `dotnet build BinaryHunter.Core/BinaryHunter.Core.csproj`
3. **ALWAYS** test with actual detector, not just diagnostic mimics
4. **ALWAYS** clean up TEST/ after verification
5. **NEVER** commit test harness files
6. **UPDATE THIS FILE** when you learn new patterns or fix recurring issues
7. **USE PYTHON** for binary analysis - much faster than C# test harnesses
8. **TEST MULTIPLE VARIANTS** before declaring pattern "universal"
9. **BINARY HEX IS THE SOURCE OF TRUTH** — if reference txt conflicts with actual binary content, trust the binary hex and correct the reference file
10. **Reference .txt ID numbers are trusted, but ECU type may be wrong** — software/hardware/upgrade numbers from the reference txt are reliable, but the stated ECU type should still be verified against the binary hex

---

## Recent Lessons Learned (Update This Section!)

### 2026-08-10: Volvo Siemens SID803A
- Observed full size: `0x200000` (2 MB), Motorola MPC555 platform.
- Observed partial size: `0x170000` (1,507,328 bytes); the SID/Siemens block is shifted while the Volvo dataset remains near `0x40000`.
- Strict evidence combines the raw `SID803` marker, a `5WS40...` Siemens hardware record at `0x6300`, an `ERCOSEK Vx.x.x MPC555` runtime, and the Volvo OEM dataset structure.
- The active 9-digit software value lives in the bounded identification block at `0x6290..0x62CF`, between two 12-character Siemens identifiers.
- Volvo calibration evidence is three identical `111VO` rows immediately followed by a `CAVOdddd.DAT` dataset. This validates the Volvo group without relying on the file path.
- Report the family as SID803A only after the complete Siemens/Volvo structure succeeds; the isolated raw marker itself may say `SID803`.
- Preserve the ERCOSEK version as `Runtime version`; generic `Version` values are removed once a strict family profile wins.
- Partial images expose the OEM hardware as packed BCD nine bytes after the `SID803` marker and the software-upgrade record as packed BCD plus a two-letter revision near `0x40230`.
- In partial images the Volvo dataset profile (for example `VO0560`) is the available software number. Diagnostic hardware/upgrade values must be decoded from raw BCD rather than copied from the paired TXT.

### 2026-08-10: Volvo Denso MB279700-96XX SH72546
- Observed partial size: `0x3C0000` (3.75 MB), representing the SH72546 calibration/code window.
- Strong identity requires the raw `R5F72546` processor marker, the VED boot marker, the `V526_AUT_AWD` Volvo project marker, and two Denso copyright blocks. Copyright years vary (observed 2017 and 2019), so match `DENSO CORPORATION`, not a fixed year.
- Volvo part numbers are stored as packed BCD rather than plain ASCII.
- Hardware is an 8-digit packed-BCD value mirrored at `0xD800` and `0xDA00`; both complete records must agree. The three padding bytes may be spaces (`20 20 20`) or zeroes (`00 00 00`).
- Software at `0x3FFE0` and upgrade at `0x3BFA80` use four packed-BCD bytes followed by a space and a two-letter revision; display them as `dddddddd_RR`.
- Packed-BCD generations do not all contain the XC60/XC90-specific `V526_AUT_AWD` string. Accept a repeated `H_VED_X{1,2}_X{1,2}_ddLddd` platform block as the model-independent Volvo project anchor (observed on V90 as `H_VED_XX_XX_16E200`).
- Earlier MB279700-96XX generations use a separate ASCII layout in the same `0x3C0000` read size: `V2AS8WENPBL_VED Ver...`, repeated `E_VED_X{1,2}_X{1,2}_ddLddd`, and a `Yddd_<1-4 letter variant>_MP` Volvo project marker (observed `A`, `AUT`, and `MAN`).
- In that ASCII layout, hardware is an identical 8-digit pair at `0xDA00`/`0xDC00`, upgrade is `ddddddddRR` at `0x3BFA80`, and software is `dddddddd RR` at `0x3BFAB0`.
- Do not treat the different 8-digit record at `0xD800` in the ASCII generation as active hardware; the mirrored `0xDA00`/`0xDC00` value is authoritative.
- OBD images may retain the `0x3C0000` size while the initial boot/hardware region is entirely `0xFF`. Confirm this format with two Denso blocks, repeated `E_VED_X{1,2}_X{1,2}_ddLddd`, `Yddd_<variant>_MP`, `BSW_VED`, and the fixed ASCII software/upgrade records.
- OBD images without the raw `R5F72546` marker may report SH72546 only as an MB279700-96XX platform inference. Do not invent a hardware number when the mirrored HW records are omitted.
- An isolated `Jddd` token in this layout is calibration/code noise, not a validated control-unit identifier.
- Denso result normalization must retain Volvo or Subaru groups for their respective profiles instead of assuming every Denso family is Mazda.

### 2026-04-08: EDC17C42 Universal Pattern
- Separator between upgrade/hardware varies: `\x91`, `\x01`, `?` (in ASCII decode)
- Terminator varies: `\x17\x08`, `\x17\x10c`, `\x17\x01\x60`
- Solution: Use universal pattern `.{1}[0-9]{3}` and `\x17.{2}`
- Software number at 0x18001A may be followed by extra digits (e.g., `10375451401194_`)
- Solution: Use prefix-only validation `^(?:10SW\d{6}|10375\d{4,5})`

### 2026-04-08: SID310 Partial Reads
- Partial 768 KB reads use length-prefixed records, not fixed layout
- Software at 0x871F: `237100827S` → code is last 5 chars `0827S`
- Upgrade at 0x84CF: `37612957HRML...` → code is 4 digits + "S"
- Upgrade codes are numeric only: `^[0-9]{4}$`

### 2026-08-09: SID310 Partial-Read Generations
- SID310 768 KB identification records are not fixed to one address: software records were observed at `0x86DF`, `0x871F`, and `0x8807`
- Require the repeated `CARFE9x0` / `RFZRFE429x000000` header, then search only `0x8000..0x8FFF` for `23710<5-char software>`
- Upgrade layout is `2<R|S>\x00{6}3761<4 digits>H...`; the R/S suffix is stored separately and must be preserved
- Example: `237108788R` gives software `8788R`, while the paired upgrade record gives `9126R`
- Renault Scenic/Talisman variants use the same records with a `CARFEAx0` / repeated `RFZRFE45Ax000000` header; examples: `1987S/2236S` and `7343R/8420R`
- Mercedes-Benz Citan W415 uses `CARFE7P0` / repeated `RFZRFE457P000000`; its records follow the same `23710...` and `2S...3761...H` layout (example `0451S/1773S`)

### 2026-08-09: SID310 J-Platform Partial Reads
- Mercedes-Benz X-Class and Nissan Navara 768 KB reads use the shared `CARFJxx0` / repeated `RFZRFJ42xx000000` header family
- Require both the repeated header and the `3701....2.3710....ECM\x00-EngineControl\x00` identification record
- Upgrade record is `23701<5-char upgrade>` in `0x8000..0x8FFF`; example `237015XF4B` → `5XF4B`
- The `5XF` upgrade prefix is the Mercedes-Benz X-Class branch; observed Nissan Navara branches use `5JK` / `5JM`
- Hardware, software and VIN values from tool metadata may be absent from the raw partial file and must not be synthesized
- Isolated `Jddd` strings in SID310 calibration data are false positives; remove them after a strict SID310 profile succeeds

### 2026-04-08: Mercedes EDC16CP31 vs BMW EDC16C35
- Mercedes EDC16CP31 shares 2 MB size and 1037xxxxxx software format with BMW EDC16C35
- Differentiator: platform path `99/1/EDC16CP31/` vs `99/1/EDC16C35/`
- Solution: Created `BoschMebEdc16Cp31Detector` and added exclusion in BMW detector
- **ALWAYS register new detectors in `AutomaticDetectorRegistry.cs`** - they won't be discovered automatically
- Detector order matters: Mercedes detector runs before BMW detector

### 2026-08-03: Mercedes EDC16CP31 Platform Path Variations
- Some Mercedes EDC16CP31 binaries use `EDC16C31` (without P) in the platform path banner, e.g. `99/1/EDC16C31/999/`
- The `BoschMebEdc16Cp31Detector` platform path pattern must match both `EDC16C31` and `EDC16CP31`
- The `BoschBmwEdc16C31Detector` (for BMW EDC16C31) needs an explicit Mercedes EDC16CP31 exclusion (`EDC16CP31[-.]?\d`)
- Without the exclusion, `BoschBmwEdc16C31Detector` matches Mercedes files via the `EDC16C31` banner and reports "BMW Group"
- Always verify detector exclusivity when two detectors share similar platform path fragments

### 2026-08-09: Honda vs BMW EDC16C31
- Honda and BMW may carry the identical `99/1/EDC16C31/999/X000/.../19810101/` platform path, so that banner cannot establish BMW ownership
- Honda full reads are 1 MiB and carry a `1037ddddddP...` calibration record at `0x10`, mirrored exactly in three flash regions
- Observed Honda calibration families include `P290`, `P432`, `P539`, `P594`, and `P777`; detection uses the mirrored-record structure rather than a software-number catalogue
- Register the Honda detector before BMW and explicitly exclude the Honda mirrored layout from `BoschBmwEdc16C31Detector`

### 2026-08-09: Honda EDC17CP06 vs BMW Heuristic
- Honda EDC17CP06 full reads are 2 MiB and carry two matching `EDC17_CP06/<variant>/P...//<calibration>///` platform records
- Require a Honda ECU reference shaped `37805-xxx-xxxx`; incidental DDE-like calibration bytes must not promote the file to BMW
- Active software is stored at `0x4001A`; the base software field is at `0x401A` and may differ
- Additional mirrored `1037...` values can occur at `0x1401A`; keep the active `0x4001A` value and expose only `0x401A` as base software
- Example: active software `1037532319`, base software `1037396114`, calibration `P519V14D`, Honda ECU part `37805-RL0-F320`
- When the strict Honda CP06 profile succeeds, remove conflicting BMW vehicle-group evidence and relabel the secondary Bosch number as base software

### 2026-08-03: Nissan/Renault EDC16CP42 Partial Reads
- Partial reads are 320 KB (0x50000) starting at 0x001B0000
- Platform path `99/1/EDC16CP42/...` identifies Nissan/Renault variants
- Software number at 0x10: `1037535099P705BF6a` → prefix `1037535099`, version `P705BF6`
- Hardware at 0x31991: `5X200`
- Upgrade at 0x31996: `6X62A`
- Created dedicated `BoschNissanEdc16Cp42Detector` to avoid generic structural analysis fallback
- Reference txt may be wrong — always verify ECU type from binary hex, not text metadata

### 2026-04-08: VAG EDC16CP34 Universal Pattern
- Existing detector was too Audi-specific (required 907401/910401 hardware patterns and V6TDI engine)
- VW Crafter has R5 2,5L EDC engine and 074906032AN upgrade pattern
- Solution: Made detector universal with platform marker + mirrored software record as primary evidence
- Added universal upgrade pattern `0\d{7,8}[A-Z]{2}` for VAG part numbers
- Added partial read support (512 KB starting at 0x00180000)
- Added BMW exclusion for EDC16CP34 platform marker
- Audi-specific identification block is now optional fallback, not required

### 2026-04-08: .NET ASCII vs Python latin1
- .NET `Encoding.ASCII.GetString()` replaces non-ASCII bytes with `?`
- Python `decode('latin1')` preserves all bytes
- When .NET shows `?`, actual byte could be anything 0x80-0xFF
- ALWAYS use hex dump (`data[offset:offset+length].hex()`) to see actual bytes

### 2026-08-03: PSA EDC17C60 Detector Relaxation
- Existing detector required packed BCD PSA identifier AND 3+ ASAM software records
- Real-world EDC17C60 binary had BCD identifier at 0x100 but only 1 ASAM software record
- Solution: Made BCD identifier optional fallback; reduced ASAM minimum count from 3 to 1
- Bosch/ASAM software and platform upgrade remain primary evidence
- Detector now matches variants with sparse ASAM records

### 2026-08-04: VAG EDC16U31/U34 Full Image Support
- Some EDC16U34 binaries are full 2 MB flashes without the `EDC16U34-3.1 MPC561` platform marker
- These files have the U31/U34 identification block (hardware, OEM software, revision, engine) and mirrored software records at 0x40000 distance
- Solution: Added full-image fallback path to `BoschVagEdc16U31U34Detector` using identification block + mirrored software as primary evidence
- Added BMW exclusion for U31/U34 identification block pattern to prevent false EDC16C35 matches
- U31/U34 detector now runs BEFORE BMW detector in registry to claim matching files first
- BMW detector exclusions must cover both platform-marker and identification-block variants
- **Lesson**: Always design detectors with device-agnostic fallbacks. Different tools produce different binary layouts; the ECU identity must be recoverable from structural evidence alone.

### 2026-08-04: VAG EDC16U1 Version Pattern Flexibility
- Original U1 detector required version to start with `P` (`P\d{3}[A-Z0-9]{4}`)
- Real-world EDC16U1 binary had version `379U85B6` (starts with digit, not P)
- Solution: Relaxed version pattern to `[A-Z0-9]{6,10}` to accept any alphanumeric version string
- Version formats vary across U1 variants — don't hardcode the `P` prefix

### 2026-08-04: BMW EDC17C41/C50 Structured Identifier Extraction
- Original detectors mislabeled all DDE-extracted identifiers as "Software Upgrade Nr."
- The 7-byte identifier structure is: 2 zero padding bytes + type byte + subtype/data + trailing byte
- EDC17C41 type bytes: 0x03 = Hardware Nr., 0x05 = Software Nr., 0x0B = Software Upgrade Nr.
- EDC17C50 type bytes: 0x0A+0x0A = Hardware Nr., 0x0A+0x0B = Software Nr., 0x69 = Software Upgrade Nr.
- Fixed extraction in both detector and `EcuIdentifierService.ExtractBoschDdeIdentifiers` to read 7 bytes from marker+1 and classify by type byte (index 2) and subtype (index 3)
- Removed hardcoded `0000` prefix; full 7-byte hex value is now preserved
- **Lesson**: When fixing detector extraction logic, also check `EcuIdentifierService.cs` for duplicate generic extraction paths that may produce stale/misclassified results

### 2026-08-04: Siemens VDO SIMOS PPD1.x Detector
- Created new detector `ContinentalVagSimosPpd15Detector` for Siemens/Continental SIMOS PPD1.x ECU family
- Identified by CASN dataset records (`CASN[A-Z0-9]{2,8}\.DAT`) and OEM block
- OEM block contains: VAG part number (`[A-Z0-9]{3}\d{6}[A-Z]{0,2}`), engine (`R4 d{,.]dl?`), ECU type (`PPD1.\d+`), 10-digit software number at fixed offset 0x10
- No Bosch/EDC markers — identified purely by Siemens/Continental dataset records and OEM block
- Module identifiers (`SN0F[A-Z0-9]{2,4}`) may vary across PPD variants and are not required
- Supports both full 2 MB and partial 256 KB reads
- File fell through to generic structural analysis because no Bosch/EDC detector could match it

### 2026-08-04: DDE701A EDC17C50 Duplicate Software Upgrade Nr. Fix
- Root cause: `ExtractBoschDdeIdentifiers` (DDE-specific) and `ExtractStructuralEcuEvidence` (via `FindMostLikelyOemReference`) both produced matches for the same value at the same offset, but with different types (Hardware/Software vs Software Upgrade)
- The generic fallback in multiple extraction methods defaults to `Software Upgrade Nr.` when the specific type byte doesn't match known patterns
- **Solution**: Added deduplication logic in `NormalizeAutomaticResults` (`EcuIdentifierService.cs`) that removes `Software Upgrade Nr.` entries when the same value at the same offset already has a more specific type (`Hardware Nr.` or `Software Nr.`) from another source
- This is a post-processing fix that avoids changing multiple extraction methods
- **Lesson**: When duplicate entries with different types appear for the same value/offset, prefer the specific type over the generic fallback in the normalization step

### 2026-08-04: Debugging Duplicate/Misclassified Entries
- Add debug output to `Identify` method to count detector vs structural matches
- Add debug output to individual extraction methods to trace which method produces which match
- Use Python to verify binary content at specific offsets (hex dump) to confirm actual bytes
- Check `DistinctBy` keys: it only removes exact `(Type, Value)` duplicates; different types at same offset are NOT removed
- `NormalizeAutomaticResults` is the right place for post-processing fixes rather than changing individual extraction methods

### 2026-08-04: BMW EDC17C41 Engine Code and Control Unit Extraction
- Engine code is embedded in secondary DDE marker as `#DST#<ENGINE>-<VARIANT>_<CONFIG>_<AT/MT>#...`
- Control unit `J108` is a standalone ASCII token, not tied to DDE structured identifiers
- Added `EngineCodePattern` (`#DST#(?<engine>[A-Z0-9]+)-`) and `ControlUnitPattern` (`(?<![A-Z0-9])J\d{3}(?![A-Z0-9])`)
- Detector output now matches diagnostic tool exactly: Read format, Vehicle group, ECU manufacturer, ECU type, BMW system type, Engine code, Control unit, Software Nr.

### 2026-08-04: EDC17C50 NullReferenceException on Missing DDE Identifiers
- `ExtractDdeIdentifiers` returns empty sequence when file lacks Hardware/Software DDE records
- `FirstOrDefault` returns `null`, then `hardware!.Type` throws NullReferenceException at runtime
- **Fix**: Replace `hardware!.Type is null` checks with proper `hardware is null` null checks
- Always guard `FirstOrDefault` results before accessing properties

### 2026-08-04: PSA EDC17C60 ASAM-Only Software Relaxation
- Some EDC17C60 files contain only ASAM software (`10SW...`), no Bosch software (`1037...`)
- Detector required both Bosch AND ASAM software → files fell through to generic structural analysis
- **Fix**: Changed condition from `boschSoftware is null || asamSoftware is null` to `boschSoftware is null && asamSoftware is null`
- When Bosch software absent, `Software Nr.` falls back to ASAM value

### 2026-08-04: Delphi DCM7.1A Normalization Against Generic False Positives
- 6 MB DCM7.1A file contains random ASCII fragments in binary blobs: `BMW`, `Bosch`, `577777...`, hex-looking hardware bytes
- Generic structural analysis produces false matches: BMW Group, Bosch (medium confidence), VIN, Hardware Nr.
- **Fix**: Added `Delphi DCM7.1A` normalization block in `NormalizeAutomaticResults` that:
  - Keeps only Delphi manufacturers
  - Keeps only PSA / Stellantis vehicle groups
  - Removes all-digit VINs
  - Removes hex-looking hardware numbers
- Pattern: same approach as existing `Delphi DCM6.2V` normalization block

### 2026-08-04: C# Variable Scoping in Nested If Blocks
- Variables declared in an `if` block are accessible in the enclosing method scope
- Cannot redeclare same variable name in sibling/else block: `CS0136: A local or parameter named 'X' cannot be declared in this scope`
- **Fix**: Use distinct names like `engineCodeFallback`, `controlUnitFallback` in fallback paths

### 2026-08-04: PSA Delphi DCM6.2A Detector
- PSA DCM6.2A files are 4 MB full flashes that fell through to generic structural analysis
- No readable hardware/software numbers; identification comes from PSA project markers (`1MPSA...`) and `FOS_<variant>_<software>_<upgrade>_` block
- Upgrade pattern relaxed to `FOS_(?:[A-Z0-9]+_)*?(?<upgrade>\d{10})` to handle variable path segment counts
- Created `DelphiPsaDcm62ADetector` and registered it in `AutomaticDetectorRegistry`
- Output: Read format, Vehicle group, ECU manufacturer, ECU family, ECU type, Software Upgrade Nr.

### 2026-08-04: DCM6.2A Normalization Against Generic False Positives
- 4 MB DCM6.2A file contains random ASCII fragments that produce false `Bosch (medium confidence)` from generic structural analysis
- Added `Delphi DCM6.2A` normalization block in `NormalizeAutomaticResults`:
  - Keeps only Delphi manufacturers
  - Keeps only PSA / Stellantis vehicle groups
  - Removes all-digit VINs
  - Removes hex-looking hardware numbers
- Pattern: same approach as existing `Delphi DCM6.2V` and `Delphi DCM7.1A` normalization blocks

### 2026-08-04: PSA Delphi DCM3.5 Partial Read
- DCM3.5 partial reads are 3,080,192 bytes (0x2F0000) starting at offset 0x00010000
- Identified by stable delivery/protocol marker: `<code>_DELIV_<version>` (e.g., `T6C1HA00_DELIV_3`)
- Hardware/software numbers are NOT present as readable ASCII in this partial layout
- Detector confirms from `_DELIV_` marker and emits Calibration version
- Existing `DelphiPsaDcm35Detector` handles this format correctly

### 2026-08-04: DCM6.2A Normalization Against Generic False Positives
- 4 MB DCM6.2A file contains random ASCII fragments that produce false `Bosch (medium confidence)` from generic structural analysis
- Added `Delphi DCM6.2A` normalization block in `NormalizeAutomaticResults`:
  - Keeps only Delphi manufacturers
  - Keeps only PSA / Stellantis vehicle groups
  - Removes all-digit VINs
  - Removes hex-looking hardware numbers
- Pattern: same approach as existing `Delphi DCM6.2V` and `Delphi DCM7.1A` normalization blocks

### 2026-08-08: BMW EDC17C50/C56 Detector
- DDE701a marker (not DDE701/721 like C41)
- Type bytes: 0x06 = Hardware Nr., 0x08+0x0B = Software Nr., 0x08+0x11 = Software Upgrade Nr.
- ECU type: DDE context (`DDE701a#C3#HWE##EDC17C50-3.51`) is the hardware identification record and takes priority over platform path (`32/1/EDC17_C56/...`)
- Platform path may be generic/reused across variants - DDE context is more reliable
- OEM hardware ID pattern: `O_7DUW-00000A11-006` (with hyphens)
- Created dedicated `BoschBmwEdc17C50Detector` to handle this variant

### 2026-08-08: Bosch MD1CP001 MEB Detector
- Full 8 MB image with platform path `46/1/MD1CP001/1/DA_MDG1`
- Software Nr. is plain ASCII 10-digit decimal (`6549022500`) located before platform path
- Hardware Nr. is at fixed offset `0x7D86D5` (`6569040000`)
- Software Upgrade Nr. pattern `654903\d{4}` excludes software number at platform path
- Generic structural analysis produces false positives: `SSM00000000 0000`, `10SW021370`, `000002134A0101`
- **Fix**: Added `Bosch MD1CP001` normalization block in `EcuIdentifierService.cs` that keeps only Bosch manufacturer, Mercedes-Benz vehicle group, and 10-digit `65xxxxxxxx` hardware/upgrade patterns

### 2026-08-08: SIMOS PPD Full/Partial Software Number Offset
- Partial reads (0x40000): CASN marker at offset 0x50, software number at offset 0x10
- Full reads (0x200000): CASN marker at offset 0x00040050, software number at offset 0x00040010
- **Key insight**: software number is always 0x40 bytes BEFORE the CASN dataset marker
- Solution: `var softwareOffset = dataset.Index - 0x40;` — works for both layouts
- Old code used fixed `softwareOffset = 0x10`, which broke full images where CASN is deeper in flash
- Upgrade/revision pattern extended to capture optional 4-digit revision suffix: `(?<revision>\d{4})`
- Engine output now includes ECU type suffix: `R4 2.0l PPD1.2`

### 2026-08-08: BMW EDC17C50/C56 Full Pipeline ECU Type Conflict
- Detector correctly extracted `EDC17C50` from DDE context `#HWE##EDC17C50-3.51`, but full pipeline normalized it to `EDC17C56` because `FindMostLikelyEcuMarker` preferred the generic platform path `32/1/EDC17_C56/...`
- Root cause: `GetExactEdc17Score` awarded +75 to platform path for 3 repetitions, while DDE context only got +25 for 1 occurrence; the `#HWE` bonus (+50) was never triggered because it only checked `trailing` (text after marker), but `#HWE` appears *before* `EDC17C50`
- **Fix in `EcuIdentifierService.cs`**: increased `#HWE`/`DME_` bonus from +50 → +200, and changed check to scan both `trailing` and `context` (24 bytes before marker)
- **Lesson**: When a detector and structural analysis disagree on ECU type, check `GetExactEdc17Score` — platform-path occurrence count can outweigh more specific DDE context unless the context bonus is large enough

### 2026-08-08: BMW EDC17C50/C56 Detector Type Byte and Marker Fixes
- DDE701a marker uses lowercase `a` suffix — the uppercase-only check `>= 'A' && <= 'Z'` rejected it; added lowercase range check
- C50 structured identifiers store the type byte at `code[3]`, not `code[2]`:
  - `0x0A` = Hardware Nr.
  - `0x0B` = Software Nr.
  - `0x11` = Software Upgrade Nr.
- DDE context regex changed from `#C3#HWE##EDC17C\d+` to `#C3?#HWE##EDC17C\d+` because some binaries omit the `#C3#` prefix
- ECU type search expanded from 4 KB after first DDE marker to full binary scan, because DDE context can be ~64 KB away from the first marker

### 2026-08-08: BMW EDC17C41 Platform-Path / BCD Layout
- Some BMW EDC17C41 files have NO DDE marker and use a platform path banner `32/1/EDC17_C41/...` (with underscore) instead
- Processor is TC1797 (not TC1766) — the `ME(D)/EDC17 SB_V10.00.00/1797` marker identifies it
- Customer-facing software/upgrade/spare numbers are stored as repeated BCD records: `00 00 08 <4 BCD bytes>` where the 0x08 byte is the first BCD digit pair (e.g. `00 00 08 57 43 51` = `08574351`)
- BCD records are terminated by `00 00` — require this to avoid false positives from random binary data
- BCD records live in the identification block region (0xFE00-0x10100) — restrict scanning to this range
- Software record repeats 3+ times; upgrade and spare appear once each after it
- Hardware number is a Bosch part number (`0281xxxxxx`) at 0x13F33
- The Bosch `1037xxxxxx` software number at offset 0x1A is the calibration number, NOT the customer software number
- Reference txt said EDC17C50 but binary platform path says EDC17C41 — trust the binary hex (AGENT_GUIDE rule #10)
- **OEM hardware identification code**: BMW files also carry a `O_<code>` hardware ID string (e.g. `O_7CWCUE223A` or `O_7DPA-00000500-052`) — matched by pattern `O_[A-Z0-9-]{8,20}` and reported as "Hardware identification"
- **Lesson**: BMW EDC17C41/C50 detectors must support both DDE-tagged and platform-path/BCD layouts
- **Tuned file lesson**: Files with names like "galia_pakelti_ir_atjungti_DPF" are modified/tuned BMW files. They may have DDE markers with underscore suffixes (e.g. `DDE721b___`) which are still valid structured identifier records. The 7-byte structured identifiers at offset 0x300025 may contain valid software numbers (e.g. `00000500100A34`) that are NOT false positives.
- **DDE721b subtype classification**: For DDE721b variants, the 7-byte structured identifier uses `code[2] = 0x05` with subtype `code[3]`:
  - `0x05 + 0x03` → "Software Nr." (e.g. `0000050301100A`)
  - `0x05 + 0x00` → "Software Upgrade Nr." (e.g. `00000500100A34`)
  - The generic fallback `0x05 + ?` → "Software Nr." is wrong for this variant

---

## Quick Reference Card

### File Locations
| What | Where |
|------|-------|
| EDC17C41 detector | `BinaryHunter.Core/Identification/Detectors/Bosch/BoschBmwEdc17C41Detector.cs` |
| EDC17C42 detector | `BinaryHunter.Core/Identification/Detectors/Bosch/BoschEdc17C42RenaultNissanOpelDetector.cs` |
| SID310 detector | `BinaryHunter.Core/Identification/Detectors/Continental/ContinentalSiemensVdoSid310Detector.cs` |
| EDC16CP31 (Mercedes) | `BinaryHunter.Core/Identification/Detectors/Bosch/BoschMebEdc16Cp31Detector.cs` |
| EDC16CP42 (Nissan/Renault) | `BinaryHunter.Core/Identification/Detectors/Bosch/BoschNissanEdc16Cp42Detector.cs` |
| EDC16CP34 (VAG) | `BinaryHunter.Core/Identification/Detectors/Bosch/BoschVagEdc16Cp34Detector.cs` |
| EDC16U31/U34 (VAG) | `BinaryHunter.Core/Identification/Detectors/Bosch/BoschVagEdc16U31U34Detector.cs` |
| EDC16U1 (VAG) | `BinaryHunter.Core/Identification/Detectors/Bosch/BoschVagEdc16U1Detector.cs` |
| EDC17C60 (PSA) | `BinaryHunter.Core/Identification/Detectors/Bosch/BoschPsaEdc17C60Detector.cs` |
| EDC16CP36 (Mercedes) | `BinaryHunter.Core/Identification/Detectors/Bosch/BoschMebEdc16Cp36Detector.cs` |
| SIMOS PPD1.x (VAG) | `BinaryHunter.Core/Identification/Detectors/Continental/ContinentalVagSimosPpd15Detector.cs` |
| Denso Subaru SH705x | `BinaryHunter.Core/Identification/Detectors/Denso/DensoSubaruSh705xDetector.cs` |
| Delphi PSA DCM6.2A | `BinaryHunter.Core/Identification/Detectors/Delphi/DelphiPsaDcm62ADetector.cs` |
| Delphi PSA DCM3.5 | `BinaryHunter.Core/Identification/Detectors/Delphi/DelphiPsaDcm35Detector.cs` |
| Detector registry | `BinaryHunter.Core/Identification/Detectors/AutomaticDetectorRegistry.cs` |
| Supported ECUs | `BinaryHunter.UI/Services/SupportedEcuCatalog.cs` |
| Test files | `TEST/` (temporary) |
| This guide | `AGENT_GUIDE.md` |

### Common Sizes
| ECU | Full | Partial |
|-----|------|---------|
| EDC17C41 | 4 MB (0x400000) | - |
| EDC17C42 | 2 MB (0x200000) | 512 KB (0x80000) |
| SID310 | 3 MB (0x300000) | 768 KB (0xC0000) |
| EDC16CP31 | 2 MB (0x200000) | - |
| EDC16CP34 | 2 MB (0x200000) | 512 KB (0x80000) |
| EDC16U31/U34 | 2 MB (0x200000) / 512 KB (0x80000) | 512 KB (0x80000) |
| EDC16U1 | 1 MB (0x100000) | - |
| EDC16CP36 | 2 MB (0x200000) | - |
| EDC16CP42 | 2 MB (0x200000) | 320 KB (0x50000) |
| SIMOS PPD1.x | 2 MB (0x200000) | 256 KB (0x40000) |
| Denso Subaru SH705x | - | 1008 KB (0xFC000) |
| Delphi PSA DCM6.2A | 4 MB (0x400000) | - |
| Delphi PSA DCM3.5 | - | 3080 KB (0x2F0000) |

### Build Times
- Core build: ~1-2 seconds
- UI build: ~3-5 seconds
- Test harness build: ~2-3 seconds

---

## Emergency Procedures

### If Everything is Broken
1. `git status` - see what changed
2. `git diff` - review changes
3. `git checkout -- .` - discard all changes, start fresh
4. `dotnet build` - verify clean state

### If Test Files Are Corrupted
```bash
# Discard TEST/ changes
git checkout -- TEST/
```

### If Build Fails with Mysterious Errors
1. Clean build: `dotnet clean`
2. Restore: `dotnet restore`
3. Rebuild: `dotnet build`
4. Check for typos in regex strings (common!)

---

## Contact & Context

- **Project**: BinaryHunter.UI - ECU Binary Identifier
- **Language**: C# / .NET 8.0
- **UI**: WPF
- **Last Updated**: 2026-08-08
- **Current Status**: EDC17C41 (DDE + platform-path/BCD layouts), EDC17C50, EDC17C60, EDC16U31/U34, SIMOS PPD1.x, Denso Subaru SH705x, Delphi DCM6.2A, Delphi DCM3.5, and Delphi DCM7.1A detectors implemented and tested

---

**REMEMBER**: This file is YOUR knowledge base. Update it whenever you learn something new or fix a bug. Future agents will thank you!
# Continental VAG SIMOS18.10 detector

- Full flash sizes observed: `0x480000` (4.5 MB) and `0x600000` (6 MB).
- Strong raw identity is the complete CASCGA OEM record, not an individual VAG part number:
  - mirrored `CASCGAxx` header and `CASCGAxx.DAT` dataset;
  - three identical `111SCG...` calibration rows;
  - internal software token directly before the dataset;
  - VAG software-upgrade number repeated after `EV_ECM20TFS020`;
  - engine text, four-digit revision, `J623`, and ECU profile `SC110` in the same bounded block.
- Known layout variants include `CASCGA10`/`SCG00A1000000`, `CASCGAB0`/`SCG00AB000000`, and Porsche `CASC8L70`/`SC800L7000000`; do not key ECU detection to one OEM part number.
- A validated `95B...` software identifier in this OEM block identifies the Porsche Macan platform; expose Porsche as vehicle manufacturer while retaining Volkswagen Group as the group.
- SIMOS18.10 platform inference: Continental ECU with Infineon TC1791.
- Present `SIMOS18.10` as the ECU identity; omit separate ECU-family and
  ECU-manufacturer rows because they repeat information already encoded by the type.
- Reject generic `Jddd` tokens outside the validated OEM block. For a confirmed SIMOS18.10 result, `J623` is the control unit; strings such as `J045` elsewhere are calibration noise.
- Generic Bosch medium-confidence evidence must not override the validated Continental SIMOS18.10 structure.
# Bosch Renault/Nissan/Opel EDC16CP33/C36/C41 detector

- Observed formats: full flash `0x200000` (2 MB) and calibration partial `0x40000` (256 KB, commonly based at `0x001C0000`).
- Strong platform evidence combines the raw `dd/1/EDC16CP33|C36|C41/...` path with the matching `BOSCH EDC16+/EDC16... MPC561/Rev...` firmware banner. The ECU types in both records must match.
- The platform is shared by Renault/Nissan and Opel/Vauxhall applications; report `Renault / Nissan / Opel` unless a separate raw vehicle marker proves a narrower manufacturer.
- The active Bosch software number is the `1037xxxxxx` value repeated in the code regions. A different single `1037xxxxxx` value near the calibration/OEM block is the base software and must not be emitted as a second active `Software Nr.`.
- The `82xxxxxxxx` identifier immediately before the platform path is the OEM software-upgrade number.
- Optional raw fields near the path include the `M9R...` engine code and calibration variant such as `94c_XXX`.
- A 256 KB partial lacks the MPC561 firmware banner. Require its leading `1037xxxxxxPddd...` calibration header, the complete platform path, and equality between header family `Pddd` and path family `Cddd`. Once these raw relationships confirm the ECU, MPC561 may be reported explicitly as a platform inference.
- Prefer the platform calibration value ending in `_XXX`; suppress the shorter generic `PdddW...` header interpretation to avoid two calibration-version rows.
- Nissan full-flash variants commonly use `C576` and a calibration header shaped as `1037xxxxxx576...` (without the Renault-style `P`). Select the header nearest the platform path as active software and retain a different repeated code-region value as base software.
- Nissan software-upgrade identifiers are five-character records such as `JG13B!037`. Multiple tagged identifiers may coexist; prefer the identifier repeated elsewhere in the image, not an isolated compatibility/library identifier.
- Nissan paths can include additional segments (for example `C576/BEGJ/EDS-.../JD2c7_XXX`), so calibration extraction must allow bounded intermediate path fields.
- Do not classify this layout as BMW merely because it shares the 2 MB EDC16/Bosch software-header shape.
# Bosch Mercedes-Benz EDC17CP46 detector

- Observed formats: full flash `0x400000` (4 MB), OBD/calibration partial `0x11E000` (1,171,456 bytes), and compact calibration partial `0xC0000` (786,432 bytes). Partials are commonly based at `0x00200000` or `0x00220000`; TC1797 platform.
- Require at least two identical `dd/1/EDC17CP46/1/P...//P_...///` platform paths plus the structured Mercedes OEM block in the same image.
- The `0x11E000` partial retains one platform path but two identical OEM blocks; require both OEM blocks and exact equality between them. Full images continue to require two matching platform paths.
- The `0xC0000` partial retains one complete platform path and one complete four-field OEM block; require both structures. Do not require duplicated OEM blocks for this compact layout.
- The OEM block carries four zero-delimited ten-digit fields. Its `ddd902dddd` value is the authoritative software number and `ddd903dddd` is the software-upgrade number.
- The first OEM field is the spare-part number. Emit the second as hardware only when it is not the all-zero placeholder.
- Internal repeated `1037xxxxxx` records belong to Bosch code/calibration segments and must not be emitted as additional active software numbers when the OEM block is confirmed.
- Template strings such as `HVAC0000000 0000` occur in unrelated module tables; remove them from CP46 software-upgrade results.
- Optional system description begins with a CP46 `CRdd-` identifier (observed `CR60-` and `CR42-`) near the OEM block. The platform path also exposes the ECU profile and calibration version.
- Confirmed CP46 images can expose internal Bosch `10SWdddddd` segment IDs. Do not present these as ASAM software when the authoritative Mercedes OEM software block is available.
- Prefer the complete platform calibration beginning with `P_`; suppress shorter generic interpretations of internal Bosch header suffixes.
# Bosch Mercedes-Benz EDC17CP10 detector

- Observed full-flash size: `0x200000` (2 MB), TC1796 platform.
- Require two identical `dd/1/EDC17CP10/1/P...//P_...///` paths, at least two matching `1037xxxxxxPddd...` Bosch software headers whose family matches the platform, and two identical Mercedes OEM records.
- The Bosch header version must also match the platform calibration token (for example platform `P_695_6JN0_...` selects a `P6956JN0` header). Family-only matching can choose an unrelated P695 software branch.
- The three-field OEM record contains spare-part, `ddd902dddd` OEM-software, and `ddd903dddd` software-upgrade numbers. Keep OEM software distinct from the primary Bosch `1037xxxxxx` software identifier.
- The system description begins with a `CR...-` identifier near the OEM record.
- A confirmed Mercedes CP10 result must replace generic Volkswagen-group classification and relabel the selected `1037xxxxxx` value from calibration to software.
