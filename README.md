# BinaryHunter

BinaryHunter is a Windows desktop application for searching large binary-file libraries and identifying automotive ECU readouts from their raw content.

Current status: Preview

Runtime: .NET 8 for Windows

## Highlights

- Search large binary libraries using ASCII, hexadecimal, or automatic input detection.
- Identify ECU readouts directly in the main window by browsing or dragging and dropping a file.
- Inspect detected ECU type, manufacturer, vehicle group, read format, processor and embedded identifiers with their raw offsets.
- Copy identification results, including column headers, from the result grid.
- View live file format, detected vehicle group and active ECU profile information while a file is being analyzed.
- Browse supported ECU profiles by vehicle group and see whether full or partial reads are supported.

## ECU identification

- Runtime identification uses only the uploaded binary. Sidecar TXT/ID files and folder or file names are not used as evidence.
- Results are produced from validated raw markers, repeated identification blocks, fixed-format OEM records and ECU-specific structural layouts.
- ECU identification always analyzes the selected file directly; it does not reuse cached identification results.
- Full and partial read formats report the real uploaded file size and, where known, the partial image base address.
- Conflicting generic text matches are filtered when a stronger multi-signal ECU profile is available.
- Duplicate ECU family/type rows are collapsed when they represent the same information.
- Files without a validated ECU-family profile fall back to Generic structural analysis. Possible embedded identifiers remain visible, while the live brand card stays Generic instead of presenting an ECU component maker as the vehicle brand.

## Supported automatic profiles

Generic structural analysis is available for unknown binary images of any size. It reuses the common raw-marker, identifier-record, calibration-header, VIN, processor and part-number readers without claiming a confirmed ECU or vehicle profile.

Each new ECU profile is maintained in two layers: strict multi-signal profile detection and reusable Generic evidence extraction. This lets newly learned record layouts improve unknown-file analysis without turning partial evidence into a false brand or ECU claim.

### Audi / Volkswagen / Škoda / SEAT

- Bosch EDC16U1 1 MB full flash
- Bosch EDC16U31 / EDC16U34 512 KB partial calibration
- Bosch EDC17C46, EDC17C54, EDC17C64, EDC17C74, EDC17CP20 and EDC17CP44
- Bosch MED17.1 / MED17.1.1 and MED9.1.1
- Delphi DCM6.2V 4 MB full flash
- Continental SIMOS6.2, SIMOS8.1, SIMOS8.2, SIMOS8.3 and SIMOS8.5

### BMW / MINI

- Bosch EDC15M
- Bosch EDC16C31 / EDC16C35
- Bosch EDC17CP02 / EDC17C06
- Bosch MD1 / MG1
- Bosch MEVD17.2 / MEV946
- Siemens/Continental MSV70 / MSS70 and MSV80 / MSD80

### Ford

- Bosch EDC17C70
- Continental SID208 and SID211

### Mazda

- Denso PCM SH725x partial flash and 2 MB OBD maps layouts
- Denso RF7/RF8-series PCM SH7058 1 MB full flash
- Denso R2AA PCM SH7058 1 MB full flash

### Volvo

- Denso Volvo MB279700-96XX SH72546 3.75 MB partial flash
- Siemens/Continental Volvo SID803A 2 MB full flash

### Renault / Nissan / Dacia / Opel

- Bosch EDC17C42 2 MB full flash
- Continental-Siemens-VDO SID310 768 KB partial or 3 MB full flash

### Opel / Vauxhall / General Motors

- Bosch EDC15M and EDC15M1
- Bosch EDC16C9 and EDC16C39, including supported full and partial layouts
- Bosch MD1CS003 on PSA/Stellantis platforms, including C48B and C70 structural variants
- Delco / Continental E98 and E98 GEN2 partial flash layouts

## Delco E98 support

- Detects the 3.875 MB partial image of a 4 MB flash with base address `0x00020000`.
- Separates E98 from E98 GEN2 using the location of the second identification block.
- Supports both observed GEN2 block revisions (`0x4E` and `0x4F`).
- Extracts Software ID, Software Upgrade ID and `Gxxxxx` software version directly from raw data.
- Rejects unrelated Bosch, BMW and generic ECU-like strings when the full E98 structure is confirmed.

## Search and interface

- Parallel library scanning and cached search data improve performance on large collections.
- The status area shows scanned file count and a green progress bar.
- Enter starts a search from the search field.
- Cancellation is handled without presenting `OperationCanceledException` as an application failure.
- Navigation, file selection and supported-profile controls use the updated dark, rounded visual style.
- Identification remains in the same window instead of opening a separate result window.

## Important limitations

- A value is shown only when it is embedded in the binary or supported by a validated structural inference.
- Hardware number, VIN or other diagnostic values are intentionally omitted when they exist only in an external tool report.
- Partial reads may not contain every identifier available through ECU diagnostics.
- Modified, damaged or unusually packaged files can remove or relocate identification structures.
- ECU and processor profile inferences should be verified before critical programming or recovery work.

## Build

From the repository root:

```powershell
dotnet restore BinaryHunter.UI\BinaryHunter.UI.csproj
dotnet build BinaryHunter.UI\BinaryHunter.UI.csproj -c Release --no-restore
```

The Windows Release build is generated under:

```text
BinaryHunter.UI/bin/Release/net8.0-windows/
```

Run `BinaryHunter.UI.exe` from that directory.

## Development structure

- `BinaryHunter.Core` contains binary search, caching and ECU identification logic.
- `BinaryHunter.Core/Identification/Detectors` contains separate manufacturer and ECU-family structural detectors.
- Detector modules can contribute lower-confidence `ExtractGenericEvidence` readers that run only when no strict profile matches.
- `BinaryHunter.UI` contains the WPF desktop interface.

New ECU examples should be used to learn repeatable raw structures, not to create a catalogue of known software or hardware numbers.

## Repository hygiene

Build output, IDE state, publish output, local tooling, ECU firmware samples and
BinaryHunter project data are intentionally excluded by `.gitignore`. Keep private
test firmware under `TEST/`; that directory is local-only and must not be committed.
