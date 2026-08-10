# Contributing to BinaryHunter

Thank you for helping improve BinaryHunter. Contributions should preserve reliable
ECU identification, a compact Windows desktop workflow and the privacy of firmware
owners.

## Development setup

Requirements:

- Windows 10 or Windows 11
- .NET 8 SDK
- Visual Studio 2022 or newer is optional

From the repository root:

```powershell
dotnet restore BinaryHunter.UI\BinaryHunter.UI.csproj
dotnet build BinaryHunter.UI\BinaryHunter.UI.csproj -c Release --no-restore
```

## Detector changes

- Detect from repeatable evidence inside the binary, not filenames or folder names.
- Prefer multiple structural signals over a single human-readable marker.
- Keep generic evidence lower confidence than a validated ECU-specific profile.
- Do not add one-off software-number catalogues as detector logic.
- Confirm offsets against more than one representative read whenever possible.
- Update the supported ECU catalogue when adding or removing a detector.

## Firmware privacy

Do not commit ECU dumps, customer data, VINs, proprietary DAMOS/A2L files or tool
reports. The repository ignores common firmware formats, but contributors remain
responsible for reviewing every staged file before committing.

For a detector request, open the detector request form with metadata only. A
maintainer can coordinate a private sample-transfer method if the sample is needed.

## Pull requests

1. Keep changes focused and explain the evidence or user-facing reason.
2. Build the Release configuration locally.
3. Confirm that no private binaries or generated output are staged.
4. Describe manual verification and known limitations.
5. Link the related issue when one exists.
