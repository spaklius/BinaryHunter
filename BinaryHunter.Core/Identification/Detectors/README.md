# ECU detection modules

`EcuIdentifierService` owns file loading, caching, result normalization, and the
generic raw-string scan. ECU-family rules belong in a detector module.

## Flow

1. The service creates one `EcuBinaryImage` for the uploaded raw file.
2. `AutomaticDetectorRegistry` runs every registered module.
3. Every module returns only raw-file evidence it can validate.
4. If no strict profile succeeds, the registry asks every module for reusable
   `ExtractGenericEvidence` candidates.
5. The service removes conflicting or weaker results before the UI displays them.

## Adding a family

1. Create `Detectors/<manufacturer>/<family>Detector.cs`.
2. Implement `IEcuDetectionModule`.
3. Use `image.Bytes` for binary layouts and `image.AsciiText` for raw ASCII markers.
4. Register the module in `AutomaticDetectorRegistry`.
5. Implement `ExtractGenericEvidence` whenever part of the learned structure can
   safely expose an identifier without confirming the complete ECU profile.
6. Verify strict-profile and Generic-mode behavior against raw files and paired ID text, without using folder names or a
   catalogue of known part numbers as detection input.

## Two-layer rule policy

Every new profile or learned layout must be reviewed for two outputs:

1. Strict profile evidence: enough independent signals to confirm the ECU type,
   manufacturer and vehicle group.
2. Generic evidence: reusable record shapes, labels, paired identifiers, processor
   markers or checks that can extract possible values from an otherwise unknown
   file.

Generic evidence must never promote a component maker to vehicle brand or claim a
confirmed ECU family. The UI deliberately remains in Generic mode until `Detect`
succeeds for one registered family module.

The first migrated module is `Siemens/SiemensBmwDetector.cs`; it owns BMW
MSS70, MSV80, and MSD80 structure detection. Bosch active rules remain in the
service for now and can be migrated family-by-family without changing the UI or
the shared result pipeline.
