using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors;

// Each ECU group owns its own raw-structure rules and returns only evidence it
// can validate from the image. The orchestrator resolves cross-module conflicts.
public interface IEcuDetectionModule
{
    string Name { get; }
    string Manufacturer { get; }
    IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image);

    // A family module can expose reusable, lower-confidence structure readers
    // here. They run only after no strict detector confirms an ECU profile, so
    // useful IDs survive in Generic mode without claiming a brand or ECU family.
    IEnumerable<IdentifierMatch> ExtractGenericEvidence(EcuBinaryImage image) => [];
}
