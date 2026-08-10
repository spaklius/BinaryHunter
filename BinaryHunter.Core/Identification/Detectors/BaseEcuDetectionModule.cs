using System.Collections.Generic;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors;

public abstract class BaseEcuDetectionModule : IBaseDetector
{
    public abstract string Name { get; }
    public abstract string Manufacturer { get; }
    public abstract bool IsFullyImplemented { get; }

    public virtual IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image)
    {
        yield break;
    }

    public virtual IEnumerable<IdentifierMatch> ExtractGenericEvidence(EcuBinaryImage image)
    {
        yield break;
    }
}
