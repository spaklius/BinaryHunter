using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors;

public interface IBaseDetector : IEcuDetectionModule
{
    bool IsFullyImplemented { get; }
}
