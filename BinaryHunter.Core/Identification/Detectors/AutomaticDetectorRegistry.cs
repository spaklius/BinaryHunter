using BinaryHunter.Core.Identification.Detectors.Bosch;
using BinaryHunter.Core.Identification.Detectors.Continental;
using BinaryHunter.Core.Identification.Detectors.Delco;
using BinaryHunter.Core.Identification.Detectors.Delphi;
using BinaryHunter.Core.Identification.Detectors.Denso;
using BinaryHunter.Core.Identification.Detectors.Siemens;
using BinaryHunter.Core.Models;

namespace BinaryHunter.Core.Identification.Detectors;

// Register new manufacturer/family modules here. The main identification service
// deliberately has no ECU-family-specific branching.
public static class AutomaticDetectorRegistry
{
    private static readonly List<IEcuDetectionModule> Modules =
    [
        new BoschEdc15MDetector(),
        new BoschBmwEdc15C4Detector(),
        new BoschOpelEdc15MDetector(),
        new BoschOpelEdc15M1Detector(),
        new BoschOpelEdc16C9Detector(),
        new BoschOpelEdc16C9MpcDetector(),
        new BoschOpelEdc16C39Detector(),
        new BoschOpelEdc16C39FullDetector(),
        new BoschPsaEdc16C34Detector(),
        new BoschPsaEdc17C60Detector(),
        new BoschPsaMd1Cs003Detector(),
        new DelcoGmE98Detector(),
        new DelcoOpelE87Detector(),
        new DelphiVagDcm62vDetector(),
        new DelphiPsaDcm35Detector(),
        new DelphiPsaDcm62ADetector(),
        new DelphiPsaDcm71ADetector(),
        new DensoMazdaSh725xDetector(),
        new DensoMazdaRf7Sh7058Detector(),
        new DensoMazdaR2aaSh7058Detector(),
        new DensoSubaruSh705xDetector(),
        new DensoVolvoMb27970096xxDetector(),
        new BoschFordEdc17C70Detector(),
        new BoschMedc179JaguarLandRoverDetector(),
        new BoschEdc17Cp55JaguarLandRoverDetector(),
        new BoschEdc17Cp11JaguarLandRoverPsaDetector(),
        new BoschEdc17C66MebDetector(),
        new BoschMercedesEdc17Cp10Detector(),
        new BoschMercedesEdc17Cp46Detector(),
        new BoschHondaEdc16C31Detector(),
        new BoschVolvoEdc16C31Detector(),
        new BoschMebEdc16Cp31Detector(),
        new BoschMebEdc16Cp36Detector(),
        new BoschMebMd1Cp001Detector(),
        new BoschVagEdc16U31U34Detector(),
        new BoschBmwEdc16Detector(),
        new BoschBmwEdc17Cp02Detector(),
        new BoschBmwEdc17Cp45Detector(),
        new BoschHondaEdc17Cp06Detector(),
        new BoschHondaEdc17Cp50Detector(),
        new BoschHondaEdc17C58Detector(),
        new BoschBmwEdc17C41Detector(),
        new BoschBmwEdc17C50Detector(),
        new BoschBmwEdc16C31Detector(),
        new BoschBmwEdc16Cp35Detector(),
        new BoschBmwMdg1Cs003Detector(),
        new BoschBmwMevdDetector(),
        new BoschVagEdc16U1Detector(),
        new BoschVagEdc16Cp34Detector(),
        new BoschVagEdc17C46Detector(),
        new BoschVagEdc17C54Detector(),
        new BoschEdc17C42RenaultNissanOpelDetector(),
        new BoschNissanEdc16Cp42Detector(),
        new BoschRenaultNissanOpelEdc16Cp33Detector(),
        new BoschNissanEdc17C84Detector(),
        new BoschVagEdc17C64Detector(),
        new BoschVagEdc17C74Detector(),
        new BoschVagEdc17Cp20Detector(),
        new BoschVagEdc17Cp44Detector(),
        new BoschVagMed1711Detector(),
        new BoschVagMed911Detector(),
        new ContinentalVagPcr21Detector(),
        new ContinentalVagSimos62Detector(),
        new ContinentalVagSimos81Detector(),
        new ContinentalVagSimos82Detector(),
        new ContinentalVagSimos83Detector(),
        new ContinentalVagSimos85Detector(),
        new ContinentalVagSimos1810Detector(),
        new ContinentalVagSimosPpd15Detector(),
        new ContinentalFordSid208Detector(),
        new ContinentalFordSid211Detector(),
        new ContinentalSiemensVdoSid208PsaDetector(),
        new ContinentalSiemensVdoSid310Detector(),
        new ContinentalSiemensVolvoSid803ADetector(),
        new SiemensBmwDetector()
    ];

    private static readonly List<IEcuDetectionModule> BaseModules =
    [
    ];

    public static event Action? ModulesChanged;

    public static IReadOnlyList<IEcuDetectionModule> DetectModules => Modules;
    public static IReadOnlyList<IEcuDetectionModule> BaseDetectors => BaseModules;

    public static IEnumerable<IdentifierMatch> Detect(EcuBinaryImage image) =>
        Modules.SelectMany(module => module.Detect(image));

    public static IEnumerable<IdentifierMatch> ExtractGenericEvidence(EcuBinaryImage image) =>
        Modules.SelectMany(module => module.ExtractGenericEvidence(image));

    public static void AddModule(IEcuDetectionModule module)
    {
        if (module is null) throw new ArgumentNullException(nameof(module));
        Modules.Add(module);
        ModulesChanged?.Invoke();
    }

    public static bool RemoveModule(IEcuDetectionModule module)
    {
        if (module is null) throw new ArgumentNullException(nameof(module));
        var removed = Modules.Remove(module);
        if (removed) ModulesChanged?.Invoke();
        return removed;
    }
}
