namespace BinaryHunter.UI.Models;

public sealed record SupportedEcuProfile(
    string Name,
    string ImageSize,
    bool SupportsFull,
    bool SupportsPartial = false,
    bool IsDraft = false);

public sealed record SupportedEcuGroup(
    string VehicleBrand,
    string BrandCode,
    IReadOnlyList<SupportedEcuProfile> Profiles)
{
    public int Count => Profiles.Count;
}
