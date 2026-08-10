using System.Text;
using System.IO;
using BinaryHunter.UI.Models;

namespace BinaryHunter.UI.Services;

public sealed record SampleEcuDefinition(string Id, string Label, int Size, IReadOnlyList<string> HeaderStrings);

public static class SampleEcuService
{
    public static IReadOnlyList<SampleEcuDefinition> Samples { get; } =
    [
        new("EDC17C64", "Audi A4 2.0 TDI (Bosch EDC17C64 - 4MB)", 0x400000,
        [
            "10/1/EDC17C64/5/P905//04L906026BK///", "ERCOSEK V4.2.1 TriCore_g", "TC1797",
            "0281019842", "EV_ECM20TDI03004L906026BK", "04L906026BK", "3120", "04L907309B",
            "1037538902", "R4 2.0L TDI", "CRBC CSHA CGLC J623", "WAUZZZ8K9DA012345"
        ]),
        new("EDC17CP02", "BMW 330d E90 (Bosch EDC17CP02 - 2MB)", 0x200000,
        [
            "EDC17_CP02/11/P_582//0281014582///", "EDC17 SB_01/1766", "0281014582",
            "1037398124", "DME_DDE701", "WBAUY31020A987654"
        ]),
        new("SID208", "Ford Transit 2.2 TDCi (Continental SID208 - 4MB)", 0x400000,
        [
            "AB39-12B684-AA\0\0\0CONTI_SID208_FRK_01\0AB39-12A650-CE\0", "BK31-14C204-AA",
            "DS-PAB39-12A650-CE1", "CONTINENTAL SID208", "WF0XXXTTFXEA54321"
        ]),
        new("DCM62V", "VW Passat 2.0 TDI (Delphi DCM6.2V - 4MB)", 0x400000,
        [
            "1MVAGAPP_DCM62V", "EV_ECM20TDI03004L906026M", "04L906026M", "5892",
            "R4 2.0l TDI", "DELPHI DCM6.2V", "WVWZZZ3CZGE123456"
        ]),
        new("EDC16C39", "Opel Astra 1.9 CDTI (Bosch EDC16C39 - 2MB)", 0x200000,
        [
            "1037386754P319_O32", "Bosch.p_319.Project.EDC16.Z19DTH",
            "BOSCH BOSCH0100/EDC16C39 MPC563/", "|10/1/EDC16C39/001/C319/",
            "EDC16C39 55567890 Z19DTH 0281014422", "W0L0AHL0861098765"
        ]),
        new("SIMOS85", "Audi S4 3.0 TFSI (Continental SIMOS8.5 - 2MB)", 0x200000,
        [
            "CAS85DAT", "S85MODULE01", "8K5907551D", "3.0l V6 TFSI", "8K5907551D 0004",
            "EV_ECM30TFS0118K5907551D", "J623", "WAUZZZ8K0BA654321"
        ]),
        new("MSV80", "BMW 528i N52 (Siemens/Continental MSV80 - 2MB)", 0x200000,
        [
            "5WK98022", "ERCOSEK V4.3.2 TriCore", "MSV80", "BMW MSV80 Continental",
            "WBAFR11080B123456"
        ])
    ];

    public static LoadedBinaryFile Create(string id)
    {
        var sample = Samples.FirstOrDefault(candidate =>
            string.Equals(candidate.Id, id, StringComparison.OrdinalIgnoreCase))
            ?? throw new ArgumentException($"Unknown sample ECU '{id}'.", nameof(id));

        var folder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "BinaryHunter", "Samples");
        Directory.CreateDirectory(folder);
        var path = Path.Combine(folder, GetFileName(sample.Id));

        if (!File.Exists(path) || new FileInfo(path).Length != sample.Size)
        {
            var bytes = new byte[sample.Size];
            for (var index = 0; index < bytes.Length; index++)
                bytes[index] = (byte)((index * 37 + (index >> 8) * 13) & 0xFF);

            var currentOffset = 0x1000;
            foreach (var text in sample.HeaderStrings)
            {
                var encoded = Encoding.UTF8.GetBytes(text);
                if (currentOffset + encoded.Length >= bytes.Length) break;
                encoded.CopyTo(bytes, currentOffset);
                currentOffset += encoded.Length + 64;
            }

            File.WriteAllBytes(path, bytes);
        }

        var info = new FileInfo(path);
        return new LoadedBinaryFile
        {
            Name = info.Name,
            FullPath = info.FullName,
            Size = info.Length,
            LastModified = info.LastWriteTime
        };
    }

    public static LoadedBinaryFile FromPath(string path)
    {
        var info = new FileInfo(path);
        return new LoadedBinaryFile
        {
            Name = info.Name,
            FullPath = info.FullName,
            Size = info.Length,
            LastModified = info.LastWriteTime
        };
    }

    private static string GetFileName(string id) => id switch
    {
        "EDC17C64" => "Audi_A4_2.0TDI_Bosch_EDC17C64_04L906026BK.bin",
        "EDC17CP02" => "BMW_330d_E90_EDC17CP02_0281014582.bin",
        "SID208" => "Ford_Transit_2.2TDCi_SID208_AB39-12A650-CE.bin",
        "DCM62V" => "VW_Passat_2.0TDI_Delphi_DCM6.2V_04L906026M.bin",
        "EDC16C39" => "Opel_Astra_1.9CDTI_Bosch_EDC16C39_0281014422.bin",
        "SIMOS85" => "Audi_S4_3.0TFSI_SIMOS8.5_8K5907551D.bin",
        "MSV80" => "BMW_528i_N52_Siemens_MSV80_5WK98022.bin",
        _ => $"{id}_sample.bin"
    };
}
