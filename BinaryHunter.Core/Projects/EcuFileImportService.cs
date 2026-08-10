using System.Globalization;

namespace BinaryHunter.Core.Projects;

public sealed class EcuFileImportService
{
    private const long MaximumNormalizedImageSize = 512L * 1024 * 1024;

    public EcuFileImportResult Import(string path)
    {
        path = Path.GetFullPath(path);
        if (!File.Exists(path)) throw new FileNotFoundException("ECU source file was not found.", path);
        if (new FileInfo(path).Length > int.MaxValue)
            throw new InvalidDataException("Files larger than 2 GB require the large-file storage engine planned for stage 2.");

        var extension = Path.GetExtension(path).ToLowerInvariant();
        return extension switch
        {
            ".hex" or ".ihex" => ParseIntelHex(path),
            ".s19" or ".s28" or ".s37" or ".srec" or ".mot" => ParseMotorolaSRecord(path),
            ".frf" => ReadContainer(path, EcuSourceFormat.FrfContainer,
                "FRF container preserved byte-for-byte; manufacturer-specific extraction is delegated to a future import adapter."),
            ".odx" or ".odx-d" or ".odx-f" or ".pdx" => ReadContainer(path, EcuSourceFormat.OdxDocument,
                "ODX/PDX source preserved byte-for-byte; diagnostic package interpretation is delegated to the DAMOS/A2L/ASAM stage."),
            ".bin" or ".ori" or ".dtf" or ".rom" or ".eep" or ".flash" =>
                ReadContainer(path, EcuSourceFormat.RawBinary, "Raw binary image."),
            _ => ReadContainer(path, EcuSourceFormat.Unknown,
                "Unknown extension imported as an unmodified byte image.")
        };
    }

    private static EcuFileImportResult ReadContainer(string path, EcuSourceFormat format, string note) => new()
    {
        EditableBytes = File.ReadAllBytes(path),
        Format = format,
        Note = note
    };

    private static EcuFileImportResult ParseIntelHex(string path)
    {
        var segments = new List<MemorySegment>();
        long addressBase = 0;
        var eofSeen = false;
        var lineNumber = 0;

        foreach (var rawLine in File.ReadLines(path))
        {
            lineNumber++;
            var line = rawLine.Trim();
            if (line.Length == 0) continue;
            if (!line.StartsWith(':'))
                throw new InvalidDataException($"Intel HEX line {lineNumber} does not start with ':'.");

            byte[] record;
            try { record = Convert.FromHexString(line[1..]); }
            catch (FormatException exception)
            {
                throw new InvalidDataException($"Intel HEX line {lineNumber} contains invalid hexadecimal data.", exception);
            }

            if (record.Length < 5) throw new InvalidDataException($"Intel HEX line {lineNumber} is too short.");
            var count = record[0];
            if (record.Length != count + 5)
                throw new InvalidDataException($"Intel HEX line {lineNumber} has an invalid byte count.");
            if ((record.Sum(value => value) & 0xFF) != 0)
                throw new InvalidDataException($"Intel HEX checksum failed at line {lineNumber}.");

            var offset = (record[1] << 8) | record[2];
            var type = record[3];
            switch (type)
            {
                case 0x00:
                    if (count > 0)
                        segments.Add(new MemorySegment(checked(addressBase + offset), record.AsSpan(4, count).ToArray()));
                    break;
                case 0x01:
                    eofSeen = true;
                    break;
                case 0x02:
                    EnsureAddressRecord(record, count, lineNumber);
                    addressBase = ((record[4] << 8) | record[5]) << 4;
                    break;
                case 0x04:
                    EnsureAddressRecord(record, count, lineNumber);
                    addressBase = (long)((record[4] << 8) | record[5]) << 16;
                    break;
                case 0x03:
                case 0x05:
                    break;
                default:
                    throw new InvalidDataException($"Unsupported Intel HEX record type 0x{type:X2} at line {lineNumber}.");
            }

            if (eofSeen) break;
        }

        var normalized = NormalizeSegments(segments, "Intel HEX");
        return new EcuFileImportResult
        {
            EditableBytes = normalized.Bytes,
            BaseAddress = normalized.BaseAddress,
            Format = EcuSourceFormat.IntelHex,
            Note = $"Intel HEX decoded to a contiguous image; base address 0x{normalized.BaseAddress:X}."
        };
    }

    private static void EnsureAddressRecord(byte[] record, byte count, int lineNumber)
    {
        if (count != 2 || record.Length < 7)
            throw new InvalidDataException($"Intel HEX address record at line {lineNumber} is invalid.");
    }

    private static EcuFileImportResult ParseMotorolaSRecord(string path)
    {
        var segments = new List<MemorySegment>();
        var lineNumber = 0;

        foreach (var rawLine in File.ReadLines(path))
        {
            lineNumber++;
            var line = rawLine.Trim();
            if (line.Length == 0) continue;
            if (line.Length < 4 || line[0] != 'S')
                throw new InvalidDataException($"Motorola S-record line {lineNumber} is invalid.");

            var addressLength = line[1] switch
            {
                '1' => 2,
                '2' => 3,
                '3' => 4,
                '0' or '5' or '6' or '7' or '8' or '9' => 0,
                _ => throw new InvalidDataException($"Unsupported S-record type S{line[1]} at line {lineNumber}.")
            };

            byte[] record;
            try { record = Convert.FromHexString(line[2..]); }
            catch (FormatException exception)
            {
                throw new InvalidDataException($"S-record line {lineNumber} contains invalid hexadecimal data.", exception);
            }

            if (record.Length < 2 || record[0] != record.Length - 1)
                throw new InvalidDataException($"S-record line {lineNumber} has an invalid byte count.");
            if ((record.Sum(value => value) & 0xFF) != 0xFF)
                throw new InvalidDataException($"S-record checksum failed at line {lineNumber}.");
            if (addressLength == 0) continue;
            if (record.Length < 1 + addressLength + 1)
                throw new InvalidDataException($"S-record line {lineNumber} is too short.");

            long address = 0;
            for (var index = 0; index < addressLength; index++)
                address = (address << 8) | record[1 + index];
            var dataLength = record[0] - addressLength - 1;
            if (dataLength > 0)
                segments.Add(new MemorySegment(address, record.AsSpan(1 + addressLength, dataLength).ToArray()));
        }

        var normalized = NormalizeSegments(segments, "Motorola S-record");
        return new EcuFileImportResult
        {
            EditableBytes = normalized.Bytes,
            BaseAddress = normalized.BaseAddress,
            Format = EcuSourceFormat.MotorolaSRecord,
            Note = $"Motorola S-record decoded to a contiguous image; base address 0x{normalized.BaseAddress:X}."
        };
    }

    private static NormalizedImage NormalizeSegments(IReadOnlyCollection<MemorySegment> segments, string formatName)
    {
        if (segments.Count == 0) throw new InvalidDataException($"{formatName} contains no data records.");
        var minimum = segments.Min(segment => segment.Address);
        var maximum = segments.Max(segment => checked(segment.Address + segment.Bytes.LongLength));
        var length = checked(maximum - minimum);
        if (length <= 0 || length > MaximumNormalizedImageSize)
            throw new InvalidDataException($"{formatName} address span ({length:N0} bytes) cannot be normalized safely.");

        var bytes = new byte[(int)length];
        Array.Fill(bytes, (byte)0xFF);
        foreach (var segment in segments)
            segment.Bytes.CopyTo(bytes, checked((int)(segment.Address - minimum)));
        return new NormalizedImage(minimum, bytes);
    }

    private sealed record MemorySegment(long Address, byte[] Bytes);
    private sealed record NormalizedImage(long BaseAddress, byte[] Bytes);
}