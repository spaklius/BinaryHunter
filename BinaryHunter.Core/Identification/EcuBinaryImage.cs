using System.Text;

namespace BinaryHunter.Core.Identification;

// Shared immutable input for every detector. ASCII is materialized only when a
// detector needs it, avoiding repeated full-file text conversions.
public sealed class EcuBinaryImage(byte[] bytes)
{
    private string? _asciiText;

    public byte[] Bytes { get; } = bytes;
    public string AsciiText => _asciiText ??= Encoding.ASCII.GetString(Bytes);
    public string DisplaySize
    {
        get
        {
            var length = Bytes.LongLength;
            if (length % (1024 * 1024) == 0) return $"{length / (1024 * 1024)} MB";
            if (length % 1024 == 0) return $"{length / 1024} KB";
            return $"{length} bytes";
        }
    }
}
