using System.Runtime.InteropServices;

namespace BinaryHunter.UI.Services;

internal static class ClipboardService
{
    private const uint ClipboardUnicodeText = 13;
    private const uint GlobalMoveable = 0x0002;
    private const int MaximumAttempts = 6;

    public static async Task<bool> TrySetTextAsync(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        for (var attempt = 0; attempt < MaximumAttempts; attempt++)
        {
            if (TrySetText(text))
                return true;

            if (attempt < MaximumAttempts - 1)
                await Task.Delay(20 * (attempt + 1));
        }

        return false;
    }

    private static bool TrySetText(string text)
    {
        if (!OpenClipboard(IntPtr.Zero))
            return false;

        IntPtr memory = IntPtr.Zero;
        IntPtr target = IntPtr.Zero;
        try
        {
            var characters = text.ToCharArray();
            memory = GlobalAlloc(GlobalMoveable, (UIntPtr)((characters.Length + 1) * sizeof(char)));
            if (memory == IntPtr.Zero)
                return false;

            target = GlobalLock(memory);
            if (target == IntPtr.Zero)
                return false;

            Marshal.Copy(characters, 0, target, characters.Length);
            Marshal.WriteInt16(target, characters.Length * sizeof(char), 0);
            GlobalUnlock(memory);
            target = IntPtr.Zero;

            if (!EmptyClipboard() || SetClipboardData(ClipboardUnicodeText, memory) == IntPtr.Zero)
                return false;

            memory = IntPtr.Zero; // The clipboard now owns the memory block.
            return true;
        }
        finally
        {
            if (target != IntPtr.Zero)
                GlobalUnlock(memory);
            if (memory != IntPtr.Zero)
                GlobalFree(memory);
            CloseClipboard();
        }
    }

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenClipboard(IntPtr owner);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseClipboard();

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EmptyClipboard();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetClipboardData(uint format, IntPtr memory);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalAlloc(uint flags, UIntPtr bytes);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalLock(IntPtr memory);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalUnlock(IntPtr memory);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalFree(IntPtr memory);
}