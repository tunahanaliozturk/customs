// P/Invoke declarations. Nothing calls them. VirtualProtect is on customs's
// short list, and so is WriteProcessMemory, here under a harmless managed
// name, because the import name is what runs. GetTickCount64 is not on the
// list, and neither is LoadLibraryW: loading a library is too common in
// benign packages.

using System.Runtime.InteropServices;

namespace Fixture.PInvoke;

public static class Native
{
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool VirtualProtect(nint address, nuint size, uint protect, out uint old);

    [DllImport("kernel32.dll")]
    internal static extern ulong GetTickCount64();

    [DllImport("kernel32", EntryPoint = "LoadLibraryW", CharSet = CharSet.Unicode)]
    internal static extern nint OpenSettings(string name);

    [DllImport("kernel32", EntryPoint = "WriteProcessMemory")]
    internal static extern bool SaveSettings(nint process, nint address, byte[] data, nuint size, out nuint written);
}
