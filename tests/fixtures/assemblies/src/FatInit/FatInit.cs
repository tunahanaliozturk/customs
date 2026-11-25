// Sixteen module initialisers. The C# compiler calls each from the .cctor
// of <Module>, five bytes of IL per call and one for the return: 81 bytes,
// more than the 63 a tiny method header can hold, so the .cctor has a fat
// header. Each initialiser only counts.

using System.Runtime.CompilerServices;

namespace Fixture.FatInit;

public static class Loader
{
    internal static int Count;

    [ModuleInitializer]
    internal static void Run00() => Count++;

    [ModuleInitializer]
    internal static void Run01() => Count++;

    [ModuleInitializer]
    internal static void Run02() => Count++;

    [ModuleInitializer]
    internal static void Run03() => Count++;

    [ModuleInitializer]
    internal static void Run04() => Count++;

    [ModuleInitializer]
    internal static void Run05() => Count++;

    [ModuleInitializer]
    internal static void Run06() => Count++;

    [ModuleInitializer]
    internal static void Run07() => Count++;

    [ModuleInitializer]
    internal static void Run08() => Count++;

    [ModuleInitializer]
    internal static void Run09() => Count++;

    [ModuleInitializer]
    internal static void Run10() => Count++;

    [ModuleInitializer]
    internal static void Run11() => Count++;

    [ModuleInitializer]
    internal static void Run12() => Count++;

    [ModuleInitializer]
    internal static void Run13() => Count++;

    [ModuleInitializer]
    internal static void Run14() => Count++;

    [ModuleInitializer]
    internal static void Run15() => Count++;
}
