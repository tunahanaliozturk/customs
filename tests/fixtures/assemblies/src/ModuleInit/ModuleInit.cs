// A module initialiser: the C# compiler emits a .cctor on <Module> that calls
// every method marked [ModuleInitializer]. This one only sets a field. The
// shape is the one of the 2024 IL-weaving campaign (ReversingLabs,
// 2024-07-11), without a payload.

using System.Runtime.CompilerServices;

namespace Fixture.ModuleInit;

public static class Loader
{
    internal static bool Ran;

    [ModuleInitializer]
    internal static void Run() => Ran = true;
}

public static class Greeter
{
    public static string Greet(string name) => "Hello, " + name;
}
