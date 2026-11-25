// No module initialiser, no P/Invoke, no marker. Two shapes customs must not
// report: a static constructor on an ordinary type (TypeDef row 2, which a
// reader that takes the wrong row for <Module> would report), and logic in
// an extension method behind a date check, the shape of the Socket case of
// 2025-11-06, which customs says it cannot see.

namespace Fixture.Plain;

public sealed class Settings
{
    internal static readonly string[] Names;

    static Settings() => Names = ["a", "b"];

    public string Name { get; set; } = "";
}

public static class Extensions
{
    public static int Checked(this int value, DateTime now) =>
        now.Year > 2030 ? value + 1 : value;
}
