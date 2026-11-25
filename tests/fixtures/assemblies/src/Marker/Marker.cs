// The marker Dotfuscator leaves in what it protects: a type named
// DotfuscatorAttribute in the global namespace, applied to the assembly.
// Here it is declared by hand; nothing is obfuscated.

[assembly: DotfuscatorAttribute("fixture", 0)]

[AttributeUsage(AttributeTargets.Assembly)]
public sealed class DotfuscatorAttribute(string text, int number) : Attribute
{
    public string Text { get; } = text;

    public int Number { get; } = number;
}

namespace Fixture.Marker
{
    public static class Plain
    {
        public static int Twice(int value) => value * 2;
    }
}
