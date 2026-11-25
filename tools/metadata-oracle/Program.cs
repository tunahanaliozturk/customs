// Prints, for every assembly it is given, what customs's metadata reader must
// agree with: whether System.Reflection.Metadata reads it as a managed
// assembly, the row count of every table from 0x00 to 0x2C, whether the first
// TypeDef row (<Module>) has a .cctor with RTSpecialName and the size of its
// IL, and every P/Invoke import of a method.
//
//     dotnet run --project tools/metadata-oracle -- PATH...
//
// A PATH is a .dll or .exe, a .nupkg (every .dll and .exe entry in it), or a
// directory (every .nupkg, .dll and .exe directly in it). The output is one
// JSON object per line, sorted by file name and entry name, so that a change
// reads well in a diff.
//
// With --digest, the imports of each assembly are written as their count and
// a 64-bit FNV-1a hash of one line per import, method, flags, name and module
// separated by tabs and ended by a line feed, in UTF-8, in method row order. The benign corpus holds about 47,000 imports,
// 3.7 MB as JSON, most of them SkiaSharp's; the digest keeps the committed
// file small and still changes when any one import does. Run without it to
// see the imports themselves.

using System.Collections.Immutable;
using System.IO.Compression;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text.Encodings.Web;
using System.Text.Json;

var digest = args.Contains("--digest");
var files = new List<string>();
foreach (var arg in args.Where(a => a != "--digest"))
{
    if (Directory.Exists(arg))
    {
        files.AddRange(Directory.GetFiles(arg).Where(IsInput));
    }
    else
    {
        files.Add(arg);
    }
}
files.Sort((a, b) => string.CompareOrdinal(Path.GetFileName(a), Path.GetFileName(b)));

using var stdout = Console.OpenStandardOutput();
foreach (var file in files)
{
    var name = Path.GetFileName(file);
    if (name.EndsWith(".nupkg", StringComparison.OrdinalIgnoreCase))
    {
        using var archive = ZipFile.OpenRead(file);
        var entries = archive.Entries.Where(e => IsAssembly(e.FullName)).ToList();
        entries.Sort((a, b) => string.CompareOrdinal(a.FullName, b.FullName));
        foreach (var entry in entries)
        {
            using var stream = entry.Open();
            using var buffer = new MemoryStream();
            stream.CopyTo(buffer);
            Describe(stdout, name, entry.FullName, buffer.ToArray(), digest);
        }
    }
    else
    {
        Describe(stdout, name, null, File.ReadAllBytes(file), digest);
    }
}

static bool IsAssembly(string name) =>
    name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
    || name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);

static bool IsInput(string path) =>
    IsAssembly(path) || path.EndsWith(".nupkg", StringComparison.OrdinalIgnoreCase);

static void Describe(Stream output, string file, string? entry, byte[] bytes, bool digest)
{
    var options = new JsonWriterOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
    using (var w = new Utf8JsonWriter(output, options))
    {
        w.WriteStartObject();
        w.WriteString("file", file);
        if (entry is null)
        {
            w.WriteNull("entry");
        }
        else
        {
            w.WriteString("entry", entry);
        }
        try
        {
            using var pe = new PEReader(ImmutableArray.Create(bytes));
            if (!pe.HasMetadata)
            {
                throw new BadImageFormatException("no CLI header");
            }
            var md = pe.GetMetadataReader();
            var rows = Enumerable.Range(0, 0x2D).Select(t => md.GetTableRowCount((TableIndex)t)).ToArray();
            var initializer = ModuleInitializer(pe, md);
            var imports = Imports(md);

            w.WriteBoolean("managed", true);
            w.WriteStartArray("rows");
            foreach (var count in rows)
            {
                w.WriteNumberValue(count);
            }
            w.WriteEndArray();
            if (initializer is { } found)
            {
                w.WriteStartObject("module_initializer");
                if (found.CodeSize is { } size)
                {
                    w.WriteNumber("code_size", size);
                }
                else
                {
                    w.WriteNull("code_size");
                }
                w.WriteEndObject();
            }
            else
            {
                w.WriteNull("module_initializer");
            }
            if (digest)
            {
                w.WriteStartObject("imports");
                w.WriteNumber("count", imports.Count);
                w.WriteString("fnv1a64", Fnv1a64(imports).ToString("x16"));
                w.WriteEndObject();
            }
            else
            {
                w.WriteStartArray("imports");
                foreach (var (method, flags, name, module) in imports)
                {
                    w.WriteStartObject();
                    w.WriteNumber("method", method);
                    w.WriteNumber("flags", flags);
                    w.WriteString("name", name);
                    w.WriteString("module", module);
                    w.WriteEndObject();
                }
                w.WriteEndArray();
            }
        }
        catch (Exception e) when (e is BadImageFormatException or InvalidOperationException or ArgumentException)
        {
            w.WriteBoolean("managed", false);
            w.WriteString("reason", e.Message);
        }
        w.WriteEndObject();
    }
    output.WriteByte((byte)'\n');
}

static ulong Fnv1a64(List<(int Method, int Flags, string Name, string Module)> imports)
{
    var hash = 0xcbf29ce484222325UL;
    foreach (var (method, flags, name, module) in imports)
    {
        foreach (var b in System.Text.Encoding.UTF8.GetBytes($"{method}\t{flags}\t{name}\t{module}\n"))
        {
            hash = (hash ^ b) * 0x100000001b3UL;
        }
    }
    return hash;
}

// The module initialiser is the type initialiser of <Module>, the first
// TypeDef row (ECMA-335 augments, II.10.5.3).
static Initializer? ModuleInitializer(PEReader pe, MetadataReader md)
{
    if (md.TypeDefinitions.Count == 0)
    {
        return null;
    }
    var module = md.GetTypeDefinition(MetadataTokens.TypeDefinitionHandle(1));
    foreach (var handle in module.GetMethods())
    {
        var method = md.GetMethodDefinition(handle);
        if ((method.Attributes & MethodAttributes.RTSpecialName) != 0
            && md.StringComparer.Equals(method.Name, ".cctor"))
        {
            int? size = null;
            if (method.RelativeVirtualAddress != 0)
            {
                try
                {
                    size = pe.GetMethodBody(method.RelativeVirtualAddress).GetILBytes()?.Length;
                }
                catch (BadImageFormatException)
                {
                }
            }
            return new Initializer(size);
        }
    }
    return null;
}

static List<(int Method, int Flags, string Name, string Module)> Imports(MetadataReader md)
{
    var imports = new List<(int, int, string, string)>();
    foreach (var handle in md.MethodDefinitions)
    {
        var import = md.GetMethodDefinition(handle).GetImport();
        if (import.Name.IsNil && import.Module.IsNil)
        {
            continue;
        }
        var module = import.Module.IsNil ? "" : md.GetString(md.GetModuleReference(import.Module).Name);
        imports.Add((MetadataTokens.GetRowNumber(handle), (int)import.Attributes, md.GetString(import.Name), module));
    }
    return imports;
}

readonly record struct Initializer(int? CodeSize);
