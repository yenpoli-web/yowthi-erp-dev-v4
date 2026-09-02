using System.ComponentModel;
using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;

namespace YowThi.DevelopmentAgent3.Runtime;

public static class ToolRegistryIdentity
{
    private static readonly Lazy<ToolRegistrySnapshot> CurrentSnapshot = new(BuildSnapshot, LazyThreadSafetyMode.ExecutionAndPublication);

    public static ToolRegistrySnapshot Current => CurrentSnapshot.Value;

    private static ToolRegistrySnapshot BuildSnapshot()
    {
        var assembly = typeof(ToolRegistryIdentity).Assembly;
        var runtimePath = assembly.Location;
        if (string.IsNullOrWhiteSpace(runtimePath) || !File.Exists(runtimePath))
            throw new InvalidOperationException("Executing Agent runtime DLL could not be resolved.");

        var contracts = assembly.GetTypes()
            .Where(type => type.GetCustomAttribute<McpServerToolTypeAttribute>() is not null)
            .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly))
            .Select(method => new { Method = method, Attribute = method.GetCustomAttribute<McpServerToolAttribute>() })
            .Where(value => value.Attribute is not null)
            .Select(value =>
            {
                var name = string.IsNullOrWhiteSpace(value.Attribute!.Name) ? value.Method.Name : value.Attribute.Name;
                var parameters = string.Join(",", value.Method.GetParameters().Select(parameter =>
                    $"{parameter.Name}:{FormatType(parameter.ParameterType)}:{(parameter.HasDefaultValue ? FormatDefault(parameter.DefaultValue) : "<required>")}"));
                var signature = $"{name}|{FormatType(value.Method.ReturnType)}|{parameters}";
                return new ToolContract(name, signature);
            })
            .OrderBy(value => value.Name, StringComparer.Ordinal)
            .ThenBy(value => value.Signature, StringComparer.Ordinal)
            .ToArray();

        var duplicateNames = contracts
            .GroupBy(value => value.Name, StringComparer.Ordinal)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToArray();
        if (duplicateNames.Length > 0)
            throw new InvalidOperationException("Duplicate MCP tool names detected: " + string.Join(", ", duplicateNames));

        var toolNames = contracts.Select(value => value.Name).ToArray();
        var canonicalContract = string.Join("\n", contracts.Select(value => value.Signature));
        var catalogSha256 = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonicalContract)));
        using var runtimeStream = new FileStream(runtimePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        var runtimeSha256 = Convert.ToHexString(SHA256.HashData(runtimeStream));

        return new ToolRegistrySnapshot(
            Environment.ProcessId,
            runtimePath,
            runtimeSha256,
            assembly.GetName().Version?.ToString() ?? string.Empty,
            toolNames.Length,
            catalogSha256,
            toolNames);
    }

    private static string FormatType(Type type)
    {
        if (type.IsArray) return FormatType(type.GetElementType()!) + "[]";
        if (!type.IsGenericType) return type.FullName ?? type.Name;
        var definitionName = type.GetGenericTypeDefinition().FullName ?? type.GetGenericTypeDefinition().Name;
        var tick = definitionName.IndexOf('`');
        if (tick >= 0) definitionName = definitionName[..tick];
        return definitionName + "<" + string.Join(",", type.GetGenericArguments().Select(FormatType)) + ">";
    }

    private static string FormatDefault(object? value) => value switch
    {
        null => "null",
        string text => "\"" + text.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal) + "\"",
        bool flag => flag ? "true" : "false",
        IFormattable formattable => formattable.ToString(null, CultureInfo.InvariantCulture) ?? string.Empty,
        _ => value.ToString() ?? string.Empty
    };

    private sealed record ToolContract(string Name, string Signature);
}

[McpServerToolType]
public static class ToolRegistryReadbackTools
{
    [McpServerTool(Name = "tool_registry_status", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Read the authoritative MCP tool-registry identity for the currently executing Agent runtime. Returns process/runtime identity, runtime DLL SHA-256, assembly version, exact tool count, a deterministic SHA-256 over tool names and method input/output contracts, and sorted tool names. This is read-only and performs no tool invocation, process mutation, filesystem mutation, network access, or registry refresh.")]
    public static ToolRegistrySnapshot ToolRegistryStatus() => ToolRegistryIdentity.Current;
}

public sealed record ToolRegistrySnapshot(
    int ProcessId,
    string RuntimeDll,
    string RuntimeSha256,
    string AssemblyVersion,
    int ToolCount,
    string CatalogSha256,
    IReadOnlyList<string> ToolNames);
