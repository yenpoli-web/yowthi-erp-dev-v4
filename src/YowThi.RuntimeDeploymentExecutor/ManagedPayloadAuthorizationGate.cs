using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace YowThi.RuntimeDeploymentExecutor;

internal static class ManagedPayloadAuthorizationGate
{
    private const string DevRoot = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string AuthorizedRoot = DevRoot + @"\.runtime-supervisor-deployment\authorized";
    private const string ExecutorExe = @"C:\ProgramData\YowThi\RuntimeDeployment\YowThi.RuntimeDeploymentExecutor.exe";
    private const string ExecutorDll = @"C:\ProgramData\YowThi\RuntimeDeployment\YowThi.RuntimeDeploymentExecutor.dll";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    [ModuleInitializer]
    internal static void ValidateAtModuleLoad()
    {
        if (!OperatingSystem.IsWindows())
            return;

        var args = Environment.GetCommandLineArgs();
        if (args.Length != 2)
            throw new UnauthorizedAccessException("Runtime deployment executor requires exactly one authorization argument.");

        var authorizationPath = RequireDirectAuthorizationPath(args[1]);
        var authorizationId = Path.GetFileNameWithoutExtension(authorizationPath);
        ValidateGuidN(authorizationId, "authorizationId");

        var authorization = JsonSerializer.Deserialize<ManagedPayloadAuthorization>(File.ReadAllBytes(authorizationPath), JsonOptions)
            ?? throw new InvalidDataException("Runtime deployment managed-payload authorization JSON is invalid.");

        if (authorization.SchemaVersion != 1 ||
            !string.Equals(authorization.AuthorizationId, authorizationId, StringComparison.Ordinal) ||
            !authorization.ProcessAuthorization)
            throw new UnauthorizedAccessException("Runtime deployment managed-payload authorization envelope is invalid.");
        RequireSha256(authorization.ExecutorSha256, "executorSha256");
        RequireSha256(authorization.ExecutorDllSha256, "executorDllSha256");
        if (authorization.ExpiresUtc <= DateTimeOffset.UtcNow)
            throw new UnauthorizedAccessException("Runtime deployment managed-payload authorization expired.");

        var processPath = Environment.ProcessPath
            ?? throw new UnauthorizedAccessException("Runtime deployment executor process path is unavailable.");
        if (!string.Equals(Path.GetFullPath(processPath), Path.GetFullPath(ExecutorExe), StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Runtime deployment executor must run from the fixed ProgramData executable.");

        ValidatePinnedFile(ExecutorExe, authorization.ExecutorSha256, "executor executable");
        ValidatePinnedFile(ExecutorDll, authorization.ExecutorDllSha256, "executor managed DLL");
    }

    private static string RequireDirectAuthorizationPath(string value)
    {
        var full = Path.GetFullPath(value);
        var root = Path.GetFullPath(AuthorizedRoot).TrimEnd('\\', '/');
        var parent = Path.GetDirectoryName(full)?.TrimEnd('\\', '/');
        if (!string.Equals(parent, root, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetExtension(full), ".json", StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(full))
            throw new UnauthorizedAccessException("Runtime deployment executor authorization must be one existing direct JSON child of the fixed authorized root.");
        if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Runtime deployment executor authorization may not be a reparse point.");
        return full;
    }

    private static void ValidatePinnedFile(string path, string expectedSha256, string label)
    {
        var full = Path.GetFullPath(path);
        if (!File.Exists(full))
            throw new FileNotFoundException("Runtime deployment " + label + " does not exist.", full);
        if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Runtime deployment " + label + " may not be a reparse point.");
        using var stream = new FileStream(full, FileMode.Open, FileAccess.Read, FileShare.Read);
        var actualSha256 = Convert.ToHexString(SHA256.HashData(stream));
        if (!string.Equals(actualSha256, expectedSha256, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Runtime deployment " + label + " SHA-256 does not match the signed authorization.");
    }

    private static void ValidateGuidN(string value, string name)
    {
        if (!Guid.TryParseExact(value, "N", out _))
            throw new InvalidDataException(name + " must be a GUID N identifier.");
    }

    private static void RequireSha256(string value, string name)
    {
        if (value.Length != 64 || value.Any(ch => !Uri.IsHexDigit(ch)))
            throw new InvalidDataException(name + " must be a 64-character SHA-256 hex digest.");
    }

    private sealed record ManagedPayloadAuthorization(
        int SchemaVersion,
        string AuthorizationId,
        string ExecutorSha256,
        string ExecutorDllSha256,
        bool ProcessAuthorization,
        DateTimeOffset ExpiresUtc);
}
