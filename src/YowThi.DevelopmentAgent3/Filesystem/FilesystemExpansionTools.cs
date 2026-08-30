using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;
using YowThi.DevelopmentAgent3.Security;

namespace YowThi.DevelopmentAgent3.Filesystem;

[McpServerToolType]
public static class FilesystemExpansionTools
{
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly ProtectedPathPolicy Paths = new();
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");

    [McpServerTool(Name="directory_list", ReadOnly=true, Destructive=false, OpenWorld=false)]
    [Description("List direct children of one absolute local directory using the native .NET filesystem API. No shell command is generated or executed.")]
    public static DirectoryEntryInfo[] DirectoryList(string path)
    {
        var target = Paths.Normalize(path);
        if (!Directory.Exists(target)) throw new DirectoryNotFoundException($"Directory does not exist: {target}");

        return new DirectoryInfo(target)
            .EnumerateFileSystemInfos()
            .OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .Select(ToEntry)
            .ToArray();
    }

    [McpServerTool(Name="file_copy_plan", ReadOnly=false, Destructive=false, OpenWorld=false)]
    [Description("Prepare a one-time signed plan to copy one local file using the native .NET filesystem API. The source may be read from a frozen path, but the destination must be mutable. No shell command is generated or stored.")]
    public static SignedPlan FileCopyPlan(string source, string destination, bool overwrite = false)
    {
        var sourceFull = Paths.Normalize(source);
        var destinationFull = Paths.RequireMutable(destination);
        if (!File.Exists(sourceFull)) throw new FileNotFoundException("Source file does not exist.", sourceFull);
        if (File.Exists(destinationFull) && !overwrite) throw new IOException("Destination already exists and overwrite=false.");

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["source"] = sourceFull,
            ["overwrite"] = overwrite ? "true" : "false",
            ["sourceSha256"] = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(sourceFull)))
        };
        return CreatePlan("file-copy", destinationFull, parameters, RiskClass.Medium, $"Copy file {sourceFull} to {destinationFull}, overwrite={overwrite}");
    }

    [McpServerTool(Name="file_copy_execute", ReadOnly=false, Destructive=false, OpenWorld=false)]
    [Description("Execute one previously prepared filesystem/file-copy plan using the native .NET filesystem API. The source SHA-256 is rechecked and the caller must repeat the signed operation, target, summary, and risk class. No PowerShell, cmd, or generic command executor is used.")]
    public static ExecutionResult FileCopyExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "file-copy", operation, target, summary, riskClass);
        try
        {
            var source = RequireParameter(plan, "source");
            var expectedHash = RequireParameter(plan, "sourceSha256");
            var overwrite = string.Equals(RequireParameter(plan, "overwrite"), "true", StringComparison.OrdinalIgnoreCase);
            Paths.RequireMutable(plan.Target);
            if (!File.Exists(source)) throw new FileNotFoundException("Source file no longer exists.", source);
            var actualHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(source)));
            if (!string.Equals(expectedHash, actualHash, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Source file SHA-256 changed after plan creation.");
            Directory.CreateDirectory(Path.GetDirectoryName(plan.Target)!);
            File.Copy(source, plan.Target, overwrite);
            Store.Consume(planId);
            var outcome = $"copied:{new FileInfo(plan.Target).Length}";
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, source, outcome }, "executed");
            return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    [McpServerTool(Name="file_move_plan", ReadOnly=false, Destructive=false, OpenWorld=false)]
    [Description("Prepare a one-time signed plan to move one local file using the native .NET filesystem API. Both source and destination must be mutable. No shell command is generated or stored.")]
    public static SignedPlan FileMovePlan(string source, string destination, bool overwrite = false)
    {
        var sourceFull = Paths.RequireMutable(source);
        var destinationFull = Paths.RequireMutable(destination);
        if (!File.Exists(sourceFull)) throw new FileNotFoundException("Source file does not exist.", sourceFull);
        if (File.Exists(destinationFull) && !overwrite) throw new IOException("Destination already exists and overwrite=false.");

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["source"] = sourceFull,
            ["overwrite"] = overwrite ? "true" : "false",
            ["sourceSha256"] = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(sourceFull)))
        };
        return CreatePlan("file-move", destinationFull, parameters, RiskClass.Medium, $"Move file {sourceFull} to {destinationFull}, overwrite={overwrite}");
    }

    [McpServerTool(Name="file_move_execute", ReadOnly=false, Destructive=false, OpenWorld=false)]
    [Description("Execute one previously prepared filesystem/file-move plan using the native .NET filesystem API. Both paths are rechecked against path policy, the source SHA-256 is rechecked, and the caller must repeat the signed operation, target, summary, and risk class. No PowerShell, cmd, or generic command executor is used.")]
    public static ExecutionResult FileMoveExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "file-move", operation, target, summary, riskClass);
        try
        {
            var source = Paths.RequireMutable(RequireParameter(plan, "source"));
            var destination = Paths.RequireMutable(plan.Target);
            var expectedHash = RequireParameter(plan, "sourceSha256");
            var overwrite = string.Equals(RequireParameter(plan, "overwrite"), "true", StringComparison.OrdinalIgnoreCase);
            if (!File.Exists(source)) throw new FileNotFoundException("Source file no longer exists.", source);
            var actualHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(source)));
            if (!string.Equals(expectedHash, actualHash, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Source file SHA-256 changed after plan creation.");
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            File.Move(source, destination, overwrite);
            Store.Consume(planId);
            var outcome = $"moved:{new FileInfo(destination).Length}";
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, source, outcome }, "executed");
            return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    [McpServerTool(Name="directory_create_plan", ReadOnly=false, Destructive=false, OpenWorld=false)]
    [Description("Prepare a one-time signed plan to create one local directory using the native .NET filesystem API. Frozen paths are blocked. No shell command is generated or stored.")]
    public static SignedPlan DirectoryCreatePlan(string path)
    {
        var target = Paths.RequireMutable(path);
        if (Directory.Exists(target)) throw new IOException("Target directory already exists.");
        return CreatePlan("directory-create", target, new Dictionary<string, string>(StringComparer.Ordinal), RiskClass.Medium, $"Create directory {target}");
    }

    [McpServerTool(Name="directory_create_execute", ReadOnly=false, Destructive=false, OpenWorld=false)]
    [Description("Execute one previously prepared filesystem/directory-create plan using the native .NET filesystem API. The caller must repeat the signed operation, target, summary, and risk class. No PowerShell, cmd, or generic command executor is used.")]
    public static ExecutionResult DirectoryCreateExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "directory-create", operation, target, summary, riskClass);
        try
        {
            var destination = Paths.RequireMutable(plan.Target);
            if (Directory.Exists(destination)) throw new IOException("Target directory already exists.");
            Directory.CreateDirectory(destination);
            Store.Consume(planId);
            const string outcome = "directory-created";
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, outcome }, "executed");
            return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    private static SignedPlan CreatePlan(string operation, string target, Dictionary<string, string> parameters, RiskClass riskClass, string summary)
    {
        var now = DateTimeOffset.UtcNow;
        var planId = Guid.NewGuid().ToString("N");
        var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var unsigned = new SignedPlan(1, planId, approvalCode, "filesystem", operation, target, parameters, riskClass, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    private static DirectoryEntryInfo ToEntry(FileSystemInfo item)
    {
        var isDirectory = item is DirectoryInfo;
        long? bytes = item is FileInfo file ? file.Length : null;
        return new DirectoryEntryInfo(item.FullName, item.Name, isDirectory ? "directory" : "file", bytes, item.CreationTimeUtc, item.LastWriteTimeUtc, item.Attributes.ToString());
    }

    private static string RequireParameter(SignedPlan plan, string name)
    {
        if (!plan.Parameters.TryGetValue(name, out var value)) throw new InvalidDataException($"{name} parameter is required.");
        return value;
    }

    private static void RequireIntentMatch(SignedPlan plan, string expectedOperation, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "filesystem", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, expectedOperation, StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, operation, StringComparison.Ordinal) ||
            !string.Equals(plan.Target, target, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(plan.Summary, summary, StringComparison.Ordinal) ||
            !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, operation, target, summary, riskClass }, "intent-mismatch");
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
        }
    }
}

public sealed record DirectoryEntryInfo(string FullName, string Name, string Kind, long? Bytes, DateTime CreationTimeUtc, DateTime LastWriteTimeUtc, string Attributes);
