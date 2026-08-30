using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;
using YowThi.DevelopmentAgent3.Security;

namespace YowThi.DevelopmentAgent3.Docker;

[McpServerToolType]
public sealed class DockerMutationTools
{
    private const string DockerExe = @"C:\Program Files\Docker\Docker\resources\bin\docker.exe";
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);
    private static readonly Regex FullContainerId = new("^[0-9a-fA-F]{64}$", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");

    [McpServerTool(Name = "docker_container_start_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to start one existing stopped local Docker container. Only a full 64-character hexadecimal container ID is accepted; names, short IDs, arbitrary Docker arguments, shell commands, and docker exec are rejected. Container identity and current state are sealed into the plan. This does not start the container until docker_container_start_execute is called.")]
    public static SignedPlan DockerContainerStartPlan(string containerId)
    {
        var id = RequireFullContainerId(containerId);
        var snapshot = InspectContainer(id);
        if (snapshot.Running)
            throw new InvalidOperationException("Target container is already running.");
        if (snapshot.Status is not ("created" or "exited"))
            throw new InvalidOperationException($"Container state '{snapshot.Status}' is not eligible for start.");
        return CreateContainerPlan("container-start", snapshot, RiskClass.High, $"Start Docker container {snapshot.Id} ({snapshot.Name})");
    }

    [McpServerTool(Name = "docker_container_start_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared docker/container-start plan. The caller repeats signed operation, target, summary, and risk class. Full container identity and pre-start state are revalidated immediately before fixed 'docker container start <sealed-id>' is executed. Arbitrary Docker arguments and docker exec are not accepted.")]
    public static ExecutionResult DockerContainerStartExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "container-start", operation, target, summary, riskClass);
        var expected = ReadSnapshot(plan);
        RequireSnapshotMatch(expected, InspectContainer(expected.Id));

        try
        {
            RunRequired("container", "start", expected.Id);
            var after = InspectContainer(expected.Id);
            if (!after.Running)
                throw new InvalidOperationException("Docker reported success but the container is not running.");
            Store.Consume(planId);
            var outcome = $"container-started:{expected.Id}";
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, outcome }, "executed");
            return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    [McpServerTool(Name = "docker_container_stop_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to stop one existing running local Docker container with a fixed 10-second Docker stop timeout. Only a full 64-character hexadecimal container ID is accepted. Container identity and running state are sealed. Arbitrary arguments, signals, timeout values, shell commands, and docker exec are rejected.")]
    public static SignedPlan DockerContainerStopPlan(string containerId)
    {
        var id = RequireFullContainerId(containerId);
        var snapshot = InspectContainer(id);
        if (!snapshot.Running || snapshot.Status != "running")
            throw new InvalidOperationException("Target container must currently be running.");
        return CreateContainerPlan("container-stop", snapshot, RiskClass.High, $"Stop Docker container {snapshot.Id} ({snapshot.Name}) with fixed 10-second timeout");
    }

    [McpServerTool(Name = "docker_container_stop_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared docker/container-stop plan using fixed 'docker container stop --time 10 <sealed-id>'. The caller repeats signed operation, target, summary, and risk class. Container identity and running state are revalidated immediately before stop. Caller-selected signals, timeouts, arbitrary Docker arguments, and docker exec are not accepted.")]
    public static ExecutionResult DockerContainerStopExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "container-stop", operation, target, summary, riskClass);
        var expected = ReadSnapshot(plan);
        RequireSnapshotMatch(expected, InspectContainer(expected.Id));

        try
        {
            RunRequired("container", "stop", "--time", "10", expected.Id);
            var after = InspectContainer(expected.Id);
            if (after.Running)
                throw new InvalidOperationException("Docker reported success but the container is still running.");
            Store.Consume(planId);
            var outcome = $"container-stopped:{expected.Id}";
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, outcome }, "executed");
            return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    [McpServerTool(Name = "docker_container_remove_plan", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to remove one existing stopped local Docker container without force and without volume removal. Only a full 64-character hexadecimal container ID is accepted. Running containers are rejected. Container identity and stopped state are sealed. Arbitrary flags, force removal, volume removal, shell commands, and docker exec are not supported.")]
    public static SignedPlan DockerContainerRemovePlan(string containerId)
    {
        var id = RequireFullContainerId(containerId);
        var snapshot = InspectContainer(id);
        if (snapshot.Running)
            throw new InvalidOperationException("Running containers cannot be removed; stop the container first.");
        if (snapshot.Status is "restarting" or "paused")
            throw new InvalidOperationException($"Container state '{snapshot.Status}' is not eligible for removal.");
        return CreateContainerPlan("container-remove", snapshot, RiskClass.High, $"Remove stopped Docker container {snapshot.Id} ({snapshot.Name}) without force or volume removal");
    }

    [McpServerTool(Name = "docker_container_remove_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute one previously prepared docker/container-remove plan using fixed 'docker container rm <sealed-id>' with no force and no volume flag. The caller repeats signed operation, target, summary, and risk class. Container identity and stopped state are revalidated immediately before removal. Arbitrary flags and running-container removal are rejected.")]
    public static ExecutionResult DockerContainerRemoveExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "container-remove", operation, target, summary, riskClass);
        var expected = ReadSnapshot(plan);
        RequireSnapshotMatch(expected, InspectContainer(expected.Id));
        if (expected.Running)
            throw new InvalidOperationException("Signed removal plan unexpectedly targets a running container.");

        try
        {
            RunRequired("container", "rm", expected.Id);
            if (TryInspectContainer(expected.Id, out _))
                throw new InvalidOperationException("Docker reported success but the container still exists.");
            Store.Consume(planId);
            var outcome = $"container-removed:{expected.Id}";
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, outcome }, "executed");
            return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    private static SignedPlan CreateContainerPlan(string operation, ContainerSnapshot snapshot, RiskClass riskClass, string summary)
    {
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["containerId"] = snapshot.Id,
            ["name"] = snapshot.Name,
            ["imageId"] = snapshot.ImageId,
            ["created"] = snapshot.Created,
            ["status"] = snapshot.Status,
            ["running"] = snapshot.Running ? "true" : "false"
        };
        var now = DateTimeOffset.UtcNow;
        var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)), "docker", operation, snapshot.Id, parameters, riskClass, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    private static void RequireIntentMatch(SignedPlan plan, string expectedOperation, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "docker", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, expectedOperation, StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, operation, StringComparison.Ordinal) ||
            !string.Equals(plan.Target, target, StringComparison.Ordinal) ||
            !string.Equals(plan.Summary, summary, StringComparison.Ordinal) ||
            !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
    }

    private static ContainerSnapshot ReadSnapshot(SignedPlan plan)
    {
        if (!plan.Parameters.TryGetValue("containerId", out var id) ||
            !plan.Parameters.TryGetValue("name", out var name) ||
            !plan.Parameters.TryGetValue("imageId", out var imageId) ||
            !plan.Parameters.TryGetValue("created", out var created) ||
            !plan.Parameters.TryGetValue("status", out var status) ||
            !plan.Parameters.TryGetValue("running", out var runningText))
            throw new InvalidDataException("Signed Docker container snapshot is incomplete.");
        RequireFullContainerId(id);
        if (!bool.TryParse(runningText, out var running))
            throw new InvalidDataException("Signed Docker running state is invalid.");
        return new ContainerSnapshot(id, name, imageId, created, status, running);
    }

    private static void RequireSnapshotMatch(ContainerSnapshot expected, ContainerSnapshot current)
    {
        if (!string.Equals(expected.Id, current.Id, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(expected.Name, current.Name, StringComparison.Ordinal) ||
            !string.Equals(expected.ImageId, current.ImageId, StringComparison.Ordinal) ||
            !string.Equals(expected.Created, current.Created, StringComparison.Ordinal) ||
            !string.Equals(expected.Status, current.Status, StringComparison.Ordinal) ||
            expected.Running != current.Running)
            throw new InvalidOperationException("Docker container identity or state changed after plan preparation.");
    }

    private static string RequireFullContainerId(string containerId)
    {
        var value = (containerId ?? string.Empty).Trim();
        if (!FullContainerId.IsMatch(value))
            throw new ArgumentException("containerId must be the full 64-character hexadecimal Docker container ID.", nameof(containerId));
        return value.ToLowerInvariant();
    }

    private static ContainerSnapshot InspectContainer(string id)
    {
        var result = Run("container", "inspect", "--format", "{{json .}}", RequireFullContainerId(id));
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"Unable to inspect Docker container {id}: {result.StdErr.Trim()}");
        using var doc = JsonDocument.Parse(result.StdOut.Trim());
        var root = doc.RootElement;
        var actualId = root.GetProperty("Id").GetString() ?? throw new InvalidDataException("Docker inspect response has no container ID.");
        actualId = RequireFullContainerId(actualId);
        if (!string.Equals(actualId, id, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Docker inspect returned an unexpected container identity.");
        var rawName = root.GetProperty("Name").GetString() ?? string.Empty;
        var imageId = root.GetProperty("Image").GetString() ?? string.Empty;
        var created = root.GetProperty("Created").GetString() ?? string.Empty;
        var state = root.GetProperty("State");
        var status = state.GetProperty("Status").GetString() ?? string.Empty;
        var running = state.GetProperty("Running").GetBoolean();
        return new ContainerSnapshot(actualId, rawName.TrimStart('/'), imageId, created, status, running);
    }

    private static bool TryInspectContainer(string id, out ContainerSnapshot? snapshot)
    {
        snapshot = null;
        var result = Run("container", "inspect", "--format", "{{json .}}", RequireFullContainerId(id));
        if (result.ExitCode != 0) return false;
        using var doc = JsonDocument.Parse(result.StdOut.Trim());
        var root = doc.RootElement;
        var actualId = RequireFullContainerId(root.GetProperty("Id").GetString() ?? string.Empty);
        var state = root.GetProperty("State");
        snapshot = new ContainerSnapshot(
            actualId,
            (root.GetProperty("Name").GetString() ?? string.Empty).TrimStart('/'),
            root.GetProperty("Image").GetString() ?? string.Empty,
            root.GetProperty("Created").GetString() ?? string.Empty,
            state.GetProperty("Status").GetString() ?? string.Empty,
            state.GetProperty("Running").GetBoolean());
        return true;
    }

    private static void RunRequired(params string[] arguments)
    {
        var result = Run(arguments);
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"Docker operation failed with exit code {result.ExitCode}: {result.StdErr.Trim()}");
    }

    private static ProcessResult Run(params string[] arguments)
    {
        if (!File.Exists(DockerExe))
            throw new FileNotFoundException("Docker CLI was not found at the fixed Docker Desktop path.", DockerExe);
        var start = new ProcessStartInfo
        {
            FileName = DockerExe,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (var argument in arguments)
            start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Unable to start the fixed Docker CLI process.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit((int)Timeout.TotalMilliseconds))
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException($"Docker operation exceeded {Timeout.TotalSeconds:0} seconds.");
        }
        Task.WaitAll(stdoutTask, stderrTask);
        return new ProcessResult(process.ExitCode, stdoutTask.Result, stderrTask.Result);
    }

    private sealed record ContainerSnapshot(string Id, string Name, string ImageId, string Created, string Status, bool Running);
    private sealed record ProcessResult(int ExitCode, string StdOut, string StdErr);
}
