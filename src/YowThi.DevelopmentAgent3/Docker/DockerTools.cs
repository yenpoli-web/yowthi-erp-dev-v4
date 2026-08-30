using System.ComponentModel;
using System.Diagnostics;
using System.Text.Json;
using ModelContextProtocol.Server;

namespace YowThi.DevelopmentAgent3.Docker;

[McpServerToolType]
public sealed class DockerTools
{
    private const string DockerExe = @"C:\Program Files\Docker\Docker\resources\bin\docker.exe";
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);

    [McpServerTool(Name = "docker_status", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Read Docker Engine status and version using the fixed Docker Desktop docker.exe binary and fixed version/info queries. No caller-provided Docker arguments, shell, PowerShell, cmd, docker exec, or mutation is supported.")]
    public static object DockerStatus()
    {
        var version = Run("version", "--format", "{{json .}}", allowFailure: true);
        var info = Run("info", "--format", "{{json .}}", allowFailure: true);
        return new
        {
            dockerExe = DockerExe,
            dockerExeExists = File.Exists(DockerExe),
            versionExitCode = version.ExitCode,
            version = ParseJsonOrText(version.StdOut),
            infoExitCode = info.ExitCode,
            info = ParseJsonOrText(info.StdOut),
            error = JoinErrors(version.StdErr, info.StdErr),
            checkedUtc = DateTimeOffset.UtcNow
        };
    }

    [McpServerTool(Name = "docker_container_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List all local Docker containers using fixed 'docker container ls --all --no-trunc --format {{json .}}'. No filters, arbitrary arguments, exec, start, stop, remove, or other mutation is accepted.")]
    public static IReadOnlyList<JsonElement> DockerContainerList() => RunJsonLines("container", "ls", "--all", "--no-trunc", "--format", "{{json .}}");

    [McpServerTool(Name = "docker_image_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List local Docker images using fixed 'docker image ls --no-trunc --format {{json .}}'. No arbitrary arguments, pull, push, build, tag, remove, or other mutation is accepted.")]
    public static IReadOnlyList<JsonElement> DockerImageList() => RunJsonLines("image", "ls", "--no-trunc", "--format", "{{json .}}");

    [McpServerTool(Name = "docker_volume_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List local Docker volumes using fixed 'docker volume ls --format {{json .}}'. No arbitrary arguments, create, remove, prune, or other mutation is accepted.")]
    public static IReadOnlyList<JsonElement> DockerVolumeList() => RunJsonLines("volume", "ls", "--format", "{{json .}}");

    [McpServerTool(Name = "docker_network_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List local Docker networks using fixed 'docker network ls --no-trunc --format {{json .}}'. No arbitrary arguments, create, connect, disconnect, remove, prune, or other mutation is accepted.")]
    public static IReadOnlyList<JsonElement> DockerNetworkList() => RunJsonLines("network", "ls", "--no-trunc", "--format", "{{json .}}");

    private static IReadOnlyList<JsonElement> RunJsonLines(params string[] arguments)
    {
        var result = Run(arguments);
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"Docker read-only query failed with exit code {result.ExitCode}: {result.StdErr.Trim()}");

        var items = new List<JsonElement>();
        foreach (var raw in result.StdOut.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            using var doc = JsonDocument.Parse(raw);
            items.Add(doc.RootElement.Clone());
        }
        return items;
    }

    private static object? ParseJsonOrText(string text)
    {
        var value = text.Trim();
        if (value.Length == 0) return null;
        try
        {
            using var doc = JsonDocument.Parse(value);
            return doc.RootElement.Clone();
        }
        catch (JsonException)
        {
            return value;
        }
    }

    private static string? JoinErrors(params string[] errors)
    {
        var values = errors.Select(x => x.Trim()).Where(x => x.Length > 0).Distinct(StringComparer.Ordinal).ToArray();
        return values.Length == 0 ? null : string.Join(" | ", values);
    }

    private static ProcessResult Run(params string[] arguments) => Run(arguments, false);

    private static ProcessResult Run(string[] arguments, bool allowFailure)
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
            throw new TimeoutException($"Docker read-only query exceeded {Timeout.TotalSeconds:0} seconds.");
        }
        Task.WaitAll(stdoutTask, stderrTask);
        var result = new ProcessResult(process.ExitCode, stdoutTask.Result, stderrTask.Result);
        if (!allowFailure && result.ExitCode != 0)
            throw new InvalidOperationException($"Docker read-only query failed with exit code {result.ExitCode}: {result.StdErr.Trim()}");
        return result;
    }

    private static ProcessResult Run(string first, string second, string third, bool allowFailure) => Run(new[] { first, second, third }, allowFailure);
    private sealed record ProcessResult(int ExitCode, string StdOut, string StdErr);
}
