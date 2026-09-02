using System.ComponentModel;
using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using ModelContextProtocol.Server;
using Npgsql;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.Build;

[McpServerToolType]
public static class EfMigrationTools
{
    private sealed record EfDevelopmentProfile(
        string Name,
        string WorkspaceRoot,
        string Host,
        int Port,
        string Database,
        string Username)
    {
        public string DatabaseIdentity => $"{Host}:{Port}/{Database}";
        public string ConnectionString =>
            $"Host={Host};Port={Port};Database={Database};Username={Username};SSL Mode=Disable;Timeout=5;Command Timeout=30;Application Name=YowThi.DevelopmentAgent3.EfMigrationTools;Pooling=false";
    }

    private const string DevRoot = @"C:\Dev";
    private const string ProductionRoot = @"C:\yowthi-erp";
    private const string DotnetEfExe = @"C:\Users\YowThi\.dotnet\tools\dotnet-ef.exe";
    private const string DotnetEfPayload = @"C:\Users\YowThi\.dotnet\tools\.store\dotnet-ef\10.0.10\dotnet-ef\10.0.10\tools\net8.0\any\dotnet-ef.dll";
    private const string DotnetEfVersion = "10.0.10";
    private const int MaxEfOutputChars = 4_000_000;

    private static readonly EfDevelopmentProfile[] DevelopmentProfiles =
    [
        new(
            "yowthi-erp-dev-v4",
            @"C:\Dev\YowThi-ERP-Dev-v4",
            "127.0.0.1",
            55432,
            "yowthi_dev",
            "yowthi_dev"),
        new(
            "yowthi-erp-v2",
            @"C:\Dev\yowthi-erp-v2",
            "127.0.0.1",
            55432,
            "yowthi_dev",
            "yowthi_dev")
    ];

    private static readonly Regex ContextNamePattern = new(
        "^[A-Za-z_][A-Za-z0-9_.]{0,255}$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex EnvironmentPattern = new(
        "^[A-Za-z][A-Za-z0-9_.-]{0,63}$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly byte[] SigningKey = SHA256.HashData(
        Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");

    [McpServerTool(Name = "ef_migration_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List EF Core migrations for one built development project/context under C:\\Dev using the fixed dotnet-ef 10.0.10 tool and a server-side registered loopback-only development database profile resolved from the workspace root. Project/startup files, stable Debug/Release build-output fingerprints, fixed dotnet-ef shim/payload SHA-256, context, environment, and database profile identity are validated first. If the registered development database cannot be opened, the tool returns a structured database-unavailable result with an empty migrations list and null migration-state fingerprint instead of throwing a generic invocation error. Path, build, tool, reparse, and identity validation failures still fail the invocation. No caller connection string, arbitrary EF arguments, production path, build, migration creation, or database mutation is supported.")]
    public static EfMigrationListResult EfMigrationList(
        string projectPath,
        string startupProjectPath,
        string contextName,
        string configuration = "Release",
        string environment = "Development")
    {
        var input = ValidateInput(projectPath, startupProjectPath, contextName, configuration, environment);
        var identity = ReadExecutionIdentity(input);
        var database = ProbeDatabaseAvailability(input.Profile);
        RequireIdentityMatch(identity, ReadExecutionIdentity(input));

        if (!database.Available)
            return ToUnavailableListResult(input, database.FailureReason);

        var snapshot = ReadMigrationSnapshot(input, 120);
        RequireIdentityMatch(identity, ReadExecutionIdentity(input));
        return ToListResult(input, snapshot);
    }

    [McpServerTool(Name = "ef_migration_status", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Read applied/pending EF Core migration status for one built development project/context under C:\\Dev against the server-side registered loopback-only development database profile for that workspace. Project/startup files, stable build-output fingerprints, fixed dotnet-ef binaries, profile identity, context, and environment are validated first. If the registered development database cannot be opened, the tool returns a structured database-unavailable result with null migration counts/fingerprint instead of throwing a generic invocation error. Path, build, tool, reparse, and identity validation failures still fail the invocation. No caller connection string or arbitrary EF arguments are accepted.")]
    public static EfMigrationStatusResult EfMigrationStatus(
        string projectPath,
        string startupProjectPath,
        string contextName,
        string configuration = "Release",
        string environment = "Development")
    {
        var input = ValidateInput(projectPath, startupProjectPath, contextName, configuration, environment);
        var identity = ReadExecutionIdentity(input);
        var database = ProbeDatabaseAvailability(input.Profile);
        RequireIdentityMatch(identity, ReadExecutionIdentity(input));

        if (!database.Available)
        {
            return new EfMigrationStatusResult(
                input.ProjectPath,
                input.StartupProjectPath,
                input.ContextName,
                input.Configuration,
                input.Environment,
                input.Profile.DatabaseIdentity,
                "database-unavailable",
                false,
                null,
                null,
                null,
                Array.Empty<string>(),
                Array.Empty<string>(),
                null,
                database.FailureReason,
                DateTimeOffset.UtcNow);
        }

        var snapshot = ReadMigrationSnapshot(input, 120);
        RequireIdentityMatch(identity, ReadExecutionIdentity(input));
        return new EfMigrationStatusResult(
            input.ProjectPath,
            input.StartupProjectPath,
            input.ContextName,
            input.Configuration,
            input.Environment,
            input.Profile.DatabaseIdentity,
            "ok",
            true,
            snapshot.Migrations.Count,
            snapshot.Migrations.Count(x => x.Applied),
            snapshot.Migrations.Count(x => !x.Applied),
            snapshot.Migrations.Where(x => x.Applied).Select(x => x.Id).ToArray(),
            snapshot.Migrations.Where(x => !x.Applied).Select(x => x.Id).ToArray(),
            snapshot.FingerprintSha256,
            null,
            DateTimeOffset.UtcNow);
    }

    [McpServerTool(Name = "ef_database_update_plan", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to apply all currently pending EF Core migrations forward to latest for one built development project/context under C:\\Dev against only the server-side registered loopback-only development database profile for that workspace. Exact project/startup SHA-256, stable build-output fingerprints, fixed EF tool binaries, profile name/identity, environment, context, timeout, and stable migration state are sealed. No down migration, migration target, caller connection string, arbitrary arguments, build, or production path is supported.")]
    public static SignedPlan EfDatabaseUpdatePlan(
        string projectPath,
        string startupProjectPath,
        string contextName,
        string configuration = "Release",
        string environment = "Development",
        int timeoutSeconds = 600)
    {
        if (timeoutSeconds < 30 || timeoutSeconds > 1800)
            throw new ArgumentOutOfRangeException(
                nameof(timeoutSeconds),
                "Timeout must be between 30 and 1800 seconds.");

        var input = ValidateInput(projectPath, startupProjectPath, contextName, configuration, environment);
        var identity = ReadExecutionIdentity(input);
        var snapshot = ReadMigrationSnapshot(input, 120);
        RequireIdentityMatch(identity, ReadExecutionIdentity(input));

        var pending = snapshot.Migrations.Where(x => !x.Applied).Select(x => x.Id).ToArray();
        if (pending.Length == 0)
            throw new InvalidOperationException(
                "No pending EF Core migrations exist for the resolved development database profile.");

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["projectPath"] = input.ProjectPath,
            ["startupProjectPath"] = input.StartupProjectPath,
            ["contextName"] = input.ContextName,
            ["configuration"] = input.Configuration,
            ["environment"] = input.Environment,
            ["databaseProfile"] = input.Profile.Name,
            ["databaseIdentity"] = input.Profile.DatabaseIdentity,
            ["timeoutSeconds"] = timeoutSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["projectSha256"] = identity.ProjectSha256,
            ["startupProjectSha256"] = identity.StartupProjectSha256,
            ["projectBuildFingerprintSha256"] = identity.ProjectBuildFingerprintSha256,
            ["startupBuildFingerprintSha256"] = identity.StartupBuildFingerprintSha256,
            ["dotnetEfVersion"] = DotnetEfVersion,
            ["dotnetEfExeSha256"] = identity.DotnetEfExeSha256,
            ["dotnetEfPayloadSha256"] = identity.DotnetEfPayloadSha256,
            ["migrationStateSha256"] = snapshot.FingerprintSha256,
            ["pendingMigrationIds"] = string.Join("\n", pending)
        };

        var now = DateTimeOffset.UtcNow;
        var target = $"{input.Profile.DatabaseIdentity}:{input.ContextName}";
        var summary =
            $"Apply {pending.Length} pending EF Core migration(s) forward to latest in development database {input.Profile.DatabaseIdentity} for context {input.ContextName}";
        var unsigned = new SignedPlan(
            1,
            Guid.NewGuid().ToString("N"),
            Convert.ToHexString(RandomNumberGenerator.GetBytes(6)),
            "ef",
            "database-update",
            target,
            parameters,
            RiskClass.High,
            summary,
            now,
            now.AddMinutes(10),
            string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(
            signed.Tool,
            signed.Operation,
            signed.Target,
            new
            {
                signed.PlanId,
                input.Profile.Name,
                databaseIdentity = input.Profile.DatabaseIdentity,
                signed.RiskClass,
                signed.Summary,
                pendingMigrations = pending
            },
            "prepared");
        return signed;
    }

    [McpServerTool(Name = "ef_database_update_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute one previously prepared ef/database-update plan using fixed dotnet-ef database update --no-build against only the sealed server-side development database profile. Exact project/startup files, stable build-output fingerprints, fixed EF tool binaries, profile identity, environment, context, and migration state are revalidated before mutation and across post-update reads. The update is forward-to-latest only and post-execution read-back must report zero pending migrations. Arbitrary targets, down migrations, caller connection strings, arguments, builds, and production paths are not supported.")]
    public static EfDatabaseUpdateResult EfDatabaseUpdateExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, operation, target, summary, riskClass);

        var input = ReadInputFromPlan(plan);
        var expectedIdentity = ReadIdentityFromPlan(plan);
        var currentIdentity = ReadExecutionIdentity(input);
        RequireIdentityMatch(expectedIdentity, currentIdentity);

        if (!string.Equals(
                RequireParameter(plan, "databaseProfile"),
                input.Profile.Name,
                StringComparison.Ordinal))
            throw new InvalidDataException("Signed EF development database profile changed.");
        if (!string.Equals(
                RequireParameter(plan, "databaseIdentity"),
                input.Profile.DatabaseIdentity,
                StringComparison.Ordinal))
            throw new InvalidDataException("Signed EF database identity changed.");
        if (!string.Equals(
                RequireParameter(plan, "dotnetEfVersion"),
                DotnetEfVersion,
                StringComparison.Ordinal))
            throw new InvalidDataException("Signed dotnet-ef version is invalid.");
        if (!int.TryParse(RequireParameter(plan, "timeoutSeconds"), out var timeoutSeconds)
            || timeoutSeconds < 30
            || timeoutSeconds > 1800)
            throw new InvalidDataException("Signed EF timeout is invalid.");

        var before = ReadMigrationSnapshot(input, 120);
        RequireIdentityMatch(currentIdentity, ReadExecutionIdentity(input));
        if (!string.Equals(
                before.FingerprintSha256,
                RequireParameter(plan, "migrationStateSha256"),
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("EF migration state changed after plan preparation.");

        var expectedPending = RequireParameter(plan, "pendingMigrationIds")
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var currentPending = before.Migrations.Where(x => !x.Applied).Select(x => x.Id).ToArray();
        if (!expectedPending.SequenceEqual(currentPending, StringComparer.Ordinal))
            throw new InvalidOperationException("Pending EF migration set changed after plan preparation.");
        if (currentPending.Length == 0)
            throw new InvalidOperationException(
                "Signed EF database-update plan no longer has pending migrations.");

        try
        {
            var execution = RunEf(
                input,
                timeoutSeconds,
                "database",
                "update",
                "--connection",
                input.Profile.ConnectionString);
            if (execution.ExitCode != 0)
                throw new InvalidOperationException(
                    $"dotnet-ef database update failed with exit code {execution.ExitCode}. stderr: {Truncate(execution.StdErr, 4000)}");

            RequireIdentityMatch(currentIdentity, ReadExecutionIdentity(input));
            var after = ReadMigrationSnapshot(input, 120);
            RequireIdentityMatch(currentIdentity, ReadExecutionIdentity(input));

            var remainingPending = after.Migrations.Where(x => !x.Applied).Select(x => x.Id).ToArray();
            if (remainingPending.Length != 0)
                throw new InvalidOperationException(
                    "EF database update verification failed because pending migrations remain.");

            var appliedAfter = new HashSet<string>(
                after.Migrations.Where(x => x.Applied).Select(x => x.Id),
                StringComparer.Ordinal);
            if (expectedPending.Any(x => !appliedAfter.Contains(x)))
                throw new InvalidOperationException(
                    "EF database update verification failed because one or more signed pending migrations are not applied.");

            Store.Consume(planId);
            Audit.Append(
                plan.Tool,
                plan.Operation,
                plan.Target,
                new
                {
                    plan.PlanId,
                    input.Profile.Name,
                    databaseIdentity = input.Profile.DatabaseIdentity,
                    applied = expectedPending,
                    execution.ExitCode,
                    after.FingerprintSha256
                },
                "executed");

            return new EfDatabaseUpdateResult(
                plan.PlanId,
                input.ProjectPath,
                input.StartupProjectPath,
                input.ContextName,
                input.Profile.DatabaseIdentity,
                expectedPending,
                after.Migrations.Count(x => x.Applied),
                after.Migrations.Count(x => !x.Applied),
                execution.ExitCode,
                execution.StdOut,
                execution.StdErr,
                DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(
                plan.Tool,
                plan.Operation,
                plan.Target,
                new
                {
                    plan.PlanId,
                    input.Profile.Name,
                    databaseIdentity = input.Profile.DatabaseIdentity,
                    error = ex.Message
                },
                "failed");
            throw;
        }
    }

    private static EfValidatedInput ValidateInput(
        string projectPath,
        string startupProjectPath,
        string contextName,
        string configuration,
        string environment)
    {
        var project = ValidateProject(projectPath, nameof(projectPath));
        var startup = ValidateProject(startupProjectPath, nameof(startupProjectPath));

        var context = (contextName ?? string.Empty).Trim();
        if (!ContextNamePattern.IsMatch(context))
            throw new ArgumentException(
                "contextName must be a simple or namespace-qualified .NET type name.",
                nameof(contextName));

        var config = (configuration ?? string.Empty).Trim();
        if (config is not ("Debug" or "Release"))
            throw new ArgumentException(
                "configuration must be Debug or Release.",
                nameof(configuration));

        var env = (environment ?? string.Empty).Trim();
        if (!EnvironmentPattern.IsMatch(env))
            throw new ArgumentException(
                "environment contains unsupported characters.",
                nameof(environment));

        var profile = ResolveDevelopmentProfile(project, startup);
        RequireEfTool();
        return new EfValidatedInput(project, startup, context, config, env, profile);
    }

    private static string ValidateProject(string path, string parameterName)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            throw new ArgumentException("Project path must be absolute.", parameterName);

        var full = Path.GetFullPath(path);
        if (!File.Exists(full))
            throw new FileNotFoundException("EF project file does not exist.", full);
        if (!string.Equals(Path.GetExtension(full), ".csproj", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("EF project/startup targets must be .csproj files.");

        if (!IsWithinRoot(full, DevRoot))
            throw new UnauthorizedAccessException(
                "EF project/startup paths must remain under the C:\\Dev development workspace root.");
        if (IsWithinRoot(full, ProductionRoot))
            throw new UnauthorizedAccessException("Production ERP paths are blocked.");

        RequireNoReparseTraversal(full, DevRoot);
        return full;
    }

    private static EfDevelopmentProfile ResolveDevelopmentProfile(
        string projectPath,
        string startupProjectPath)
    {
        var projectMatches = DevelopmentProfiles
            .Where(profile => IsWithinRoot(projectPath, profile.WorkspaceRoot))
            .OrderByDescending(profile => profile.WorkspaceRoot.Length)
            .ToArray();
        var startupMatches = DevelopmentProfiles
            .Where(profile => IsWithinRoot(startupProjectPath, profile.WorkspaceRoot))
            .OrderByDescending(profile => profile.WorkspaceRoot.Length)
            .ToArray();

        if (projectMatches.Length == 0)
            throw new InvalidOperationException(
                $"No server-side EF development database profile is registered for project workspace: {projectPath}");
        if (startupMatches.Length == 0)
            throw new InvalidOperationException(
                $"No server-side EF development database profile is registered for startup workspace: {startupProjectPath}");
        if (!string.Equals(projectMatches[0].Name, startupMatches[0].Name, StringComparison.Ordinal))
            throw new InvalidOperationException(
                "EF project and startup project must resolve to the same server-side development database profile.");

        var profile = projectMatches[0];
        if (!IsLoopbackHost(profile.Host))
            throw new InvalidOperationException(
                "EF development database profiles must use a loopback host.");
        if (profile.Port < 1 || profile.Port > 65535)
            throw new InvalidOperationException(
                "EF development database profile port is invalid.");
        if (string.IsNullOrWhiteSpace(profile.Database) || string.IsNullOrWhiteSpace(profile.Username))
            throw new InvalidOperationException(
                "EF development database profile identity is incomplete.");

        return profile;
    }

    private static EfDatabaseAvailability ProbeDatabaseAvailability(EfDevelopmentProfile profile)
    {
        try
        {
            using var connection = new NpgsqlConnection(profile.ConnectionString);
            connection.Open();
            return new EfDatabaseAvailability(true, null);
        }
        catch (PostgresException ex)
        {
            return new EfDatabaseAvailability(
                false,
                $"PostgreSQL rejected the registered development database profile {profile.DatabaseIdentity} (SQLSTATE {ex.SqlState}).");
        }
        catch (NpgsqlException ex) when (ex.InnerException is SocketException socket)
        {
            return new EfDatabaseAvailability(
                false,
                $"Development database {profile.DatabaseIdentity} is unavailable ({NormalizeSocketError(socket.SocketErrorCode)}).");
        }
        catch (NpgsqlException)
        {
            return new EfDatabaseAvailability(
                false,
                $"Development database {profile.DatabaseIdentity} could not be opened using the registered server-side profile.");
        }
        catch (SocketException ex)
        {
            return new EfDatabaseAvailability(
                false,
                $"Development database {profile.DatabaseIdentity} is unavailable ({NormalizeSocketError(ex.SocketErrorCode)}).");
        }
        catch (TimeoutException)
        {
            return new EfDatabaseAvailability(
                false,
                $"Development database {profile.DatabaseIdentity} connection timed out.");
        }
    }

    private static string NormalizeSocketError(SocketError error)
        => error switch
        {
            SocketError.ConnectionRefused => "connection-refused",
            SocketError.HostNotFound => "host-not-found",
            SocketError.TimedOut => "timeout",
            SocketError.NetworkUnreachable => "network-unreachable",
            SocketError.HostUnreachable => "host-unreachable",
            _ => $"socket-{error}"
        };

    private static bool IsLoopbackHost(string host)
        => string.Equals(host, "127.0.0.1", StringComparison.OrdinalIgnoreCase)
            || string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
            || string.Equals(host, "::1", StringComparison.OrdinalIgnoreCase);

    private static bool IsWithinRoot(string path, string rootPath)
    {
        var root = Path.GetFullPath(rootPath)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var full = Path.GetFullPath(path);
        return string.Equals(full, root, StringComparison.OrdinalIgnoreCase)
            || full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static void RequireNoReparseTraversal(string filePath, string rootPath)
    {
        if ((File.GetAttributes(filePath) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Reparse-point project files are not allowed.");

        var root = Path.GetFullPath(rootPath)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var directory = new DirectoryInfo(Path.GetDirectoryName(filePath)!);
        while (directory is not null)
        {
            if ((directory.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException(
                    "Reparse-point traversal is not allowed for EF project paths.");
            if (string.Equals(
                    directory.FullName.TrimEnd(
                        Path.DirectorySeparatorChar,
                        Path.AltDirectorySeparatorChar),
                    root,
                    StringComparison.OrdinalIgnoreCase))
                return;
            directory = directory.Parent;
        }

        throw new UnauthorizedAccessException("EF project path root validation failed.");
    }

    private static void RequireEfTool()
    {
        if (!File.Exists(DotnetEfExe))
            throw new FileNotFoundException(
                "Fixed dotnet-ef executable is missing.",
                DotnetEfExe);
        if (!File.Exists(DotnetEfPayload))
            throw new FileNotFoundException(
                "Fixed dotnet-ef payload is missing.",
                DotnetEfPayload);
        if ((File.GetAttributes(DotnetEfExe) & FileAttributes.ReparsePoint) != 0
            || (File.GetAttributes(DotnetEfPayload) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException(
                "Fixed dotnet-ef binaries may not be reparse points.");
    }

    private static EfExecutionIdentity ReadExecutionIdentity(EfValidatedInput input)
        => new(
            Sha256File(input.ProjectPath),
            Sha256File(input.StartupProjectPath),
            ComputeBuildFingerprint(input.ProjectPath, input.Configuration),
            ComputeBuildFingerprint(input.StartupProjectPath, input.Configuration),
            Sha256File(DotnetEfExe),
            Sha256File(DotnetEfPayload));

    private static string ComputeBuildFingerprint(string projectPath, string configuration)
    {
        var projectDirectory = Path.GetDirectoryName(projectPath)!;
        var buildRoot = Path.Combine(projectDirectory, "bin", configuration);
        if (!Directory.Exists(buildRoot))
            throw new DirectoryNotFoundException(
                $"Built output directory does not exist: {buildRoot}. Build the project before using EF tools.");
        if ((File.GetAttributes(buildRoot) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException(
                "Reparse-point build output directories are not allowed.");

        var files = EnumerateBuildFiles(buildRoot)
            .Where(file => !IsEfDesignBuildHostFile(buildRoot, file))
            .OrderBy(file => Path.GetRelativePath(buildRoot, file), StringComparer.Ordinal)
            .ToArray();
        if (files.Length == 0)
            throw new InvalidOperationException(
                $"Stable built output directory is empty: {buildRoot}.");

        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var file in files)
        {
            var relative = Path.GetRelativePath(buildRoot, file).Replace('\\', '/');
            hash.AppendData(Encoding.UTF8.GetBytes(relative));
            hash.AppendData(new byte[] { 0 });
            hash.AppendData(BitConverter.GetBytes(new FileInfo(file).Length));
            using var stream = new FileStream(
                file,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read);
            hash.AppendData(SHA256.HashData(stream));
        }

        return Convert.ToHexString(hash.GetHashAndReset());
    }

    private static IEnumerable<string> EnumerateBuildFiles(string buildRoot)
    {
        var stack = new Stack<string>();
        stack.Push(buildRoot);
        while (stack.Count > 0)
        {
            var current = stack.Pop();
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException(
                    "Reparse-point build output directories are not allowed.");

            foreach (var entry in Directory.EnumerateFileSystemEntries(current))
            {
                var attributes = File.GetAttributes(entry);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                    throw new UnauthorizedAccessException(
                        "Reparse-point build output entries are not allowed.");
                if ((attributes & FileAttributes.Directory) != 0)
                    stack.Push(entry);
                else
                    yield return entry;
            }
        }
    }

    private static bool IsEfDesignBuildHostFile(string buildRoot, string file)
    {
        var relative = Path.GetRelativePath(buildRoot, file).Replace('\\', '/');
        return relative.StartsWith("BuildHost-net472/", StringComparison.OrdinalIgnoreCase)
            || relative.StartsWith("BuildHost-netcore/", StringComparison.OrdinalIgnoreCase);
    }

    private static EfMigrationSnapshot ReadMigrationSnapshot(
        EfValidatedInput input,
        int timeoutSeconds)
    {
        var execution = RunEf(
            input,
            timeoutSeconds,
            "migrations",
            "list",
            "--connection",
            input.Profile.ConnectionString,
            "--json");

        if (execution.ExitCode != 0)
            throw new InvalidOperationException(
                $"dotnet-ef migrations list failed with exit code {execution.ExitCode}. stderr: {Truncate(execution.StdErr, 4000)}");

        var json = ExtractJsonArray(execution.StdOut);
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException(
                "dotnet-ef migrations list JSON root is not an array.");

        var migrations = new List<EfMigrationEntry>();
        foreach (var item in document.RootElement.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException(
                    "dotnet-ef migration JSON contains a non-object entry.");

            var id = RequireJsonString(item, "id");
            var name = RequireJsonString(item, "name");
            if (!TryGetJsonBoolean(item, "applied", out var applied))
                throw new InvalidDataException(
                    "dotnet-ef migration JSON does not contain a boolean applied state.");

            migrations.Add(new EfMigrationEntry(id, name, applied));
        }

        if (migrations.Select(x => x.Id).Distinct(StringComparer.Ordinal).Count() != migrations.Count)
            throw new InvalidDataException(
                "dotnet-ef migration JSON contains duplicate migration IDs.");

        migrations.Sort((a, b) => StringComparer.Ordinal.Compare(a.Id, b.Id));
        var canonical = string.Join(
            "\n",
            migrations.Select(x => $"{x.Id}|{x.Name}|{(x.Applied ? "1" : "0")}"));
        return new EfMigrationSnapshot(
            migrations,
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))));
    }

    private static EfProcessResult RunEf(
        EfValidatedInput input,
        int timeoutSeconds,
        params string[] commandArguments)
    {
        var projectDirectory = Path.GetDirectoryName(input.ProjectPath)!;
        var startupDirectory = Path.GetDirectoryName(input.StartupProjectPath)!;

        var psi = new ProcessStartInfo
        {
            FileName = DotnetEfExe,
            WorkingDirectory = startupDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            CreateNoWindow = true
        };

        foreach (var argument in commandArguments)
            psi.ArgumentList.Add(argument);

        psi.ArgumentList.Add("--project");
        psi.ArgumentList.Add(projectDirectory);
        psi.ArgumentList.Add("--startup-project");
        psi.ArgumentList.Add(startupDirectory);
        psi.ArgumentList.Add("--context");
        psi.ArgumentList.Add(input.ContextName);
        psi.ArgumentList.Add("--configuration");
        psi.ArgumentList.Add(input.Configuration);
        psi.ArgumentList.Add("--no-build");
        psi.ArgumentList.Add("--no-color");

        psi.Environment["DOTNET_ENVIRONMENT"] = input.Environment;
        psi.Environment["ASPNETCORE_ENVIRONMENT"] = input.Environment;
        psi.Environment["DOTNET_CLI_UI_LANGUAGE"] = "en-US";
        psi.Environment["DOTNET_NOLOGO"] = "1";
        psi.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("dotnet-ef process failed to start.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));

        try
        {
            process.WaitForExitAsync(cts.Token).GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
            try
            {
                if (!process.HasExited)
                    process.Kill(entireProcessTree: true);
            }
            catch
            {
            }

            try
            {
                process.WaitForExit(5000);
            }
            catch
            {
            }

            throw new TimeoutException(
                $"dotnet-ef operation exceeded {timeoutSeconds} seconds.");
        }

        var stdout = stdoutTask.GetAwaiter().GetResult();
        var stderr = stderrTask.GetAwaiter().GetResult();
        if (stdout.Length > MaxEfOutputChars || stderr.Length > MaxEfOutputChars)
            throw new InvalidDataException(
                "dotnet-ef output exceeded the fixed safe output limit.");

        return new EfProcessResult(process.ExitCode, stdout, stderr);
    }

    private static string ExtractJsonArray(string stdout)
    {
        var text = (stdout ?? string.Empty).Trim().TrimStart('\uFEFF');
        if (text.Length == 0)
            throw new InvalidDataException(
                "dotnet-ef returned empty stdout instead of JSON.");

        if (IsCompleteJsonArray(text))
            return text;

        var candidateStarts = new List<int>();
        for (var i = 0; i < text.Length; i++)
        {
            if (text[i] != '[')
                continue;
            if (i == 0 || text[i - 1] == '\n' || text[i - 1] == '\r')
                candidateStarts.Add(i);
        }

        for (var i = candidateStarts.Count - 1; i >= 0; i--)
        {
            var candidate = text[candidateStarts[i]..].Trim();
            if (IsCompleteJsonArray(candidate))
                return candidate;
        }

        throw new InvalidDataException(
            $"dotnet-ef did not return one complete top-level JSON migration array. stdout: {Truncate(text, 4000)}");
    }

    private static bool IsCompleteJsonArray(string candidate)
    {
        try
        {
            using var document = JsonDocument.Parse(candidate);
            return document.RootElement.ValueKind == JsonValueKind.Array;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static string RequireJsonString(JsonElement element, string propertyName)
    {
        foreach (var property in element.EnumerateObject())
        {
            if (string.Equals(
                    property.Name,
                    propertyName,
                    StringComparison.OrdinalIgnoreCase)
                && property.Value.ValueKind == JsonValueKind.String)
                return property.Value.GetString()
                    ?? throw new InvalidDataException(
                        $"EF migration JSON property {propertyName} is null.");
        }

        throw new InvalidDataException(
            $"EF migration JSON property {propertyName} is missing.");
    }

    private static bool TryGetJsonBoolean(
        JsonElement element,
        string propertyName,
        out bool value)
    {
        foreach (var property in element.EnumerateObject())
        {
            if (!string.Equals(
                    property.Name,
                    propertyName,
                    StringComparison.OrdinalIgnoreCase))
                continue;
            if (property.Value.ValueKind is JsonValueKind.True or JsonValueKind.False)
            {
                value = property.Value.GetBoolean();
                return true;
            }
        }

        value = false;
        return false;
    }

    private static EfMigrationListResult ToListResult(
        EfValidatedInput input,
        EfMigrationSnapshot snapshot)
        => new(
            input.ProjectPath,
            input.StartupProjectPath,
            input.ContextName,
            input.Configuration,
            input.Environment,
            input.Profile.DatabaseIdentity,
            "ok",
            true,
            snapshot.Migrations.ToArray(),
            snapshot.FingerprintSha256,
            null,
            DateTimeOffset.UtcNow);

    private static EfMigrationListResult ToUnavailableListResult(
        EfValidatedInput input,
        string? failureReason)
        => new(
            input.ProjectPath,
            input.StartupProjectPath,
            input.ContextName,
            input.Configuration,
            input.Environment,
            input.Profile.DatabaseIdentity,
            "database-unavailable",
            false,
            Array.Empty<EfMigrationEntry>(),
            null,
            failureReason,
            DateTimeOffset.UtcNow);

    private static EfValidatedInput ReadInputFromPlan(SignedPlan plan)
        => ValidateInput(
            RequireParameter(plan, "projectPath"),
            RequireParameter(plan, "startupProjectPath"),
            RequireParameter(plan, "contextName"),
            RequireParameter(plan, "configuration"),
            RequireParameter(plan, "environment"));

    private static EfExecutionIdentity ReadIdentityFromPlan(SignedPlan plan)
        => new(
            RequireParameter(plan, "projectSha256"),
            RequireParameter(plan, "startupProjectSha256"),
            RequireParameter(plan, "projectBuildFingerprintSha256"),
            RequireParameter(plan, "startupBuildFingerprintSha256"),
            RequireParameter(plan, "dotnetEfExeSha256"),
            RequireParameter(plan, "dotnetEfPayloadSha256"));

    private static void RequireIdentityMatch(
        EfExecutionIdentity expected,
        EfExecutionIdentity current)
    {
        if (!string.Equals(expected.ProjectSha256, current.ProjectSha256, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(expected.StartupProjectSha256, current.StartupProjectSha256, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(expected.ProjectBuildFingerprintSha256, current.ProjectBuildFingerprintSha256, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(expected.StartupBuildFingerprintSha256, current.StartupBuildFingerprintSha256, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(expected.DotnetEfExeSha256, current.DotnetEfExeSha256, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(expected.DotnetEfPayloadSha256, current.DotnetEfPayloadSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException(
                "EF project/startup/build/tool identity changed during the typed EF operation.");
    }

    private static void RequireIntentMatch(
        SignedPlan plan,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        if (!string.Equals(plan.Tool, "ef", StringComparison.Ordinal)
            || !string.Equals(plan.Operation, "database-update", StringComparison.Ordinal)
            || !string.Equals(plan.Operation, operation, StringComparison.Ordinal)
            || !string.Equals(plan.Target, target, StringComparison.Ordinal)
            || !string.Equals(plan.Summary, summary, StringComparison.Ordinal)
            || !string.Equals(
                plan.RiskClass.ToString(),
                riskClass,
                StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
    }

    private static string RequireParameter(SignedPlan plan, string key)
        => plan.Parameters.TryGetValue(key, out var value)
            && !string.IsNullOrWhiteSpace(value)
                ? value
                : throw new InvalidDataException(
                    $"Signed EF parameter {key} is required.");

    private static string Sha256File(string path)
    {
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static string Truncate(string value, int length)
        => value.Length <= length ? value : value[..length];

    private sealed record EfValidatedInput(
        string ProjectPath,
        string StartupProjectPath,
        string ContextName,
        string Configuration,
        string Environment,
        EfDevelopmentProfile Profile);

    private sealed record EfExecutionIdentity(
        string ProjectSha256,
        string StartupProjectSha256,
        string ProjectBuildFingerprintSha256,
        string StartupBuildFingerprintSha256,
        string DotnetEfExeSha256,
        string DotnetEfPayloadSha256);

    private sealed record EfMigrationSnapshot(
        List<EfMigrationEntry> Migrations,
        string FingerprintSha256);

    private sealed record EfProcessResult(
        int ExitCode,
        string StdOut,
        string StdErr);

    private sealed record EfDatabaseAvailability(
        bool Available,
        string? FailureReason);
}

public sealed record EfMigrationEntry(string Id, string Name, bool Applied);

public sealed record EfMigrationListResult(
    string ProjectPath,
    string StartupProjectPath,
    string ContextName,
    string Configuration,
    string Environment,
    string DatabaseIdentity,
    string Status,
    bool DatabaseAvailable,
    IReadOnlyList<EfMigrationEntry> Migrations,
    string? StateFingerprintSha256,
    string? FailureReason,
    DateTimeOffset CheckedUtc);

public sealed record EfMigrationStatusResult(
    string ProjectPath,
    string StartupProjectPath,
    string ContextName,
    string Configuration,
    string Environment,
    string DatabaseIdentity,
    string Status,
    bool DatabaseAvailable,
    int? TotalCount,
    int? AppliedCount,
    int? PendingCount,
    IReadOnlyList<string> AppliedMigrationIds,
    IReadOnlyList<string> PendingMigrationIds,
    string? StateFingerprintSha256,
    string? FailureReason,
    DateTimeOffset CheckedUtc);

public sealed record EfDatabaseUpdateResult(
    string PlanId,
    string ProjectPath,
    string StartupProjectPath,
    string ContextName,
    string DatabaseIdentity,
    IReadOnlyList<string> AppliedMigrationIds,
    int AppliedCountAfter,
    int PendingCountAfter,
    int ExitCode,
    string StdOut,
    string StdErr,
    DateTimeOffset ExecutedUtc);