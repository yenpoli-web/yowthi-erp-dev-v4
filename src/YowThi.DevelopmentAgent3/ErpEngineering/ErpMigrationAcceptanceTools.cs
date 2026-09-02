using System.ComponentModel;
using ModelContextProtocol.Server;
using Npgsql;
using YowThi.DevelopmentAgent3.Build;

namespace YowThi.DevelopmentAgent3.ErpEngineering;

[McpServerToolType]
public static class ErpMigrationAcceptanceTools
{
    private const string DatabaseIdentity = "127.0.0.1:55432/yowthi_dev";
    private const string ExpectedDatabase = "yowthi_dev";
    private const string ExpectedUser = "yowthi_dev";
    private const string ConnectionString = "Host=127.0.0.1;Port=55432;Database=yowthi_dev;Username=yowthi_dev;SSL Mode=Disable;Timeout=5;Command Timeout=5;Application Name=YowThi.DevelopmentAgent3.ErpMigrationAcceptance;Pooling=false";

    [McpServerTool(Name = "erp_migration_acceptance", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Evaluate the ERP migration release prerequisite for one built development EF Core project/context by reusing the typed ef_migration_status capability and a fixed read-only PostgreSQL identity query against 127.0.0.1:55432/yowthi_dev. Acceptance requires a non-empty migration chain, zero pending migrations, exact fixed database/user identity, PostgreSQL 18, and non-recovery state. The result includes migration counts, applied/pending IDs, migration-state fingerprint, database identity, server version, recovery state, acceptance decision, and failure reasons. No migrations are applied, no SQL is caller-provided, no connection settings are caller-configurable, and production paths remain blocked by the typed EF input policy.")]
    public static ErpMigrationAcceptanceResult ErpMigrationAcceptance(
        string projectPath,
        string startupProjectPath,
        string contextName,
        string configuration = "Release",
        string environment = "Development")
    {
        var migration = EfMigrationTools.EfMigrationStatus(
            projectPath,
            startupProjectPath,
            contextName,
            configuration,
            environment);

        var database = ReadDatabaseIdentity();
        var failures = new List<string>();

        if (!string.Equals(migration.DatabaseIdentity, DatabaseIdentity, StringComparison.Ordinal))
            failures.Add("typed EF database identity does not match the fixed ERP development database");
        if (migration.TotalCount <= 0)
            failures.Add("migration chain is empty");
        if (migration.PendingCount != 0)
            failures.Add($"{migration.PendingCount} pending migration(s) remain");
        if (!string.Equals(database.CurrentDatabase, ExpectedDatabase, StringComparison.Ordinal))
            failures.Add("current PostgreSQL database identity is not yowthi_dev");
        if (!string.Equals(database.CurrentUser, ExpectedUser, StringComparison.Ordinal))
            failures.Add("current PostgreSQL role identity is not yowthi_dev");
        if (!database.Version.StartsWith("PostgreSQL 18", StringComparison.OrdinalIgnoreCase))
            failures.Add("PostgreSQL server major version is not 18");
        if (database.IsInRecovery)
            failures.Add("PostgreSQL development endpoint is in recovery mode");

        return new ErpMigrationAcceptanceResult(
            migration.ProjectPath,
            migration.StartupProjectPath,
            migration.ContextName,
            migration.Configuration,
            migration.Environment,
            migration.DatabaseIdentity,
            migration.TotalCount,
            migration.AppliedCount,
            migration.PendingCount,
            migration.AppliedMigrationIds,
            migration.PendingMigrationIds,
            migration.StateFingerprintSha256,
            database.Version,
            database.CurrentDatabase,
            database.CurrentUser,
            database.ServerAddress,
            database.ServerPort,
            database.IsInRecovery,
            failures.Count == 0,
            failures,
            DateTimeOffset.UtcNow);
    }

    private static DatabaseIdentityResult ReadDatabaseIdentity()
    {
        using var connection = new NpgsqlConnection(ConnectionString);
        connection.Open();
        using var command = new NpgsqlCommand(
            "select version(), current_database(), current_user, inet_server_addr()::text, inet_server_port(), pg_is_in_recovery();",
            connection);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
            throw new InvalidOperationException("ERP migration acceptance database identity query returned no row.");

        return new DatabaseIdentityResult(
            reader.GetString(0),
            reader.GetString(1),
            reader.GetString(2),
            reader.IsDBNull(3) ? null : reader.GetString(3),
            reader.IsDBNull(4) ? null : reader.GetInt32(4),
            reader.GetBoolean(5));
    }

    private sealed record DatabaseIdentityResult(
        string Version,
        string CurrentDatabase,
        string CurrentUser,
        string? ServerAddress,
        int? ServerPort,
        bool IsInRecovery);
}

public sealed record ErpMigrationAcceptanceResult(
    string ProjectPath,
    string StartupProjectPath,
    string ContextName,
    string Configuration,
    string Environment,
    string DatabaseIdentity,
    int? TotalMigrationCount,
    int? AppliedMigrationCount,
    int? PendingMigrationCount,
    IReadOnlyList<string> AppliedMigrationIds,
    IReadOnlyList<string> PendingMigrationIds,
    string? MigrationStateFingerprintSha256,
    string PostgreSqlVersion,
    string CurrentDatabase,
    string CurrentUser,
    string? ServerAddress,
    int? ServerPort,
    bool IsInRecovery,
    bool Accepted,
    IReadOnlyList<string> FailureReasons,
    DateTimeOffset CheckedUtc);