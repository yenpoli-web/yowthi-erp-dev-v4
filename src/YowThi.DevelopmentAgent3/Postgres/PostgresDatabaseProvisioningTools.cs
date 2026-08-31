using System.ComponentModel;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using ModelContextProtocol.Server;
using Npgsql;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.Postgres;

[McpServerToolType]
public static class PostgresDatabaseProvisioningTools
{
    private const string Host = "127.0.0.1";
    private const int Port = 55432;
    private const string MaintenanceDatabase = "postgres";
    private const string ExpectedOwner = "yowthi_dev";
    private const string FixedEncoding = "UTF8";
    private const string FixedTemplate = "template0";
    private static readonly Regex MutableDatabaseName = new("^dev_[a-z][a-z0-9_]{0,46}$", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");

    [McpServerTool(Name = "postgres_database_inspect", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Inspect one database in the fixed local PostgreSQL 18 development cluster at 127.0.0.1:55432 using Npgsql and fixed catalog queries. The result includes database owner, encoding, locale, template/connection flags, active sessions, and non-system object count when the database accepts connections. Host, port, role, SQL, and connection string are not caller-configurable. This is read-only.")]
    public static PostgresDatabaseInspectResult PostgresDatabaseInspect(string databaseName)
    {
        var name = RequireInspectableDatabaseName(databaseName);
        var cluster = ReadClusterIdentity();
        var snapshot = ReadDatabaseSnapshot(name, includeObjectCount: true);
        if (!snapshot.Exists)
            throw new InvalidOperationException($"PostgreSQL database '{name}' does not exist on the fixed development cluster.");
        return ToInspectResult(cluster, snapshot);
    }

    [McpServerTool(Name = "postgres_database_create_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to create one empty development database in the fixed PostgreSQL cluster at 127.0.0.1:55432. Only names matching dev_[a-z][a-z0-9_]{0,46} are accepted. Owner is fixed to yowthi_dev, template is fixed to template0, and encoding is fixed to UTF8. Caller-selected owner, template, locale, tablespace, connection limit, SQL, host, port, role, or connection string are not supported. Cluster/role/template identity and target absence are sealed.")]
    public static SignedPlan PostgresDatabaseCreatePlan(string databaseName)
    {
        var name = RequireMutableDatabaseName(databaseName);
        var cluster = ReadClusterIdentity();
        RequireProvisioningRole(cluster);
        var target = ReadDatabaseSnapshot(name, includeObjectCount: false);
        if (target.Exists)
            throw new InvalidOperationException($"PostgreSQL database '{name}' already exists.");
        var template = ReadDatabaseSnapshot(FixedTemplate, includeObjectCount: false);
        if (!template.Exists || !template.IsTemplate || template.AllowConnections)
            throw new InvalidOperationException("Fixed PostgreSQL template0 identity is not in the expected template/non-connectable state.");
        if (!string.Equals(template.Encoding, FixedEncoding, StringComparison.Ordinal))
            throw new InvalidOperationException($"Fixed PostgreSQL template0 encoding is {template.Encoding}; expected {FixedEncoding}.");

        return CreatePlan(
            "database-create",
            name,
            cluster,
            target,
            template,
            RiskClass.High,
            $"Create empty PostgreSQL development database {name} from fixed template0 with owner {ExpectedOwner} and UTF8 encoding");
    }

    [McpServerTool(Name = "postgres_database_create_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared postgres/database-create plan against only the fixed local PostgreSQL development cluster. Cluster/role/template identity and target absence are revalidated before fixed CREATE DATABASE semantics run with owner yowthi_dev, template0, and UTF8. Post-create read-back must prove the database is non-template, connectable, owned by yowthi_dev, locale-matched to sealed template0, has zero active sessions, and contains zero non-system objects. Arbitrary SQL and caller-selected database options are not supported.")]
    public static PostgresDatabaseMutationResult PostgresDatabaseCreateExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "database-create", operation, target, summary, riskClass);
        var name = RequireMutableDatabaseName(RequireParameter(plan, "databaseName"));
        var cluster = ReadClusterIdentity();
        RevalidateCluster(plan, cluster);
        RequireProvisioningRole(cluster);

        var before = ReadDatabaseSnapshot(name, includeObjectCount: false);
        if (before.Exists || !string.Equals(RequireParameter(plan, "exists"), "false", StringComparison.Ordinal))
            throw new InvalidOperationException("PostgreSQL database target existence changed after plan preparation.");

        var template = ReadDatabaseSnapshot(FixedTemplate, includeObjectCount: false);
        RevalidateTemplate(plan, template);

        try
        {
            using var connection = OpenMaintenanceConnection();
            using var command = new NpgsqlCommand(
                $"CREATE DATABASE \"{name}\" WITH OWNER = \"{ExpectedOwner}\" TEMPLATE = {FixedTemplate} ENCODING = '{FixedEncoding}'",
                connection)
            {
                CommandTimeout = 30
            };
            command.ExecuteNonQuery();

            var after = ReadDatabaseSnapshot(name, includeObjectCount: true);
            ValidateCreatedDatabase(after, template);
            Store.Consume(planId);
            var outcome = $"database-created:{name}";
            Audit.Append(plan.Tool, plan.Operation, plan.Target,
                new { plan.PlanId, outcome, owner = after.Owner, after.Encoding, after.Collation, after.CType },
                "executed");
            return new PostgresDatabaseMutationResult(plan.PlanId, name, outcome, ToInspectResult(cluster, after), DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    [McpServerTool(Name = "postgres_database_drop_plan", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to drop one empty development database from the fixed PostgreSQL cluster. Only names matching dev_[a-z][a-z0-9_]{0,46} are accepted. The database must exist, be owned by yowthi_dev, be non-template and connectable, have zero active sessions, and contain zero non-system objects. WITH (FORCE), session termination, arbitrary SQL, system/default databases, and caller-selected connection settings are not supported. Full database and cluster state is sealed.")]
    public static SignedPlan PostgresDatabaseDropPlan(string databaseName)
    {
        var name = RequireMutableDatabaseName(databaseName);
        var cluster = ReadClusterIdentity();
        RequireProvisioningRole(cluster);
        var snapshot = ReadDatabaseSnapshot(name, includeObjectCount: true);
        RequireDropEligible(snapshot);
        return CreatePlan(
            "database-drop",
            name,
            cluster,
            snapshot,
            template: null,
            RiskClass.High,
            $"Drop empty PostgreSQL development database {name} without FORCE or session termination");
    }

    [McpServerTool(Name = "postgres_database_drop_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute one previously prepared postgres/database-drop plan using fixed DROP DATABASE semantics without FORCE. The exact database, owner, encoding/locale, template/connectability flags, active-session count, non-system object count, cluster identity, and provisioning role are revalidated before mutation. A second active-session check is performed immediately before DROP DATABASE. Post-drop read-back must prove absence. Arbitrary SQL, session termination, and forced drop are not supported.")]
    public static PostgresDatabaseMutationResult PostgresDatabaseDropExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "database-drop", operation, target, summary, riskClass);
        var name = RequireMutableDatabaseName(RequireParameter(plan, "databaseName"));
        var cluster = ReadClusterIdentity();
        RevalidateCluster(plan, cluster);
        RequireProvisioningRole(cluster);

        var current = ReadDatabaseSnapshot(name, includeObjectCount: true);
        var expected = ReadSnapshot(plan);
        RequireSnapshotMatch(expected, current);
        RequireDropEligible(current);
        if (ReadActiveSessions(name) != 0)
            throw new InvalidOperationException("PostgreSQL database gained an active session immediately before drop.");

        try
        {
            using var connection = OpenMaintenanceConnection();
            using var command = new NpgsqlCommand($"DROP DATABASE \"{name}\"", connection) { CommandTimeout = 30 };
            command.ExecuteNonQuery();
            var after = ReadDatabaseSnapshot(name, includeObjectCount: false);
            if (after.Exists)
                throw new InvalidOperationException("PostgreSQL database drop read-back verification failed.");
            Store.Consume(planId);
            var outcome = $"database-dropped:{name}";
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, outcome }, "executed");
            return new PostgresDatabaseMutationResult(plan.PlanId, name, outcome, null, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    private static SignedPlan CreatePlan(
        string operation,
        string databaseName,
        ClusterIdentity cluster,
        DatabaseSnapshot snapshot,
        DatabaseSnapshot? template,
        RiskClass riskClass,
        string summary)
    {
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["databaseName"] = databaseName,
            ["clusterFingerprintSha256"] = cluster.FingerprintSha256,
            ["serverVersion"] = cluster.ServerVersion,
            ["serverAddress"] = cluster.ServerAddress,
            ["serverPort"] = cluster.ServerPort.ToString(CultureInfo.InvariantCulture),
            ["postmasterStartUtc"] = cluster.PostmasterStartUtc,
            ["roleName"] = cluster.RoleName,
            ["roleOid"] = cluster.RoleOid.ToString(CultureInfo.InvariantCulture),
            ["roleSuperuser"] = cluster.RoleSuperuser ? "true" : "false",
            ["roleCreateDb"] = cluster.RoleCreateDb ? "true" : "false",
            ["exists"] = snapshot.Exists ? "true" : "false",
            ["owner"] = snapshot.Owner ?? string.Empty,
            ["encoding"] = snapshot.Encoding ?? string.Empty,
            ["collation"] = snapshot.Collation ?? string.Empty,
            ["ctype"] = snapshot.CType ?? string.Empty,
            ["allowConnections"] = snapshot.AllowConnections ? "true" : "false",
            ["isTemplate"] = snapshot.IsTemplate ? "true" : "false",
            ["connectionLimit"] = snapshot.ConnectionLimit.ToString(CultureInfo.InvariantCulture),
            ["activeSessions"] = snapshot.ActiveSessions.ToString(CultureInfo.InvariantCulture),
            ["nonSystemObjectCount"] = snapshot.NonSystemObjectCount.ToString(CultureInfo.InvariantCulture)
        };
        if (template is not null)
        {
            parameters["templateName"] = FixedTemplate;
            parameters["templateEncoding"] = template.Encoding ?? string.Empty;
            parameters["templateCollation"] = template.Collation ?? string.Empty;
            parameters["templateCType"] = template.CType ?? string.Empty;
            parameters["templateIsTemplate"] = template.IsTemplate ? "true" : "false";
            parameters["templateAllowConnections"] = template.AllowConnections ? "true" : "false";
        }

        var now = DateTimeOffset.UtcNow;
        var unsigned = new SignedPlan(
            1,
            Guid.NewGuid().ToString("N"),
            Convert.ToHexString(RandomNumberGenerator.GetBytes(6)),
            "postgres",
            operation,
            databaseName,
            parameters,
            riskClass,
            summary,
            now,
            now.AddMinutes(10),
            string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target,
            new { signed.PlanId, signed.RiskClass, signed.Summary, cluster = cluster.FingerprintSha256 },
            "prepared");
        return signed;
    }

    private static ClusterIdentity ReadClusterIdentity()
    {
        using var connection = OpenMaintenanceConnection();
        const string sql = "select version(), inet_server_addr()::text, inet_server_port(), pg_postmaster_start_time()::text, r.oid::bigint, r.rolname, r.rolsuper, r.rolcreatedb from pg_roles r where r.rolname=current_user;";
        using var command = new NpgsqlCommand(sql, connection);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
            throw new InvalidOperationException("PostgreSQL cluster identity query returned no role row.");
        var version = reader.GetString(0);
        var address = reader.IsDBNull(1) ? Host : reader.GetString(1);
        var serverPort = reader.IsDBNull(2) ? Port : reader.GetInt32(2);
        var postmasterStart = reader.GetString(3);
        var roleOid = reader.GetInt64(4);
        var roleName = reader.GetString(5);
        var roleSuperuser = reader.GetBoolean(6);
        var roleCreateDb = reader.GetBoolean(7);
        var canonical = string.Join("\n", version, address, serverPort.ToString(CultureInfo.InvariantCulture), postmasterStart, roleOid.ToString(CultureInfo.InvariantCulture), roleName, roleSuperuser, roleCreateDb);
        return new ClusterIdentity(version, address, serverPort, postmasterStart, roleOid, roleName, roleSuperuser, roleCreateDb, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))));
    }

    private static DatabaseSnapshot ReadDatabaseSnapshot(string databaseName, bool includeObjectCount)
    {
        var name = RequireInspectableDatabaseName(databaseName);
        using var connection = OpenMaintenanceConnection();
        const string sql = "select d.datname, pg_get_userbyid(d.datdba), pg_encoding_to_char(d.encoding), d.datcollate, d.datctype, d.datallowconn, d.datistemplate, d.datconnlimit, (select count(*)::int from pg_stat_activity a where a.datname=d.datname) from pg_database d where d.datname=@name;";
        using var command = new NpgsqlCommand(sql, connection);
        command.Parameters.AddWithValue("name", name);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
            return DatabaseSnapshot.Absent(name);
        var snapshot = new DatabaseSnapshot(
            reader.GetString(0),
            true,
            reader.GetString(1),
            reader.GetString(2),
            reader.GetString(3),
            reader.GetString(4),
            reader.GetBoolean(5),
            reader.GetBoolean(6),
            reader.GetInt32(7),
            reader.GetInt32(8),
            0);
        reader.Close();

        if (includeObjectCount && snapshot.AllowConnections)
            snapshot = snapshot with { NonSystemObjectCount = ReadNonSystemObjectCount(name) };
        return snapshot;
    }

    private static int ReadActiveSessions(string databaseName)
    {
        using var connection = OpenMaintenanceConnection();
        using var command = new NpgsqlCommand("select count(*)::int from pg_stat_activity where datname=@name;", connection);
        command.Parameters.AddWithValue("name", RequireInspectableDatabaseName(databaseName));
        return (int)(command.ExecuteScalar() ?? 0);
    }

    private static int ReadNonSystemObjectCount(string databaseName)
    {
        using var connection = OpenDatabaseConnection(databaseName);
        const string sql = "select ((select count(*) from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname not in ('pg_catalog','information_schema') and n.nspname not like 'pg_toast%' and c.relkind in ('r','p','v','m','S','f')) + (select count(*) from pg_proc p join pg_namespace n on n.oid=p.pronamespace where n.nspname not in ('pg_catalog','information_schema') and n.nspname not like 'pg_toast%') + (select count(*) from pg_type t join pg_namespace n on n.oid=t.typnamespace where n.nspname not in ('pg_catalog','information_schema') and n.nspname not like 'pg_toast%' and t.typtype in ('c','d','e','r')))::int;";
        using var command = new NpgsqlCommand(sql, connection);
        return (int)(command.ExecuteScalar() ?? 0);
    }

    private static NpgsqlConnection OpenMaintenanceConnection() => OpenDatabaseConnection(MaintenanceDatabase);

    private static NpgsqlConnection OpenDatabaseConnection(string databaseName)
    {
        var builder = new NpgsqlConnectionStringBuilder
        {
            Host = Host,
            Port = Port,
            Database = RequireInspectableDatabaseName(databaseName),
            Username = ExpectedOwner,
            SslMode = SslMode.Disable,
            Timeout = 5,
            CommandTimeout = 10,
            ApplicationName = "YowThi.DevelopmentAgent3.PostgresDatabaseProvisioningTools",
            Pooling = false
        };
        var connection = new NpgsqlConnection(builder.ConnectionString);
        connection.Open();
        return connection;
    }

    private static void RequireProvisioningRole(ClusterIdentity cluster)
    {
        if (!string.Equals(cluster.RoleName, ExpectedOwner, StringComparison.Ordinal))
            throw new UnauthorizedAccessException($"Fixed PostgreSQL provisioning role is {cluster.RoleName}; expected {ExpectedOwner}.");
        if (!cluster.RoleSuperuser && !cluster.RoleCreateDb)
            throw new UnauthorizedAccessException($"PostgreSQL role {ExpectedOwner} does not have CREATEDB capability.");
    }

    private static void RequireDropEligible(DatabaseSnapshot snapshot)
    {
        if (!snapshot.Exists)
            throw new InvalidOperationException($"PostgreSQL database '{snapshot.Name}' does not exist.");
        RequireMutableDatabaseName(snapshot.Name);
        if (!string.Equals(snapshot.Owner, ExpectedOwner, StringComparison.Ordinal))
            throw new InvalidOperationException($"PostgreSQL database '{snapshot.Name}' is not owned by {ExpectedOwner}.");
        if (snapshot.IsTemplate)
            throw new InvalidOperationException("Template databases cannot be dropped by this capability.");
        if (!snapshot.AllowConnections)
            throw new InvalidOperationException("Database must allow connections so emptiness can be verified before drop.");
        if (snapshot.ActiveSessions != 0)
            throw new InvalidOperationException($"PostgreSQL database '{snapshot.Name}' has {snapshot.ActiveSessions} active session(s); session termination and FORCE are not supported.");
        if (snapshot.NonSystemObjectCount != 0)
            throw new InvalidOperationException($"PostgreSQL database '{snapshot.Name}' contains {snapshot.NonSystemObjectCount} non-system object(s); only empty development databases may be dropped.");
    }

    private static void ValidateCreatedDatabase(DatabaseSnapshot after, DatabaseSnapshot template)
    {
        if (!after.Exists || !string.Equals(after.Owner, ExpectedOwner, StringComparison.Ordinal) || !string.Equals(after.Encoding, FixedEncoding, StringComparison.Ordinal))
            throw new InvalidOperationException("PostgreSQL database create read-back owner/encoding verification failed.");
        if (after.IsTemplate || !after.AllowConnections)
            throw new InvalidOperationException("Created PostgreSQL database has unexpected template/connectability flags.");
        if (!string.Equals(after.Collation, template.Collation, StringComparison.Ordinal) || !string.Equals(after.CType, template.CType, StringComparison.Ordinal))
            throw new InvalidOperationException("Created PostgreSQL database locale does not match sealed template0 locale.");
        if (after.ActiveSessions != 0 || after.NonSystemObjectCount != 0)
            throw new InvalidOperationException("Created PostgreSQL database is not empty or has unexpected active sessions.");
    }

    private static void RevalidateCluster(SignedPlan plan, ClusterIdentity current)
    {
        if (!string.Equals(current.FingerprintSha256, RequireParameter(plan, "clusterFingerprintSha256"), StringComparison.OrdinalIgnoreCase)
            || !string.Equals(current.RoleName, RequireParameter(plan, "roleName"), StringComparison.Ordinal)
            || current.RoleOid.ToString(CultureInfo.InvariantCulture) != RequireParameter(plan, "roleOid")
            || current.RoleSuperuser != bool.Parse(RequireParameter(plan, "roleSuperuser"))
            || current.RoleCreateDb != bool.Parse(RequireParameter(plan, "roleCreateDb")))
            throw new InvalidOperationException("PostgreSQL cluster or provisioning-role identity changed after plan preparation.");
    }

    private static void RevalidateTemplate(SignedPlan plan, DatabaseSnapshot template)
    {
        if (!template.Exists
            || !string.Equals(RequireParameter(plan, "templateName"), FixedTemplate, StringComparison.Ordinal)
            || !string.Equals(template.Encoding, RequireParameter(plan, "templateEncoding"), StringComparison.Ordinal)
            || !string.Equals(template.Collation, RequireParameter(plan, "templateCollation"), StringComparison.Ordinal)
            || !string.Equals(template.CType, RequireParameter(plan, "templateCType"), StringComparison.Ordinal)
            || template.IsTemplate != bool.Parse(RequireParameter(plan, "templateIsTemplate"))
            || template.AllowConnections != bool.Parse(RequireParameter(plan, "templateAllowConnections")))
            throw new InvalidOperationException("PostgreSQL fixed template0 identity changed after plan preparation.");
    }

    private static DatabaseSnapshot ReadSnapshot(SignedPlan plan)
    {
        var name = RequireMutableDatabaseName(RequireParameter(plan, "databaseName"));
        return new DatabaseSnapshot(
            name,
            bool.Parse(RequireParameter(plan, "exists")),
            EmptyToNull(plan.Parameters.GetValueOrDefault("owner")),
            EmptyToNull(plan.Parameters.GetValueOrDefault("encoding")),
            EmptyToNull(plan.Parameters.GetValueOrDefault("collation")),
            EmptyToNull(plan.Parameters.GetValueOrDefault("ctype")),
            bool.Parse(RequireParameter(plan, "allowConnections")),
            bool.Parse(RequireParameter(plan, "isTemplate")),
            int.Parse(RequireParameter(plan, "connectionLimit"), CultureInfo.InvariantCulture),
            int.Parse(RequireParameter(plan, "activeSessions"), CultureInfo.InvariantCulture),
            int.Parse(RequireParameter(plan, "nonSystemObjectCount"), CultureInfo.InvariantCulture));
    }

    private static void RequireSnapshotMatch(DatabaseSnapshot expected, DatabaseSnapshot current)
    {
        if (!string.Equals(expected.Name, current.Name, StringComparison.Ordinal)
            || expected.Exists != current.Exists
            || !string.Equals(expected.Owner, current.Owner, StringComparison.Ordinal)
            || !string.Equals(expected.Encoding, current.Encoding, StringComparison.Ordinal)
            || !string.Equals(expected.Collation, current.Collation, StringComparison.Ordinal)
            || !string.Equals(expected.CType, current.CType, StringComparison.Ordinal)
            || expected.AllowConnections != current.AllowConnections
            || expected.IsTemplate != current.IsTemplate
            || expected.ConnectionLimit != current.ConnectionLimit
            || expected.ActiveSessions != current.ActiveSessions
            || expected.NonSystemObjectCount != current.NonSystemObjectCount)
            throw new InvalidOperationException("PostgreSQL database identity or state changed after plan preparation.");
    }

    private static PostgresDatabaseInspectResult ToInspectResult(ClusterIdentity cluster, DatabaseSnapshot snapshot)
        => new(
            snapshot.Name,
            snapshot.Owner ?? string.Empty,
            snapshot.Encoding ?? string.Empty,
            snapshot.Collation ?? string.Empty,
            snapshot.CType ?? string.Empty,
            snapshot.AllowConnections,
            snapshot.IsTemplate,
            snapshot.ConnectionLimit,
            snapshot.ActiveSessions,
            snapshot.NonSystemObjectCount,
            cluster.RoleName,
            cluster.RoleSuperuser,
            cluster.RoleCreateDb,
            cluster.FingerprintSha256,
            DateTimeOffset.UtcNow);

    private static void RequireIntentMatch(SignedPlan plan, string expectedOperation, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "postgres", StringComparison.Ordinal)
            || !string.Equals(plan.Operation, expectedOperation, StringComparison.Ordinal)
            || !string.Equals(plan.Operation, operation, StringComparison.Ordinal)
            || !string.Equals(plan.Target, target, StringComparison.Ordinal)
            || !string.Equals(plan.Summary, summary, StringComparison.Ordinal)
            || !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
    }

    private static string RequireParameter(SignedPlan plan, string key)
        => plan.Parameters.TryGetValue(key, out var value) && value is not null
            ? value
            : throw new InvalidDataException($"Signed PostgreSQL database parameter {key} is missing.");

    private static string RequireMutableDatabaseName(string databaseName)
    {
        var value = (databaseName ?? string.Empty).Trim();
        if (!MutableDatabaseName.IsMatch(value))
            throw new ArgumentException("databaseName must match dev_[a-z][a-z0-9_]{0,46}.", nameof(databaseName));
        return value;
    }

    private static string RequireInspectableDatabaseName(string databaseName)
    {
        var value = (databaseName ?? string.Empty).Trim();
        if (value.Length is < 1 or > 63 || value.Contains('\0') || value.Any(char.IsControl))
            throw new ArgumentException("databaseName must be a non-empty PostgreSQL database name up to 63 characters without NUL/control characters.", nameof(databaseName));
        return value;
    }

    private static string? EmptyToNull(string? value) => string.IsNullOrEmpty(value) ? null : value;

    private sealed record ClusterIdentity(
        string ServerVersion,
        string ServerAddress,
        int ServerPort,
        string PostmasterStartUtc,
        long RoleOid,
        string RoleName,
        bool RoleSuperuser,
        bool RoleCreateDb,
        string FingerprintSha256);

    private sealed record DatabaseSnapshot(
        string Name,
        bool Exists,
        string? Owner,
        string? Encoding,
        string? Collation,
        string? CType,
        bool AllowConnections,
        bool IsTemplate,
        int ConnectionLimit,
        int ActiveSessions,
        int NonSystemObjectCount)
    {
        public static DatabaseSnapshot Absent(string name) => new(name, false, null, null, null, null, false, false, 0, 0, 0);
    }
}

public sealed record PostgresDatabaseInspectResult(
    string Name,
    string Owner,
    string Encoding,
    string Collation,
    string CType,
    bool AllowConnections,
    bool IsTemplate,
    int ConnectionLimit,
    int ActiveSessions,
    int NonSystemObjectCount,
    string ProvisioningRole,
    bool ProvisioningRoleSuperuser,
    bool ProvisioningRoleCreateDb,
    string ClusterFingerprintSha256,
    DateTimeOffset CheckedUtc);

public sealed record PostgresDatabaseMutationResult(
    string PlanId,
    string DatabaseName,
    string Outcome,
    PostgresDatabaseInspectResult? Database,
    DateTimeOffset ExecutedUtc);