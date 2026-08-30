using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using ModelContextProtocol.Server;
using Npgsql;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;
using YowThi.DevelopmentAgent3.Security;

namespace YowThi.DevelopmentAgent3.Postgres;

[McpServerToolType]
public sealed class PostgresMutationTools
{
    private const string ConnectionString = "Host=127.0.0.1;Port=55432;Database=yowthi_dev;Username=yowthi_dev;SSL Mode=Disable;Timeout=5;Command Timeout=5;Application Name=YowThi.DevelopmentAgent3.PostgresMutationTools;Pooling=false";
    private const string DatabaseName = "yowthi_dev";
    private const string ExpectedOwner = "yowthi_dev";
    private static readonly Regex MutableSchemaName = new("^dev_[a-z][a-z0-9_]{0,46}$", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");

    [McpServerTool(Name = "postgres_schema_create_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to create one empty development schema in the fixed yowthi_dev PostgreSQL database. Only lowercase names matching dev_[a-z][a-z0-9_]{0,46} are accepted. Existing schemas, arbitrary SQL, owner selection, authorization clauses, hosts, ports, databases, users, and connection strings are rejected. Current schema absence is sealed into the plan.")]
    public static SignedPlan PostgresSchemaCreatePlan(string schemaName)
    {
        var name = RequireMutableSchemaName(schemaName);
        var snapshot = ReadSchemaSnapshot(name);
        if (snapshot.Exists)
            throw new InvalidOperationException($"Schema '{name}' already exists.");
        return CreatePlan("schema-create", snapshot, RiskClass.High, $"Create empty PostgreSQL development schema {DatabaseName}.{name}");
    }

    [McpServerTool(Name = "postgres_schema_create_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared postgres/schema-create plan. The caller repeats signed operation, target, summary, and risk class. Schema absence is revalidated immediately before a fixed CREATE SCHEMA statement is executed in yowthi_dev. Arbitrary SQL, owner selection, and connection parameters are not accepted.")]
    public static ExecutionResult PostgresSchemaCreateExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "schema-create", operation, target, summary, riskClass);
        var expected = ReadSnapshot(plan);
        RequireSnapshotMatch(expected, ReadSchemaSnapshot(expected.Name));
        if (expected.Exists)
            throw new InvalidOperationException("Signed schema-create plan unexpectedly targets an existing schema.");

        try
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction();
            using var command = new NpgsqlCommand($"CREATE SCHEMA \"{expected.Name}\"", connection, transaction);
            command.ExecuteNonQuery();
            transaction.Commit();
            var after = ReadSchemaSnapshot(expected.Name);
            if (!after.Exists || !string.Equals(after.Owner, ExpectedOwner, StringComparison.Ordinal) || after.ObjectCount != 0)
                throw new InvalidOperationException("PostgreSQL schema create verification failed.");
            Store.Consume(planId);
            var outcome = $"schema-created:{DatabaseName}.{expected.Name}";
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, outcome }, "executed");
            return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    [McpServerTool(Name = "postgres_schema_drop_plan", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to drop one empty development schema from the fixed yowthi_dev PostgreSQL database using RESTRICT. Only lowercase names matching dev_[a-z][a-z0-9_]{0,46} are accepted. The schema must exist, be owned by yowthi_dev, and contain zero objects. CASCADE, arbitrary SQL, system/public schemas, and connection parameters are not supported. Owner and object-count state are sealed into the plan.")]
    public static SignedPlan PostgresSchemaDropPlan(string schemaName)
    {
        var name = RequireMutableSchemaName(schemaName);
        var snapshot = ReadSchemaSnapshot(name);
        if (!snapshot.Exists)
            throw new InvalidOperationException($"Schema '{name}' does not exist.");
        if (!string.Equals(snapshot.Owner, ExpectedOwner, StringComparison.Ordinal))
            throw new InvalidOperationException($"Schema '{name}' is not owned by {ExpectedOwner}.");
        if (snapshot.ObjectCount != 0)
            throw new InvalidOperationException($"Schema '{name}' is not empty; DROP CASCADE is not supported.");
        return CreatePlan("schema-drop", snapshot, RiskClass.High, $"Drop empty PostgreSQL development schema {DatabaseName}.{name} with RESTRICT");
    }

    [McpServerTool(Name = "postgres_schema_drop_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute one previously prepared postgres/schema-drop plan using fixed DROP SCHEMA <sealed-name> RESTRICT. The caller repeats signed operation, target, summary, and risk class. Schema identity, owner, and empty state are revalidated immediately before drop. CASCADE and arbitrary SQL are not supported.")]
    public static ExecutionResult PostgresSchemaDropExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "schema-drop", operation, target, summary, riskClass);
        var expected = ReadSnapshot(plan);
        RequireSnapshotMatch(expected, ReadSchemaSnapshot(expected.Name));
        if (!expected.Exists || !string.Equals(expected.Owner, ExpectedOwner, StringComparison.Ordinal) || expected.ObjectCount != 0)
            throw new InvalidOperationException("Signed schema-drop snapshot is not eligible for drop.");

        try
        {
            using var connection = OpenConnection();
            using var transaction = connection.BeginTransaction();
            using var command = new NpgsqlCommand($"DROP SCHEMA \"{expected.Name}\" RESTRICT", connection, transaction);
            command.ExecuteNonQuery();
            transaction.Commit();
            if (ReadSchemaSnapshot(expected.Name).Exists)
                throw new InvalidOperationException("PostgreSQL schema drop verification failed.");
            Store.Consume(planId);
            var outcome = $"schema-dropped:{DatabaseName}.{expected.Name}";
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, outcome }, "executed");
            return new ExecutionResult(plan.PlanId, plan.Tool, plan.Operation, plan.Target, outcome, DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    private static SignedPlan CreatePlan(string operation, SchemaSnapshot snapshot, RiskClass riskClass, string summary)
    {
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["database"] = DatabaseName,
            ["schemaName"] = snapshot.Name,
            ["exists"] = snapshot.Exists ? "true" : "false",
            ["owner"] = snapshot.Owner ?? string.Empty,
            ["objectCount"] = snapshot.ObjectCount.ToString(System.Globalization.CultureInfo.InvariantCulture)
        };
        var now = DateTimeOffset.UtcNow;
        var target = $"{DatabaseName}.{snapshot.Name}";
        var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)), "postgres", operation, target, parameters, riskClass, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    private static void RequireIntentMatch(SignedPlan plan, string expectedOperation, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "postgres", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, expectedOperation, StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, operation, StringComparison.Ordinal) ||
            !string.Equals(plan.Target, target, StringComparison.Ordinal) ||
            !string.Equals(plan.Summary, summary, StringComparison.Ordinal) ||
            !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
    }

    private static SchemaSnapshot ReadSnapshot(SignedPlan plan)
    {
        if (!plan.Parameters.TryGetValue("database", out var database) ||
            !plan.Parameters.TryGetValue("schemaName", out var name) ||
            !plan.Parameters.TryGetValue("exists", out var existsText) ||
            !plan.Parameters.TryGetValue("owner", out var owner) ||
            !plan.Parameters.TryGetValue("objectCount", out var objectCountText))
            throw new InvalidDataException("Signed PostgreSQL schema snapshot is incomplete.");
        if (!string.Equals(database, DatabaseName, StringComparison.Ordinal))
            throw new InvalidDataException("Signed PostgreSQL database identity is invalid.");
        RequireMutableSchemaName(name);
        if (!bool.TryParse(existsText, out var exists) || !int.TryParse(objectCountText, out var objectCount) || objectCount < 0)
            throw new InvalidDataException("Signed PostgreSQL schema state is invalid.");
        return new SchemaSnapshot(name, exists, owner.Length == 0 ? null : owner, objectCount);
    }

    private static void RequireSnapshotMatch(SchemaSnapshot expected, SchemaSnapshot current)
    {
        if (!string.Equals(expected.Name, current.Name, StringComparison.Ordinal) ||
            expected.Exists != current.Exists ||
            !string.Equals(expected.Owner, current.Owner, StringComparison.Ordinal) ||
            expected.ObjectCount != current.ObjectCount)
            throw new InvalidOperationException("PostgreSQL schema identity or state changed after plan preparation.");
    }

    private static string RequireMutableSchemaName(string schemaName)
    {
        var value = (schemaName ?? string.Empty).Trim();
        if (!MutableSchemaName.IsMatch(value))
            throw new ArgumentException("schemaName must match dev_[a-z][a-z0-9_]{0,46}.", nameof(schemaName));
        return value;
    }

    private static SchemaSnapshot ReadSchemaSnapshot(string schemaName)
    {
        var name = RequireMutableSchemaName(schemaName);
        using var connection = OpenConnection();
        const string sql = "select n.nspname, pg_get_userbyid(n.nspowner), (select count(*)::int from pg_class c where c.relnamespace=n.oid) + (select count(*)::int from pg_proc p where p.pronamespace=n.oid) + (select count(*)::int from pg_type t where t.typnamespace=n.oid and t.typtype in ('c','d','e','r')) from pg_namespace n where n.nspname=@name;";
        using var command = new NpgsqlCommand(sql, connection);
        command.Parameters.AddWithValue("name", name);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
            return new SchemaSnapshot(name, false, null, 0);
        return new SchemaSnapshot(reader.GetString(0), true, reader.GetString(1), reader.GetInt32(2));
    }

    private static NpgsqlConnection OpenConnection()
    {
        var connection = new NpgsqlConnection(ConnectionString);
        connection.Open();
        if (!string.Equals(connection.Database, DatabaseName, StringComparison.Ordinal))
        {
            connection.Dispose();
            throw new InvalidOperationException("Connected PostgreSQL database is not the fixed yowthi_dev target.");
        }
        return connection;
    }

    private sealed record SchemaSnapshot(string Name, bool Exists, string? Owner, int ObjectCount);
}
