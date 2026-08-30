using System.ComponentModel;
using ModelContextProtocol.Server;
using Npgsql;

namespace YowThi.DevelopmentAgent3.Postgres;

[McpServerToolType]
public sealed class PostgresTools
{
    private const string Host = "127.0.0.1";
    private const int Port = 55432;
    private const string Database = "yowthi_dev";
    private const string Username = "yowthi_dev";
    private const string ConnectionString = "Host=127.0.0.1;Port=55432;Database=yowthi_dev;Username=yowthi_dev;SSL Mode=Disable;Timeout=5;Command Timeout=5;Application Name=YowThi.DevelopmentAgent3.PostgresTools;Pooling=false";

    [McpServerTool(Name = "postgres_status", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Read the fixed YowThi PostgreSQL 18 development endpoint status at 127.0.0.1:55432/yowthi_dev using Npgsql and fixed read-only SQL. Host, port, database, user, connection string, and SQL are not caller-configurable.")]
    public static object PostgresStatus()
    {
        using var connection = OpenConnection();
        using var command = new NpgsqlCommand("select version(), current_database(), current_user, inet_server_addr()::text, inet_server_port(), pg_is_in_recovery();", connection);
        using var reader = command.ExecuteReader();
        if (!reader.Read())
            throw new InvalidOperationException("PostgreSQL status query returned no row.");

        return new
        {
            host = Host,
            port = Port,
            database = Database,
            username = Username,
            version = reader.GetString(0),
            currentDatabase = reader.GetString(1),
            currentUser = reader.GetString(2),
            serverAddress = reader.IsDBNull(3) ? null : reader.GetString(3),
            serverPort = reader.IsDBNull(4) ? (int?)null : reader.GetInt32(4),
            isInRecovery = reader.GetBoolean(5),
            checkedUtc = DateTimeOffset.UtcNow
        };
    }

    [McpServerTool(Name = "postgres_database_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List databases visible from the fixed YowThi PostgreSQL 18 development endpoint using a fixed pg_database query. No caller-provided SQL, filters, database names, hosts, ports, users, or connection strings are accepted.")]
    public static IReadOnlyList<object> PostgresDatabaseList()
    {
        const string sql = "select datname, datallowconn, datistemplate, pg_encoding_to_char(encoding), datcollate, datctype from pg_database order by datname;";
        using var connection = OpenConnection();
        using var command = new NpgsqlCommand(sql, connection);
        using var reader = command.ExecuteReader();
        var rows = new List<object>();
        while (reader.Read())
        {
            rows.Add(new
            {
                name = reader.GetString(0),
                allowConnections = reader.GetBoolean(1),
                isTemplate = reader.GetBoolean(2),
                encoding = reader.GetString(3),
                collation = reader.GetString(4),
                ctype = reader.GetString(5)
            });
        }
        return rows;
    }

    [McpServerTool(Name = "postgres_schema_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List non-temporary schemas in the fixed yowthi_dev database using a fixed pg_namespace query. No caller-provided SQL, filters, schema names, hosts, ports, databases, users, or connection strings are accepted.")]
    public static IReadOnlyList<object> PostgresSchemaList()
    {
        const string sql = "select n.nspname, pg_get_userbyid(n.nspowner) from pg_namespace n where n.nspname not like 'pg_toast_temp_%' and n.nspname not like 'pg_temp_%' order by n.nspname;";
        using var connection = OpenConnection();
        using var command = new NpgsqlCommand(sql, connection);
        using var reader = command.ExecuteReader();
        var rows = new List<object>();
        while (reader.Read())
            rows.Add(new { name = reader.GetString(0), owner = reader.GetString(1) });
        return rows;
    }

    [McpServerTool(Name = "postgres_table_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List ordinary and partitioned tables in the fixed yowthi_dev database using fixed PostgreSQL catalog queries. No caller-provided SQL, filters, table/schema names, hosts, ports, databases, users, or connection strings are accepted.")]
    public static IReadOnlyList<object> PostgresTableList()
    {
        const string sql = "select n.nspname, c.relname, c.relkind::text, pg_get_userbyid(c.relowner), c.relispartition from pg_class c join pg_namespace n on n.oid=c.relnamespace where c.relkind in ('r','p') and n.nspname not in ('pg_catalog','information_schema') and n.nspname not like 'pg_toast%' order by n.nspname, c.relname;";
        using var connection = OpenConnection();
        using var command = new NpgsqlCommand(sql, connection);
        using var reader = command.ExecuteReader();
        var rows = new List<object>();
        while (reader.Read())
        {
            rows.Add(new
            {
                schema = reader.GetString(0),
                name = reader.GetString(1),
                kind = reader.GetString(2),
                owner = reader.GetString(3),
                isPartition = reader.GetBoolean(4)
            });
        }
        return rows;
    }

    private static NpgsqlConnection OpenConnection()
    {
        var connection = new NpgsqlConnection(ConnectionString);
        connection.Open();
        return connection;
    }
}
