using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace YowThi.DevelopmentAgent3.Audit;

public sealed class AuditChain
{
    private readonly string _directory;
    private readonly object _gate = new();

    public AuditChain(string directory) => _directory = Path.GetFullPath(directory);

    public string Append(string tool, string operation, string target, object? detail, string outcome)
    {
        lock (_gate)
        {
            Directory.CreateDirectory(_directory);
            var log = Path.Combine(_directory, "actions.jsonl");
            var head = Path.Combine(_directory, "chain-head.txt");
            var previousHash = File.Exists(head) ? File.ReadAllText(head).Trim() : new string('0', 64);
            var payload = JsonSerializer.SerializeToUtf8Bytes(new
            {
                chainVersion = 1,
                utc = DateTimeOffset.UtcNow,
                machine = Environment.MachineName,
                tool,
                operation,
                target,
                detail,
                outcome,
                previousHash
            });
            var hash = Convert.ToHexString(SHA256.HashData(payload));
            File.AppendAllText(log, JsonSerializer.Serialize(new { payloadBase64 = Convert.ToBase64String(payload), hash }) + Environment.NewLine, Encoding.UTF8);
            File.WriteAllText(head, hash, Encoding.ASCII);
            return hash;
        }
    }
}
