using System.Collections;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.Windows;

[SupportedOSPlatform("windows")]
[McpServerToolType]
public static class FirewallMutationTools
{
    private const string RulePrefix = "YowThi ";
    private const string ManagedDescription = "YowThi ERP Dev v4 controlled inbound TCP allow rule.";
    private const string ManagedGrouping = "YowThi ERP Dev v4";
    private const string LocalSubnetRemoteAddresses = "LocalSubnet";
    private const string TailscaleRemoteAddresses = "100.64.0.0/10,fd7a:115c:a1e0::/48";
    private const int NetFwIpProtocolTcp = 6;
    private const int NetFwRuleDirIn = 1;
    private const int NetFwActionAllow = 1;
    private const int NetFwProfileDomain = 1;
    private const int NetFwProfilePrivate = 2;
    private const int NetFwProfilePublic = 4;

    private static readonly string[] AllowedProgramRoots =
    [
        @"C:\Dev\YowThi-ERP-Dev-v4",
        @"C:\ProgramData\YowThi"
    ];

    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");

    [McpServerTool(Name = "firewall_yowthi_rule_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List only Windows Firewall rules whose names begin with the fixed 'YowThi ' prefix. The result exposes typed rule metadata but does not enumerate unrelated firewall rules and does not modify firewall state. The Windows Firewall COM API is used directly; PowerShell, cmd, netsh, WMI command execution, and generic command execution are not used.")]
    public static IReadOnlyList<FirewallRuleItem> FirewallYowThiRuleList()
        => ReadYowThiRules()
            .Select(ToItem)
            .OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    [McpServerTool(Name = "firewall_tcp_allow_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to create one narrowly constrained YowThi-owned Windows Firewall inbound TCP allow rule. Rule name must start with 'YowThi ', the program must be an existing non-reparse .exe under C:\\Dev\\YowThi-ERP-Dev-v4 or C:\\ProgramData\\YowThi, local port must be 1-65535, direction/action/protocol are fixed to inbound/allow/TCP, edge traversal is fixed off, and remote scope is restricted to LocalSubnet or the fixed Tailscale CIDRs. Rule absence, executable SHA-256, and the complete normalized rule shape are sealed. No arbitrary firewall properties, PowerShell, cmd, netsh, shell, or generic command execution are supported.")]
    public static SignedPlan FirewallTcpAllowPlan(string ruleName, string programPath, int localPort, string remoteScope = "LocalSubnet")
    {
        var normalizedName = NormalizeRuleName(ruleName);
        var normalizedProgram = ValidateProgramPath(programPath);
        if (localPort is < 1 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(localPort), "localPort must be between 1 and 65535.");

        var scope = NormalizeRemoteScope(remoteScope);
        var shape = CreateDesiredSnapshot(normalizedName, normalizedProgram, localPort, scope);
        if (ReadRuleByName(normalizedName) is not null)
            throw new InvalidOperationException($"Firewall rule {normalizedName} already exists.");

        var programSha256 = ComputeSha256(normalizedProgram);
        var parameters = SnapshotToParameters(shape);
        parameters["programSha256"] = programSha256;
        parameters["remoteScope"] = scope;
        parameters["ruleAbsent"] = "true";

        var now = DateTimeOffset.UtcNow;
        var summary = $"Create constrained inbound TCP allow firewall rule {normalizedName} for {normalizedProgram} port {localPort} scope {scope}";
        var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)), "firewall", "tcp-allow", normalizedName, parameters, RiskClass.High, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    [McpServerTool(Name = "firewall_tcp_allow_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared firewall/tcp-allow plan using the Windows Firewall COM API. Exact signed intent, rule absence, YowThi-owned executable path and SHA-256, fixed inbound/allow/TCP shape, fixed edge-traversal-off state, profile set, local port, and LocalSubnet/Tailscale remote scope are revalidated immediately before creation. Post-create read-back must exactly match the sealed rule; failed verification triggers best-effort removal of only the newly created named rule.")]
    public static FirewallRuleMutationResult FirewallTcpAllowExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "tcp-allow", operation, target, summary, riskClass);
        var expected = ReadSnapshotFromPlan(plan);
        RequireManagedShape(expected);

        var programSha256 = RequireParameter(plan, "programSha256");
        var remoteScope = NormalizeRemoteScope(RequireParameter(plan, "remoteScope"));
        if (!string.Equals(RequireParameter(plan, "ruleAbsent"), "true", StringComparison.Ordinal))
            throw new InvalidDataException("Signed rule absence state is invalid.");

        var currentProgram = ValidateProgramPath(expected.ApplicationName);
        if (!string.Equals(currentProgram, expected.ApplicationName, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Firewall program path normalization changed after plan preparation.");
        if (!string.Equals(ComputeSha256(currentProgram), programSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Firewall program executable changed after plan preparation.");

        var desiredNow = CreateDesiredSnapshot(expected.Name, currentProgram, ParseSinglePort(expected.LocalPorts), remoteScope);
        RequireSnapshotMatch(expected, desiredNow, "Signed firewall rule shape is inconsistent with the constrained server-side rule shape.");
        if (ReadRuleByName(expected.Name) is not null)
            throw new InvalidOperationException("Firewall rule appeared after plan preparation.");

        var created = false;
        try
        {
            AddRule(expected);
            created = true;
            var after = ReadRuleByName(expected.Name) ?? throw new InvalidOperationException("Firewall rule creation verification could not find the new rule.");
            RequireSnapshotMatch(expected, after, "Firewall rule creation verification failed.");
            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, outcome = "rule-created", expected.Name, expected.ApplicationName, expected.LocalPorts, expected.RemoteAddresses, expected.Profiles }, "executed");
            return new FirewallRuleMutationResult(plan.PlanId, plan.Operation, expected.Name, false, true, ToItem(after), "rule-created", DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            if (created)
            {
                try { RemoveRule(expected.Name); } catch { }
            }
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    [McpServerTool(Name = "firewall_rule_remove_plan", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to remove one existing firewall rule only when it is a constrained YowThi-managed rule: fixed YowThi prefix/grouping/description, inbound allow TCP, program path under an approved YowThi root, edge traversal off, one explicit local port, and either the fixed LocalSubnet or fixed Tailscale remote scope. The complete current rule snapshot is sealed. Unrelated or broader firewall rules cannot be targeted.")]
    public static SignedPlan FirewallRuleRemovePlan(string ruleName)
    {
        var normalizedName = NormalizeRuleName(ruleName);
        var snapshot = ReadRuleByName(normalizedName) ?? throw new InvalidOperationException($"Firewall rule {normalizedName} does not exist.");
        RequireManagedShape(snapshot);
        _ = ValidateProgramPath(snapshot.ApplicationName);
        _ = ParseSinglePort(snapshot.LocalPorts);
        _ = RemoteScopeFromSnapshot(snapshot);

        var parameters = SnapshotToParameters(snapshot);
        parameters["rulePresent"] = "true";
        var now = DateTimeOffset.UtcNow;
        var summary = $"Remove constrained YowThi firewall rule {snapshot.Name} for {snapshot.ApplicationName} port {snapshot.LocalPorts}";
        var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)), "firewall", "rule-remove", snapshot.Name, parameters, RiskClass.High, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    [McpServerTool(Name = "firewall_rule_remove_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute one previously prepared firewall/rule-remove plan using the Windows Firewall COM API. The exact YowThi-managed rule snapshot is re-read and must still match every sealed property before only that named rule is removed. Post-remove read-back must prove absence. Arbitrary firewall rule removal is not supported.")]
    public static FirewallRuleMutationResult FirewallRuleRemoveExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "rule-remove", operation, target, summary, riskClass);
        var expected = ReadSnapshotFromPlan(plan);
        RequireManagedShape(expected);
        if (!string.Equals(RequireParameter(plan, "rulePresent"), "true", StringComparison.Ordinal))
            throw new InvalidDataException("Signed rule presence state is invalid.");

        var current = ReadRuleByName(expected.Name) ?? throw new InvalidOperationException("Firewall rule disappeared after plan preparation.");
        RequireManagedShape(current);
        RequireSnapshotMatch(expected, current, "Firewall rule changed after plan preparation.");

        try
        {
            RemoveRule(expected.Name);
            if (ReadRuleByName(expected.Name) is not null)
                throw new InvalidOperationException("Firewall rule removal verification failed.");
            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, outcome = "rule-removed", expected.Name, expected.ApplicationName, expected.LocalPorts }, "executed");
            return new FirewallRuleMutationResult(plan.PlanId, plan.Operation, expected.Name, true, false, ToItem(expected), "rule-removed", DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    private static FirewallRuleSnapshot CreateDesiredSnapshot(string ruleName, string programPath, int localPort, string remoteScope)
    {
        var (profiles, remoteAddresses) = remoteScope switch
        {
            "LocalSubnet" => (NetFwProfileDomain | NetFwProfilePrivate, LocalSubnetRemoteAddresses),
            "Tailscale" => (NetFwProfileDomain | NetFwProfilePrivate | NetFwProfilePublic, TailscaleRemoteAddresses),
            _ => throw new InvalidOperationException("Unsupported normalized remote scope.")
        };
        return new FirewallRuleSnapshot(ruleName, ManagedDescription, ManagedGrouping, programPath, NetFwIpProtocolTcp, localPort.ToString(CultureInfo.InvariantCulture), NetFwRuleDirIn, NetFwActionAllow, true, profiles, remoteAddresses, false);
    }

    private static IReadOnlyList<FirewallRuleSnapshot> ReadYowThiRules()
    {
        var result = new List<FirewallRuleSnapshot>();
        dynamic policy = CreatePolicy();
        IEnumerable rules = (IEnumerable)policy.Rules;
        foreach (var item in rules)
        {
            dynamic rule = item!;
            var name = Convert.ToString(rule.Name, CultureInfo.InvariantCulture) ?? string.Empty;
            if (!name.StartsWith(RulePrefix, StringComparison.OrdinalIgnoreCase))
                continue;
            try { result.Add(ReadRuleSnapshot(rule)); } catch { }
        }
        return result;
    }

    private static FirewallRuleSnapshot? ReadRuleByName(string ruleName)
        => ReadYowThiRules().FirstOrDefault(x => string.Equals(x.Name, ruleName, StringComparison.OrdinalIgnoreCase));

    private static FirewallRuleSnapshot ReadRuleSnapshot(dynamic rule)
        => new(
            Convert.ToString(rule.Name, CultureInfo.InvariantCulture) ?? string.Empty,
            Convert.ToString(rule.Description, CultureInfo.InvariantCulture) ?? string.Empty,
            Convert.ToString(rule.Grouping, CultureInfo.InvariantCulture) ?? string.Empty,
            Convert.ToString(rule.ApplicationName, CultureInfo.InvariantCulture) ?? string.Empty,
            Convert.ToInt32(rule.Protocol, CultureInfo.InvariantCulture),
            Convert.ToString(rule.LocalPorts, CultureInfo.InvariantCulture) ?? string.Empty,
            Convert.ToInt32(rule.Direction, CultureInfo.InvariantCulture),
            Convert.ToInt32(rule.Action, CultureInfo.InvariantCulture),
            Convert.ToBoolean(rule.Enabled, CultureInfo.InvariantCulture),
            Convert.ToInt32(rule.Profiles, CultureInfo.InvariantCulture),
            Convert.ToString(rule.RemoteAddresses, CultureInfo.InvariantCulture) ?? string.Empty,
            Convert.ToBoolean(rule.EdgeTraversal, CultureInfo.InvariantCulture));

    private static dynamic CreatePolicy()
    {
        var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true)
            ?? throw new InvalidOperationException("Windows Firewall policy COM type is unavailable.");
        return Activator.CreateInstance(type) ?? throw new InvalidOperationException("Unable to create Windows Firewall policy COM object.");
    }

    private static dynamic CreateRule()
    {
        var type = Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)
            ?? throw new InvalidOperationException("Windows Firewall rule COM type is unavailable.");
        return Activator.CreateInstance(type) ?? throw new InvalidOperationException("Unable to create Windows Firewall rule COM object.");
    }

    private static void AddRule(FirewallRuleSnapshot snapshot)
    {
        dynamic rule = CreateRule();
        rule.Name = snapshot.Name;
        rule.Description = snapshot.Description;
        rule.Grouping = snapshot.Grouping;
        rule.ApplicationName = snapshot.ApplicationName;
        rule.Protocol = snapshot.Protocol;
        rule.LocalPorts = snapshot.LocalPorts;
        rule.Direction = snapshot.Direction;
        rule.Action = snapshot.Action;
        rule.Enabled = snapshot.Enabled;
        rule.Profiles = snapshot.Profiles;
        rule.RemoteAddresses = snapshot.RemoteAddresses;
        rule.EdgeTraversal = snapshot.EdgeTraversal;
        dynamic policy = CreatePolicy();
        policy.Rules.Add(rule);
    }

    private static void RemoveRule(string ruleName)
    {
        dynamic policy = CreatePolicy();
        policy.Rules.Remove(ruleName);
    }

    private static void RequireManagedShape(FirewallRuleSnapshot snapshot)
    {
        _ = NormalizeRuleName(snapshot.Name);
        var program = ValidateProgramPath(snapshot.ApplicationName);
        if (!string.Equals(program, snapshot.ApplicationName, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(snapshot.Description, ManagedDescription, StringComparison.Ordinal) ||
            !string.Equals(snapshot.Grouping, ManagedGrouping, StringComparison.Ordinal) ||
            snapshot.Protocol != NetFwIpProtocolTcp ||
            snapshot.Direction != NetFwRuleDirIn ||
            snapshot.Action != NetFwActionAllow ||
            !snapshot.Enabled ||
            snapshot.EdgeTraversal)
            throw new UnauthorizedAccessException("Firewall rule is not a constrained YowThi-managed inbound TCP allow rule.");

        _ = ParseSinglePort(snapshot.LocalPorts);
        _ = RemoteScopeFromSnapshot(snapshot);
    }

    private static string RemoteScopeFromSnapshot(FirewallRuleSnapshot snapshot)
    {
        if (snapshot.Profiles == (NetFwProfileDomain | NetFwProfilePrivate) && string.Equals(snapshot.RemoteAddresses, LocalSubnetRemoteAddresses, StringComparison.OrdinalIgnoreCase))
            return "LocalSubnet";
        if (snapshot.Profiles == (NetFwProfileDomain | NetFwProfilePrivate | NetFwProfilePublic) && string.Equals(NormalizeAddressList(snapshot.RemoteAddresses), NormalizeAddressList(TailscaleRemoteAddresses), StringComparison.OrdinalIgnoreCase))
            return "Tailscale";
        throw new UnauthorizedAccessException("Firewall rule remote scope or profile set is outside the constrained YowThi contract.");
    }

    private static Dictionary<string, string> SnapshotToParameters(FirewallRuleSnapshot snapshot)
        => new(StringComparer.Ordinal)
        {
            ["name"] = snapshot.Name,
            ["description"] = snapshot.Description,
            ["grouping"] = snapshot.Grouping,
            ["applicationName"] = snapshot.ApplicationName,
            ["protocol"] = snapshot.Protocol.ToString(CultureInfo.InvariantCulture),
            ["localPorts"] = snapshot.LocalPorts,
            ["direction"] = snapshot.Direction.ToString(CultureInfo.InvariantCulture),
            ["action"] = snapshot.Action.ToString(CultureInfo.InvariantCulture),
            ["enabled"] = snapshot.Enabled ? "true" : "false",
            ["profiles"] = snapshot.Profiles.ToString(CultureInfo.InvariantCulture),
            ["remoteAddresses"] = snapshot.RemoteAddresses,
            ["edgeTraversal"] = snapshot.EdgeTraversal ? "true" : "false"
        };

    private static FirewallRuleSnapshot ReadSnapshotFromPlan(SignedPlan plan)
    {
        if (!int.TryParse(RequireParameter(plan, "protocol"), NumberStyles.None, CultureInfo.InvariantCulture, out var protocol) ||
            !int.TryParse(RequireParameter(plan, "direction"), NumberStyles.None, CultureInfo.InvariantCulture, out var direction) ||
            !int.TryParse(RequireParameter(plan, "action"), NumberStyles.None, CultureInfo.InvariantCulture, out var action) ||
            !bool.TryParse(RequireParameter(plan, "enabled"), out var enabled) ||
            !int.TryParse(RequireParameter(plan, "profiles"), NumberStyles.None, CultureInfo.InvariantCulture, out var profiles) ||
            !bool.TryParse(RequireParameter(plan, "edgeTraversal"), out var edgeTraversal))
            throw new InvalidDataException("Signed firewall rule snapshot is invalid.");

        return new FirewallRuleSnapshot(
            NormalizeRuleName(RequireParameter(plan, "name")),
            RequireParameter(plan, "description"),
            RequireParameter(plan, "grouping"),
            ValidateProgramPath(RequireParameter(plan, "applicationName")),
            protocol,
            RequireParameter(plan, "localPorts"),
            direction,
            action,
            enabled,
            profiles,
            RequireParameter(plan, "remoteAddresses"),
            edgeTraversal);
    }

    private static void RequireSnapshotMatch(FirewallRuleSnapshot expected, FirewallRuleSnapshot current, string message)
    {
        if (!string.Equals(expected.Name, current.Name, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(expected.Description, current.Description, StringComparison.Ordinal) ||
            !string.Equals(expected.Grouping, current.Grouping, StringComparison.Ordinal) ||
            !string.Equals(expected.ApplicationName, current.ApplicationName, StringComparison.OrdinalIgnoreCase) ||
            expected.Protocol != current.Protocol ||
            !string.Equals(expected.LocalPorts, current.LocalPorts, StringComparison.OrdinalIgnoreCase) ||
            expected.Direction != current.Direction ||
            expected.Action != current.Action ||
            expected.Enabled != current.Enabled ||
            expected.Profiles != current.Profiles ||
            !string.Equals(NormalizeAddressList(expected.RemoteAddresses), NormalizeAddressList(current.RemoteAddresses), StringComparison.OrdinalIgnoreCase) ||
            expected.EdgeTraversal != current.EdgeTraversal)
            throw new InvalidOperationException(message);
    }

    private static FirewallRuleItem ToItem(FirewallRuleSnapshot x)
        => new(x.Name, x.Description, x.Grouping, x.ApplicationName, x.Protocol == NetFwIpProtocolTcp ? "TCP" : x.Protocol.ToString(CultureInfo.InvariantCulture), x.LocalPorts, x.Direction == NetFwRuleDirIn ? "Inbound" : x.Direction.ToString(CultureInfo.InvariantCulture), x.Action == NetFwActionAllow ? "Allow" : x.Action.ToString(CultureInfo.InvariantCulture), x.Enabled, ProfileNames(x.Profiles), x.RemoteAddresses, x.EdgeTraversal);

    private static IReadOnlyList<string> ProfileNames(int profiles)
    {
        var result = new List<string>();
        if ((profiles & NetFwProfileDomain) != 0) result.Add("Domain");
        if ((profiles & NetFwProfilePrivate) != 0) result.Add("Private");
        if ((profiles & NetFwProfilePublic) != 0) result.Add("Public");
        return result;
    }

    private static string NormalizeRuleName(string ruleName)
    {
        var value = (ruleName ?? string.Empty).Trim();
        if (!value.StartsWith(RulePrefix, StringComparison.Ordinal) || value.Length > 128 || value.Length <= RulePrefix.Length)
            throw new ArgumentException("ruleName must begin with 'YowThi ', contain a suffix, and be 128 characters or fewer.", nameof(ruleName));
        if (value.Any(c => char.IsControl(c) || !(char.IsLetterOrDigit(c) || char.IsWhiteSpace(c) || ".-_()[]".Contains(c))))
            throw new ArgumentException("ruleName contains unsupported characters.", nameof(ruleName));
        return value;
    }

    private static string NormalizeRemoteScope(string remoteScope)
    {
        var value = (remoteScope ?? string.Empty).Trim();
        if (value.Equals("LocalSubnet", StringComparison.OrdinalIgnoreCase)) return "LocalSubnet";
        if (value.Equals("Tailscale", StringComparison.OrdinalIgnoreCase)) return "Tailscale";
        throw new ArgumentException("remoteScope must be LocalSubnet or Tailscale.", nameof(remoteScope));
    }

    private static string ValidateProgramPath(string programPath)
    {
        if (string.IsNullOrWhiteSpace(programPath) || !Path.IsPathFullyQualified(programPath))
            throw new ArgumentException("programPath must be an absolute path.", nameof(programPath));
        var full = Path.GetFullPath(programPath);
        if (!string.Equals(Path.GetExtension(full), ".exe", StringComparison.OrdinalIgnoreCase) || !File.Exists(full))
            throw new FileNotFoundException("Firewall program must be an existing .exe file.", full);

        var allowedRoot = AllowedProgramRoots
            .Select(Path.GetFullPath)
            .FirstOrDefault(root => IsUnderRoot(full, root));
        if (allowedRoot is null)
            throw new UnauthorizedAccessException("Firewall program must be under an approved YowThi development or program-data root.");

        if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Firewall program may not be a reparse point.");
        var current = Directory.GetParent(full);
        var normalizedRoot = allowedRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        while (current is not null)
        {
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException("Firewall program path may not traverse a reparse-point directory.");
            if (string.Equals(current.FullName.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), normalizedRoot, StringComparison.OrdinalIgnoreCase))
                break;
            current = current.Parent;
        }
        if (current is null)
            throw new UnauthorizedAccessException("Firewall program root validation failed.");
        return full;
    }

    private static bool IsUnderRoot(string path, string root)
    {
        var normalizedRoot = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return path.StartsWith(normalizedRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static int ParseSinglePort(string text)
    {
        if (!int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port is < 1 or > 65535)
            throw new InvalidDataException("Firewall rule local port must be one explicit port from 1 to 65535.");
        return port;
    }

    private static string ComputeSha256(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static string NormalizeAddressList(string value)
        => string.Join(",", (value ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).OrderBy(x => x, StringComparer.OrdinalIgnoreCase));

    private static void RequireIntentMatch(SignedPlan plan, string expectedOperation, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "firewall", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, expectedOperation, StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, operation, StringComparison.Ordinal) ||
            !string.Equals(plan.Target, target, StringComparison.Ordinal) ||
            !string.Equals(plan.Summary, summary, StringComparison.Ordinal) ||
            !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
    }

    private static string RequireParameter(SignedPlan plan, string key)
        => plan.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : throw new InvalidDataException($"{key} parameter is required.");

    private sealed record FirewallRuleSnapshot(
        string Name,
        string Description,
        string Grouping,
        string ApplicationName,
        int Protocol,
        string LocalPorts,
        int Direction,
        int Action,
        bool Enabled,
        int Profiles,
        string RemoteAddresses,
        bool EdgeTraversal);
}

public sealed record FirewallRuleItem(
    string Name,
    string Description,
    string Grouping,
    string ApplicationName,
    string Protocol,
    string LocalPorts,
    string Direction,
    string Action,
    bool Enabled,
    IReadOnlyList<string> Profiles,
    string RemoteAddresses,
    bool EdgeTraversal);

public sealed record FirewallRuleMutationResult(
    string PlanId,
    string Operation,
    string RuleName,
    bool PresentBefore,
    bool PresentAfter,
    FirewallRuleItem Rule,
    string Outcome,
    DateTimeOffset ExecutedUtc);