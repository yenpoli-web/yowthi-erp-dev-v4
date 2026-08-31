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
public static class FirewallAcceptanceTools
{
    private const string RuleName = "YowThi Network v3 Acceptance Fixed";
    private const string DescriptionText = "YowThi ERP Dev v4 controlled inbound TCP allow rule.";
    private const string GroupingText = "YowThi ERP Dev v4";
    private const string ProgramPath = @"C:\Dev\YowThi-ERP-Dev-v4\acceptance\network-v3-firewall-build\YowThi.DevelopmentAgent3.exe";
    private const string RemoteAddresses = "LocalSubnet";
    private const int LocalPort = 65534;
    private const int ProtocolTcp = 6;
    private const int DirectionInbound = 1;
    private const int ActionAllow = 1;
    private const int Profiles = 3;

    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");

    [McpServerTool(Name = "firewall_acceptance_create_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan for one fixed Network v3 acceptance firewall rule. All rule properties are server-side constants: exact YowThi rule name, exact YowThi acceptance executable, inbound TCP allow, local port 65534, Domain+Private profiles, LocalSubnet remote scope, enabled, and edge traversal off. The caller cannot choose a rule name, program, port, direction, action, protocol, profile, or remote scope. Rule absence and executable SHA-256 are sealed. No PowerShell, cmd, netsh, shell, WMI command execution, or generic command execution is supported.")]
    public static SignedPlan FirewallAcceptanceCreatePlan()
    {
        var programSha256 = ValidateProgramAndHash();
        if (ReadRule() is not null)
            throw new InvalidOperationException($"Acceptance firewall rule {RuleName} already exists.");

        var parameters = FixedParameters(programSha256);
        parameters["ruleAbsent"] = "true";
        var now = DateTimeOffset.UtcNow;
        var summary = $"Create fixed Network v3 acceptance firewall rule {RuleName}";
        var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)), "firewall-acceptance", "fixed-create", RuleName, parameters, RiskClass.High, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    [McpServerTool(Name = "firewall_acceptance_create_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute only a previously prepared fixed Network v3 firewall acceptance plan. The only caller inputs are planId and approvalCode. The server revalidates the fixed tool/operation/target, every fixed rule property, rule absence, exact acceptance executable path and SHA-256, then creates only that one fixed rule using the Windows Firewall COM API. Post-create read-back must exactly match; failure triggers best-effort removal of only the fixed acceptance rule.")]
    public static FirewallAcceptanceResult FirewallAcceptanceCreateExecute(string planId, string approvalCode)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireFixedPlan(plan, "fixed-create");
        if (!string.Equals(RequireParameter(plan, "ruleAbsent"), "true", StringComparison.Ordinal))
            throw new InvalidDataException("Signed acceptance rule absence state is invalid.");
        var programSha256 = ValidateProgramAndHash();
        if (!string.Equals(programSha256, RequireParameter(plan, "programSha256"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Acceptance executable changed after plan preparation.");
        RequireFixedParameters(plan, programSha256);
        if (ReadRule() is not null)
            throw new InvalidOperationException("Acceptance firewall rule appeared after plan preparation.");

        var created = false;
        try
        {
            AddFixedRule();
            created = true;
            var after = ReadRule() ?? throw new InvalidOperationException("Acceptance firewall rule creation read-back failed.");
            RequireFixedSnapshot(after);
            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, outcome = "acceptance-rule-created" }, "executed");
            return new FirewallAcceptanceResult(plan.PlanId, plan.Operation, RuleName, false, true, "acceptance-rule-created", DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            if (created) { try { RemoveFixedRule(); } catch { } }
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    [McpServerTool(Name = "firewall_acceptance_remove_plan", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to remove only the single fixed Network v3 acceptance firewall rule. The caller cannot name or target any firewall rule. The existing fixed rule must exactly match the server-side acceptance shape before a plan is issued.")]
    public static SignedPlan FirewallAcceptanceRemovePlan()
    {
        var programSha256 = ValidateProgramAndHash();
        var current = ReadRule() ?? throw new InvalidOperationException($"Acceptance firewall rule {RuleName} does not exist.");
        RequireFixedSnapshot(current);

        var parameters = FixedParameters(programSha256);
        parameters["rulePresent"] = "true";
        var now = DateTimeOffset.UtcNow;
        var summary = $"Remove fixed Network v3 acceptance firewall rule {RuleName}";
        var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)), "firewall-acceptance", "fixed-remove", RuleName, parameters, RiskClass.High, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    [McpServerTool(Name = "firewall_acceptance_remove_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute only a previously prepared fixed Network v3 firewall acceptance removal plan. The only caller inputs are planId and approvalCode. The server revalidates the fixed plan and exact current acceptance rule snapshot, removes only that fixed rule using the Windows Firewall COM API, and proves absence by read-back. No arbitrary firewall rule can be targeted.")]
    public static FirewallAcceptanceResult FirewallAcceptanceRemoveExecute(string planId, string approvalCode)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireFixedPlan(plan, "fixed-remove");
        if (!string.Equals(RequireParameter(plan, "rulePresent"), "true", StringComparison.Ordinal))
            throw new InvalidDataException("Signed acceptance rule presence state is invalid.");
        var programSha256 = ValidateProgramAndHash();
        RequireFixedParameters(plan, programSha256);
        var current = ReadRule() ?? throw new InvalidOperationException("Acceptance firewall rule disappeared after plan preparation.");
        RequireFixedSnapshot(current);

        try
        {
            RemoveFixedRule();
            if (ReadRule() is not null)
                throw new InvalidOperationException("Acceptance firewall rule removal read-back failed.");
            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, outcome = "acceptance-rule-removed" }, "executed");
            return new FirewallAcceptanceResult(plan.PlanId, plan.Operation, RuleName, true, false, "acceptance-rule-removed", DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
    }

    private static Dictionary<string, string> FixedParameters(string programSha256) => new(StringComparer.Ordinal)
    {
        ["name"] = RuleName,
        ["description"] = DescriptionText,
        ["grouping"] = GroupingText,
        ["applicationName"] = ProgramPath,
        ["protocol"] = ProtocolTcp.ToString(CultureInfo.InvariantCulture),
        ["localPorts"] = LocalPort.ToString(CultureInfo.InvariantCulture),
        ["direction"] = DirectionInbound.ToString(CultureInfo.InvariantCulture),
        ["action"] = ActionAllow.ToString(CultureInfo.InvariantCulture),
        ["enabled"] = "true",
        ["profiles"] = Profiles.ToString(CultureInfo.InvariantCulture),
        ["remoteAddresses"] = RemoteAddresses,
        ["edgeTraversal"] = "false",
        ["programSha256"] = programSha256
    };

    private static void RequireFixedPlan(SignedPlan plan, string operation)
    {
        if (!string.Equals(plan.Tool, "firewall-acceptance", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, operation, StringComparison.Ordinal) ||
            !string.Equals(plan.Target, RuleName, StringComparison.Ordinal) ||
            plan.RiskClass != RiskClass.High)
            throw new UnauthorizedAccessException("Acceptance firewall plan identity is invalid.");
    }

    private static void RequireFixedParameters(SignedPlan plan, string programSha256)
    {
        foreach (var pair in FixedParameters(programSha256))
            if (!string.Equals(RequireParameter(plan, pair.Key), pair.Value, StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException($"Acceptance firewall plan parameter {pair.Key} does not match the fixed contract.");
    }

    private static string ValidateProgramAndHash()
    {
        var full = Path.GetFullPath(ProgramPath);
        if (!File.Exists(full) || !string.Equals(Path.GetExtension(full), ".exe", StringComparison.OrdinalIgnoreCase))
            throw new FileNotFoundException("Fixed acceptance executable is missing.", full);
        if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Fixed acceptance executable may not be a reparse point.");
        using var stream = File.OpenRead(full);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static void AddFixedRule()
    {
        dynamic rule = CreateRule();
        rule.Name = RuleName;
        rule.Description = DescriptionText;
        rule.Grouping = GroupingText;
        rule.ApplicationName = ProgramPath;
        rule.Protocol = ProtocolTcp;
        rule.LocalPorts = LocalPort.ToString(CultureInfo.InvariantCulture);
        rule.Direction = DirectionInbound;
        rule.Action = ActionAllow;
        rule.Enabled = true;
        rule.Profiles = Profiles;
        rule.RemoteAddresses = RemoteAddresses;
        rule.EdgeTraversal = false;
        dynamic policy = CreatePolicy();
        policy.Rules.Add(rule);
    }

    private static void RemoveFixedRule()
    {
        dynamic policy = CreatePolicy();
        policy.Rules.Remove(RuleName);
    }

    private static AcceptanceSnapshot? ReadRule()
    {
        dynamic policy = CreatePolicy();
        IEnumerable rules = (IEnumerable)policy.Rules;
        foreach (var item in rules)
        {
            dynamic rule = item!;
            var name = Convert.ToString(rule.Name, CultureInfo.InvariantCulture) ?? string.Empty;
            if (!string.Equals(name, RuleName, StringComparison.OrdinalIgnoreCase)) continue;
            return new AcceptanceSnapshot(
                name,
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
        }
        return null;
    }

    private static void RequireFixedSnapshot(AcceptanceSnapshot x)
    {
        if (!string.Equals(x.Name, RuleName, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(x.Description, DescriptionText, StringComparison.Ordinal) ||
            !string.Equals(x.Grouping, GroupingText, StringComparison.Ordinal) ||
            !string.Equals(Path.GetFullPath(x.ApplicationName), Path.GetFullPath(ProgramPath), StringComparison.OrdinalIgnoreCase) ||
            x.Protocol != ProtocolTcp ||
            !string.Equals(x.LocalPorts, LocalPort.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal) ||
            x.Direction != DirectionInbound || x.Action != ActionAllow || !x.Enabled ||
            x.Profiles != Profiles ||
            !string.Equals(x.RemoteAddresses, RemoteAddresses, StringComparison.OrdinalIgnoreCase) ||
            x.EdgeTraversal)
            throw new UnauthorizedAccessException("Current firewall rule does not match the fixed acceptance contract.");
    }

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

    private static string RequireParameter(SignedPlan plan, string key)
        => plan.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new InvalidDataException($"{key} parameter is required.");

    private sealed record AcceptanceSnapshot(string Name, string Description, string Grouping, string ApplicationName, int Protocol, string LocalPorts, int Direction, int Action, bool Enabled, int Profiles, string RemoteAddresses, bool EdgeTraversal);
}

public sealed record FirewallAcceptanceResult(string PlanId, string Operation, string RuleName, bool PresentBefore, bool PresentAfter, string Outcome, DateTimeOffset ExecutedUtc);