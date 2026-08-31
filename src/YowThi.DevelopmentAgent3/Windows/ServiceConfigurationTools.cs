using System.Collections.Concurrent;
using System.ComponentModel;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.Windows;

[McpServerToolType]
[SupportedOSPlatform("windows")]
public static class ServiceConfigurationTools
{
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");
    private static readonly ConcurrentDictionary<string, PendingEnvironmentPayload> EnvironmentPayloads = new(StringComparer.Ordinal);

    private const string ServiceRegistryRoot = @"SYSTEM\CurrentControlSet\Services";
    private const string ServiceEnvironmentValue = "Environment";
    private const int MaxEnvironmentBlockChars = 32767;

    [McpServerTool(Name = "service_environment_status", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Read service-specific Environment REG_MULTI_SZ metadata for one YowThi-owned Windows service. Values are never returned; only variable names, value SHA-256 digests, value lengths, and an environment fingerprint are exposed. The service must still satisfy the existing YowThi ownership and protected-production checks. No PowerShell, cmd, sc.exe, reg.exe, or generic command executor is used.")]
    public static ServiceEnvironmentStatusResult ServiceEnvironmentStatus(string serviceName)
    {
        serviceName = ValidateRegistrySafeServiceName(serviceName);
        var status = ServiceTools.ServiceStatus(serviceName);
        RequireMutationEligible(status);
        var environment = ReadEnvironmentSnapshot(serviceName);
        return ToEnvironmentStatus(status, environment);
    }

    [McpServerTool(Name = "service_environment_replace_plan", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to replace the complete service-specific Environment REG_MULTI_SZ value for one stopped YowThi-owned Windows service. Raw environment values are not placed in the signed plan, audit record, or result; they are retained only in an expiring in-memory payload owned by this Agent runtime. Service configuration, stopped state, current environment fingerprint, proposed environment fingerprint, variable names, and value digests are sealed. Production-linked services and arbitrary registry paths are blocked.")]
    public static SignedPlan ServiceEnvironmentReplacePlan(string serviceName, Dictionary<string, string> variables)
    {
        CleanupExpiredPayloads();
        serviceName = ValidateRegistrySafeServiceName(serviceName);
        var status = ReadEligibleStoppedService(serviceName);
        var before = ReadEnvironmentSnapshot(serviceName);
        var afterEntries = NormalizeRequestedEnvironment(variables);
        var after = BuildEnvironmentSnapshot(afterEntries);

        if (string.Equals(before.FingerprintSha256, after.FingerprintSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Requested service environment is identical to the current environment.");

        var now = DateTimeOffset.UtcNow;
        var planId = Guid.NewGuid().ToString("N");
        var approvalCode = Convert.ToHexString(RandomNumberGenerator.GetBytes(6));
        var target = $"{serviceName}:environment";
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["serviceName"] = serviceName,
            ["serviceConfigFingerprint"] = status.ConfigFingerprint,
            ["effectiveImageTarget"] = status.EffectiveImageTarget!,
            ["expectedState"] = "Stopped",
            ["environmentBeforeSha256"] = before.FingerprintSha256,
            ["environmentAfterSha256"] = after.FingerprintSha256,
            ["variableNames"] = string.Join("\n", after.Variables.Select(x => x.Name)),
            ["valueDigests"] = string.Join("\n", after.Variables.Select(x => $"{x.Name}={x.ValueSha256}"))
        };
        var summary = $"Replace service-specific environment for YowThi-owned Windows service {serviceName} with {after.Variables.Count} variable(s); values redacted";
        var unsigned = new SignedPlan(1, planId, approvalCode, "service", "service-environment-replace", target, parameters, RiskClass.High, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        EnvironmentPayloads[planId] = new PendingEnvironmentPayload(signed.ExpiresUtc, before.Entries, after.Entries);
        Audit.Append(signed.Tool, signed.Operation, signed.Target,
            new { signed.PlanId, signed.RiskClass, signed.Summary, before = before.FingerprintSha256, after = after.FingerprintSha256, variableNames = after.Variables.Select(x => x.Name).ToArray() },
            "prepared");
        return signed;
    }

    [McpServerTool(Name = "service_environment_replace_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute one previously prepared service/service-environment-replace plan. Only the exact stopped YowThi-owned service and the expiring in-memory environment payload associated with the signed plan may be used. Service configuration, effective image target, stopped state, and environment-before fingerprint are revalidated before the native Registry API writes Environment as REG_MULTI_SZ. Post-write read-back must match the signed environment-after fingerprint; failed verification triggers a best-effort rollback to the sealed pre-plan environment.")]
    public static ServiceEnvironmentMutationResult ServiceEnvironmentReplaceExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        CleanupExpiredPayloads();
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "service-environment-replace", operation, target, summary, riskClass);
        if (!EnvironmentPayloads.TryGetValue(planId, out var payload) || payload.ExpiresUtc <= DateTimeOffset.UtcNow)
            throw new InvalidOperationException("Service environment payload is unavailable or expired.");

        var serviceName = ValidateRegistrySafeServiceName(RequireParameter(plan, "serviceName"));
        var status = ReadEligibleStoppedService(serviceName);
        RevalidateServiceContext(plan, status);
        var before = ReadEnvironmentSnapshot(serviceName);
        if (!string.Equals(before.FingerprintSha256, RequireParameter(plan, "environmentBeforeSha256"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Service environment changed after plan preparation.");

        var proposed = BuildEnvironmentSnapshot(payload.AfterEntries);
        if (!string.Equals(proposed.FingerprintSha256, RequireParameter(plan, "environmentAfterSha256"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("In-memory service environment payload does not match the signed plan.");

        var wrote = false;
        try
        {
            WriteEnvironment(serviceName, payload.AfterEntries);
            wrote = true;
            var after = ReadEnvironmentSnapshot(serviceName);
            if (!string.Equals(after.FingerprintSha256, proposed.FingerprintSha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Service environment read-back fingerprint does not match the signed target state.");

            Store.Consume(planId);
            EnvironmentPayloads.TryRemove(planId, out _);
            Audit.Append(plan.Tool, plan.Operation, plan.Target,
                new { plan.PlanId, before = before.FingerprintSha256, after = after.FingerprintSha256, variables = after.Variables.Select(x => x.Name).ToArray() },
                "executed");
            return new ServiceEnvironmentMutationResult(plan.PlanId, serviceName, before.FingerprintSha256, after.FingerprintSha256, after.Variables, "environment-replaced", DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            var rollback = "not-required";
            if (wrote)
            {
                try
                {
                    WriteEnvironment(serviceName, payload.BeforeEntries);
                    rollback = "restored-before-environment";
                }
                catch (Exception rollbackEx)
                {
                    rollback = $"rollback-failed:{rollbackEx.GetType().Name}";
                }
            }
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message, rollback }, "failed");
            throw;
        }
    }

    private static ServiceStatusResult ReadEligibleStoppedService(string serviceName)
    {
        var status = ServiceTools.ServiceStatus(serviceName);
        RequireMutationEligible(status);
        if (!string.Equals(status.State, "Stopped", StringComparison.Ordinal))
            throw new InvalidOperationException($"Service configuration mutation requires Stopped state. Current state: {status.State}.");
        return status;
    }

    private static void RequireMutationEligible(ServiceStatusResult status)
    {
        if (!status.MutationEligible || string.IsNullOrWhiteSpace(status.EffectiveImageTarget))
            throw new UnauthorizedAccessException($"Service configuration mutation is blocked: {status.EligibilityReason}");
    }

    private static void RevalidateServiceContext(SignedPlan plan, ServiceStatusResult status)
    {
        RequireMutationEligible(status);
        if (!string.Equals(status.State, RequireParameter(plan, "expectedState"), StringComparison.Ordinal))
            throw new InvalidOperationException("Service state changed after plan preparation.");
        if (!string.Equals(status.ConfigFingerprint, RequireParameter(plan, "serviceConfigFingerprint"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Service configuration changed after plan preparation.");
        if (!string.Equals(status.EffectiveImageTarget, RequireParameter(plan, "effectiveImageTarget"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Service effective image target changed after plan preparation.");
    }

    private static EnvironmentSnapshot ReadEnvironmentSnapshot(string serviceName)
    {
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var serviceKey = baseKey.OpenSubKey($@"{ServiceRegistryRoot}\{serviceName}", writable: false)
            ?? throw new InvalidOperationException($"Service registry key does not exist for {serviceName}.");

        var hasValue = serviceKey.GetValueNames().Any(x => string.Equals(x, ServiceEnvironmentValue, StringComparison.OrdinalIgnoreCase));
        if (!hasValue)
            return BuildEnvironmentSnapshot(Array.Empty<string>());
        if (serviceKey.GetValueKind(ServiceEnvironmentValue) != RegistryValueKind.MultiString)
            throw new InvalidDataException("Service Environment registry value exists but is not REG_MULTI_SZ.");

        var entries = serviceKey.GetValue(ServiceEnvironmentValue, Array.Empty<string>(), RegistryValueOptions.DoNotExpandEnvironmentNames) as string[]
            ?? throw new InvalidDataException("Service Environment REG_MULTI_SZ could not be read as string[].");
        return BuildEnvironmentSnapshot(entries);
    }

    private static EnvironmentSnapshot BuildEnvironmentSnapshot(IEnumerable<string> entries)
    {
        var variables = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
        {
            if (entry is null)
                throw new InvalidDataException("Service environment contains a null REG_MULTI_SZ entry.");
            var separator = entry.IndexOf('=');
            if (separator <= 0)
                throw new InvalidDataException("Service environment contains an invalid NAME=VALUE entry.");
            var name = ValidateEnvironmentName(entry[..separator]);
            var value = ValidateEnvironmentValue(entry[(separator + 1)..]);
            if (!variables.TryAdd(name, value))
                throw new InvalidDataException($"Service environment contains duplicate variable name {name}.");
        }

        var canonicalEntries = variables
            .OrderBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.Key, StringComparer.Ordinal)
            .Select(x => $"{x.Key}={x.Value}")
            .ToArray();
        ValidateEnvironmentBlockSize(canonicalEntries);

        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var metadata = new List<ServiceEnvironmentVariableMetadata>(canonicalEntries.Length);
        foreach (var entry in canonicalEntries)
        {
            var separator = entry.IndexOf('=');
            var name = entry[..separator];
            var value = entry[(separator + 1)..];
            var valueBytes = Encoding.UTF8.GetBytes(value);
            var valueSha256 = Convert.ToHexString(SHA256.HashData(valueBytes));
            hash.AppendData(Encoding.UTF8.GetBytes(name.ToUpperInvariant()));
            hash.AppendData(new byte[] { 0 });
            hash.AppendData(valueBytes);
            hash.AppendData(new byte[] { 0 });
            metadata.Add(new ServiceEnvironmentVariableMetadata(name, valueSha256, value.Length));
        }

        return new EnvironmentSnapshot(canonicalEntries, metadata, Convert.ToHexString(hash.GetHashAndReset()));
    }

    private static string[] NormalizeRequestedEnvironment(Dictionary<string, string> variables)
    {
        if (variables is null)
            throw new ArgumentNullException(nameof(variables));
        var normalized = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in variables)
        {
            var name = ValidateEnvironmentName(pair.Key);
            var value = ValidateEnvironmentValue(pair.Value);
            if (!normalized.TryAdd(name, value))
                throw new ArgumentException($"Duplicate environment variable name {name}.", nameof(variables));
        }

        var entries = normalized
            .OrderBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.Key, StringComparer.Ordinal)
            .Select(x => $"{x.Key}={x.Value}")
            .ToArray();
        ValidateEnvironmentBlockSize(entries);
        return entries;
    }

    private static string ValidateEnvironmentName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("Environment variable name is required.");
        var trimmed = name.Trim();
        if (trimmed.Contains('=') || trimmed.Contains('\0') || trimmed.Any(char.IsControl))
            throw new ArgumentException("Environment variable name contains unsupported characters.");
        return trimmed;
    }

    private static string ValidateEnvironmentValue(string value)
    {
        value ??= string.Empty;
        if (value.Contains('\0'))
            throw new ArgumentException("Environment variable value cannot contain NUL.");
        return value;
    }

    private static void ValidateEnvironmentBlockSize(IEnumerable<string> entries)
    {
        var chars = 1;
        foreach (var entry in entries)
            chars = checked(chars + entry.Length + 1);
        if (chars > MaxEnvironmentBlockChars)
            throw new ArgumentOutOfRangeException(nameof(entries), $"Service environment block exceeds {MaxEnvironmentBlockChars} UTF-16 characters.");
    }

    private static void WriteEnvironment(string serviceName, string[] entries)
    {
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var serviceKey = baseKey.OpenSubKey($@"{ServiceRegistryRoot}\{serviceName}", writable: true)
            ?? throw new InvalidOperationException($"Writable service registry key does not exist for {serviceName}.");
        if (entries.Length == 0)
            serviceKey.DeleteValue(ServiceEnvironmentValue, throwOnMissingValue: false);
        else
            serviceKey.SetValue(ServiceEnvironmentValue, entries, RegistryValueKind.MultiString);
        serviceKey.Flush();
    }

    private static ServiceEnvironmentStatusResult ToEnvironmentStatus(ServiceStatusResult status, EnvironmentSnapshot environment)
        => new(status.ServiceName, status.State, status.ConfigFingerprint, status.EffectiveImageTarget!, environment.FingerprintSha256, environment.Variables, DateTimeOffset.UtcNow);

    private static SignedPlan CreatePlan(string operation, string target, Dictionary<string, string> parameters, RiskClass riskClass, string summary)
    {
        var now = DateTimeOffset.UtcNow;
        var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)), "service", operation, target, parameters, riskClass, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    private static string ValidateRegistrySafeServiceName(string serviceName)
    {
        if (string.IsNullOrWhiteSpace(serviceName) || serviceName.Length > 256 || serviceName.Contains('\0') || serviceName.Contains('\\') || serviceName.Contains('/') || serviceName.Any(char.IsControl))
            throw new ArgumentException("Service name is invalid for service configuration access.", nameof(serviceName));
        return serviceName.Trim();
    }

    private static void RequireIntentMatch(SignedPlan plan, string expectedOperation, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "service", StringComparison.Ordinal)
            || !string.Equals(plan.Operation, expectedOperation, StringComparison.Ordinal)
            || !string.Equals(plan.Operation, operation, StringComparison.Ordinal)
            || !string.Equals(plan.Target, target, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(plan.Summary, summary, StringComparison.Ordinal)
            || !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
    }

    private static string RequireParameter(SignedPlan plan, string key)
        => plan.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new InvalidDataException($"Signed service parameter {key} is required.");

    private static void CleanupExpiredPayloads()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var item in EnvironmentPayloads)
            if (item.Value.ExpiresUtc <= now)
                EnvironmentPayloads.TryRemove(item.Key, out _);
    }

    private sealed record PendingEnvironmentPayload(DateTimeOffset ExpiresUtc, string[] BeforeEntries, string[] AfterEntries);
    private sealed record EnvironmentSnapshot(string[] Entries, IReadOnlyList<ServiceEnvironmentVariableMetadata> Variables, string FingerprintSha256);
}

public sealed record ServiceEnvironmentVariableMetadata(string Name, string ValueSha256, int ValueLength);

public sealed record ServiceEnvironmentStatusResult(
    string ServiceName,
    string State,
    string ServiceConfigFingerprint,
    string EffectiveImageTarget,
    string EnvironmentFingerprintSha256,
    IReadOnlyList<ServiceEnvironmentVariableMetadata> Variables,
    DateTimeOffset CheckedUtc);

public sealed record ServiceEnvironmentMutationResult(
    string PlanId,
    string ServiceName,
    string BeforeEnvironmentFingerprintSha256,
    string AfterEnvironmentFingerprintSha256,
    IReadOnlyList<ServiceEnvironmentVariableMetadata> Variables,
    string Outcome,
    DateTimeOffset ExecutedUtc);