using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.Windows;

[System.Runtime.Versioning.SupportedOSPlatform("windows")]
[McpServerToolType]
public static class LocalGroupTools
{
    private const int NERR_Success = 0;
    private const int ERROR_MORE_DATA = 234;
    private const int ERROR_INSUFFICIENT_BUFFER = 122;
    private const int MAX_PREFERRED_LENGTH = -1;

    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");

    [McpServerTool(Name = "local_group_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List local Windows groups on the current machine using the native NetLocalGroupEnum API. This is read-only and does not use PowerShell, cmd, net.exe, WMI command execution, or generic command execution.")]
    public static IReadOnlyList<LocalGroupListItem> LocalGroupList()
    {
        var result = new List<LocalGroupListItem>();
        var resume = IntPtr.Zero;
        while (true)
        {
            var status = NetLocalGroupEnum(null, 1, out var buffer, MAX_PREFERRED_LENGTH, out var entriesRead, out _, ref resume);
            try
            {
                if (status != NERR_Success && status != ERROR_MORE_DATA)
                    throw new Win32Exception(status, "Unable to enumerate local Windows groups.");
                var size = Marshal.SizeOf<LOCALGROUP_INFO_1>();
                for (var i = 0; i < entriesRead; i++)
                {
                    var item = Marshal.PtrToStructure<LOCALGROUP_INFO_1>(IntPtr.Add(buffer, i * size));
                    var name = Marshal.PtrToStringUni(item.lgrpi1_name) ?? string.Empty;
                    var comment = Marshal.PtrToStringUni(item.lgrpi1_comment) ?? string.Empty;
                    if (!string.IsNullOrWhiteSpace(name)) result.Add(new LocalGroupListItem(name, comment));
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
            }
            if (status == NERR_Success) break;
        }
        return result.OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    [McpServerTool(Name = "local_group_member_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List members of one existing local Windows group using the native NetLocalGroupGetMembers API. The result includes account name and SID usage type. This is read-only and does not add, remove, or modify group membership.")]
    public static IReadOnlyList<LocalGroupMemberItem> LocalGroupMemberList(string groupName)
        => ReadMembers(ValidateGroupName(groupName))
            .Select(x => new LocalGroupMemberItem(x.CanonicalName, SidUsageName(x.SidUsage)))
            .OrderBy(x => x.AccountName, StringComparer.OrdinalIgnoreCase)
            .ToArray();

    [McpServerTool(Name = "local_group_member_add_plan", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to add one resolved Windows principal to one existing local Windows group. The local group canonical identity and SID, principal canonical identity and SID, SID usage values, and current non-membership state are sealed. No PowerShell, net.exe, shell, or generic command execution is used.")]
    public static SignedPlan LocalGroupMemberAddPlan(string groupName, string accountName)
    {
        var snapshot = ReadMutationSnapshot(groupName, accountName);
        if (snapshot.IsMember)
            throw new InvalidOperationException($"Account {snapshot.Account.CanonicalName} is already a member of {snapshot.GroupName}.");
        return CreatePlan("member-add", snapshot, $"Add {snapshot.Account.CanonicalName} ({snapshot.Account.Sid}) to local group {snapshot.GroupName}");
    }

    [McpServerTool(Name = "local_group_member_add_execute", ReadOnly = false, Destructive = false, OpenWorld = false)]
    [Description("Execute one previously prepared local-group/member-add plan using native NetLocalGroupAddMembers with the sealed group and principal identities. Group SID, principal SID, SID usage, and non-membership state are revalidated immediately before mutation, followed by read-back verification.")]
    public static LocalGroupMutationResult LocalGroupMemberAddExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
        => ExecuteMutation(planId, approvalCode, operation, target, summary, riskClass, "member-add", false);

    [McpServerTool(Name = "local_group_member_remove_plan", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to remove one resolved Windows principal from one existing local Windows group. The local group canonical identity and SID, principal canonical identity and SID, SID usage values, and current membership state are sealed. No PowerShell, net.exe, shell, or generic command execution is used.")]
    public static SignedPlan LocalGroupMemberRemovePlan(string groupName, string accountName)
    {
        var snapshot = ReadMutationSnapshot(groupName, accountName);
        if (!snapshot.IsMember)
            throw new InvalidOperationException($"Account {snapshot.Account.CanonicalName} is not a member of {snapshot.GroupName}.");
        return CreatePlan("member-remove", snapshot, $"Remove {snapshot.Account.CanonicalName} ({snapshot.Account.Sid}) from local group {snapshot.GroupName}");
    }

    [McpServerTool(Name = "local_group_member_remove_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute one previously prepared local-group/member-remove plan using native NetLocalGroupDelMembers with the sealed group and principal identities. Group SID, principal SID, SID usage, and membership state are revalidated immediately before mutation, followed by read-back verification.")]
    public static LocalGroupMutationResult LocalGroupMemberRemoveExecute(string planId, string approvalCode, string operation, string target, string summary, string riskClass)
        => ExecuteMutation(planId, approvalCode, operation, target, summary, riskClass, "member-remove", true);

    private static LocalGroupMutationResult ExecuteMutation(string planId, string approvalCode, string operation, string target, string summary, string riskClass, string expectedOperation, bool expectedMemberBefore)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, expectedOperation, operation, target, summary, riskClass);
        var expected = ReadSnapshot(plan);
        if (expected.IsMember != expectedMemberBefore)
            throw new InvalidDataException("Signed local-group membership state is inconsistent with the requested operation.");

        var current = ReadMutationSnapshot(expected.GroupName, expected.Account.CanonicalName);
        RequireSnapshotMatch(expected, current);

        var sidBytes = SidStringToBytes(current.Account.Sid);
        var sidPtr = Marshal.AllocHGlobal(sidBytes.Length);
        try
        {
            Marshal.Copy(sidBytes, 0, sidPtr, sidBytes.Length);
            var info = new LOCALGROUP_MEMBERS_INFO_0 { lgrmi0_sid = sidPtr };
            var status = expectedOperation == "member-add"
                ? NetLocalGroupAddMembers(null, current.GroupName, 0, ref info, 1)
                : NetLocalGroupDelMembers(null, current.GroupName, 0, ref info, 1);
            if (status != NERR_Success)
                throw new Win32Exception(status, $"Unable to {expectedOperation} account {current.Account.CanonicalName} for local group {current.GroupName}.");
        }
        catch (Exception ex)
        {
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message }, "failed");
            throw;
        }
        finally
        {
            Marshal.FreeHGlobal(sidPtr);
        }

        var after = ReadMutationSnapshot(current.GroupName, current.Account.CanonicalName);
        var expectedAfter = !expectedMemberBefore;
        if (after.IsMember != expectedAfter ||
            !string.Equals(after.Group.Sid, current.Group.Sid, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(after.Account.Sid, current.Account.Sid, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Local group membership mutation verification failed.");

        Store.Consume(planId);
        var outcome = expectedOperation == "member-add" ? "member-added" : "member-removed";
        Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, outcome, group = current.GroupName, groupSid = current.Group.Sid, account = current.Account.CanonicalName, accountSid = current.Account.Sid }, "executed");
        return new LocalGroupMutationResult(plan.PlanId, plan.Operation, current.GroupName, current.Group.Sid, current.Account.CanonicalName, current.Account.Sid, SidUsageName(current.Account.SidUsage), expectedMemberBefore, expectedAfter, outcome, DateTimeOffset.UtcNow);
    }

    private static SignedPlan CreatePlan(string operation, MembershipSnapshot snapshot, string summary)
    {
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["groupName"] = snapshot.GroupName,
            ["groupCanonicalName"] = snapshot.Group.CanonicalName,
            ["groupSid"] = snapshot.Group.Sid,
            ["groupSidUsage"] = snapshot.Group.SidUsage.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["accountCanonicalName"] = snapshot.Account.CanonicalName,
            ["accountSid"] = snapshot.Account.Sid,
            ["accountSidUsage"] = snapshot.Account.SidUsage.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["isMember"] = snapshot.IsMember ? "true" : "false"
        };
        var now = DateTimeOffset.UtcNow;
        var target = $"{snapshot.GroupName}:{snapshot.Account.Sid}";
        var unsigned = new SignedPlan(1, Guid.NewGuid().ToString("N"), Convert.ToHexString(RandomNumberGenerator.GetBytes(6)), "local-group", operation, target, parameters, RiskClass.High, summary, now, now.AddMinutes(10), string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target, new { signed.PlanId, signed.RiskClass, signed.Summary }, "prepared");
        return signed;
    }

    private static MembershipSnapshot ReadSnapshot(SignedPlan plan)
    {
        var groupName = RequireParameter(plan, "groupName");
        var groupCanonicalName = RequireParameter(plan, "groupCanonicalName");
        var groupSid = RequireParameter(plan, "groupSid");
        var groupSidUsageText = RequireParameter(plan, "groupSidUsage");
        var accountCanonicalName = RequireParameter(plan, "accountCanonicalName");
        var accountSid = RequireParameter(plan, "accountSid");
        var accountSidUsageText = RequireParameter(plan, "accountSidUsage");
        var isMemberText = RequireParameter(plan, "isMember");
        if (!int.TryParse(groupSidUsageText, out var groupSidUsage) || !int.TryParse(accountSidUsageText, out var accountSidUsage) || !bool.TryParse(isMemberText, out var isMember))
            throw new InvalidDataException("Signed local-group membership snapshot is invalid.");
        groupName = ValidateGroupName(groupName);
        _ = SidStringToBytes(groupSid);
        _ = SidStringToBytes(accountSid);
        return new MembershipSnapshot(groupName, new AccountIdentity(groupCanonicalName, groupSid, groupSidUsage), new AccountIdentity(accountCanonicalName, accountSid, accountSidUsage), isMember);
    }

    private static MembershipSnapshot ReadMutationSnapshot(string groupName, string accountName)
    {
        groupName = ValidateGroupName(groupName);
        accountName = ValidateAccountName(accountName);
        var group = ResolveAccount($"{Environment.MachineName}\\{groupName}");
        if (group.SidUsage != 4)
            throw new InvalidOperationException($"{groupName} did not resolve as a local alias group.");
        var account = ResolveAccount(accountName);
        var isMember = ReadMembers(groupName).Any(x => string.Equals(x.Sid, account.Sid, StringComparison.OrdinalIgnoreCase));
        return new MembershipSnapshot(groupName, group, account, isMember);
    }

    private static void RequireSnapshotMatch(MembershipSnapshot expected, MembershipSnapshot current)
    {
        if (!string.Equals(expected.GroupName, current.GroupName, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(expected.Group.CanonicalName, current.Group.CanonicalName, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(expected.Group.Sid, current.Group.Sid, StringComparison.OrdinalIgnoreCase) ||
            expected.Group.SidUsage != current.Group.SidUsage ||
            !string.Equals(expected.Account.CanonicalName, current.Account.CanonicalName, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(expected.Account.Sid, current.Account.Sid, StringComparison.OrdinalIgnoreCase) ||
            expected.Account.SidUsage != current.Account.SidUsage ||
            expected.IsMember != current.IsMember)
            throw new InvalidOperationException("Local group, account identity, or membership state changed after plan preparation.");
    }

    private static void RequireIntentMatch(SignedPlan plan, string expectedOperation, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "local-group", StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, expectedOperation, StringComparison.Ordinal) ||
            !string.Equals(plan.Operation, operation, StringComparison.Ordinal) ||
            !string.Equals(plan.Target, target, StringComparison.Ordinal) ||
            !string.Equals(plan.Summary, summary, StringComparison.Ordinal) ||
            !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
    }

    private static IReadOnlyList<AccountIdentity> ReadMembers(string groupName)
    {
        groupName = ValidateGroupName(groupName);
        var result = new List<AccountIdentity>();
        var resume = IntPtr.Zero;
        while (true)
        {
            var status = NetLocalGroupGetMembers(null, groupName, 2, out var buffer, MAX_PREFERRED_LENGTH, out var entriesRead, out _, ref resume);
            try
            {
                if (status != NERR_Success && status != ERROR_MORE_DATA)
                    throw new Win32Exception(status, $"Unable to enumerate members of local group {groupName}.");
                var size = Marshal.SizeOf<LOCALGROUP_MEMBERS_INFO_2>();
                for (var i = 0; i < entriesRead; i++)
                {
                    var item = Marshal.PtrToStructure<LOCALGROUP_MEMBERS_INFO_2>(IntPtr.Add(buffer, i * size));
                    var canonical = Marshal.PtrToStringUni(item.lgrmi2_domainandname) ?? string.Empty;
                    result.Add(new AccountIdentity(canonical, SidPointerToString(item.lgrmi2_sid), item.lgrmi2_sidusage));
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
            }
            if (status == NERR_Success) break;
        }
        return result;
    }

    private static AccountIdentity ResolveAccount(string accountName)
    {
        var sidSize = 0;
        var domainSize = 0;
        _ = LookupAccountNameW(null, accountName, IntPtr.Zero, ref sidSize, null, ref domainSize, out _);
        var error = Marshal.GetLastWin32Error();
        if (error != ERROR_INSUFFICIENT_BUFFER || sidSize <= 0)
            throw new Win32Exception(error, $"Unable to resolve Windows account {accountName}.");
        var sidPtr = Marshal.AllocHGlobal(sidSize);
        try
        {
            var domain = new StringBuilder(Math.Max(domainSize, 1));
            var sidSize2 = sidSize;
            var domainSize2 = domain.Capacity;
            if (!LookupAccountNameW(null, accountName, sidPtr, ref sidSize2, domain, ref domainSize2, out var sidUsage))
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"Unable to resolve Windows account {accountName}.");
            return new AccountIdentity(LookupCanonicalName(sidPtr, sidUsage), SidPointerToString(sidPtr), sidUsage);
        }
        finally
        {
            Marshal.FreeHGlobal(sidPtr);
        }
    }

    private static string LookupCanonicalName(IntPtr sidPtr, int sidUsage)
    {
        var nameSize = 0;
        var domainSize = 0;
        _ = LookupAccountSidW(null, sidPtr, null, ref nameSize, null, ref domainSize, out _);
        var error = Marshal.GetLastWin32Error();
        if (error != ERROR_INSUFFICIENT_BUFFER || nameSize <= 0)
            throw new Win32Exception(error, "Unable to resolve canonical account name from SID.");
        var name = new StringBuilder(nameSize);
        var domain = new StringBuilder(Math.Max(domainSize, 1));
        var nameSize2 = name.Capacity;
        var domainSize2 = domain.Capacity;
        if (!LookupAccountSidW(null, sidPtr, name, ref nameSize2, domain, ref domainSize2, out var resolvedUsage))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to resolve canonical account name from SID.");
        if (resolvedUsage != sidUsage) throw new InvalidOperationException("Windows SID usage changed during account resolution.");
        return domain.Length == 0 ? name.ToString() : $"{domain}\\{name}";
    }

    private static string SidPointerToString(IntPtr sidPtr)
    {
        if (sidPtr == IntPtr.Zero || !IsValidSid(sidPtr)) throw new InvalidDataException("Windows account SID is invalid.");
        var length = GetLengthSid(sidPtr);
        if (length <= 0) throw new InvalidDataException("Windows account SID length is invalid.");
        var bytes = new byte[length];
        Marshal.Copy(sidPtr, bytes, 0, length);
        return new SecurityIdentifier(bytes, 0).Value;
    }

    private static byte[] SidStringToBytes(string sid)
    {
        try
        {
            var value = new SecurityIdentifier(sid);
            var bytes = new byte[value.BinaryLength];
            value.GetBinaryForm(bytes, 0);
            return bytes;
        }
        catch (Exception ex)
        {
            throw new InvalidDataException("Signed Windows SID is invalid.", ex);
        }
    }

    private static string ValidateGroupName(string groupName)
    {
        if (string.IsNullOrWhiteSpace(groupName) || groupName.Length > 256 || groupName.Any(char.IsControl) || groupName.Contains('\0'))
            throw new ArgumentException("Local group name is invalid.", nameof(groupName));
        return groupName.Trim();
    }

    private static string ValidateAccountName(string accountName)
    {
        if (string.IsNullOrWhiteSpace(accountName) || accountName.Length > 512 || accountName.Any(char.IsControl) || accountName.Contains('\0'))
            throw new ArgumentException("Windows account name is invalid.", nameof(accountName));
        return accountName.Trim();
    }

    private static string RequireParameter(SignedPlan plan, string key)
        => plan.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value) ? value : throw new InvalidDataException($"{key} parameter is required.");

    private static string SidUsageName(int value) => value switch
    {
        1 => "User", 2 => "Group", 3 => "Domain", 4 => "Alias", 5 => "WellKnownGroup", 6 => "DeletedAccount", 7 => "Invalid", 8 => "Unknown", 9 => "Computer", 10 => "Label", 11 => "LogonSession", _ => $"Unknown({value})"
    };

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int NetLocalGroupEnum(string? servername, int level, out IntPtr bufptr, int prefmaxlen, out int entriesread, out int totalentries, ref IntPtr resume_handle);
    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int NetLocalGroupGetMembers(string? servername, string localgroupname, int level, out IntPtr bufptr, int prefmaxlen, out int entriesread, out int totalentries, ref IntPtr resume_handle);
    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int NetLocalGroupAddMembers(string? servername, string groupname, int level, ref LOCALGROUP_MEMBERS_INFO_0 buf, int totalentries);
    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int NetLocalGroupDelMembers(string? servername, string groupname, int level, ref LOCALGROUP_MEMBERS_INFO_0 buf, int totalentries);
    [DllImport("Netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupAccountNameW(string? lpSystemName, string lpAccountName, IntPtr Sid, ref int cbSid, StringBuilder? ReferencedDomainName, ref int cchReferencedDomainName, out int peUse);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupAccountSidW(string? lpSystemName, IntPtr Sid, StringBuilder? Name, ref int cchName, StringBuilder? ReferencedDomainName, ref int cchReferencedDomainName, out int peUse);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsValidSid(IntPtr pSid);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int GetLengthSid(IntPtr pSid);

    [StructLayout(LayoutKind.Sequential)] private struct LOCALGROUP_INFO_1 { public IntPtr lgrpi1_name; public IntPtr lgrpi1_comment; }
    [StructLayout(LayoutKind.Sequential)] private struct LOCALGROUP_MEMBERS_INFO_0 { public IntPtr lgrmi0_sid; }
    [StructLayout(LayoutKind.Sequential)] private struct LOCALGROUP_MEMBERS_INFO_2 { public IntPtr lgrmi2_sid; public int lgrmi2_sidusage; public IntPtr lgrmi2_domainandname; }

    private sealed record AccountIdentity(string CanonicalName, string Sid, int SidUsage);
    private sealed record MembershipSnapshot(string GroupName, AccountIdentity Group, AccountIdentity Account, bool IsMember);
}

public sealed record LocalGroupListItem(string Name, string Comment);
public sealed record LocalGroupMemberItem(string AccountName, string SidUsage);
public sealed record LocalGroupMutationResult(string PlanId, string Operation, string GroupName, string GroupSid, string AccountName, string AccountSid, string SidUsage, bool MemberBefore, bool MemberAfter, string Outcome, DateTimeOffset ExecutedUtc);
