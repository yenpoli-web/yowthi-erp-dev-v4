using System.ComponentModel;
using System.Runtime.InteropServices;
using ModelContextProtocol.Server;

namespace YowThi.DevelopmentAgent3.Windows;

[McpServerToolType]
public static class LocalGroupTools
{
    private const int NERR_Success = 0;
    private const int ERROR_MORE_DATA = 234;
    private const int MAX_PREFERRED_LENGTH = -1;

    [McpServerTool(Name = "local_group_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List local Windows groups on the current machine using the native NetLocalGroupEnum API. This is read-only and does not use PowerShell, cmd, net.exe, WMI command execution, or generic command execution.")]
    public static IReadOnlyList<LocalGroupListItem> LocalGroupList()
    {
        var result = new List<LocalGroupListItem>();
        var resume = IntPtr.Zero;
        try
        {
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
        }
        finally
        {
            if (resume != IntPtr.Zero) resume = IntPtr.Zero;
        }

        return result.OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    [McpServerTool(Name = "local_group_member_list", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("List members of one existing local Windows group using the native NetLocalGroupGetMembers API. The result includes account name and SID usage type. This is read-only and does not add, remove, or modify group membership.")]
    public static IReadOnlyList<LocalGroupMemberItem> LocalGroupMemberList(string groupName)
    {
        groupName = ValidateGroupName(groupName);
        var result = new List<LocalGroupMemberItem>();
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
                    var domainAndName = Marshal.PtrToStringUni(item.lgrmi2_domainandname) ?? string.Empty;
                    result.Add(new LocalGroupMemberItem(domainAndName, SidUsageName(item.lgrmi2_sidusage)));
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
            }

            if (status == NERR_Success) break;
        }

        return result.OrderBy(x => x.AccountName, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static string ValidateGroupName(string groupName)
    {
        if (string.IsNullOrWhiteSpace(groupName) || groupName.Length > 256 || groupName.Any(char.IsControl) || groupName.Contains('\0'))
            throw new ArgumentException("Local group name is invalid.", nameof(groupName));
        return groupName.Trim();
    }

    private static string SidUsageName(int value) => value switch
    {
        1 => "User",
        2 => "Group",
        3 => "Domain",
        4 => "Alias",
        5 => "WellKnownGroup",
        6 => "DeletedAccount",
        7 => "Invalid",
        8 => "Unknown",
        9 => "Computer",
        10 => "Label",
        11 => "LogonSession",
        _ => $"Unknown({value})"
    };

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int NetLocalGroupEnum(string? servername, int level, out IntPtr bufptr, int prefmaxlen, out int entriesread, out int totalentries, ref IntPtr resume_handle);

    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int NetLocalGroupGetMembers(string? servername, string localgroupname, int level, out IntPtr bufptr, int prefmaxlen, out int entriesread, out int totalentries, ref IntPtr resume_handle);

    [DllImport("Netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);

    [StructLayout(LayoutKind.Sequential)]
    private struct LOCALGROUP_INFO_1
    {
        public IntPtr lgrpi1_name;
        public IntPtr lgrpi1_comment;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LOCALGROUP_MEMBERS_INFO_2
    {
        public IntPtr lgrmi2_sid;
        public int lgrmi2_sidusage;
        public IntPtr lgrmi2_domainandname;
    }
}

public sealed record LocalGroupListItem(string Name, string Comment);
public sealed record LocalGroupMemberItem(string AccountName, string SidUsage);
