using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;
using ModelContextProtocol.Server;

namespace YowThi.DevelopmentAgent3.Windows;

[McpServerToolType]
[SupportedOSPlatform("windows")]
public sealed class SystemHardwareTools
{
    private const int ERROR_INSUFFICIENT_BUFFER = 122;
    private const int RelationProcessorCore = 0;
    private const uint DISPLAY_DEVICE_ATTACHED_TO_DESKTOP = 0x00000001;
    private const uint ENUM_CURRENT_SETTINGS = 0xFFFFFFFF;
    private const string DisplayClassPath = @"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}";
    private const string GraphicsConfigurationPath = @"SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Configuration";

    [McpServerTool(Name = "system_hardware_info", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Read local Windows hardware and operating-system information using only native Windows APIs and the .NET Registry/Runtime APIs. Returns CPU identity and physical/logical processor counts, total physical memory, display adapters with best-effort dedicated video-memory and driver metadata, active display modes, and Windows version metadata. This is read-only and does not use PowerShell, cmd, WMI command execution, shell execution, external utilities, network access, or generic command execution.")]
    public static SystemHardwareInfoResult SystemHardwareInfo()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("system_hardware_info is supported only on Windows.");

        return new SystemHardwareInfoResult(
            Environment.MachineName,
            ReadCpu(),
            ReadMemory(),
            ReadGraphicsAdapters(),
            ReadDisplays(),
            ReadWindows());
    }

    private static CpuInfo ReadCpu()
    {
        string? name = null;
        string? vendor = null;
        string? identifier = null;

        using (var key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0", writable: false))
        {
            name = ReadRegistryString(key, "ProcessorNameString")?.Trim();
            vendor = ReadRegistryString(key, "VendorIdentifier")?.Trim();
            identifier = ReadRegistryString(key, "Identifier")?.Trim();
        }

        return new CpuInfo(
            name,
            vendor,
            identifier,
            ReadPhysicalCoreCount(),
            Environment.ProcessorCount,
            RuntimeInformation.ProcessArchitecture.ToString());
    }

    private static int? ReadPhysicalCoreCount()
    {
        uint length = 0;
        var first = GetLogicalProcessorInformationEx(RelationProcessorCore, IntPtr.Zero, ref length);
        var error = Marshal.GetLastWin32Error();
        if (first || error != ERROR_INSUFFICIENT_BUFFER || length < 8)
            return null;

        var buffer = Marshal.AllocHGlobal(checked((int)length));
        try
        {
            if (!GetLogicalProcessorInformationEx(RelationProcessorCore, buffer, ref length))
                return null;

            var offset = 0;
            var count = 0;
            while (offset + 8 <= length)
            {
                var relation = Marshal.ReadInt32(buffer, offset);
                var size = unchecked((uint)Marshal.ReadInt32(buffer, offset + 4));
                if (size < 8 || offset + size > length)
                    return null;

                if (relation == RelationProcessorCore)
                    count++;

                offset += checked((int)size);
            }

            return count > 0 ? count : null;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static MemoryInfo ReadMemory()
    {
        var status = new MEMORYSTATUSEX
        {
            dwLength = checked((uint)Marshal.SizeOf<MEMORYSTATUSEX>())
        };

        if (!GlobalMemoryStatusEx(ref status))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to read physical memory information.");

        return new MemoryInfo(status.ullTotalPhys, BytesToGiB(status.ullTotalPhys));
    }

    private static IReadOnlyList<GraphicsAdapterInfo> ReadGraphicsAdapters()
    {
        var result = new List<GraphicsAdapterInfo>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (uint index = 0; ; index++)
        {
            var device = CreateDisplayDevice();
            if (!EnumDisplayDevicesW(null, index, ref device, 0))
                break;

            var description = device.DeviceString?.TrimEnd('\0').Trim();
            if (string.IsNullOrWhiteSpace(description))
                continue;

            var deviceId = device.DeviceID?.TrimEnd('\0').Trim() ?? string.Empty;
            var identity = $"{description}|{deviceId}";
            if (!seen.Add(identity))
                continue;

            var memoryBytes = TryReadAdapterMemoryBytes(device.DeviceKey);
            var driver = TryReadAdapterDriverMetadata(device.DeviceKey);
            result.Add(new GraphicsAdapterInfo(
                index,
                device.DeviceName?.TrimEnd('\0') ?? string.Empty,
                description,
                deviceId,
                (device.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP) != 0,
                memoryBytes,
                memoryBytes.HasValue ? BytesToGiB(memoryBytes.Value) : null,
                driver.Version,
                driver.Provider,
                driver.Date));
        }

        // Session 0 often has no interactive display-device enumeration. Fall back to the
        // display-adapter class registry, which still exposes installed physical adapters.
        using var classKey = Registry.LocalMachine.OpenSubKey(DisplayClassPath, writable: false);
        if (classKey is not null)
        {
            foreach (var subKeyName in classKey.GetSubKeyNames().OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
            {
                if (subKeyName.Length != 4 || !subKeyName.All(char.IsDigit))
                    continue;

                using var adapterKey = classKey.OpenSubKey(subKeyName, writable: false);
                if (adapterKey is null)
                    continue;

                var description = ReadRegistryString(adapterKey, "DriverDesc")?.Trim();
                if (string.IsNullOrWhiteSpace(description))
                    continue;

                var deviceId = ReadRegistryString(adapterKey, "MatchingDeviceId")?.Trim()
                    ?? ReadRegistryString(adapterKey, "HardwareID")?.Trim()
                    ?? string.Empty;

                var identity = $"{description}|{deviceId}";
                if (!seen.Add(identity))
                    continue;

                var memoryBytes = TryReadAdapterMemoryBytes(adapterKey);
                result.Add(new GraphicsAdapterInfo(
                    checked((uint)result.Count),
                    $"registry:{subKeyName}",
                    description,
                    deviceId,
                    IsAdapterRepresentedInGraphicsConfiguration(deviceId),
                    memoryBytes,
                    memoryBytes.HasValue ? BytesToGiB(memoryBytes.Value) : null,
                    ReadRegistryString(adapterKey, "DriverVersion")?.Trim(),
                    ReadRegistryString(adapterKey, "ProviderName")?.Trim(),
                    ReadRegistryString(adapterKey, "DriverDate")?.Trim()));
            }
        }

        return result;
    }

    private static bool IsAdapterRepresentedInGraphicsConfiguration(string? deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId))
            return false;

        var vendor = ExtractPciToken(deviceId, "VEN_");
        var device = ExtractPciToken(deviceId, "DEV_");
        if (vendor is null || device is null)
            return false;

        using var root = Registry.LocalMachine.OpenSubKey(GraphicsConfigurationPath, writable: false);
        if (root is null)
            return false;

        var marker = $"{vendor}_{device}";
        return root.GetSubKeyNames().Any(name => name.Contains(marker, StringComparison.OrdinalIgnoreCase));
    }

    private static string? ExtractPciToken(string value, string marker)
    {
        var index = value.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (index < 0 || index + marker.Length + 4 > value.Length)
            return null;

        var token = value.Substring(index + marker.Length, 4);
        return token.All(Uri.IsHexDigit) ? token.ToUpperInvariant() : null;
    }

    private static ulong? TryReadAdapterMemoryBytes(string? deviceKey)
    {
        if (string.IsNullOrWhiteSpace(deviceKey))
            return null;

        const string prefix = @"\Registry\Machine\";
        if (!deviceKey.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            return null;

        var subKeyPath = deviceKey[prefix.Length..];
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(subKeyPath, writable: false);
            return TryReadAdapterMemoryBytes(key);
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
        catch (System.Security.SecurityException)
        {
            return null;
        }
    }

    private static (string? Version, string? Provider, string? Date) TryReadAdapterDriverMetadata(string? deviceKey)
    {
        if (string.IsNullOrWhiteSpace(deviceKey))
            return (null, null, null);

        const string prefix = @"\Registry\Machine\";
        if (!deviceKey.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            return (null, null, null);

        var subKeyPath = deviceKey[prefix.Length..];
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(subKeyPath, writable: false);
            return (
                ReadRegistryString(key, "DriverVersion")?.Trim(),
                ReadRegistryString(key, "ProviderName")?.Trim(),
                ReadRegistryString(key, "DriverDate")?.Trim());
        }
        catch (UnauthorizedAccessException)
        {
            return (null, null, null);
        }
        catch (System.Security.SecurityException)
        {
            return (null, null, null);
        }
    }

    private static ulong? TryReadAdapterMemoryBytes(RegistryKey? key)
    {
        if (key is null)
            return null;

        foreach (var valueName in new[] { "HardwareInformation.qwMemorySize", "HardwareInformation.MemorySize" })
        {
            var value = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            switch (value)
            {
                case long signed when signed > 0:
                    return unchecked((ulong)signed);
                case int signed when signed > 0:
                    return unchecked((uint)signed);
                case byte[] bytes when bytes.Length >= 8:
                    return BitConverter.ToUInt64(bytes, 0);
                case byte[] bytes when bytes.Length >= 4:
                    return BitConverter.ToUInt32(bytes, 0);
            }
        }

        return null;
    }

    private static IReadOnlyList<DisplayModeInfo> ReadDisplays()
    {
        var result = new List<DisplayModeInfo>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (uint index = 0; ; index++)
        {
            var device = CreateDisplayDevice();
            if (!EnumDisplayDevicesW(null, index, ref device, 0))
                break;

            if ((device.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP) == 0 || string.IsNullOrWhiteSpace(device.DeviceName))
                continue;

            var mode = CreateDevMode();
            if (!EnumDisplaySettingsW(device.DeviceName, ENUM_CURRENT_SETTINGS, ref mode))
                continue;

            var width = checked((int)mode.dmPelsWidth);
            var height = checked((int)mode.dmPelsHeight);
            var frequency = checked((int)mode.dmDisplayFrequency);
            var identity = $"{device.DeviceName}|{width}x{height}|{frequency}";
            if (!seen.Add(identity))
                continue;

            result.Add(new DisplayModeInfo(
                device.DeviceName.TrimEnd('\0'),
                device.DeviceString?.TrimEnd('\0') ?? string.Empty,
                width,
                height,
                frequency,
                checked((int)mode.dmBitsPerPel)));
        }

        // On service/session-0 runtimes EnumDisplayDevices may be empty. GraphicsDrivers\Configuration
        // retains the active surface geometry and refresh rational, so use it as a bounded read-only fallback.
        using var configurationRoot = Registry.LocalMachine.OpenSubKey(GraphicsConfigurationPath, writable: false);
        if (configurationRoot is not null)
        {
            foreach (var entry in EnumerateGraphicsConfigurationModes(configurationRoot))
            {
                var identity = $"{entry.DeviceName}|{entry.Width}x{entry.Height}|{entry.RefreshRateHz}";
                if (seen.Add(identity))
                    result.Add(entry);
            }
        }

        return result;
    }

    private static IEnumerable<DisplayModeInfo> EnumerateGraphicsConfigurationModes(RegistryKey root)
    {
        var emitted = 0;
        foreach (var configurationName in root.GetSubKeyNames().Take(64))
        {
            using var configurationKey = root.OpenSubKey(configurationName, writable: false);
            if (configurationKey is null)
                continue;

            foreach (var path in new[] { "00", @"00\00" })
            {
                using var modeKey = configurationKey.OpenSubKey(path, writable: false);
                if (modeKey is null)
                    continue;

                var width = ReadRegistryInt(modeKey, "PrimSurfSize.cx") ?? ReadRegistryInt(modeKey, "ActiveSize.cx");
                var height = ReadRegistryInt(modeKey, "PrimSurfSize.cy") ?? ReadRegistryInt(modeKey, "ActiveSize.cy");
                if (width is null or <= 0 || height is null or <= 0)
                    continue;

                yield return new DisplayModeInfo(
                    $"registry:{configurationName}",
                    "GraphicsDrivers Configuration",
                    width.Value,
                    height.Value,
                    ReadRefreshRate(modeKey),
                    ReadBitsPerPixel(modeKey));

                emitted++;
                if (emitted >= 16)
                    yield break;
            }
        }
    }

    private static int ReadRefreshRate(RegistryKey key)
    {
        foreach (var prefix in new[] { "RefreshRate", "VirtualRefreshRate" })
        {
            var numerator = ReadRegistryInt64(key, $"{prefix}.Numerator");
            var denominator = ReadRegistryInt64(key, $"{prefix}.Denominator");
            if (numerator is > 0 && denominator is > 0)
            {
                var hz = (int)Math.Round(numerator.Value / (double)denominator.Value, MidpointRounding.AwayFromZero);
                if (hz is > 0 and <= 1000)
                    return hz;
            }
        }

        foreach (var name in new[] { "RefreshRate", "VirtualRefreshRate", "DefaultSettings.VRefresh" })
        {
            var value = ReadRegistryInt64(key, name);
            if (value is > 0 and <= 1000)
                return checked((int)value.Value);
        }

        return 0;
    }

    private static int ReadBitsPerPixel(RegistryKey key)
    {
        foreach (var name in new[] { "BitsPerPixel", "BitsPerPel", "ColorDepth" })
        {
            var value = ReadRegistryInt64(key, name);
            if (value is > 0 and <= 128)
                return checked((int)value.Value);
        }

        return 0;
    }

    private static WindowsInfo ReadWindows()
    {
        string? productName = null;
        string? displayVersion = null;
        string? build = null;
        int? ubr = null;

        using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", writable: false))
        {
            productName = ReadRegistryString(key, "ProductName");
            displayVersion = ReadRegistryString(key, "DisplayVersion");
            build = ReadRegistryString(key, "CurrentBuildNumber");
            var ubrValue = key?.GetValue("UBR");
            if (ubrValue is int i)
                ubr = i;
        }

        return new WindowsInfo(
            productName,
            displayVersion,
            build,
            ubr,
            Environment.OSVersion.Version.ToString(),
            RuntimeInformation.OSDescription,
            Environment.Is64BitOperatingSystem,
            RuntimeInformation.OSArchitecture.ToString());
    }

    private static string? ReadRegistryString(RegistryKey? key, string name) => key?.GetValue(name) as string;

    private static int? ReadRegistryInt(RegistryKey key, string name)
    {
        var value = ReadRegistryInt64(key, name);
        return value is >= int.MinValue and <= int.MaxValue ? checked((int)value.Value) : null;
    }

    private static long? ReadRegistryInt64(RegistryKey key, string name)
    {
        var value = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        return value switch
        {
            int i => i,
            long l => l,
            uint ui => ui,
            byte[] bytes when bytes.Length >= 8 => BitConverter.ToInt64(bytes, 0),
            byte[] bytes when bytes.Length >= 4 => BitConverter.ToInt32(bytes, 0),
            _ => null
        };
    }

    private static double BytesToGiB(ulong bytes) => Math.Round(bytes / 1073741824d, 2, MidpointRounding.AwayFromZero);

    private static DISPLAY_DEVICE CreateDisplayDevice() => new()
    {
        cb = checked((uint)Marshal.SizeOf<DISPLAY_DEVICE>()),
        DeviceName = string.Empty,
        DeviceString = string.Empty,
        DeviceID = string.Empty,
        DeviceKey = string.Empty
    };

    private static DEVMODE CreateDevMode() => new()
    {
        dmDeviceName = string.Empty,
        dmFormName = string.Empty,
        dmSize = checked((ushort)Marshal.SizeOf<DEVMODE>())
    };

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetLogicalProcessorInformationEx(int relationshipType, IntPtr buffer, ref uint returnedLength);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumDisplayDevicesW(string? lpDevice, uint iDevNum, ref DISPLAY_DEVICE lpDisplayDevice, uint dwFlags);

    [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumDisplaySettingsW(string lpszDeviceName, uint iModeNum, ref DEVMODE lpDevMode);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DISPLAY_DEVICE
    {
        public uint cb;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string DeviceName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceString;
        public uint StateFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceID;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string DeviceKey;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DEVMODE
    {
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmDeviceName;
        public ushort dmSpecVersion;
        public ushort dmDriverVersion;
        public ushort dmSize;
        public ushort dmDriverExtra;
        public uint dmFields;
        public int dmPositionX;
        public int dmPositionY;
        public uint dmDisplayOrientation;
        public uint dmDisplayFixedOutput;
        public short dmColor;
        public short dmDuplex;
        public short dmYResolution;
        public short dmTTOption;
        public short dmCollate;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)] public string dmFormName;
        public ushort dmLogPixels;
        public uint dmBitsPerPel;
        public uint dmPelsWidth;
        public uint dmPelsHeight;
        public uint dmDisplayFlags;
        public uint dmDisplayFrequency;
        public uint dmICMMethod;
        public uint dmICMIntent;
        public uint dmMediaType;
        public uint dmDitherType;
        public uint dmReserved1;
        public uint dmReserved2;
        public uint dmPanningWidth;
        public uint dmPanningHeight;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }
}

public sealed record SystemHardwareInfoResult(
    string MachineName,
    CpuInfo Cpu,
    MemoryInfo Memory,
    IReadOnlyList<GraphicsAdapterInfo> GraphicsAdapters,
    IReadOnlyList<DisplayModeInfo> Displays,
    WindowsInfo Windows);

public sealed record CpuInfo(
    string? Name,
    string? Vendor,
    string? Identifier,
    int? PhysicalCoreCount,
    int LogicalProcessorCount,
    string ProcessArchitecture);

public sealed record MemoryInfo(
    ulong TotalPhysicalBytes,
    double TotalPhysicalGiB);

public sealed record GraphicsAdapterInfo(
    uint Index,
    string DeviceName,
    string Description,
    string DeviceId,
    bool AttachedToDesktop,
    ulong? DedicatedMemoryBytes,
    double? DedicatedMemoryGiB,
    string? DriverVersion,
    string? DriverProvider,
    string? DriverDate);

public sealed record DisplayModeInfo(
    string DeviceName,
    string Description,
    int Width,
    int Height,
    int RefreshRateHz,
    int BitsPerPixel);

public sealed record WindowsInfo(
    string? ProductName,
    string? DisplayVersion,
    string? BuildNumber,
    int? UpdateBuildRevision,
    string OsVersion,
    string OsDescription,
    bool Is64Bit,
    string OsArchitecture);