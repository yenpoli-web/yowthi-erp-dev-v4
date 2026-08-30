namespace YowThi.DevelopmentAgent3.Security;

public enum PathProtectionMode
{
    Normal,
    Controlled,
    Frozen
}

public sealed record ProtectedZone(string Root, PathProtectionMode Mode, string Reason);

public sealed class ProtectedPathPolicy
{
    private readonly IReadOnlyList<ProtectedZone> _zones;

    public ProtectedPathPolicy(IEnumerable<ProtectedZone>? zones = null)
    {
        _zones = (zones ?? DefaultZones()).
            Select(z => z with { Root = NormalizeRoot(z.Root) }).
            ToArray();
    }

    public IReadOnlyList<ProtectedZone> Zones => _zones;

    public string Normalize(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("Path is required.", nameof(path));
        if (!Path.IsPathFullyQualified(path))
            throw new ArgumentException("Absolute path is required.", nameof(path));
        return Path.GetFullPath(path);
    }

    public ProtectedZone? GetZone(string path)
    {
        var full = Normalize(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return _zones
            .Where(z => IsSameOrChild(full, z.Root))
            .OrderByDescending(z => z.Root.Length)
            .FirstOrDefault();
    }

    public PathProtectionMode GetMode(string path) => GetZone(path)?.Mode ?? PathProtectionMode.Normal;

    public string RequireMutable(string path)
    {
        var full = Normalize(path);
        var zone = GetZone(full);
        if (zone?.Mode == PathProtectionMode.Frozen)
            throw new UnauthorizedAccessException($"Frozen path is read-only: {full}. Reason: {zone.Reason}");
        return full;
    }

    private static IEnumerable<ProtectedZone> DefaultZones()
    {
        yield return new ProtectedZone(
            @"C:\yowthi-erp",
            PathProtectionMode.Frozen,
            "Legacy production ERP still in service");
    }

    private static string NormalizeRoot(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("Protected zone root is required.", nameof(path));
        if (!Path.IsPathFullyQualified(path))
            throw new ArgumentException("Protected zone root must be absolute.", nameof(path));
        return Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    private static bool IsSameOrChild(string fullPath, string root)
    {
        return fullPath.Equals(root, StringComparison.OrdinalIgnoreCase) ||
               fullPath.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }
}
