namespace YowThi.DevelopmentAgent3.Security;

public sealed class LifecyclePathPolicy
{
    private readonly ProtectedPathPolicy _inner = new();

    public string Normalize(string path) => _inner.Normalize(path);
    public ProtectedZone? GetZone(string path) => _inner.GetZone(path);
    public PathProtectionMode GetMode(string path) => _inner.GetMode(path);
    public string RequireMutable(string path) => _inner.RequireMutable(path);
    public IReadOnlyList<ProtectedZone> Zones => _inner.Zones;
}
