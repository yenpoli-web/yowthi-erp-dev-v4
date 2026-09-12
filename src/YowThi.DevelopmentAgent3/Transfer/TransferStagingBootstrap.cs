namespace YowThi.DevelopmentAgent3.Transfer;

public static class TransferStagingBootstrap
{
    private const string DevRoot = @"C:\Dev\YowThi-ERP-Dev-v4";
    private const string TransferRoot = @"C:\Dev\YowThi-ERP-Dev-v4\staging\transfer";
    private const string InboxRoot = @"C:\Dev\YowThi-ERP-Dev-v4\staging\transfer\inbox";
    private const string OutboxRoot = @"C:\Dev\YowThi-ERP-Dev-v4\staging\transfer\outbox";

    public static void EnsureExists()
    {
        EnsureDirectory(TransferRoot);
        EnsureDirectory(InboxRoot);
        EnsureDirectory(OutboxRoot);
    }

    private static void EnsureDirectory(string path)
    {
        var full = Path.GetFullPath(path);
        var devRoot = Path.GetFullPath(DevRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!full.StartsWith(devRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Transfer staging bootstrap path escaped the fixed development root.");

        var parent = Path.GetDirectoryName(full) ?? throw new InvalidOperationException("Transfer staging bootstrap path has no parent.");
        RequireNoReparseTraversal(Directory.Exists(parent) ? parent : DevRoot);
        Directory.CreateDirectory(full);
        RequireNoReparseTraversal(full);

        if ((File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException($"Transfer staging bootstrap directory may not be a reparse point: {full}");
    }

    private static void RequireNoReparseTraversal(string path)
    {
        var devRoot = Path.GetFullPath(DevRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var current = new DirectoryInfo(Path.GetFullPath(path));
        while (current is not null)
        {
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException($"Transfer staging bootstrap may not traverse a reparse-point directory: {current.FullName}");

            if (string.Equals(current.FullName.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar), devRoot, StringComparison.OrdinalIgnoreCase))
                return;

            current = current.Parent;
        }

        throw new UnauthorizedAccessException("Transfer staging bootstrap root validation failed.");
    }
}
