namespace YowThi.RuntimeSupervisor;

internal static class RuntimeSupervisorPathSafety
{
    internal static void RequireSafeDirectoryTraversal(string path, string boundary)
    {
        var full = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var root = Path.GetFullPath(boundary).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!Directory.Exists(full))
            throw new DirectoryNotFoundException("Required fixed directory does not exist: " + full);
        if (!string.Equals(full, root, StringComparison.OrdinalIgnoreCase) &&
            !full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Fixed directory escaped its boundary: " + full);

        var current = new DirectoryInfo(full);
        while (current is not null)
        {
            if ((current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException("Reparse point rejected in fixed directory traversal: " + current.FullName);

            var currentFull = current.FullName.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            if (string.Equals(currentFull, root, StringComparison.OrdinalIgnoreCase))
                return;
            current = current.Parent;
        }

        throw new UnauthorizedAccessException("Fixed directory traversal did not reach its boundary: " + full);
    }

    internal static void RejectReparseIfExists(string path)
    {
        var full = Path.GetFullPath(path);
        if (File.Exists(full) && (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
            throw new UnauthorizedAccessException("Reparse point rejected: " + full);
    }
}
