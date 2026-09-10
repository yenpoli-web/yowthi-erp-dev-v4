using System.Runtime.CompilerServices;

namespace YowThi.DevelopmentAgent3.Windows;

internal static class InteractiveDesktopKeyboardBootstrap
{
    [ModuleInitializer]
    internal static void Initialize()
    {
        var args = Environment.GetCommandLineArgs().Skip(1).ToArray();
        if (!args.Any(x => string.Equals(x, InteractiveDesktopKeyboardBridge.HelperSwitch, StringComparison.Ordinal)))
            return;

        var handled = InteractiveDesktopKeyboardBridge.TryRunHelperAsync(args).GetAwaiter().GetResult();
        Environment.Exit(handled ? 0 : 2);
    }
}
