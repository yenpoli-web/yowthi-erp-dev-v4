using Xunit;

namespace YowThi.DotnetAcceptanceTests;

public sealed class RuntimeDeploymentElevationTokenContractTests
{
    [Fact]
    public void ElevationGate_UsesProcessTokenHandleForTokenElevationQuery()
    {
        var source = ReadAuthorizerSource("ElevationGate.cs");
        Assert.Contains("TokenQuery = 0x0008", source, StringComparison.Ordinal);
        Assert.Contains("OpenProcessToken(process.Handle, TokenQuery, out var tokenHandle)", source, StringComparison.Ordinal);
        Assert.Contains("GetTokenInformation(\n                    tokenHandle", source, StringComparison.Ordinal);
        Assert.Contains("CloseHandle(tokenHandle)", source, StringComparison.Ordinal);
        Assert.Contains("OpenProcessToken", source, StringComparison.Ordinal);
        Assert.DoesNotContain("GetTokenInformation(\n                process.Handle", source, StringComparison.Ordinal);
    }

    [Fact]
    public void AuthorizerHealthValidation_RemainsStrictlyLoopbackOnly()
    {
        var source = ReadAuthorizerSource("Program.cs");
        Assert.Contains("NormalizeHealthUrl", source, StringComparison.Ordinal);
        Assert.Contains("!IPAddress.TryParse(uri.Host, out var address) || !IPAddress.IsLoopback(address) || uri.Port <= 0", source, StringComparison.Ordinal);
        Assert.Contains("healthUrl must be the exact loopback /health endpoint using an IP literal.", source, StringComparison.Ordinal);
    }

    private static string ReadAuthorizerSource(string fileName) => File.ReadAllText(Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", "YowThi.RuntimeDeploymentAuthorizer", fileName)));
}
