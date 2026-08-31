using Xunit;

namespace YowThi.DotnetAcceptanceTests;

public sealed class LongRunningCancellationTests
{
    [Fact]
    public async Task LongRunningCancellationProbe()
    {
        await Task.Delay(TimeSpan.FromSeconds(60));
    }
}
