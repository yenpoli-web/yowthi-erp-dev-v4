using ModelContextProtocol.AspNetCore;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Runtime;
using YowThi.DevelopmentAgent3.Security;

YowThi.DevelopmentAgent3.Windows.DesktopDpiAwareness.EnableForInteractiveHelper(args);
if (await YowThi.DevelopmentAgent3.Windows.InteractiveDesktopCaptureTools.TryRunHelperAsync(args))
    return;
if (await YowThi.DevelopmentAgent3.Windows.InteractiveDesktopKeyboardBridge.TryRunHelperAsync(args))
    return;
if (await YowThi.DevelopmentAgent3.Windows.InteractiveDesktopSessionBridge.TryRunHelperAsync(args))
    return;

var builder = WebApplication.CreateBuilder(args);
builder.Host.UseWindowsService(options => options.ServiceName = "YowThi Development Agent 3");
builder.WebHost.UseUrls(Environment.GetEnvironmentVariable("YOWTHI_AGENT3_URL") ?? "http://127.0.0.1:8791");
builder.Services.AddSingleton<ProtectedPathPolicy>();
builder.Services.AddMcpServer()
    .WithHttpTransport(options => options.SessionMode = HttpServerSessionMode.Stateless)
    .WithToolsFromAssembly()
    .WithTools<YowThi.DevelopmentAgent3.Windows.NetworkTools>()
    .WithTools<YowThi.DevelopmentAgent3.Windows.DesktopTools>()
    .WithTools<YowThi.DevelopmentAgent3.Windows.DesktopMutationTools>()
    .WithTools<YowThi.DevelopmentAgent3.Docker.DockerTools>()
    .WithTools<YowThi.DevelopmentAgent3.Docker.DockerMutationTools>()
    .WithTools<YowThi.DevelopmentAgent3.Postgres.PostgresTools>()
    .WithTools<YowThi.DevelopmentAgent3.Postgres.PostgresMutationTools>();

var app = builder.Build();
app.MapGet("/health", () =>
{
    var registry = ToolRegistryIdentity.Current;
    return Results.Ok(new
    {
        service = "YowThi Development Agent 3",
        version = "3.0.0-alpha.1",
        status = "ok",
        machine = Environment.MachineName,
        processId = registry.ProcessId,
        runtimeSha256 = registry.RuntimeSha256,
        toolCatalogCount = registry.ToolCount,
        toolCatalogSha256 = registry.CatalogSha256,
        utc = DateTimeOffset.UtcNow
    });
});
app.MapMcp("/mcp");
await app.RunAsync();