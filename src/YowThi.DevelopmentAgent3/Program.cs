using ModelContextProtocol.AspNetCore;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Security;

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
app.MapGet("/health", () => Results.Ok(new { service = "YowThi Development Agent 3", version = "3.0.0-alpha.1", status = "ok", machine = Environment.MachineName, utc = DateTimeOffset.UtcNow }));
app.MapMcp("/mcp");
await app.RunAsync();