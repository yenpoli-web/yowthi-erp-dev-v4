using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using YowThi.RuntimeSupervisor;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "YowThi V4 Runtime Supervisor");
builder.Services.AddHostedService<RuntimeSupervisorWorker>();
await builder.Build().RunAsync();
