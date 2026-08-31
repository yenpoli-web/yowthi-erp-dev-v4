using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using ModelContextProtocol.Server;
using YowThi.DevelopmentAgent3.Audit;
using YowThi.DevelopmentAgent3.Core;

namespace YowThi.DevelopmentAgent3.Docker;

[McpServerToolType]
public static class DockerProvisioningTools
{
    private const string DockerExe = @"C:\Program Files\Docker\Docker\resources\bin\docker.exe";
    private const string ManagedLabel = "com.yowthi.agent3.managed";
    private const string PlanLabel = "com.yowthi.agent3.plan-id";
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);
    private static readonly Regex FullContainerId = new("^[0-9a-fA-F]{64}$", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex FullNetworkId = new("^[0-9a-fA-F]{64}$", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex FullImageId = new("^sha256:[0-9a-fA-F]{64}$", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex ContainerNamePattern = new("^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex VolumeNamePattern = new("^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly byte[] SigningKey = SHA256.HashData(Encoding.UTF8.GetBytes("YowThi-Agent3-Development-Key-v1"));
    private static readonly PlanSigner Signer = new(SigningKey);
    private static readonly PlanStore Store = new(Signer);
    private static readonly AuditChain Audit = new(@"C:\Dev\YowThi-ERP-Dev-v4\.agent3-audit");

    [McpServerTool(Name = "docker_container_inspect", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Inspect one local Docker container by full 64-character container ID using fixed 'docker container inspect'. The result is a typed safe projection of identity, state, image, network, port, mount, command, and security configuration. Container environment values and label values are never returned; only names, SHA-256 value digests, and lengths are exposed. No arbitrary inspect target, Docker arguments, exec, shell, or mutation is supported.")]
    public static DockerContainerInspectResult DockerContainerInspect(string containerId)
        => ToContainerInspect(ReadContainer(RequireFullContainerId(containerId)));

    [McpServerTool(Name = "docker_image_inspect", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Inspect one existing local Docker image by immutable full sha256 image ID using fixed 'docker image inspect'. Tags and pull operations are not accepted as identity. Image environment values are not returned; only variable names, SHA-256 value digests, and lengths are exposed. No arbitrary Docker arguments or mutation is supported.")]
    public static DockerImageInspectResult DockerImageInspect(string imageId)
        => ToImageInspect(ReadImage(RequireFullImageId(imageId)));

    [McpServerTool(Name = "docker_network_inspect", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Inspect one existing local Docker network by full 64-character network ID using fixed 'docker network inspect'. The result is a typed projection of network identity, driver, scope, internal/attachable flags, IPAM configuration, option names, label names, and attached container identities. No arbitrary Docker arguments or mutation is supported.")]
    public static DockerNetworkInspectResult DockerNetworkInspect(string networkId)
        => ToNetworkInspect(ReadNetwork(RequireFullNetworkId(networkId)));

    [McpServerTool(Name = "docker_volume_inspect", ReadOnly = true, Destructive = false, OpenWorld = false)]
    [Description("Inspect one existing local Docker named volume using fixed 'docker volume inspect'. Volume names are strictly validated. The result exposes volume identity, driver, scope, mountpoint, creation time, option names, and label names; option and label values are not returned. Bind mounts and arbitrary Docker arguments are not supported.")]
    public static DockerVolumeInspectResult DockerVolumeInspect(string volumeName)
        => ToVolumeInspect(ReadVolume(RequireVolumeName(volumeName)));

    [McpServerTool(Name = "docker_container_create_plan", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Prepare a one-time signed High-risk plan to create one stopped Docker container from an existing immutable local image ID. The container uses one existing local bridge network, optional loopback-only TCP port bindings, and optional existing local named-volume mounts. Image tags/pulls, environment variables, command/entrypoint overrides, bind mounts, host/none networks, privileged mode, added capabilities, devices, Docker socket mounts, restart-policy overrides, and automatic start are not supported. Docker CLI SHA-256, Docker context/engine identity, image/network/volume identities, container-name absence, and the normalized create configuration are sealed.")]
    public static SignedPlan DockerContainerCreatePlan(
        string imageId,
        string containerName,
        string networkId,
        DockerTcpPortBindingInput[]? tcpPorts = null,
        DockerNamedVolumeMountInput[]? volumes = null)
    {
        var engine = ReadEngineIdentity();
        var image = ReadImage(RequireFullImageId(imageId));
        var name = RequireContainerName(containerName);
        var network = ReadNetwork(RequireFullNetworkId(networkId));
        RequireCreateEligibleNetwork(network);
        EnsureContainerNameAbsent(name);

        var normalizedPorts = NormalizePortBindings(tcpPorts);
        var normalizedMounts = NormalizeVolumeMounts(volumes);
        var volumeSnapshots = normalizedMounts
            .Select(mount => new DockerVolumeCreateSnapshot(ReadVolume(mount.VolumeName), mount.ContainerPath, mount.ReadOnly))
            .ToArray();
        foreach (var volume in volumeSnapshots)
            RequireCreateEligibleVolume(volume.Volume);

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["dockerExeSha256"] = engine.DockerExeSha256,
            ["dockerContext"] = engine.Context,
            ["dockerEngineId"] = engine.EngineId,
            ["imageId"] = image.Id,
            ["imageCreated"] = image.Created,
            ["imageEnvironmentSha256"] = image.EnvironmentFingerprintSha256,
            ["containerName"] = name,
            ["containerNameAbsent"] = "true",
            ["networkId"] = network.Id,
            ["networkName"] = network.Name,
            ["networkDriver"] = network.Driver,
            ["networkScope"] = network.Scope,
            ["networkInternal"] = network.Internal ? "true" : "false",
            ["tcpPortsJson"] = JsonSerializer.Serialize(normalizedPorts),
            ["volumesJson"] = JsonSerializer.Serialize(volumeSnapshots.Select(ToSignedVolumeSnapshot).ToArray())
        };

        var now = DateTimeOffset.UtcNow;
        var planId = Guid.NewGuid().ToString("N");
        var summary = $"Create stopped Docker container {name} from immutable image {image.Id} on local bridge network {network.Name}; tcpPorts={normalizedPorts.Length}, namedVolumes={volumeSnapshots.Length}";
        var unsigned = new SignedPlan(
            1,
            planId,
            Convert.ToHexString(RandomNumberGenerator.GetBytes(6)),
            "docker",
            "container-create",
            name,
            parameters,
            RiskClass.High,
            summary,
            now,
            now.AddMinutes(10),
            string.Empty);
        var signed = unsigned with { Signature = Signer.Sign(unsigned) };
        Store.Add(signed);
        Audit.Append(signed.Tool, signed.Operation, signed.Target,
            new
            {
                signed.PlanId,
                signed.RiskClass,
                signed.Summary,
                imageId = image.Id,
                networkId = network.Id,
                tcpPorts = normalizedPorts,
                volumes = volumeSnapshots.Select(x => new { x.Volume.Name, x.ContainerPath, x.ReadOnly }).ToArray()
            },
            "prepared");
        return signed;
    }

    [McpServerTool(Name = "docker_container_create_execute", ReadOnly = false, Destructive = true, OpenWorld = false)]
    [Description("Execute one previously prepared docker/container-create plan using only fixed 'docker container create' semantics. Docker CLI/context/engine, immutable image, local bridge network, named volumes, and container-name absence are revalidated. The command cannot set environment, command/entrypoint, bind mounts, host networking, privilege/capabilities/devices, Docker socket access, restart policy other than 'no', or start the container. Post-create typed inspect must prove the new container is stopped/created and matches the signed image, network, ports, named volumes, inherited image environment, fixed labels, and security constraints; failed verification triggers removal of only the newly created stopped container.")]
    public static DockerContainerCreateResult DockerContainerCreateExecute(
        string planId,
        string approvalCode,
        string operation,
        string target,
        string summary,
        string riskClass)
    {
        var plan = Store.GetValidated(planId, approvalCode);
        RequireIntentMatch(plan, "container-create", operation, target, summary, riskClass);

        var engine = ReadEngineIdentity();
        RevalidateEngineIdentity(plan, engine);

        var image = ReadImage(RequireFullImageId(RequireParameter(plan, "imageId")));
        if (!string.Equals(image.Created, RequireParameter(plan, "imageCreated"), StringComparison.Ordinal)
            || !string.Equals(image.EnvironmentFingerprintSha256, RequireParameter(plan, "imageEnvironmentSha256"), StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Docker image identity or default environment changed after plan preparation.");

        var name = RequireContainerName(RequireParameter(plan, "containerName"));
        if (!string.Equals(RequireParameter(plan, "containerNameAbsent"), "true", StringComparison.Ordinal))
            throw new InvalidDataException("Signed Docker container-name absence marker is invalid.");
        EnsureContainerNameAbsent(name);

        var network = ReadNetwork(RequireFullNetworkId(RequireParameter(plan, "networkId")));
        RequireCreateEligibleNetwork(network);
        if (!string.Equals(network.Name, RequireParameter(plan, "networkName"), StringComparison.Ordinal)
            || !string.Equals(network.Driver, RequireParameter(plan, "networkDriver"), StringComparison.Ordinal)
            || !string.Equals(network.Scope, RequireParameter(plan, "networkScope"), StringComparison.Ordinal)
            || network.Internal != bool.Parse(RequireParameter(plan, "networkInternal")))
            throw new InvalidOperationException("Docker network identity changed after plan preparation.");

        var ports = JsonSerializer.Deserialize<DockerNormalizedTcpPortBinding[]>(RequireParameter(plan, "tcpPortsJson"))
            ?? throw new InvalidDataException("Signed Docker TCP port configuration is invalid.");
        ports = NormalizePortBindings(ports.Select(x => new DockerTcpPortBindingInput { HostPort = x.HostPort, ContainerPort = x.ContainerPort }).ToArray());

        var signedVolumes = JsonSerializer.Deserialize<DockerSignedVolumeSnapshot[]>(RequireParameter(plan, "volumesJson"))
            ?? throw new InvalidDataException("Signed Docker volume configuration is invalid.");
        var volumeSnapshots = signedVolumes.Select(RevalidateSignedVolume).ToArray();

        string? createdId = null;
        try
        {
            var arguments = new List<string>
            {
                "container", "create",
                "--name", name,
                "--network", network.Id,
                "--restart", "no",
                "--label", $"{ManagedLabel}=true",
                "--label", $"{PlanLabel}={plan.PlanId}"
            };

            foreach (var port in ports)
            {
                arguments.Add("--publish");
                arguments.Add($"127.0.0.1:{port.HostPort}:{port.ContainerPort}/tcp");
            }

            foreach (var mount in volumeSnapshots)
            {
                arguments.Add("--mount");
                arguments.Add(BuildVolumeMountArgument(mount));
            }

            arguments.Add(image.Id);
            var create = Run(arguments.ToArray());
            if (create.ExitCode != 0)
                throw new InvalidOperationException($"Docker container create failed with exit code {create.ExitCode}: {create.StdErr.Trim()}");

            createdId = RequireFullContainerId(create.StdOut.Trim());
            var created = ReadContainer(createdId);
            ValidateCreatedContainer(created, plan, image, network, ports, volumeSnapshots);

            Store.Consume(planId);
            Audit.Append(plan.Tool, plan.Operation, plan.Target,
                new { plan.PlanId, containerId = created.Id, created.Name, created.ImageId, networkId = network.Id, tcpPorts = ports, volumes = volumeSnapshots.Select(x => new { x.Volume.Name, x.ContainerPath, x.ReadOnly }).ToArray() },
                "executed");
            return new DockerContainerCreateResult(
                plan.PlanId,
                created.Id,
                created.Name,
                created.ImageId,
                network.Id,
                network.Name,
                ports.Select(x => new DockerTcpPortBinding(x.HostPort, x.ContainerPort, "127.0.0.1", "tcp")).ToArray(),
                volumeSnapshots.Select(x => new DockerVolumeMount(x.Volume.Name, x.ContainerPath, x.ReadOnly, "volume")).ToArray(),
                "container-created-stopped",
                DateTimeOffset.UtcNow);
        }
        catch (Exception ex)
        {
            var rollback = "not-required";
            if (!string.IsNullOrWhiteSpace(createdId))
            {
                try
                {
                    if (TryReadContainer(createdId, out var candidate) && candidate is not null && !candidate.Running)
                    {
                        var remove = Run("container", "rm", candidate.Id);
                        rollback = remove.ExitCode == 0 ? "removed-new-container" : $"rollback-rm-exit-{remove.ExitCode}";
                    }
                    else
                    {
                        rollback = "new-container-not-safely-removable";
                    }
                }
                catch (Exception rollbackEx)
                {
                    rollback = $"rollback-failed:{rollbackEx.GetType().Name}";
                }
            }
            Audit.Append(plan.Tool, plan.Operation, plan.Target, new { plan.PlanId, error = ex.Message, createdId, rollback }, "failed");
            throw;
        }
    }

    private static DockerEngineIdentity ReadEngineIdentity()
    {
        if (!File.Exists(DockerExe))
            throw new FileNotFoundException("Docker CLI was not found at the fixed Docker Desktop path.", DockerExe);
        var context = RunRequiredSingleLine("context", "show");
        var engineIdJson = RunRequiredSingleLine("info", "--format", "{{json .ID}}");
        var engineId = JsonSerializer.Deserialize<string>(engineIdJson) ?? throw new InvalidDataException("Docker Engine ID query returned null.");
        if (string.IsNullOrWhiteSpace(context) || string.IsNullOrWhiteSpace(engineId))
            throw new InvalidDataException("Docker context or Engine ID is empty.");
        return new DockerEngineIdentity(Sha256File(DockerExe), context, engineId);
    }

    private static DockerContainerSnapshot ReadContainer(string id)
    {
        var result = Run("container", "inspect", "--format", "{{json .}}", RequireFullContainerId(id));
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"Unable to inspect Docker container {id}: {result.StdErr.Trim()}");
        return ParseContainerSnapshot(result.StdOut, id);
    }

    private static bool TryReadContainer(string id, out DockerContainerSnapshot? snapshot)
    {
        snapshot = null;
        var result = Run("container", "inspect", "--format", "{{json .}}", RequireFullContainerId(id));
        if (result.ExitCode != 0) return false;
        snapshot = ParseContainerSnapshot(result.StdOut, id);
        return true;
    }

    private static DockerContainerSnapshot ParseContainerSnapshot(string json, string expectedId)
    {
        using var doc = JsonDocument.Parse(json.Trim());
        var root = doc.RootElement;
        var id = RequireFullContainerId(RequireString(root, "Id"));
        if (!string.Equals(id, expectedId, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Docker container inspect returned an unexpected identity.");

        var state = root.GetProperty("State");
        var config = root.GetProperty("Config");
        var hostConfig = root.GetProperty("HostConfig");
        var env = ReadEnvironment(config.TryGetProperty("Env", out var envElement) ? envElement : default);
        var labelNames = ReadObjectPropertyNames(config.TryGetProperty("Labels", out var labels) ? labels : default);
        var managed = TryGetObjectString(config.TryGetProperty("Labels", out labels) ? labels : default, ManagedLabel, out var managedValue)
            && string.Equals(managedValue, "true", StringComparison.OrdinalIgnoreCase);
        var planId = TryGetObjectString(config.TryGetProperty("Labels", out labels) ? labels : default, PlanLabel, out var planValue) ? planValue : null;
        var health = state.TryGetProperty("Health", out var healthElement) && healthElement.ValueKind == JsonValueKind.Object && healthElement.TryGetProperty("Status", out var healthStatus)
            ? healthStatus.GetString()
            : null;

        var ports = ReadHostPortBindings(hostConfig);
        var mounts = ReadMounts(root.TryGetProperty("Mounts", out var mountsElement) ? mountsElement : default);
        var networks = ReadContainerNetworks(root);
        var restartPolicy = hostConfig.TryGetProperty("RestartPolicy", out var restart) && restart.ValueKind == JsonValueKind.Object && restart.TryGetProperty("Name", out var restartName)
            ? restartName.GetString() ?? string.Empty
            : string.Empty;
        var networkMode = hostConfig.TryGetProperty("NetworkMode", out var networkModeElement) ? networkModeElement.GetString() ?? string.Empty : string.Empty;
        var privileged = hostConfig.TryGetProperty("Privileged", out var privilegedElement) && privilegedElement.ValueKind == JsonValueKind.True;
        var capAddCount = hostConfig.TryGetProperty("CapAdd", out var capAdd) && capAdd.ValueKind == JsonValueKind.Array ? capAdd.GetArrayLength() : 0;
        var deviceCount = hostConfig.TryGetProperty("Devices", out var devices) && devices.ValueKind == JsonValueKind.Array ? devices.GetArrayLength() : 0;
        var bindCount = hostConfig.TryGetProperty("Binds", out var binds) && binds.ValueKind == JsonValueKind.Array ? binds.GetArrayLength() : 0;

        return new DockerContainerSnapshot(
            id,
            RequireString(root, "Name").TrimStart('/'),
            RequireString(root, "Image"),
            RequireString(root, "Created"),
            state.GetProperty("Status").GetString() ?? string.Empty,
            state.GetProperty("Running").GetBoolean(),
            state.TryGetProperty("ExitCode", out var exitCode) && exitCode.TryGetInt32(out var code) ? code : 0,
            health,
            config.TryGetProperty("Image", out var imageReference) ? imageReference.GetString() ?? string.Empty : string.Empty,
            ReadStringArray(config.TryGetProperty("Entrypoint", out var entrypoint) ? entrypoint : default),
            ReadStringArray(config.TryGetProperty("Cmd", out var cmd) ? cmd : default),
            env,
            labelNames,
            managed,
            planId,
            restartPolicy,
            networkMode,
            privileged,
            capAddCount,
            deviceCount,
            bindCount,
            ports,
            mounts,
            networks);
    }

    private static DockerImageSnapshot ReadImage(string imageId)
    {
        var result = Run("image", "inspect", "--format", "{{json .}}", RequireFullImageId(imageId));
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"Unable to inspect Docker image {imageId}: {result.StdErr.Trim()}");
        using var doc = JsonDocument.Parse(result.StdOut.Trim());
        var root = doc.RootElement;
        var id = RequireFullImageId(RequireString(root, "Id"));
        if (!string.Equals(id, imageId, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Docker image inspect returned an unexpected identity.");
        var config = root.GetProperty("Config");
        var environment = ReadEnvironment(config.TryGetProperty("Env", out var env) ? env : default);
        return new DockerImageSnapshot(
            id,
            RequireString(root, "Created"),
            root.TryGetProperty("Architecture", out var architecture) ? architecture.GetString() ?? string.Empty : string.Empty,
            root.TryGetProperty("Os", out var os) ? os.GetString() ?? string.Empty : string.Empty,
            root.TryGetProperty("Size", out var size) && size.TryGetInt64(out var bytes) ? bytes : 0,
            ReadStringArray(root.TryGetProperty("RepoTags", out var tags) ? tags : default),
            ReadStringArray(root.TryGetProperty("RepoDigests", out var digests) ? digests : default),
            environment,
            ReadStringArray(config.TryGetProperty("Entrypoint", out var entrypoint) ? entrypoint : default),
            ReadStringArray(config.TryGetProperty("Cmd", out var cmd) ? cmd : default),
            ReadObjectPropertyNames(config.TryGetProperty("ExposedPorts", out var exposed) ? exposed : default),
            ReadObjectPropertyNames(config.TryGetProperty("Volumes", out var volumes) ? volumes : default));
    }

    private static DockerNetworkSnapshot ReadNetwork(string networkId)
    {
        var result = Run("network", "inspect", "--format", "{{json .}}", RequireFullNetworkId(networkId));
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"Unable to inspect Docker network {networkId}: {result.StdErr.Trim()}");
        using var doc = JsonDocument.Parse(result.StdOut.Trim());
        var root = doc.RootElement;
        var id = RequireFullNetworkId(RequireString(root, "Id"));
        if (!string.Equals(id, networkId, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Docker network inspect returned an unexpected identity.");
        var ipam = new List<DockerNetworkIpamConfig>();
        if (root.TryGetProperty("IPAM", out var ipamElement) && ipamElement.ValueKind == JsonValueKind.Object
            && ipamElement.TryGetProperty("Config", out var configs) && configs.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in configs.EnumerateArray())
                ipam.Add(new DockerNetworkIpamConfig(
                    item.TryGetProperty("Subnet", out var subnet) ? subnet.GetString() : null,
                    item.TryGetProperty("Gateway", out var gateway) ? gateway.GetString() : null,
                    item.TryGetProperty("IPRange", out var range) ? range.GetString() : null));
        }
        var containers = new List<DockerNetworkContainer>();
        if (root.TryGetProperty("Containers", out var containerObject) && containerObject.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in containerObject.EnumerateObject())
            {
                var value = property.Value;
                containers.Add(new DockerNetworkContainer(
                    property.Name,
                    value.TryGetProperty("Name", out var name) ? name.GetString() ?? string.Empty : string.Empty,
                    value.TryGetProperty("IPv4Address", out var ipv4) ? ipv4.GetString() : null,
                    value.TryGetProperty("IPv6Address", out var ipv6) ? ipv6.GetString() : null));
            }
        }
        return new DockerNetworkSnapshot(
            id,
            RequireString(root, "Name"),
            root.TryGetProperty("Driver", out var driver) ? driver.GetString() ?? string.Empty : string.Empty,
            root.TryGetProperty("Scope", out var scope) ? scope.GetString() ?? string.Empty : string.Empty,
            root.TryGetProperty("Internal", out var internalElement) && internalElement.ValueKind == JsonValueKind.True,
            root.TryGetProperty("Attachable", out var attachable) && attachable.ValueKind == JsonValueKind.True,
            root.TryGetProperty("EnableIPv6", out var ipv6Enabled) && ipv6Enabled.ValueKind == JsonValueKind.True,
            ipam.ToArray(),
            ReadObjectPropertyNames(root.TryGetProperty("Options", out var options) ? options : default),
            ReadObjectPropertyNames(root.TryGetProperty("Labels", out var labels) ? labels : default),
            containers.ToArray());
    }

    private static DockerVolumeSnapshot ReadVolume(string volumeName)
    {
        var result = Run("volume", "inspect", "--format", "{{json .}}", RequireVolumeName(volumeName));
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"Unable to inspect Docker volume {volumeName}: {result.StdErr.Trim()}");
        using var doc = JsonDocument.Parse(result.StdOut.Trim());
        var root = doc.RootElement;
        var name = RequireVolumeName(RequireString(root, "Name"));
        if (!string.Equals(name, volumeName, StringComparison.Ordinal))
            throw new InvalidOperationException("Docker volume inspect returned an unexpected identity.");
        return new DockerVolumeSnapshot(
            name,
            root.TryGetProperty("Driver", out var driver) ? driver.GetString() ?? string.Empty : string.Empty,
            root.TryGetProperty("Scope", out var scope) ? scope.GetString() ?? string.Empty : string.Empty,
            root.TryGetProperty("Mountpoint", out var mountpoint) ? mountpoint.GetString() ?? string.Empty : string.Empty,
            root.TryGetProperty("CreatedAt", out var createdAt) ? createdAt.GetString() : null,
            ReadObjectPropertyNames(root.TryGetProperty("Options", out var options) ? options : default),
            ReadObjectPropertyNames(root.TryGetProperty("Labels", out var labels) ? labels : default));
    }

    private static void RequireCreateEligibleNetwork(DockerNetworkSnapshot network)
    {
        if (!string.Equals(network.Driver, "bridge", StringComparison.Ordinal)
            || !string.Equals(network.Scope, "local", StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Controlled Docker container creation requires an existing local bridge network; host, none, overlay, remote, and plugin network drivers are not supported.");
    }

    private static void RequireCreateEligibleVolume(DockerVolumeSnapshot volume)
    {
        if (!string.Equals(volume.Driver, "local", StringComparison.Ordinal)
            || !string.Equals(volume.Scope, "local", StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Controlled Docker container creation supports only existing local named volumes using the local volume driver.");
    }

    private static DockerNormalizedTcpPortBinding[] NormalizePortBindings(DockerTcpPortBindingInput[]? ports)
    {
        if (ports is null || ports.Length == 0) return Array.Empty<DockerNormalizedTcpPortBinding>();
        if (ports.Length > 32)
            throw new ArgumentOutOfRangeException(nameof(ports), "At most 32 TCP port bindings are allowed.");
        var result = new List<DockerNormalizedTcpPortBinding>(ports.Length);
        var hostPorts = new HashSet<int>();
        var containerPorts = new HashSet<int>();
        foreach (var port in ports)
        {
            if (port is null)
                throw new ArgumentException("TCP port binding entries cannot be null.", nameof(ports));
            if (port.HostPort is < 1024 or > 65535)
                throw new ArgumentOutOfRangeException(nameof(ports), "Host ports must be between 1024 and 65535.");
            if (port.ContainerPort is < 1 or > 65535)
                throw new ArgumentOutOfRangeException(nameof(ports), "Container ports must be between 1 and 65535.");
            if (!hostPorts.Add(port.HostPort))
                throw new ArgumentException($"Duplicate host TCP port {port.HostPort}.", nameof(ports));
            if (!containerPorts.Add(port.ContainerPort))
                throw new ArgumentException($"Duplicate container TCP port {port.ContainerPort}.", nameof(ports));
            result.Add(new DockerNormalizedTcpPortBinding(port.HostPort, port.ContainerPort));
        }
        return result.OrderBy(x => x.ContainerPort).ThenBy(x => x.HostPort).ToArray();
    }

    private static DockerNormalizedVolumeMount[] NormalizeVolumeMounts(DockerNamedVolumeMountInput[]? volumes)
    {
        if (volumes is null || volumes.Length == 0) return Array.Empty<DockerNormalizedVolumeMount>();
        if (volumes.Length > 16)
            throw new ArgumentOutOfRangeException(nameof(volumes), "At most 16 named-volume mounts are allowed.");
        var names = new HashSet<string>(StringComparer.Ordinal);
        var paths = new HashSet<string>(StringComparer.Ordinal);
        var result = new List<DockerNormalizedVolumeMount>(volumes.Length);
        foreach (var mount in volumes)
        {
            if (mount is null)
                throw new ArgumentException("Named-volume mount entries cannot be null.", nameof(volumes));
            var name = RequireVolumeName(mount.VolumeName);
            var path = RequireContainerVolumePath(mount.ContainerPath);
            if (!names.Add(name))
                throw new ArgumentException($"Duplicate named volume {name}.", nameof(volumes));
            if (!paths.Add(path))
                throw new ArgumentException($"Duplicate container volume path {path}.", nameof(volumes));
            result.Add(new DockerNormalizedVolumeMount(name, path, mount.ReadOnly));
        }
        return result.OrderBy(x => x.ContainerPath, StringComparer.Ordinal).ThenBy(x => x.VolumeName, StringComparer.Ordinal).ToArray();
    }

    private static DockerVolumeCreateSnapshot RevalidateSignedVolume(DockerSignedVolumeSnapshot signed)
    {
        var name = RequireVolumeName(signed.VolumeName);
        var path = RequireContainerVolumePath(signed.ContainerPath);
        var current = ReadVolume(name);
        RequireCreateEligibleVolume(current);
        if (!string.Equals(current.Driver, signed.Driver, StringComparison.Ordinal)
            || !string.Equals(current.Scope, signed.Scope, StringComparison.Ordinal)
            || !string.Equals(current.Mountpoint, signed.Mountpoint, StringComparison.Ordinal))
            throw new InvalidOperationException($"Docker named volume {name} identity changed after plan preparation.");
        return new DockerVolumeCreateSnapshot(current, path, signed.ReadOnly);
    }

    private static DockerSignedVolumeSnapshot ToSignedVolumeSnapshot(DockerVolumeCreateSnapshot snapshot)
        => new(snapshot.Volume.Name, snapshot.Volume.Driver, snapshot.Volume.Scope, snapshot.Volume.Mountpoint, snapshot.ContainerPath, snapshot.ReadOnly);

    private static string BuildVolumeMountArgument(DockerVolumeCreateSnapshot mount)
        => $"type=volume,src={mount.Volume.Name},dst={mount.ContainerPath}" + (mount.ReadOnly ? ",readonly" : string.Empty);

    private static void ValidateCreatedContainer(
        DockerContainerSnapshot created,
        SignedPlan plan,
        DockerImageSnapshot image,
        DockerNetworkSnapshot network,
        DockerNormalizedTcpPortBinding[] ports,
        DockerVolumeCreateSnapshot[] volumes)
    {
        if (!string.Equals(created.Name, RequireParameter(plan, "containerName"), StringComparison.Ordinal)
            || !string.Equals(created.ImageId, image.Id, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Created Docker container identity does not match the signed target.");
        if (created.Running || !string.Equals(created.Status, "created", StringComparison.Ordinal))
            throw new InvalidOperationException($"Created Docker container must remain stopped in created state; actual state={created.Status}, running={created.Running}.");
        if (created.Privileged || created.CapAddCount != 0 || created.DeviceCount != 0 || created.BindCount != 0)
            throw new InvalidOperationException("Created Docker container unexpectedly has privileged, added-capability, device, or bind-mount configuration.");
        if (!string.Equals(created.RestartPolicy, "no", StringComparison.Ordinal))
            throw new InvalidOperationException($"Created Docker container restart policy must be 'no'; actual={created.RestartPolicy}.");
        if (!created.AgentManaged || !string.Equals(created.CreatedPlanId, plan.PlanId, StringComparison.Ordinal))
            throw new InvalidOperationException("Created Docker container fixed Agent ownership labels are missing or mismatched.");
        if (!string.Equals(created.Environment.FingerprintSha256, image.EnvironmentFingerprintSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Created Docker container environment differs from the immutable image default environment; caller environment injection is not supported.");

        var expectedPorts = ports.Select(x => new DockerTcpPortBinding(x.HostPort, x.ContainerPort, "127.0.0.1", "tcp")).OrderBy(x => x.ContainerPort).ThenBy(x => x.HostPort).ToArray();
        var actualPorts = created.Ports.Where(x => string.Equals(x.Protocol, "tcp", StringComparison.OrdinalIgnoreCase)).OrderBy(x => x.ContainerPort).ThenBy(x => x.HostPort).ToArray();
        if (!expectedPorts.SequenceEqual(actualPorts))
            throw new InvalidOperationException("Created Docker container TCP port bindings do not match the signed loopback-only configuration.");
        if (created.Ports.Any(x => !string.Equals(x.HostIp, "127.0.0.1", StringComparison.Ordinal) || !string.Equals(x.Protocol, "tcp", StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("Created Docker container contains a non-loopback or non-TCP published port.");

        var expectedMounts = volumes.Select(x => new DockerVolumeMount(x.Volume.Name, x.ContainerPath, x.ReadOnly, "volume")).OrderBy(x => x.ContainerPath, StringComparer.Ordinal).ToArray();
        var actualMounts = created.Mounts.Where(x => string.Equals(x.Type, "volume", StringComparison.Ordinal)).Select(x => new DockerVolumeMount(x.Name, x.Destination, !x.Rw, x.Type)).OrderBy(x => x.ContainerPath, StringComparer.Ordinal).ToArray();
        if (!expectedMounts.SequenceEqual(actualMounts))
            throw new InvalidOperationException("Created Docker container named-volume mounts do not match the signed configuration.");
        if (created.Mounts.Any(x => !string.Equals(x.Type, "volume", StringComparison.Ordinal)))
            throw new InvalidOperationException("Created Docker container unexpectedly contains a non-volume mount.");

        var networkMatch = created.Networks.Any(x => string.Equals(x.NetworkId, network.Id, StringComparison.OrdinalIgnoreCase) || string.Equals(x.Name, network.Name, StringComparison.Ordinal));
        if (!networkMatch && !string.Equals(created.NetworkMode, network.Id, StringComparison.OrdinalIgnoreCase) && !string.Equals(created.NetworkMode, network.Name, StringComparison.Ordinal))
            throw new InvalidOperationException("Created Docker container network configuration does not match the signed local bridge network.");
    }

    private static void EnsureContainerNameAbsent(string name)
    {
        var result = Run("container", "inspect", "--format", "{{json .Id}}", name);
        if (result.ExitCode == 0)
            throw new InvalidOperationException($"Docker container name {name} already exists.");
        var list = Run("container", "ls", "--all", "--no-trunc", "--format", "{{json .}}");
        if (list.ExitCode != 0)
            throw new InvalidOperationException($"Unable to verify Docker container-name absence: {list.StdErr.Trim()}");
        foreach (var line in list.StdOut.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            using var doc = JsonDocument.Parse(line);
            if (doc.RootElement.TryGetProperty("Names", out var names) && string.Equals(names.GetString(), name, StringComparison.Ordinal))
                throw new InvalidOperationException($"Docker container name {name} already exists.");
        }
    }

    private static DockerEnvironmentSnapshot ReadEnvironment(JsonElement element)
    {
        if (element.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
            return new DockerEnvironmentSnapshot(Array.Empty<DockerEnvironmentVariableMetadata>(), EmptySha256());
        if (element.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Docker environment configuration is not an array.");

        var variables = new List<DockerEnvironmentVariableMetadata>();
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var item in element.EnumerateArray())
        {
            var raw = item.GetString() ?? string.Empty;
            var separator = raw.IndexOf('=');
            var name = separator >= 0 ? raw[..separator] : raw;
            var value = separator >= 0 ? raw[(separator + 1)..] : string.Empty;
            var valueBytes = Encoding.UTF8.GetBytes(value);
            var digest = Convert.ToHexString(SHA256.HashData(valueBytes));
            variables.Add(new DockerEnvironmentVariableMetadata(name, digest, value.Length));
            hash.AppendData(Encoding.UTF8.GetBytes(name.ToUpperInvariant()));
            hash.AppendData(new byte[] { 0 });
            hash.AppendData(valueBytes);
            hash.AppendData(new byte[] { 0 });
        }
        return new DockerEnvironmentSnapshot(variables.ToArray(), Convert.ToHexString(hash.GetHashAndReset()));
    }

    private static DockerTcpPortBinding[] ReadHostPortBindings(JsonElement hostConfig)
    {
        var result = new List<DockerTcpPortBinding>();
        if (!hostConfig.TryGetProperty("PortBindings", out var bindings) || bindings.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
            return Array.Empty<DockerTcpPortBinding>();
        if (bindings.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("Docker HostConfig.PortBindings is not an object.");
        foreach (var property in bindings.EnumerateObject())
        {
            var slash = property.Name.IndexOf('/');
            if (slash <= 0 || !int.TryParse(property.Name[..slash], out var containerPort))
                continue;
            var protocol = property.Name[(slash + 1)..];
            if (property.Value.ValueKind != JsonValueKind.Array) continue;
            foreach (var binding in property.Value.EnumerateArray())
            {
                var hostIp = binding.TryGetProperty("HostIp", out var ip) ? ip.GetString() ?? string.Empty : string.Empty;
                var hostPortText = binding.TryGetProperty("HostPort", out var port) ? port.GetString() ?? string.Empty : string.Empty;
                if (!int.TryParse(hostPortText, out var hostPort)) continue;
                result.Add(new DockerTcpPortBinding(hostPort, containerPort, hostIp, protocol));
            }
        }
        return result.OrderBy(x => x.ContainerPort).ThenBy(x => x.HostPort).ThenBy(x => x.HostIp, StringComparer.Ordinal).ToArray();
    }

    private static DockerContainerMount[] ReadMounts(JsonElement element)
    {
        if (element.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
            return Array.Empty<DockerContainerMount>();
        if (element.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Docker Mounts is not an array.");
        var result = new List<DockerContainerMount>();
        foreach (var mount in element.EnumerateArray())
        {
            result.Add(new DockerContainerMount(
                mount.TryGetProperty("Type", out var type) ? type.GetString() ?? string.Empty : string.Empty,
                mount.TryGetProperty("Name", out var name) ? name.GetString() ?? string.Empty : string.Empty,
                mount.TryGetProperty("Source", out var source) ? source.GetString() ?? string.Empty : string.Empty,
                mount.TryGetProperty("Destination", out var destination) ? destination.GetString() ?? string.Empty : string.Empty,
                mount.TryGetProperty("Driver", out var driver) ? driver.GetString() ?? string.Empty : string.Empty,
                mount.TryGetProperty("Mode", out var mode) ? mode.GetString() ?? string.Empty : string.Empty,
                mount.TryGetProperty("RW", out var rw) && rw.ValueKind == JsonValueKind.True));
        }
        return result.OrderBy(x => x.Destination, StringComparer.Ordinal).ToArray();
    }

    private static DockerContainerNetwork[] ReadContainerNetworks(JsonElement root)
    {
        var result = new List<DockerContainerNetwork>();
        if (!root.TryGetProperty("NetworkSettings", out var networkSettings) || networkSettings.ValueKind != JsonValueKind.Object
            || !networkSettings.TryGetProperty("Networks", out var networks) || networks.ValueKind != JsonValueKind.Object)
            return Array.Empty<DockerContainerNetwork>();
        foreach (var property in networks.EnumerateObject())
        {
            var value = property.Value;
            result.Add(new DockerContainerNetwork(
                property.Name,
                value.TryGetProperty("NetworkID", out var id) ? id.GetString() ?? string.Empty : string.Empty,
                value.TryGetProperty("IPAddress", out var ipv4) ? ipv4.GetString() : null,
                value.TryGetProperty("GlobalIPv6Address", out var ipv6) ? ipv6.GetString() : null));
        }
        return result.OrderBy(x => x.Name, StringComparer.Ordinal).ToArray();
    }

    private static string[] ReadStringArray(JsonElement element)
    {
        if (element.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
            return Array.Empty<string>();
        if (element.ValueKind != JsonValueKind.Array)
            return Array.Empty<string>();
        return element.EnumerateArray().Select(x => x.GetString() ?? string.Empty).ToArray();
    }

    private static string[] ReadObjectPropertyNames(JsonElement element)
    {
        if (element.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
            return Array.Empty<string>();
        if (element.ValueKind != JsonValueKind.Object)
            return Array.Empty<string>();
        return element.EnumerateObject().Select(x => x.Name).OrderBy(x => x, StringComparer.Ordinal).ToArray();
    }

    private static bool TryGetObjectString(JsonElement element, string propertyName, out string value)
    {
        value = string.Empty;
        if (element.ValueKind != JsonValueKind.Object) return false;
        if (!element.TryGetProperty(propertyName, out var property) || property.ValueKind != JsonValueKind.String) return false;
        value = property.GetString() ?? string.Empty;
        return true;
    }

    private static string RequireString(JsonElement element, string propertyName)
        => element.TryGetProperty(propertyName, out var property) && property.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(property.GetString())
            ? property.GetString()!
            : throw new InvalidDataException($"Docker inspect property {propertyName} is missing or empty.");

    private static string RequireFullContainerId(string value)
    {
        var normalized = (value ?? string.Empty).Trim();
        if (!FullContainerId.IsMatch(normalized))
            throw new ArgumentException("containerId must be the full 64-character hexadecimal Docker container ID.", nameof(value));
        return normalized.ToLowerInvariant();
    }

    private static string RequireFullNetworkId(string value)
    {
        var normalized = (value ?? string.Empty).Trim();
        if (!FullNetworkId.IsMatch(normalized))
            throw new ArgumentException("networkId must be the full 64-character hexadecimal Docker network ID.", nameof(value));
        return normalized.ToLowerInvariant();
    }

    private static string RequireFullImageId(string value)
    {
        var normalized = (value ?? string.Empty).Trim();
        if (!FullImageId.IsMatch(normalized))
            throw new ArgumentException("imageId must be an immutable Docker image ID in sha256:<64-hex> form.", nameof(value));
        return "sha256:" + normalized[7..].ToLowerInvariant();
    }

    private static string RequireContainerName(string value)
    {
        var normalized = (value ?? string.Empty).Trim();
        if (!ContainerNamePattern.IsMatch(normalized))
            throw new ArgumentException("containerName must start with an alphanumeric character and contain only alphanumeric, dot, underscore, or hyphen characters (maximum 128 characters).", nameof(value));
        return normalized;
    }

    private static string RequireVolumeName(string value)
    {
        var normalized = (value ?? string.Empty).Trim();
        if (!VolumeNamePattern.IsMatch(normalized))
            throw new ArgumentException("volumeName must start with an alphanumeric character and contain only alphanumeric, dot, underscore, or hyphen characters (maximum 128 characters).", nameof(value));
        return normalized;
    }

    private static string RequireContainerVolumePath(string value)
    {
        var normalized = (value ?? string.Empty).Trim();
        if (normalized.Length < 2 || normalized.Length > 1024 || !normalized.StartsWith("/", StringComparison.Ordinal) || normalized.Contains('\\') || normalized.Contains('\0'))
            throw new ArgumentException("Container volume path must be an absolute Linux path between 2 and 1024 characters.", nameof(value));
        var segments = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Any(x => x is "." or ".."))
            throw new ArgumentException("Container volume path cannot contain '.' or '..' path segments.", nameof(value));
        if (normalized.Equals("/proc", StringComparison.Ordinal) || normalized.StartsWith("/proc/", StringComparison.Ordinal)
            || normalized.Equals("/sys", StringComparison.Ordinal) || normalized.StartsWith("/sys/", StringComparison.Ordinal)
            || normalized.Equals("/dev", StringComparison.Ordinal) || normalized.StartsWith("/dev/", StringComparison.Ordinal)
            || normalized.Equals("/run", StringComparison.Ordinal) || normalized.StartsWith("/run/", StringComparison.Ordinal)
            || normalized.Equals("/var/run/docker.sock", StringComparison.Ordinal) || normalized.StartsWith("/var/run/docker.sock/", StringComparison.Ordinal))
            throw new UnauthorizedAccessException("Container volume path targets a protected runtime, pseudo-filesystem, device, or Docker socket location.");
        return normalized.TrimEnd('/');
    }

    private static void RequireIntentMatch(SignedPlan plan, string expectedOperation, string operation, string target, string summary, string riskClass)
    {
        if (!string.Equals(plan.Tool, "docker", StringComparison.Ordinal)
            || !string.Equals(plan.Operation, expectedOperation, StringComparison.Ordinal)
            || !string.Equals(plan.Operation, operation, StringComparison.Ordinal)
            || !string.Equals(plan.Target, target, StringComparison.Ordinal)
            || !string.Equals(plan.Summary, summary, StringComparison.Ordinal)
            || !string.Equals(plan.RiskClass.ToString(), riskClass, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("Plan execution intent mismatch.");
    }

    private static void RevalidateEngineIdentity(SignedPlan plan, DockerEngineIdentity current)
    {
        if (!string.Equals(current.DockerExeSha256, RequireParameter(plan, "dockerExeSha256"), StringComparison.OrdinalIgnoreCase)
            || !string.Equals(current.Context, RequireParameter(plan, "dockerContext"), StringComparison.Ordinal)
            || !string.Equals(current.EngineId, RequireParameter(plan, "dockerEngineId"), StringComparison.Ordinal))
            throw new InvalidOperationException("Docker CLI, context, or Engine identity changed after plan preparation.");
    }

    private static string RequireParameter(SignedPlan plan, string key)
        => plan.Parameters.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : throw new InvalidDataException($"Signed Docker parameter {key} is required.");

    private static string Sha256File(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static string EmptySha256() => Convert.ToHexString(SHA256.HashData(Array.Empty<byte>()));

    private static string RunRequiredSingleLine(params string[] arguments)
    {
        var result = Run(arguments);
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"Docker query failed with exit code {result.ExitCode}: {result.StdErr.Trim()}");
        var value = result.StdOut.Trim();
        if (string.IsNullOrWhiteSpace(value) || value.Contains('\n') || value.Contains('\r'))
            throw new InvalidDataException("Docker query did not return exactly one non-empty line.");
        return value;
    }

    private static DockerProcessResult Run(params string[] arguments)
    {
        if (!File.Exists(DockerExe))
            throw new FileNotFoundException("Docker CLI was not found at the fixed Docker Desktop path.", DockerExe);
        var start = new ProcessStartInfo
        {
            FileName = DockerExe,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (var argument in arguments)
            start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Unable to start the fixed Docker CLI process.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit((int)Timeout.TotalMilliseconds))
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException($"Docker operation exceeded {Timeout.TotalSeconds:0} seconds.");
        }
        Task.WaitAll(stdoutTask, stderrTask);
        return new DockerProcessResult(process.ExitCode, stdoutTask.Result, stderrTask.Result);
    }

    private static DockerContainerInspectResult ToContainerInspect(DockerContainerSnapshot snapshot)
        => new(
            snapshot.Id,
            snapshot.Name,
            snapshot.ImageId,
            snapshot.ImageReference,
            snapshot.Created,
            snapshot.Status,
            snapshot.Running,
            snapshot.ExitCode,
            snapshot.HealthStatus,
            snapshot.Entrypoint,
            snapshot.Command,
            snapshot.Environment.FingerprintSha256,
            snapshot.Environment.Variables,
            snapshot.LabelNames,
            snapshot.AgentManaged,
            snapshot.RestartPolicy,
            snapshot.NetworkMode,
            snapshot.Privileged,
            snapshot.CapAddCount,
            snapshot.DeviceCount,
            snapshot.BindCount,
            snapshot.Ports,
            snapshot.Mounts,
            snapshot.Networks,
            DateTimeOffset.UtcNow);

    private static DockerImageInspectResult ToImageInspect(DockerImageSnapshot snapshot)
        => new(
            snapshot.Id,
            snapshot.Created,
            snapshot.Architecture,
            snapshot.Os,
            snapshot.SizeBytes,
            snapshot.RepoTags,
            snapshot.RepoDigests,
            snapshot.Entrypoint,
            snapshot.Command,
            snapshot.ExposedPorts,
            snapshot.DeclaredVolumes,
            snapshot.EnvironmentFingerprintSha256,
            snapshot.Environment.Variables,
            DateTimeOffset.UtcNow);

    private static DockerNetworkInspectResult ToNetworkInspect(DockerNetworkSnapshot snapshot)
        => new(snapshot.Id, snapshot.Name, snapshot.Driver, snapshot.Scope, snapshot.Internal, snapshot.Attachable, snapshot.EnableIpv6, snapshot.Ipam, snapshot.OptionNames, snapshot.LabelNames, snapshot.Containers, DateTimeOffset.UtcNow);

    private static DockerVolumeInspectResult ToVolumeInspect(DockerVolumeSnapshot snapshot)
        => new(snapshot.Name, snapshot.Driver, snapshot.Scope, snapshot.Mountpoint, snapshot.CreatedAt, snapshot.OptionNames, snapshot.LabelNames, DateTimeOffset.UtcNow);

    private sealed record DockerEngineIdentity(string DockerExeSha256, string Context, string EngineId);
    private sealed record DockerProcessResult(int ExitCode, string StdOut, string StdErr);
    private sealed record DockerEnvironmentSnapshot(IReadOnlyList<DockerEnvironmentVariableMetadata> Variables, string FingerprintSha256);
    private sealed record DockerNormalizedTcpPortBinding(int HostPort, int ContainerPort);
    private sealed record DockerNormalizedVolumeMount(string VolumeName, string ContainerPath, bool ReadOnly);
    private sealed record DockerSignedVolumeSnapshot(string VolumeName, string Driver, string Scope, string Mountpoint, string ContainerPath, bool ReadOnly);
    private sealed record DockerVolumeCreateSnapshot(DockerVolumeSnapshot Volume, string ContainerPath, bool ReadOnly);
    private sealed record DockerImageSnapshot(
        string Id,
        string Created,
        string Architecture,
        string Os,
        long SizeBytes,
        string[] RepoTags,
        string[] RepoDigests,
        DockerEnvironmentSnapshot Environment,
        string[] Entrypoint,
        string[] Command,
        string[] ExposedPorts,
        string[] DeclaredVolumes)
    {
        public string EnvironmentFingerprintSha256 => Environment.FingerprintSha256;
    }
    private sealed record DockerNetworkSnapshot(
        string Id,
        string Name,
        string Driver,
        string Scope,
        bool Internal,
        bool Attachable,
        bool EnableIpv6,
        DockerNetworkIpamConfig[] Ipam,
        string[] OptionNames,
        string[] LabelNames,
        DockerNetworkContainer[] Containers);
    private sealed record DockerVolumeSnapshot(string Name, string Driver, string Scope, string Mountpoint, string? CreatedAt, string[] OptionNames, string[] LabelNames);
    private sealed record DockerContainerSnapshot(
        string Id,
        string Name,
        string ImageId,
        string Created,
        string Status,
        bool Running,
        int ExitCode,
        string? HealthStatus,
        string ImageReference,
        string[] Entrypoint,
        string[] Command,
        DockerEnvironmentSnapshot Environment,
        string[] LabelNames,
        bool AgentManaged,
        string? CreatedPlanId,
        string RestartPolicy,
        string NetworkMode,
        bool Privileged,
        int CapAddCount,
        int DeviceCount,
        int BindCount,
        DockerTcpPortBinding[] Ports,
        DockerContainerMount[] Mounts,
        DockerContainerNetwork[] Networks);
}

public sealed class DockerTcpPortBindingInput
{
    public int HostPort { get; init; }
    public int ContainerPort { get; init; }
}

public sealed class DockerNamedVolumeMountInput
{
    public string VolumeName { get; init; } = string.Empty;
    public string ContainerPath { get; init; } = string.Empty;
    public bool ReadOnly { get; init; }
}

public sealed record DockerEnvironmentVariableMetadata(string Name, string ValueSha256, int ValueLength);
public sealed record DockerTcpPortBinding(int HostPort, int ContainerPort, string HostIp, string Protocol);
public sealed record DockerVolumeMount(string VolumeName, string ContainerPath, bool ReadOnly, string Type);
public sealed record DockerContainerMount(string Type, string Name, string Source, string Destination, string Driver, string Mode, bool Rw);
public sealed record DockerContainerNetwork(string Name, string NetworkId, string? Ipv4Address, string? Ipv6Address);
public sealed record DockerNetworkIpamConfig(string? Subnet, string? Gateway, string? IpRange);
public sealed record DockerNetworkContainer(string ContainerId, string Name, string? Ipv4Address, string? Ipv6Address);

public sealed record DockerContainerInspectResult(
    string Id,
    string Name,
    string ImageId,
    string ImageReference,
    string Created,
    string Status,
    bool Running,
    int ExitCode,
    string? HealthStatus,
    IReadOnlyList<string> Entrypoint,
    IReadOnlyList<string> Command,
    string EnvironmentFingerprintSha256,
    IReadOnlyList<DockerEnvironmentVariableMetadata> EnvironmentVariables,
    IReadOnlyList<string> LabelNames,
    bool AgentManaged,
    string RestartPolicy,
    string NetworkMode,
    bool Privileged,
    int AddedCapabilityCount,
    int DeviceCount,
    int BindMountCount,
    IReadOnlyList<DockerTcpPortBinding> Ports,
    IReadOnlyList<DockerContainerMount> Mounts,
    IReadOnlyList<DockerContainerNetwork> Networks,
    DateTimeOffset CheckedUtc);

public sealed record DockerImageInspectResult(
    string Id,
    string Created,
    string Architecture,
    string Os,
    long SizeBytes,
    IReadOnlyList<string> RepoTags,
    IReadOnlyList<string> RepoDigests,
    IReadOnlyList<string> Entrypoint,
    IReadOnlyList<string> Command,
    IReadOnlyList<string> ExposedPorts,
    IReadOnlyList<string> DeclaredVolumes,
    string EnvironmentFingerprintSha256,
    IReadOnlyList<DockerEnvironmentVariableMetadata> EnvironmentVariables,
    DateTimeOffset CheckedUtc);

public sealed record DockerNetworkInspectResult(
    string Id,
    string Name,
    string Driver,
    string Scope,
    bool Internal,
    bool Attachable,
    bool EnableIpv6,
    IReadOnlyList<DockerNetworkIpamConfig> Ipam,
    IReadOnlyList<string> OptionNames,
    IReadOnlyList<string> LabelNames,
    IReadOnlyList<DockerNetworkContainer> Containers,
    DateTimeOffset CheckedUtc);

public sealed record DockerVolumeInspectResult(
    string Name,
    string Driver,
    string Scope,
    string Mountpoint,
    string? CreatedAt,
    IReadOnlyList<string> OptionNames,
    IReadOnlyList<string> LabelNames,
    DateTimeOffset CheckedUtc);

public sealed record DockerContainerCreateResult(
    string PlanId,
    string ContainerId,
    string ContainerName,
    string ImageId,
    string NetworkId,
    string NetworkName,
    IReadOnlyList<DockerTcpPortBinding> TcpPorts,
    IReadOnlyList<DockerVolumeMount> Volumes,
    string Outcome,
    DateTimeOffset ExecutedUtc);