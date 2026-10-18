using System.Net;
using System.Net.NetworkInformation;

namespace LinuxDiscovery.Tests;

internal static class TestData
{
    /// <summary>Builds an adapter snapshot. Addresses are given as "a.b.c.d/len".</summary>
    public static AdapterInfo Adapter(string name, int index, string[] cidrs, bool up = true)
    {
        var bindings = cidrs.Select(c =>
        {
            string[] parts = c.Split('/');
            return new Ipv4Binding(IPAddress.Parse(parts[0]), int.Parse(parts[1]));
        }).ToList();

        return new AdapterInfo(index, $"id-{index}", name, name + " adapter", NetworkInterfaceType.Ethernet,
            up ? OperationalStatus.Up : OperationalStatus.Down, bindings, null, false,
            up ? null : "Not connected", false);
    }

    public static SshBanner Banner(string raw)
    {
        Assert.True(SshBanner.TryParse(raw, out SshBanner? b));
        return b!;
    }

    public static HostEvidence Host(string ip, SshProbeResult ssh, IcmpResult? icmp = null)
    {
        IPAddress address = IPAddress.Parse(ip);
        return new HostEvidence(address, TargetNetworks.Find(address)!, new PhysicalAddress(new byte[] { 1, 2, 3, 4, 5, 6 }),
            ssh, icmp ?? new IcmpResult(false, null, 0));
    }

    public static string TempJournalPath() => Path.Combine(Path.GetTempPath(), $"ld-test-{Guid.NewGuid():N}.json");
}

/// <summary>In-memory stand-in for the real IP Helper configurator. Touches no network adapter.</summary>
internal sealed class FakeConfigurator : IAddressConfigurator
{
    /// <summary>Addresses that "exist" already (not created by the tool). Must never be removed.</summary>
    public HashSet<string> PreExisting { get; } = new();
    /// <summary>Addresses the tool created and that are currently present.</summary>
    public HashSet<string> Present { get; } = new();
    /// <summary>Addresses that another device already uses (duplicate address detection fails).</summary>
    public HashSet<string> DuplicateOnDad { get; } = new();
    public HashSet<string> FailRemove { get; } = new();
    public List<string> RemoveCalls { get; } = new();

    public AddResult Create(int interfaceIndex, IPAddress address, int prefixLength)
    {
        string key = address.ToString();
        if (PreExisting.Contains(key)) return new AddResult(AddStatus.AlreadyExists, 5010, "exists");
        Present.Add(key);
        return new AddResult(AddStatus.Success);
    }

    public Task<DadOutcome> WaitUntilUsableAsync(int interfaceIndex, IPAddress address, int prefixLength,
        TimeSpan timeout, CancellationToken ct) =>
        Task.FromResult(DuplicateOnDad.Contains(address.ToString()) ? DadOutcome.Duplicate : DadOutcome.Usable);

    public RemoveResult Remove(int interfaceIndex, IPAddress address, int prefixLength)
    {
        string key = address.ToString();
        RemoveCalls.Add(key);
        if (FailRemove.Contains(key)) return new RemoveResult(RemoveStatus.Failed, 5, "access denied");
        return Present.Remove(key) ? new RemoveResult(RemoveStatus.Removed) : new RemoveResult(RemoveStatus.AlreadyGone, 1168);
    }
}

internal sealed class FakeArp : IArpProber
{
    public Dictionary<string, PhysicalAddress> Hosts { get; } = new();

    public ArpResult Probe(IPAddress target, IPAddress source) =>
        Hosts.TryGetValue(target.ToString(), out PhysicalAddress? mac)
            ? new ArpResult(ArpStatus.Replied, mac)
            : new ArpResult(ArpStatus.NoReply);
}

internal sealed class FakeSsh : ITcpSshProber
{
    public Dictionary<string, SshProbeResult> Results { get; } = new();

    public Task<SshProbeResult> ProbeAsync(IPAddress source, IPAddress target, int port, CancellationToken ct) =>
        Task.FromResult(Results.TryGetValue(target.ToString(), out SshProbeResult? r)
            ? r
            : new SshProbeResult(PortState.Closed, null, "refused"));
}

internal sealed class FakeIcmp : IIcmpProber
{
    private int _calls;

    public Dictionary<string, IcmpResult> Results { get; } = new();
    public int Calls => Volatile.Read(ref _calls);

    public Task<IcmpResult> PingAsync(IPAddress target, CancellationToken ct)
    {
        Interlocked.Increment(ref _calls);
        return Task.FromResult(Results.TryGetValue(target.ToString(), out IcmpResult? r) ? r : new IcmpResult(false, null, 0));
    }
}
