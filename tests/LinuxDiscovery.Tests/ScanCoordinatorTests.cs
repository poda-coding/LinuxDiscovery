using System.Net;
using System.Net.NetworkInformation;

namespace LinuxDiscovery.Tests;

public class ScanCoordinatorTests
{
    private readonly FakeArp _arp = new();
    private readonly FakeSsh _ssh = new();
    private readonly FakeIcmp _icmp = new();

    private static readonly PhysicalAddress Mac = new(new byte[] { 0xAA, 0xBB, 0xCC, 0, 0, 1 });

    private async Task<IReadOnlyList<Candidate>> RunAsync()
    {
        var coordinator = new ScanCoordinator(_arp, _ssh, _icmp);
        var targets = new[]
        {
            new ScanTarget(TargetNetworks.Subnet0, IPAddress.Parse("192.168.0.231")),
            new ScanTarget(TargetNetworks.Subnet1, IPAddress.Parse("192.168.1.231")),
        };
        var own = new HashSet<IPAddress> { IPAddress.Parse("192.168.0.231"), IPAddress.Parse("192.168.1.231") };

        ScanResult result = await coordinator.ScanAsync(targets, own, new InlineProgress<ScanProgress>(_ => { }), CancellationToken.None);
        Assert.Equal(2 * 254 - 2, result.ProbedAddresses); // own addresses are skipped
        return CandidateClassifier.Classify(result.Responders);
    }

    private static SshProbeResult OpenSsh(string banner) => new(PortState.Open, TestData.Banner(banner), null);

    [Fact]
    public async Task Finds_ssh_host_even_though_ping_is_blocked()
    {
        _arp.Hosts["192.168.1.42"] = Mac;
        _ssh.Results["192.168.1.42"] = OpenSsh("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13");

        var candidates = await RunAsync();

        Assert.Equal("192.168.1.42", Assert.Single(candidates).Host.Address.ToString());
    }

    [Fact]
    public async Task Host_with_ping_but_closed_ssh_is_not_reported()
    {
        _arp.Hosts["192.168.0.77"] = Mac;
        _icmp.Results["192.168.0.77"] = new IcmpResult(true, 64, 1);

        Assert.Empty(await RunAsync());
    }

    [Fact]
    public async Task Multiple_ssh_servers_are_all_returned()
    {
        foreach (string ip in new[] { "192.168.0.10", "192.168.1.20" })
        {
            _arp.Hosts[ip] = Mac;
            _ssh.Results[ip] = OpenSsh("SSH-2.0-OpenSSH_9.2p1 Debian-2");
        }

        Assert.Equal(2, (await RunAsync()).Count);
    }

    [Fact]
    public async Task No_responders_gives_no_candidates()
    {
        Assert.Empty(await RunAsync());
    }

    [Fact]
    public async Task Icmp_is_skipped_for_subnets_shared_with_another_adapter()
    {
        _arp.Hosts["192.168.1.42"] = Mac;
        _arp.Hosts["192.168.0.42"] = Mac;
        _ssh.Results["192.168.1.42"] = OpenSsh("SSH-2.0-OpenSSH_9.6");
        _ssh.Results["192.168.0.42"] = OpenSsh("SSH-2.0-OpenSSH_9.6");

        var coordinator = new ScanCoordinator(_arp, _ssh, _icmp);
        var targets = new[]
        {
            new ScanTarget(TargetNetworks.Subnet0, IPAddress.Parse("192.168.0.231"), UseIcmp: true),
            new ScanTarget(TargetNetworks.Subnet1, IPAddress.Parse("192.168.1.231"), UseIcmp: false),
        };

        ScanResult result = await coordinator.ScanAsync(targets, new HashSet<IPAddress>(),
            new InlineProgress<ScanProgress>(_ => { }), CancellationToken.None);

        Assert.Equal(1, _icmp.Calls); // only the non-shared subnet was pinged
        Assert.True(result.Responders.Single(h => h.Address.ToString() == "192.168.1.42").Icmp.Skipped);
        Assert.False(result.Responders.Single(h => h.Address.ToString() == "192.168.0.42").Icmp.Skipped);
    }

    [Fact]
    public async Task Scans_subnets_2_and_3_and_never_probes_outside_the_scope()
    {
        _arp.Hosts["192.168.2.50"] = Mac;
        _arp.Hosts["192.168.3.60"] = Mac;
        _ssh.Results["192.168.2.50"] = OpenSsh("SSH-2.0-OpenSSH_9.2p1 Debian-2");
        _ssh.Results["192.168.3.60"] = OpenSsh("SSH-2.0-OpenSSH_9.2p1 Debian-2");

        var probed = new System.Collections.Concurrent.ConcurrentBag<string>();
        var recording = new RecordingArp(_arp, probed);
        var coordinator = new ScanCoordinator(recording, _ssh, _icmp);

        var targets = TargetNetworks.All
            .Select(s => new ScanTarget(s, s.Host(231)))
            .ToList();

        ScanResult result = await coordinator.ScanAsync(targets, new HashSet<IPAddress>(),
            new InlineProgress<ScanProgress>(_ => { }), CancellationToken.None);

        Assert.Equal(4 * 254, result.ProbedAddresses);
        Assert.Equal(2, CandidateClassifier.Classify(result.Responders).Count);
        Assert.All(probed, ip => Assert.NotNull(TargetNetworks.Find(IPAddress.Parse(ip))));
    }

    private sealed class RecordingArp : IArpProber
    {
        private readonly IArpProber _inner;
        private readonly System.Collections.Concurrent.ConcurrentBag<string> _log;
        public RecordingArp(IArpProber inner, System.Collections.Concurrent.ConcurrentBag<string> log) { _inner = inner; _log = log; }

        public ArpResult Probe(IPAddress target, IPAddress source)
        {
            _log.Add(target.ToString());
            return _inner.Probe(target, source);
        }
    }

    [Fact]
    public async Task Cancellation_stops_the_scan()
    {
        var coordinator = new ScanCoordinator(_arp, _ssh, _icmp);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => coordinator.ScanAsync(
            new[] { new ScanTarget(TargetNetworks.Subnet0, IPAddress.Parse("192.168.0.231")) },
            new HashSet<IPAddress>(), new InlineProgress<ScanProgress>(_ => { }), cts.Token));
    }
}
