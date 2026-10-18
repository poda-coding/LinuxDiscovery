using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;

namespace LinuxDiscovery;

/// <summary>
/// A subnet to scan plus the local address (existing or temporary) that pins traffic to the selected adapter.
/// <paramref name="UseIcmp"/> is false when another adapter shares the subnet: System.Net Ping cannot bind a
/// source address, so the echo could leave through the wrong adapter and its TTL would be misleading.
/// </summary>
internal sealed record ScanTarget(TargetSubnet Subnet, IPAddress SourceAddress, bool UseIcmp = true);

internal sealed record ScanOptions(int ArpConcurrency = 128, int TcpConcurrency = 32, int SshPort = 22);

internal sealed record ScanProgress(string Phase, int Done, int Total, int Responders);

internal sealed record ScanResult(
    IReadOnlyList<HostEvidence> Responders,
    int ProbedAddresses,
    int NoReply,
    int ArpErrors,
    int FirstArpErrorCode,
    IReadOnlyDictionary<int, int> ArpErrorCounts);

/// <summary>IProgress that runs synchronously on the reporting thread (Progress&lt;T&gt; posts asynchronously and reorders output).</summary>
internal sealed class InlineProgress<T> : IProgress<T>
{
    private readonly Action<T> _handler;
    public InlineProgress(Action<T> handler) => _handler = handler;
    public void Report(T value) => _handler(value);
}

/// <summary>
/// Two-phase discovery: (1) ARP sweep of every candidate address, (2) TCP/22 + banner + ICMP only against
/// hosts that answered ARP. Concurrency is bounded. All probing goes through interfaces, so tests use fakes.
/// </summary>
internal sealed class ScanCoordinator
{
    private readonly IArpProber _arp;
    private readonly ITcpSshProber _ssh;
    private readonly IIcmpProber _icmp;
    private readonly ScanOptions _options;

    static ScanCoordinator()
    {
        // SendARP is a blocking call. Make sure the thread pool can run enough of them in parallel
        // instead of ramping up slowly (which would stretch the sweep to minutes).
        ThreadPool.GetMinThreads(out int worker, out int io);
        if (worker < 192) ThreadPool.SetMinThreads(192, io);
    }

    public ScanCoordinator(IArpProber arp, ITcpSshProber ssh, IIcmpProber icmp, ScanOptions? options = null)
    {
        _arp = arp;
        _ssh = ssh;
        _icmp = icmp;
        _options = options ?? new ScanOptions();
    }

    public async Task<ScanResult> ScanAsync(
        IReadOnlyList<ScanTarget> targets,
        IReadOnlySet<IPAddress> ownAddresses,
        IProgress<ScanProgress> progress,
        CancellationToken ct)
    {
        // Scope guard: only addresses of the target subnets, never our own addresses.
        var work = targets
            .Where(t => TargetNetworks.All.Contains(t.Subnet))
            .SelectMany(t => t.Subnet.HostAddresses()
                .Where(a => !ownAddresses.Contains(a))
                .Select(a => (t.Subnet, Source: t.SourceAddress, Address: a, t.UseIcmp)))
            .ToList();

        // ---- Phase 1: ARP sweep ----
        var arpHits = new ConcurrentBag<(TargetSubnet Subnet, IPAddress Source, IPAddress Address, PhysicalAddress Mac, bool UseIcmp)>();
        int done = 0, hits = 0, noReply = 0, errors = 0, firstError = 0;
        var errorCounts = new ConcurrentDictionary<int, int>();

        await Parallel.ForEachAsync(
            work,
            new ParallelOptions { MaxDegreeOfParallelism = _options.ArpConcurrency, CancellationToken = ct },
            async (item, token) =>
            {
                ArpResult r = await Task.Run(() => _arp.Probe(item.Address, item.Source), token).ConfigureAwait(false);

                switch (r.Status)
                {
                    case ArpStatus.Replied when r.Mac is not null:
                        arpHits.Add((item.Subnet, item.Source, item.Address, r.Mac, item.UseIcmp));
                        Interlocked.Increment(ref hits);
                        break;
                    case ArpStatus.Error:
                        Interlocked.Increment(ref errors);
                        Interlocked.CompareExchange(ref firstError, r.ErrorCode, 0);
                        errorCounts.AddOrUpdate(r.ErrorCode, 1, (_, n) => n + 1);
                        break;
                    default:
                        Interlocked.Increment(ref noReply);
                        break;
                }

                int d = Interlocked.Increment(ref done);
                progress.Report(new ScanProgress("ARP sweep", d, work.Count, Volatile.Read(ref hits)));
            }).ConfigureAwait(false);

        // ---- Phase 2: TCP 22 + banner + ICMP on ARP responders only ----
        var responders = arpHits.OrderBy(h => IpMath.ToHostOrder(h.Address)).ToList();
        var evidence = new ConcurrentBag<HostEvidence>();
        int done2 = 0;

        await Parallel.ForEachAsync(
            responders,
            new ParallelOptions { MaxDegreeOfParallelism = _options.TcpConcurrency, CancellationToken = ct },
            async (hit, token) =>
            {
                Task<SshProbeResult> ssh = _ssh.ProbeAsync(hit.Source, hit.Address, _options.SshPort, token);
                Task<IcmpResult> icmp = hit.UseIcmp
                    ? _icmp.PingAsync(hit.Address, token)
                    : Task.FromResult(new IcmpResult(false, null, 0, Skipped: true));
                await Task.WhenAll(ssh, icmp).ConfigureAwait(false);

                evidence.Add(new HostEvidence(hit.Address, hit.Subnet, hit.Mac, ssh.Result, icmp.Result));

                int d = Interlocked.Increment(ref done2);
                progress.Report(new ScanProgress("Checking SSH", d, responders.Count, responders.Count));
            }).ConfigureAwait(false);

        return new ScanResult(
            evidence.OrderBy(e => IpMath.ToHostOrder(e.Address)).ToList(),
            work.Count, noReply, errors, firstError, errorCounts.ToDictionary(kv => kv.Key, kv => kv.Value));
    }
}
