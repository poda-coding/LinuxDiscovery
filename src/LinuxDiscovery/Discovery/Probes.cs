using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace LinuxDiscovery;

// ---------- ARP ----------

internal enum ArpStatus { Replied, NoReply, Error }

internal sealed record ArpResult(ArpStatus Status, PhysicalAddress? Mac = null, int ErrorCode = 0);

internal interface IArpProber
{
    /// <summary>Sends an ARP request for <paramref name="target"/> out of the adapter that owns <paramref name="source"/>.</summary>
    ArpResult Probe(IPAddress target, IPAddress source);
}

/// <summary>
/// ARP through IP Helper SendARP. The source address selects the outgoing interface, which is how
/// the scan stays pinned to the adapter the user selected. Blocking call: run it on worker threads.
/// </summary>
internal sealed class SendArpProber : IArpProber
{
    public ArpResult Probe(IPAddress target, IPAddress source)
    {
        var mac = new byte[8];
        uint length = (uint)mac.Length;

        uint rc = NativeMethods.SendARP(IpMath.ToNative(target), IpMath.ToNative(source), mac, ref length);

        if (rc == 0 && length >= 6)
            return new ArpResult(ArpStatus.Replied, new PhysicalAddress(mac[..6]));

        if (rc is NativeMethods.ErrorBadNetName or NativeMethods.ErrorNotFound)
            return new ArpResult(ArpStatus.NoReply);

        return new ArpResult(ArpStatus.Error, null, (int)rc);
    }
}

// ---------- TCP / SSH ----------

internal enum PortState { Open, Closed, Filtered, Inconclusive }

internal sealed record SshProbeResult(PortState State, SshBanner? Banner, string? Detail);

internal interface ITcpSshProber
{
    Task<SshProbeResult> ProbeAsync(IPAddress source, IPAddress target, int port, CancellationToken cancellationToken);
}

/// <summary>
/// Connects to the SSH port from the explicit temporary/own source address and reads the SSH identification
/// string the server sends first (RFC 4253 section 4.2). Nothing is sent: no authentication, no key exchange.
/// </summary>
internal sealed class TcpSshProber : ITcpSshProber
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan BannerTimeout = TimeSpan.FromSeconds(3);

    public async Task<SshProbeResult> ProbeAsync(IPAddress source, IPAddress target, int port, CancellationToken ct)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

        try
        {
            socket.Bind(new IPEndPoint(source, 0));
        }
        catch (SocketException ex)
        {
            return new SshProbeResult(PortState.Inconclusive, null, $"Cannot bind to {source}: {ex.SocketErrorCode}");
        }

        using (var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            connectCts.CancelAfter(ConnectTimeout);
            try
            {
                await socket.ConnectAsync(new IPEndPoint(target, port), connectCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return new SshProbeResult(PortState.Filtered, null, "No answer to the TCP SYN (dropped by a firewall?)");
            }
            catch (SocketException ex)
            {
                return MapConnectError(ex);
            }
        }

        // Connected: the port is open. Now read the identification string.
        var buffer = new byte[512];
        int total = 0;
        string? detail = null;
        SshBanner? banner = null;

        using var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        readCts.CancelAfter(BannerTimeout);

        try
        {
            while (total < buffer.Length)
            {
                int n = await socket.ReceiveAsync(buffer.AsMemory(total), SocketFlags.None, readCts.Token).ConfigureAwait(false);
                if (n == 0) break; // server closed the connection
                total += n;

                if (SshBanner.TryExtract(Encoding.ASCII.GetString(buffer, 0, total), out banner)) break;
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            detail = "Timed out waiting for an SSH identification string.";
        }
        catch (SocketException ex)
        {
            detail = $"Read failed: {ex.SocketErrorCode}";
        }

        if (banner is not null) return new SshProbeResult(PortState.Open, banner, null);

        return new SshProbeResult(PortState.Open, null,
            detail ?? "Port is open but the service did not send an SSH identification string.");
    }

    private static SshProbeResult MapConnectError(SocketException ex) => ex.SocketErrorCode switch
    {
        SocketError.ConnectionRefused => new SshProbeResult(PortState.Closed, null, "Connection refused (host is up, port closed)"),
        SocketError.TimedOut => new SshProbeResult(PortState.Filtered, null, "Connection timed out (likely filtered)"),
        SocketError.HostUnreachable or SocketError.NetworkUnreachable or SocketError.HostDown =>
            new SshProbeResult(PortState.Inconclusive, null, $"Unreachable ({ex.SocketErrorCode})"),
        _ => new SshProbeResult(PortState.Inconclusive, null, $"Socket error {ex.SocketErrorCode}")
    };
}

// ---------- ICMP (diagnostic only) ----------

internal sealed record IcmpResult(bool Replied, int? Ttl, long RoundTripMs, bool Skipped = false);

internal interface IIcmpProber
{
    Task<IcmpResult> PingAsync(IPAddress target, CancellationToken cancellationToken);
}

/// <summary>
/// Optional extra evidence (reply TTL). Discovery never depends on it: firewalls often block echo requests.
/// System.Net Ping cannot bind a source address, so this is only run against hosts already seen via ARP.
/// </summary>
internal sealed class PingIcmpProber : IIcmpProber
{
    public async Task<IcmpResult> PingAsync(IPAddress target, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        try
        {
            using var ping = new Ping();
            PingReply reply = await ping.SendPingAsync(target, 1000).ConfigureAwait(false);
            return reply.Status == IPStatus.Success
                ? new IcmpResult(true, reply.Options?.Ttl, reply.RoundtripTime)
                : new IcmpResult(false, null, 0);
        }
        catch (PingException)
        {
            return new IcmpResult(false, null, 0);
        }
    }
}
