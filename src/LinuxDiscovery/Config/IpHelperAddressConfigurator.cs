using System.ComponentModel;
using System.Net;

namespace LinuxDiscovery;

/// <summary>
/// Adds/removes IPv4 unicast addresses through the IP Helper API (iphlpapi.dll). No PowerShell, no netsh,
/// so there is no command-line construction and no localized output to parse.
/// </summary>
internal sealed class IpHelperAddressConfigurator : IAddressConfigurator
{
    private const ushort AfInet = 2;
    private const int PrefixOriginManual = 1;
    private const int SuffixOriginManual = 1;

    public AddResult Create(int interfaceIndex, IPAddress address, int prefixLength)
    {
        MibUnicastIpAddressRow row = BuildRow(interfaceIndex, address, prefixLength);

        // CHANGES SYSTEM CONFIGURATION: adds one secondary IPv4 address to the adapter.
        uint rc = NativeMethods.CreateUnicastIpAddressEntry(ref row);

        return rc switch
        {
            0 => new AddResult(AddStatus.Success),
            NativeMethods.ErrorObjectAlreadyExists =>
                new AddResult(AddStatus.AlreadyExists, (int)rc, "The address already exists on this adapter."),
            NativeMethods.ErrorAccessDenied =>
                new AddResult(AddStatus.AccessDenied, (int)rc, "Access denied. Run the tool as administrator."),
            _ => new AddResult(AddStatus.Failed, (int)rc, new Win32Exception((int)rc).Message)
        };
    }

    public async Task<DadOutcome> WaitUntilUsableAsync(int interfaceIndex, IPAddress address, int prefixLength,
        TimeSpan timeout, CancellationToken cancellationToken)
    {
        DateTime deadline = DateTime.UtcNow + timeout;

        while (true)
        {
            MibUnicastIpAddressRow row = BuildRow(interfaceIndex, address, prefixLength);
            uint rc = NativeMethods.GetUnicastIpAddressEntry(ref row);

            if (rc == 0)
            {
                if (row.DadState == NativeMethods.DadPreferred) return DadOutcome.Usable;
                if (row.DadState == NativeMethods.DadDuplicate) return DadOutcome.Duplicate;
                // Tentative (probing) or transitional: keep polling.
            }

            if (DateTime.UtcNow >= deadline) return DadOutcome.TimedOut;
            await Task.Delay(100, cancellationToken).ConfigureAwait(false);
        }
    }

    public RemoveResult Remove(int interfaceIndex, IPAddress address, int prefixLength)
    {
        MibUnicastIpAddressRow row = BuildRow(interfaceIndex, address, prefixLength);

        // CHANGES SYSTEM CONFIGURATION: removes exactly the address this tool added.
        uint rc = NativeMethods.DeleteUnicastIpAddressEntry(ref row);

        return rc switch
        {
            0 => new RemoveResult(RemoveStatus.Removed),
            NativeMethods.ErrorNotFound => new RemoveResult(RemoveStatus.AlreadyGone, (int)rc),
            _ => new RemoveResult(RemoveStatus.Failed, (int)rc, new Win32Exception((int)rc).Message)
        };
    }

    private static MibUnicastIpAddressRow BuildRow(int interfaceIndex, IPAddress address, int prefixLength)
    {
        NativeMethods.InitializeUnicastIpAddressEntry(out MibUnicastIpAddressRow row);
        row.Address.Family = AfInet;
        row.Address.Ipv4 = IpMath.ToNative(address);
        row.InterfaceIndex = (uint)interfaceIndex;
        row.OnLinkPrefixLength = (byte)prefixLength;
        row.PrefixOrigin = PrefixOriginManual;
        row.SuffixOrigin = SuffixOriginManual;
        // SkipAsSource is deliberately false. An earlier version set it to true so that Windows would not use
        // the address for ordinary traffic, but a manual test (New-NetIPAddress with SkipAsSource False) worked
        // where the scan found nothing, and SendARP is not documented to accept such an address as its source.
        // Trade-off: while the temporary address exists, Windows may use it for traffic to this /24 and may
        // register it in DNS if the adapter has dynamic DNS registration enabled.
        row.SkipAsSource = 0;
        return row;
    }
}
