using System.Net;
using System.Net.NetworkInformation;

namespace LinuxDiscovery;

internal sealed record Ipv4Binding(IPAddress Address, int PrefixLength)
{
    public override string ToString() => $"{Address}/{PrefixLength}";
}

/// <summary>Snapshot of one Windows network adapter. Immutable; re-enumerate to refresh.</summary>
internal sealed record AdapterInfo(
    int Index,
    string Id,
    string Name,
    string Description,
    NetworkInterfaceType Type,
    OperationalStatus Status,
    IReadOnlyList<Ipv4Binding> Addresses,
    IPAddress? Gateway,
    bool IsDhcp,
    string? IneligibleReason,
    bool IsVirtual)
{
    /// <summary>Null reason means the adapter can be offered for scanning.</summary>
    public bool IsEligible => IneligibleReason is null;

    public string Ipv4Text => Addresses.Count == 0
        ? "Not configured"
        : string.Join(", ", Addresses.Select(a => a.ToString()));
}
