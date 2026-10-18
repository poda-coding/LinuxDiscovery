using System.Net;
using System.Net.NetworkInformation;

namespace LinuxDiscovery;

internal enum SubnetAccess
{
    /// <summary>The selected adapter already has an on-link address covering the whole subnet.</summary>
    OnLink,
    /// <summary>A temporary secondary address must be added to reach the subnet at layer 2.</summary>
    NeedsTemporaryAddress,
    /// <summary>The subnet is skipped because adding an address would overlap an existing prefix.</summary>
    Blocked
}

internal sealed record SubnetPlan(
    TargetSubnet Subnet,
    SubnetAccess Access,
    IPAddress? ExistingSource,
    string? Reason,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<string> ConflictingAdapters);

/// <summary>
/// Decides, per target subnet, whether the selected adapter can already reach it.
/// Pure logic over adapter snapshots, so it is unit-testable without touching a real adapter.
/// </summary>
internal static class ReachabilityPlanner
{
    public static IReadOnlyList<SubnetPlan> Plan(AdapterInfo selected, IReadOnlyList<AdapterInfo> all)
    {
        var plans = new List<SubnetPlan>();

        foreach (TargetSubnet subnet in TargetNetworks.All)
        {
            // Other connected adapters that already sit in this subnet make routing ambiguous.
            List<string> conflicting = all
                .Where(a => a.Id != selected.Id
                            && a.Status == OperationalStatus.Up
                            && a.Addresses.Any(b => Overlaps(b, subnet)))
                .Select(a => a.Name)
                .ToList();

            Ipv4Binding? covering = selected.Addresses.FirstOrDefault(b => Covers(b, subnet));
            Ipv4Binding? partial = selected.Addresses.FirstOrDefault(b => !Covers(b, subnet) && Overlaps(b, subnet));

            if (covering is not null)
            {
                var warnings = new List<string>();
                if (conflicting.Count > 0)
                {
                    warnings.Add($"Adapter(s) {string.Join(", ", conflicting)} are also in {subnet}; " +
                                 "replies may be ambiguous. Disconnect them for the cleanest result.");
                }
                plans.Add(new SubnetPlan(subnet, SubnetAccess.OnLink, covering.Address, null, warnings, conflicting));
            }
            else if (partial is not null)
            {
                plans.Add(new SubnetPlan(subnet, SubnetAccess.Blocked, null,
                    $"The adapter has {partial}, which overlaps {subnet} with a longer prefix than /24. " +
                    "A temporary /24 would overlap it.", Array.Empty<string>(), conflicting));
            }
            else
            {
                // Another connected adapter in the same subnet is a risk, not a blocker: the address is
                // temporary and scan traffic is pinned to the selected adapter. The user is told about the
                // risk before anything is changed (see ConsoleUi.ExplainChanges).
                var warnings = new List<string>();
                if (conflicting.Count > 0)
                {
                    warnings.Add($"Adapter(s) {string.Join(", ", conflicting)} are also in {subnet} (see the note below).");
                }
                plans.Add(new SubnetPlan(subnet, SubnetAccess.NeedsTemporaryAddress, null, null, warnings, conflicting));
            }
        }

        return plans;
    }

    /// <summary>The binding's connected prefix contains the entire /24.</summary>
    private static bool Covers(Ipv4Binding b, TargetSubnet s) =>
        b.PrefixLength <= TargetSubnet.PrefixLength &&
        IpMath.InSameNetwork(b.Address, s.NetworkAddress, b.PrefixLength);

    /// <summary>The binding's connected prefix covers or partially intersects the /24.</summary>
    private static bool Overlaps(Ipv4Binding b, TargetSubnet s) =>
        Covers(b, s) || (b.PrefixLength > TargetSubnet.PrefixLength && s.Contains(b.Address));
}
