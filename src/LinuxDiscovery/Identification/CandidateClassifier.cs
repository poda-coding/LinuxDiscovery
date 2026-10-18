using System.Net.NetworkInformation;
using System.Text.RegularExpressions;

namespace LinuxDiscovery;

internal enum EvidenceLevel
{
    /// <summary>Valid SSH banner that names a Linux distribution.</summary>
    LinuxLikely = 0,
    /// <summary>Valid SSH banner and an ICMP TTL typical of Unix-like systems (weak OS hint).</summary>
    SshServerUnixLikeTtl = 1,
    /// <summary>Valid SSH banner only. Operating system not established.</summary>
    SshServer = 2
}

internal sealed record Candidate(HostEvidence Host, EvidenceLevel Level, IReadOnlyList<string> Reasons)
{
    public string Summary => Level switch
    {
        EvidenceLevel.LinuxLikely => "Linux likely (SSH banner names a Linux distribution)",
        EvidenceLevel.SshServerUnixLikeTtl => "SSH server, Unix-like TTL (operating system not confirmed)",
        _ => "SSH server (operating system not confirmed)"
    };
}

internal sealed record HostEvidence(
    System.Net.IPAddress Address,
    TargetSubnet Subnet,
    PhysicalAddress? Mac,
    SshProbeResult Ssh,
    IcmpResult Icmp);

/// <summary>
/// Turns raw per-host evidence into ranked candidates. Only hosts that answered ARP, accepted TCP 22 and
/// sent a valid SSH identification string are candidates. The tool never states that a host is Linux
/// unless the banner itself supports that.
/// </summary>
internal static class CandidateClassifier
{
    private static readonly Regex DistroHint = new(
        @"\b(Ubuntu|Debian|Raspbian|Linux|Fedora|CentOS|Alpine|openSUSE|SUSE|Red\s?Hat|Yocto)\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static IReadOnlyList<Candidate> Classify(IEnumerable<HostEvidence> hosts)
    {
        var candidates = new List<Candidate>();

        foreach (HostEvidence host in hosts)
        {
            if (host.Ssh.State != PortState.Open || host.Ssh.Banner is null) continue;

            var reasons = new List<string>
            {
                "Answered ARP on the selected interface",
                "TCP port open",
                $"Valid SSH identification string: {host.Ssh.Banner.Raw}"
            };

            EvidenceLevel level = EvidenceLevel.SshServer;

            Match hint = DistroHint.Match(host.Ssh.Banner.Raw);
            bool unixTtl = host.Icmp.Replied && host.Icmp.Ttl is >= 33 and <= 64;

            if (unixTtl) reasons.Add($"ICMP reply TTL {host.Icmp.Ttl} is typical of Unix-like systems (weak evidence)");
            if (host.Icmp.Skipped) reasons.Add("ICMP not used on this subnet (another adapter shares it, so a reply could come from the wrong adapter)");
            else if (!host.Icmp.Replied) reasons.Add("No ICMP echo reply (ping may be blocked; not required)");

            if (hint.Success)
            {
                level = EvidenceLevel.LinuxLikely;
                reasons.Add($"Banner mentions '{hint.Value}'");
            }
            else if (unixTtl)
            {
                level = EvidenceLevel.SshServerUnixLikeTtl;
            }

            candidates.Add(new Candidate(host, level, reasons));
        }

        return candidates
            .OrderBy(c => c.Level)
            .ThenBy(c => IpMath.ToHostOrder(c.Host.Address))
            .ToList();
    }
}
