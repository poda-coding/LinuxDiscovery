using System.Net;
using System.Net.Sockets;

namespace LinuxDiscovery;

/// <summary>One of the two subnets this tool is allowed to touch (always a /24 in 192.168.x.0).</summary>
internal sealed record TargetSubnet(string Cidr, byte ThirdOctet)
{
    public const int PrefixLength = 24;

    public IPAddress NetworkAddress => new IPAddress(new byte[] { 192, 168, ThirdOctet, 0 });

    public IPAddress Host(byte lastOctet) => new IPAddress(new byte[] { 192, 168, ThirdOctet, lastOctet });

    public bool Contains(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork) return false;
        byte[] b = address.GetAddressBytes();
        return b[0] == 192 && b[1] == 168 && b[2] == ThirdOctet;
    }

    /// <summary>Host addresses .1 through .254.</summary>
    public IEnumerable<IPAddress> HostAddresses()
    {
        for (int i = 1; i <= 254; i++) yield return Host((byte)i);
    }

    public override string ToString() => Cidr;
}

/// <summary>The fixed scan scope (192.168.0.0/24 to 192.168.3.0/24). Nothing outside these subnets is ever probed.</summary>
internal static class TargetNetworks
{
    public static readonly TargetSubnet Subnet0 = new("192.168.0.0/24", 0);
    public static readonly TargetSubnet Subnet1 = new("192.168.1.0/24", 1);
    public static readonly TargetSubnet Subnet2 = new("192.168.2.0/24", 2);
    public static readonly TargetSubnet Subnet3 = new("192.168.3.0/24", 3);

    /// <summary>The complete scan scope. To change it, edit this list only.</summary>
    public static readonly IReadOnlyList<TargetSubnet> All = new[] { Subnet0, Subnet1, Subnet2, Subnet3 };

    /// <summary>
    /// Host numbers tried (in order) for the temporary address. High numbers are unlikely to be
    /// in use by DHCP pools; conflicts are still detected through Windows duplicate address detection.
    /// </summary>
    public static readonly byte[] TemporaryHostOctets = { 231, 232, 233, 234, 235, 236, 237, 238 };

    public static TargetSubnet? Find(IPAddress address) => All.FirstOrDefault(s => s.Contains(address));
}
