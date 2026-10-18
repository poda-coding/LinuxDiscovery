using System.Net;

namespace LinuxDiscovery.Tests;

public class TargetNetworksTests
{
    [Theory]
    [InlineData("192.168.0.1", true)]
    [InlineData("192.168.1.254", true)]
    [InlineData("192.168.2.50", true)]
    [InlineData("192.168.3.9", true)]
    [InlineData("192.168.4.1", false)]   // just outside the scope
    [InlineData("192.169.1.1", false)]
    [InlineData("10.0.0.1", false)]
    public void Scope_contains_only_the_four_target_subnets(string ip, bool inScope)
    {
        Assert.Equal(inScope, TargetNetworks.Find(IPAddress.Parse(ip)) is not null);
    }

    [Fact]
    public void Each_subnet_has_254_host_addresses_and_excludes_network_and_broadcast()
    {
        foreach (TargetSubnet s in TargetNetworks.All)
        {
            var hosts = s.HostAddresses().ToList();
            Assert.Equal(254, hosts.Count);
            Assert.DoesNotContain(hosts, h => h.GetAddressBytes()[3] is 0 or 255);
        }
    }

    [Fact]
    public void Temporary_host_numbers_are_inside_the_host_range()
    {
        Assert.All(TargetNetworks.TemporaryHostOctets, o => Assert.InRange((int)o, 1, 254));
    }
}
