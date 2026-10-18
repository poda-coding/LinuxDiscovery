using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace LinuxDiscovery;

/// <summary>
/// Enumerates adapters through the managed NetworkInterface API (a thin wrapper over IP Helper),
/// so no localized command output is ever parsed.
/// </summary>
internal static class AdapterEnumerator
{
    // Heuristic only; --include-virtual overrides it.
    private static readonly string[] VirtualMarkers =
    {
        "Hyper-V", "vEthernet", "VMware", "VirtualBox", "Virtual Adapter", "WSL", "TAP-Windows"
    };

    public static IReadOnlyList<AdapterInfo> Enumerate(bool includeVirtual)
    {
        var result = new List<AdapterInfo>();

        foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            int index = 0;
            bool dhcp = false;
            string? reason = null;
            IPAddress? gateway = null;
            var addresses = new List<Ipv4Binding>();

            try
            {
                IPInterfaceProperties props = nic.GetIPProperties();

                foreach (UnicastIPAddressInformation ua in props.UnicastAddresses)
                {
                    if (ua.Address.AddressFamily == AddressFamily.InterNetwork)
                        addresses.Add(new Ipv4Binding(ua.Address, ua.PrefixLength));
                }

                gateway = props.GatewayAddresses
                    .Select(g => g.Address)
                    .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any));

                // Throws NetworkInformationException when IPv4 is not enabled on the adapter.
                IPv4InterfaceProperties v4 = props.GetIPv4Properties();
                index = v4.Index;
                dhcp = v4.IsDhcpEnabled;
            }
            catch (NetworkInformationException)
            {
                reason = "IPv4 is not enabled on this adapter";
            }

            bool isVirtual = LooksVirtual(nic);

            reason ??= nic.NetworkInterfaceType switch
            {
                NetworkInterfaceType.Loopback => "Loopback interface",
                NetworkInterfaceType.Tunnel => "Tunnel adapter",
                _ => null
            };

            if (reason is null && nic.OperationalStatus != OperationalStatus.Up)
                reason = $"Not connected (status: {nic.OperationalStatus})";

            if (reason is null && isVirtual && !includeVirtual)
                reason = "Virtual adapter (use --include-virtual to allow)";

            result.Add(new AdapterInfo(
                index, nic.Id, nic.Name, nic.Description, nic.NetworkInterfaceType, nic.OperationalStatus,
                addresses, gateway, dhcp, reason, isVirtual));
        }

        return result;
    }

    private static bool LooksVirtual(NetworkInterface nic) =>
        VirtualMarkers.Any(m =>
            nic.Description.Contains(m, StringComparison.OrdinalIgnoreCase) ||
            nic.Name.Contains(m, StringComparison.OrdinalIgnoreCase));
}
