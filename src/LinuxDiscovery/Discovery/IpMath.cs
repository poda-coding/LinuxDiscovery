using System.Buffers.Binary;
using System.Net;

namespace LinuxDiscovery;

internal static class IpMath
{
    /// <summary>The 4 address bytes in memory order, as Win32 IPAddr/in_addr expects (network byte order).</summary>
    public static uint ToNative(IPAddress address) => BitConverter.ToUInt32(address.GetAddressBytes(), 0);

    /// <summary>Numeric value with a.b.c.d == (a&lt;&lt;24)|(b&lt;&lt;16)|(c&lt;&lt;8)|d. Useful for masks and sorting.</summary>
    public static uint ToHostOrder(IPAddress address) => BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes());

    public static uint Mask(int prefixLength) =>
        prefixLength <= 0 ? 0u : prefixLength >= 32 ? uint.MaxValue : uint.MaxValue << (32 - prefixLength);

    public static bool InSameNetwork(IPAddress a, IPAddress b, int prefixLength)
    {
        uint mask = Mask(prefixLength);
        return (ToHostOrder(a) & mask) == (ToHostOrder(b) & mask);
    }
}
