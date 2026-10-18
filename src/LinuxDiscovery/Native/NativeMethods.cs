using System.Runtime.InteropServices;

namespace LinuxDiscovery;

/// <summary>IPv4 view of the Win32 SOCKADDR_INET union (28 bytes in total).</summary>
[StructLayout(LayoutKind.Explicit, Size = 28)]
internal struct SockAddrInet
{
    [FieldOffset(0)] public ushort Family;   // AF_INET = 2
    [FieldOffset(2)] public ushort Port;
    [FieldOffset(4)] public uint Ipv4;       // in_addr: the 4 address bytes in memory order
}

/// <summary>Mirror of MIB_UNICASTIPADDRESS_ROW (80 bytes on x64/ARM64).</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct MibUnicastIpAddressRow
{
    public SockAddrInet Address;       // offset 0
    public ulong InterfaceLuid;        // offset 32 (8-byte aligned)
    public uint InterfaceIndex;
    public int PrefixOrigin;           // NL_PREFIX_ORIGIN
    public int SuffixOrigin;           // NL_SUFFIX_ORIGIN
    public uint ValidLifetime;
    public uint PreferredLifetime;
    public byte OnLinkPrefixLength;
    public byte SkipAsSource;          // BOOLEAN
    public int DadState;               // NL_DAD_STATE
    public uint ScopeId;
    public long CreationTimeStamp;
}

internal static class NativeMethods
{
    // Win32 error codes returned by IP Helper.
    public const uint ErrorAccessDenied = 5;
    public const uint ErrorBadNetName = 67;     // SendARP: no ARP reply
    public const uint ErrorNotFound = 1168;
    public const uint ErrorObjectAlreadyExists = 5010;

    // NL_DAD_STATE values.
    public const int DadTentative = 1;
    public const int DadDuplicate = 2;
    public const int DadPreferred = 4;

    // https://learn.microsoft.com/windows/win32/api/iphlpapi/nf-iphlpapi-sendarp
    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    public static extern uint SendARP(uint destIp, uint srcIp, byte[] macAddr, ref uint phyAddrLen);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    public static extern void InitializeUnicastIpAddressEntry(out MibUnicastIpAddressRow row);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    public static extern uint CreateUnicastIpAddressEntry(ref MibUnicastIpAddressRow row);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    public static extern uint GetUnicastIpAddressEntry(ref MibUnicastIpAddressRow row);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    public static extern uint DeleteUnicastIpAddressEntry(ref MibUnicastIpAddressRow row);

    public delegate bool ConsoleCtrlDelegate(uint ctrlType);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetConsoleCtrlHandler(ConsoleCtrlDelegate handler, [MarshalAs(UnmanagedType.Bool)] bool add);
}
