using System.Security.Principal;

namespace LinuxDiscovery;

internal static class Elevation
{
    /// <summary>True when the process token is a member of the local Administrators group (elevated).</summary>
    public static bool IsElevated()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
