using System.Net;

namespace LinuxDiscovery;

internal enum AddStatus { Success, AlreadyExists, AccessDenied, Failed }

internal sealed record AddResult(AddStatus Status, int Win32Error = 0, string? Message = null);

internal enum RemoveStatus { Removed, AlreadyGone, Failed }

internal sealed record RemoveResult(RemoveStatus Status, int Win32Error = 0, string? Message = null);

/// <summary>Outcome of Windows duplicate address detection for a freshly added address.</summary>
internal enum DadOutcome { Usable, Duplicate, TimedOut }

internal sealed class ConfigurationException : Exception
{
    public ConfigurationException(string message) : base(message) { }
    public ConfigurationException(string message, Exception inner) : base(message, inner) { }
}

/// <summary>
/// The only component that modifies Windows network configuration. Keeping it behind an interface
/// lets the rest of the app (session, journal, planner) be tested without touching a real adapter.
/// </summary>
internal interface IAddressConfigurator
{
    /// <summary>Adds a non-persistent secondary IPv4 address. Never replaces existing addresses.</summary>
    AddResult Create(int interfaceIndex, IPAddress address, int prefixLength);

    /// <summary>Waits until Windows duplicate address detection has finished for the address.</summary>
    Task<DadOutcome> WaitUntilUsableAsync(int interfaceIndex, IPAddress address, int prefixLength,
        TimeSpan timeout, CancellationToken cancellationToken);

    /// <summary>Removes exactly the given address. A missing address counts as already gone.</summary>
    RemoveResult Remove(int interfaceIndex, IPAddress address, int prefixLength);
}
