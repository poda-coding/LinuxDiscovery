namespace LinuxDiscovery;

/// <summary>Process exit codes. Documented in README.md.</summary>
internal static class ExitCodes
{
    public const int Success = 0;
    public const int NotFound = 1;
    public const int NotElevated = 2;
    public const int NoEligibleInterface = 3;
    public const int ConfigurationFailed = 4;
    public const int Cancelled = 5;
    public const int CleanupFailed = 6;
    public const int ConnectivityLost = 7;
    public const int AlreadyRunning = 8;
    public const int UnexpectedError = 10;
    public const int UsageError = 64;
}
