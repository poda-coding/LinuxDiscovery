namespace LinuxDiscovery;

/// <summary>
/// Runs a cleanup action when the console window is closed or the user logs off / shuts down.
/// Ctrl+C is handled separately through Console.CancelKeyPress. Windows gives the process only a few
/// seconds after these events, so the action must be quick (removing an IP address is).
/// </summary>
internal static class ConsoleEvents
{
    private const uint CtrlCloseEvent = 2;
    private const uint CtrlLogoffEvent = 5;
    private const uint CtrlShutdownEvent = 6;

    // Static field keeps the delegate alive for as long as it is registered with Windows.
    private static NativeMethods.ConsoleCtrlDelegate? _handler;
    private static volatile Action? _onTerminate;

    public static IDisposable OnTerminate(Action cleanup)
    {
        _onTerminate = cleanup;
        _handler ??= new NativeMethods.ConsoleCtrlDelegate(Handle);
        NativeMethods.SetConsoleCtrlHandler(_handler, true);
        return new Registration();
    }

    private static bool Handle(uint ctrlType)
    {
        if (ctrlType is CtrlCloseEvent or CtrlLogoffEvent or CtrlShutdownEvent)
        {
            try
            {
                _onTerminate?.Invoke();
            }
            catch
            {
                // Nothing useful can be reported here: the process is being terminated by Windows.
            }
        }

        return false; // let the default handler terminate the process
    }

    private sealed class Registration : IDisposable
    {
        public void Dispose()
        {
            if (_handler is not null) NativeMethods.SetConsoleCtrlHandler(_handler, false);
            _onTerminate = null;
        }
    }
}
