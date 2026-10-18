namespace LinuxDiscovery;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        var ui = new ConsoleUi();
        int exitCode;

        try
        {
            exitCode = await RunAsync(args, ui).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            // Last-resort handler. ScanOnceAsync has already cleaned up temporary addresses by this point.
            ui.Error($"Unexpected error: {ex}");
            exitCode = ExitCodes.UnexpectedError;
        }

        // The window must stay open after success, failure and handled errors alike.
        ui.WaitForEnter();
        return exitCode;
    }

    private static async Task<int> RunAsync(string[] args, ConsoleUi ui)
    {
        Options options = Options.Parse(args);

        if (options.Error is not null)
        {
            ui.Error(options.Error);
            ui.Info(Options.Usage);
            return ExitCodes.UsageError;
        }

        if (options.ShowHelp)
        {
            ui.Info(Options.Usage);
            return ExitCodes.Success;
        }

        // Only one instance at a time: two instances would fight over the recovery journal.
        // A semaphore (not a mutex) is used because async code may continue on a different thread.
        using var gate = new Semaphore(1, 1, @"Global\LinuxDiscovery.SingleInstance");
        if (!gate.WaitOne(0))
        {
            ui.Error("Another instance of this tool is already running.");
            return ExitCodes.AlreadyRunning;
        }

        try
        {
            using var cts = new CancellationTokenSource();
            ConsoleCancelEventHandler onCancel = (_, e) =>
            {
                e.Cancel = true; // keep the process alive so cleanup can run
                cts.Cancel();
            };
            Console.CancelKeyPress += onCancel;

            try
            {
                var app = new App(
                    ui,
                    new IpHelperAddressConfigurator(),
                    new ChangeJournal(),
                    new SendArpProber(),
                    new TcpSshProber(),
                    new PingIcmpProber());

                return await app.RunAsync(options, cts.Token).ConfigureAwait(false);
            }
            finally
            {
                Console.CancelKeyPress -= onCancel;
            }
        }
        finally
        {
            gate.Release();
        }
    }
}
