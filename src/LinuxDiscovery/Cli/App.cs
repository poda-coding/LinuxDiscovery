using System.Net;
using System.Net.NetworkInformation;

namespace LinuxDiscovery;

/// <summary>Orchestrates the workflow. Delegates every real job to a dedicated component.</summary>
internal sealed class App
{
    private const int SshPort = 22;

    private readonly ConsoleUi _ui;
    private readonly IAddressConfigurator _configurator;
    private readonly ChangeJournal _journal;
    private readonly IArpProber _arp;
    private readonly ITcpSshProber _ssh;
    private readonly IIcmpProber _icmp;

    public App(ConsoleUi ui, IAddressConfigurator configurator, ChangeJournal journal,
        IArpProber arp, ITcpSshProber ssh, IIcmpProber icmp)
    {
        _ui = ui;
        _configurator = configurator;
        _journal = journal;
        _arp = arp;
        _ssh = ssh;
        _icmp = icmp;
    }

    public async Task<int> RunAsync(Options options, CancellationToken ct)
    {
        try
        {
            return await RunCoreAsync(options, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Ctrl+C, or console input was closed while a prompt was waiting.
            _ui.Warn("Cancelled.");
            return ExitCodes.Cancelled;
        }
    }

    private async Task<int> RunCoreAsync(Options options, CancellationToken ct)
    {
        _ui.Title();

        // ---- Step 1: privileges ----
        if (!Elevation.IsElevated())
        {
            _ui.Error("This tool must run as administrator because it temporarily adds IP addresses to a network adapter.");
            _ui.Info("Right-click the executable and choose 'Run as administrator', or start it from an elevated terminal.");
            return ExitCodes.NotElevated;
        }

        // Leftovers from a previous run that was killed (journal-based recovery).
        if (!JournalRecovery.Run(_journal, _configurator, _ui, options.AssumeYes))
        {
            _ui.Warn("Leftover temporary addresses are still present. Continuing anyway.");
        }

        AdapterInfo? retrySame = null;
        int? requestedIndex = options.InterfaceIndex;

        while (true)
        {
            ct.ThrowIfCancellationRequested();

            IReadOnlyList<AdapterInfo> adapters = AdapterEnumerator.Enumerate(options.IncludeVirtual);
            List<AdapterInfo> eligible = adapters.Where(a => a.IsEligible).ToList();

            // ---- Step 2: choose the interface ----
            AdapterInfo selected;

            if (retrySame is not null)
            {
                AdapterInfo? refreshed = eligible.FirstOrDefault(a => a.Id == retrySame.Id);
                if (refreshed is null)
                {
                    _ui.Error($"Interface '{retrySame.Name}' is no longer available.");
                    return ExitCodes.NoEligibleInterface;
                }
                selected = refreshed;
                retrySame = null;
            }
            else
            {
                _ui.ShowAdapters(adapters);

                if (eligible.Count == 0)
                {
                    _ui.Error("No suitable network interface is available. Connect a cable or Wi-Fi network and try again.");
                    return ExitCodes.NoEligibleInterface;
                }

                if (requestedIndex is int idx)
                {
                    requestedIndex = null;
                    AdapterInfo? byIndex = eligible.FirstOrDefault(a => a.Index == idx);
                    if (byIndex is null)
                    {
                        _ui.Error($"Interface index {idx} is not in the list of available interfaces.");
                        return ExitCodes.NoEligibleInterface;
                    }
                    selected = byIndex;
                }
                else
                {
                    selected = _ui.SelectAdapter(eligible) ?? throw new OperationCanceledException(ct);
                }
            }

            int exitCode = await ScanOnceAsync(selected, adapters, options, ct).ConfigureAwait(false);

            if (exitCode != ExitCodes.NotFound || options.AssumeYes) return exitCode;

            switch (_ui.AskRetryChoice())
            {
                case RetryChoice.Retry:
                    retrySame = selected;
                    break;
                case RetryChoice.ChooseAnother:
                    break;
                default:
                    return ExitCodes.NotFound;
            }
        }
    }

    private async Task<int> ScanOnceAsync(AdapterInfo selected, IReadOnlyList<AdapterInfo> all, Options options, CancellationToken ct)
    {
        _ui.Info($"Selected interface: {selected.Name} (ifIndex {selected.Index}, IPv4: {selected.Ipv4Text})");
        _ui.Info("");

        // ---- Step 3: decide what, if anything, must be changed ----
        IReadOnlyList<SubnetPlan> plans = ReachabilityPlanner.Plan(selected, all);
        _ui.ShowPlans(plans);

        if (plans.All(p => p.Access == SubnetAccess.Blocked))
        {
            _ui.Error("Both target subnets were skipped (see the reasons above). Nothing can be scanned with this interface.");
            return ExitCodes.ConfigurationFailed;
        }

        List<SubnetPlan> needTemporary = plans.Where(p => p.Access == SubnetAccess.NeedsTemporaryAddress).ToList();

        if (needTemporary.Count > 0)
        {
            _ui.ExplainChanges(selected, needTemporary);
            if (!options.AssumeYes && !_ui.AskYesNo("Apply these temporary changes and start the scan?"))
            {
                _ui.Info("No changes were made.");
                return ExitCodes.Cancelled;
            }
        }

        using var session = new ConfigurationSession(_configurator, _journal, _ui.Info);
        // Also clean up if the console window is closed or Windows logs off / shuts down.
        using IDisposable terminateHook = ConsoleEvents.OnTerminate(() => session.Cleanup());

        var targets = new List<ScanTarget>();
        ScanResult? scan = null;
        string? configProblem = null;
        string? lostReason = null;
        bool cancelled = false;
        CleanupReport report;

        try
        {
            // ---- Step 3 (apply): add temporary addresses where needed ----
            foreach (SubnetPlan plan in plans)
            {
                if (plan.Access == SubnetAccess.OnLink)
                {
                    targets.Add(new ScanTarget(plan.Subnet, plan.ExistingSource!, UseIcmp: plan.ConflictingAdapters.Count == 0));
                }
                else if (plan.Access == SubnetAccess.NeedsTemporaryAddress)
                {
                    try
                    {
                        IPAddress temp = await session.AddTemporaryAddressAsync(selected, plan.Subnet, ct).ConfigureAwait(false);
                        _ui.Info($"Added temporary address {temp}/{TargetSubnet.PrefixLength} for {plan.Subnet}.");
                        targets.Add(new ScanTarget(plan.Subnet, temp, UseIcmp: plan.ConflictingAdapters.Count == 0));
                    }
                    catch (ConfigurationException ex)
                    {
                        configProblem = ex.Message;
                        _ui.Error($"{plan.Subnet}: {ex.Message}");
                    }
                }
            }

            if (targets.Count == 0)
            {
                configProblem ??= "No target subnet could be prepared.";
            }
            else
            {
                // ---- Step 4: scan ----
                _ui.Info("");
                _ui.Info($"Scanning {string.Join(" and ", targets.Select(t => t.Subnet.ToString()))} through '{selected.Name}'...");

                var own = new HashSet<IPAddress>(selected.Addresses.Select(a => a.Address));
                foreach (ScanTarget t in targets) own.Add(t.SourceAddress);

                var coordinator = new ScanCoordinator(_arp, _ssh, _icmp, new ScanOptions(SshPort: SshPort));
                using var scanCts = CancellationTokenSource.CreateLinkedTokenSource(ct);

                // Detect lost connectivity (cable pulled, adapter disabled) while scanning.
                Task watchdog = WatchAdapterAsync(selected, reason =>
                {
                    lostReason = reason;
                    scanCts.Cancel();
                }, scanCts.Token);

                try
                {
                    scan = await coordinator.ScanAsync(targets, own, new InlineProgress<ScanProgress>(_ui.ShowProgress), scanCts.Token)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested && lostReason is not null)
                {
                    // Connectivity was lost; reported below after cleanup.
                }
                finally
                {
                    scanCts.Cancel(); // stops the watchdog
                    await watchdog.ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            cancelled = true;
        }
        finally
        {
            // ---- Step 7: cleanup. Runs on success, failure, cancellation and unexpected exceptions. ----
            _ui.Info("");
            _ui.Info("Cleaning up temporary network configuration...");
            report = session.Cleanup();
            _ui.ShowCleanup(report, selected);
        }

        // ---- Evaluate the outcome ----
        int result;

        if (cancelled)
        {
            _ui.Warn("Scan cancelled by the user.");
            result = ExitCodes.Cancelled;
        }
        else if (lostReason is not null)
        {
            _ui.Error($"Network connectivity was lost during the scan: {lostReason}");
            result = ExitCodes.ConnectivityLost;
        }
        else if (scan is null)
        {
            _ui.Error(configProblem ?? "The scan could not be started.");
            result = ExitCodes.ConfigurationFailed;
        }
        else
        {
            if (options.Verbose) _ui.ShowDiagnostics(scan, targets);
            result = ReportScanResult(selected, scan);
        }

        return report.Succeeded ? result : ExitCodes.CleanupFailed;
    }

    // ---- Steps 5 and 6: identify and display ----
    private int ReportScanResult(AdapterInfo selected, ScanResult scan)
    {
        IReadOnlyList<Candidate> candidates = CandidateClassifier.Classify(scan.Responders);

        if (candidates.Count == 0)
        {
            _ui.ShowNoCandidate(selected, scan, SshPort);
            return ExitCodes.NotFound;
        }

        Candidate? chosen = candidates.Count == 1 ? candidates[0] : _ui.ChooseCandidate(candidates);
        if (chosen is null) return ExitCodes.Cancelled;

        var others = scan.Responders.Where(h => !ReferenceEquals(h, chosen.Host)).ToList();
        _ui.ShowSuccess(selected, chosen, others, SshPort);
        return ExitCodes.Success;
    }

    private static async Task WatchAdapterAsync(AdapterInfo adapter, Action<string> onLost, CancellationToken stop)
    {
        try
        {
            while (!stop.IsCancellationRequested)
            {
                await Task.Delay(1000, stop).ConfigureAwait(false);

                NetworkInterface? nic = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.Id == adapter.Id);
                if (nic is null)
                {
                    onLost($"adapter '{adapter.Name}' disappeared");
                    return;
                }
                if (nic.OperationalStatus != OperationalStatus.Up)
                {
                    onLost($"adapter '{adapter.Name}' is now {nic.OperationalStatus}");
                    return;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown of the watchdog.
        }
    }
}
