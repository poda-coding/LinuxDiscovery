using System.Globalization;

namespace LinuxDiscovery;

internal enum RetryChoice { Retry, ChooseAnother, Quit }

/// <summary>All console input/output. No networking logic lives here.</summary>
internal sealed class ConsoleUi
{
    private readonly object _gate = new();
    private bool _progressLineActive;
    private int _progressWidth;

    // ---------- basic output ----------

    public void Title()
    {
        Info("");
        Info("==========================================");
        Info("   Linux Device Network Discovery");
        Info("==========================================");
        Info("");
    }

    public void Info(string message)
    {
        lock (_gate)
        {
            EndProgressLine();
            Console.WriteLine(message);
        }
    }

    public void Warn(string message) => Colored(ConsoleColor.Yellow, "WARNING: " + message);

    public void Error(string message) => Colored(ConsoleColor.Red, "ERROR: " + message);

    public void Good(string message) => Colored(ConsoleColor.Green, message);

    private void Colored(ConsoleColor color, string message)
    {
        lock (_gate)
        {
            EndProgressLine();
            ConsoleColor previous = Console.ForegroundColor;
            Console.ForegroundColor = color;
            Console.WriteLine(message);
            Console.ForegroundColor = previous;
        }
    }

    public void ShowProgress(ScanProgress p)
    {
        lock (_gate)
        {
            // Redraw on every 4th probe and at the end, to keep the console responsive.
            if (p.Done % 4 != 0 && p.Done != p.Total) return;

            int percent = p.Total == 0 ? 100 : p.Done * 100 / p.Total;
            int filled = percent / 5;
            string text = $"  {p.Phase,-12} [{new string('#', filled)}{new string('-', 20 - filled)}] {percent,3}%  ({p.Done}/{p.Total})  responders: {p.Responders}";
            Console.Write("\r" + text.PadRight(_progressWidth));
            _progressWidth = text.Length;
            _progressLineActive = true;
        }
    }

    private void EndProgressLine()
    {
        if (!_progressLineActive) return;
        Console.WriteLine();
        _progressLineActive = false;
    }

    // ---------- input ----------

    public bool AskYesNo(string question)
    {
        while (true)
        {
            Console.Write($"{question} [y/N]: ");
            string? line = Console.ReadLine();
            if (line is null) return false; // input closed: treat as "no"
            string answer = line.Trim().ToLowerInvariant();
            if (answer is "y" or "yes") return true;
            if (answer is "" or "n" or "no") return false;
            Warn("Please answer y or n.");
        }
    }

    public AdapterInfo? SelectAdapter(IReadOnlyList<AdapterInfo> eligible)
    {
        while (true)
        {
            Console.Write($"Select an interface to scan [1-{eligible.Count}]: ");
            string? line = Console.ReadLine();
            if (line is null) return null;

            if (int.TryParse(line.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out int n)
                && n >= 1 && n <= eligible.Count)
            {
                return eligible[n - 1];
            }

            Warn($"Invalid selection '{line.Trim()}'. Enter a number from 1 to {eligible.Count}.");
        }
    }

    public Candidate? ChooseCandidate(IReadOnlyList<Candidate> candidates)
    {
        Info("");
        Info($"{candidates.Count} possible devices were found:");
        Info("");
        for (int i = 0; i < candidates.Count; i++)
        {
            Candidate c = candidates[i];
            Info($"[{i + 1}] {c.Host.Address}");
            Info($"    MAC: {FormatMac(c.Host)}   Subnet: {c.Host.Subnet}");
            Info($"    SSH banner: {c.Host.Ssh.Banner?.Raw}");
            Info($"    Assessment: {c.Summary}");
        }
        Info("");

        while (true)
        {
            Console.Write($"Which one is your device? [1-{candidates.Count}]: ");
            string? line = Console.ReadLine();
            if (line is null) return null;

            if (int.TryParse(line.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out int n)
                && n >= 1 && n <= candidates.Count)
            {
                return candidates[n - 1];
            }

            Warn("Invalid selection.");
        }
    }

    public RetryChoice AskRetryChoice()
    {
        while (true)
        {
            Console.Write("[R] Retry the same interface   [C] Choose another interface   [Q] Quit : ");
            string? line = Console.ReadLine();
            if (line is null) return RetryChoice.Quit;

            switch (line.Trim().ToLowerInvariant())
            {
                case "r": return RetryChoice.Retry;
                case "c": return RetryChoice.ChooseAnother;
                case "q": case "": return RetryChoice.Quit;
                default: Warn("Please enter R, C or Q."); break;
            }
        }
    }

    public void WaitForEnter()
    {
        Info("");
        Console.Write("Press Enter to exit...");
        try { Console.ReadLine(); }
        catch (IOException) { /* no console input available */ }
    }

    // ---------- screens ----------

    public void ShowAdapters(IReadOnlyList<AdapterInfo> all)
    {
        List<AdapterInfo> eligible = all.Where(a => a.IsEligible).ToList();

        Info("Available network interfaces:");
        Info("");

        if (eligible.Count == 0) Info("    (none)");

        for (int i = 0; i < eligible.Count; i++)
        {
            AdapterInfo a = eligible[i];
            Info($"[{i + 1}] {a.Name}  (ifIndex {a.Index})");
            Info($"    Description: {a.Description}");
            Info($"    Type: {a.Type}   Status: {a.Status}");
            Info($"    IPv4: {a.Ipv4Text}{(a.IsDhcp ? "  (DHCP)" : "")}");
            Info($"    Gateway: {(a.Gateway?.ToString() ?? "Not configured")}");
            Info("");
        }

        List<AdapterInfo> unavailable = all.Where(a => !a.IsEligible).ToList();
        if (unavailable.Count > 0)
        {
            Info("Unavailable interfaces:");
            foreach (AdapterInfo a in unavailable)
                Info($"    {a.Name}: {a.IneligibleReason}");
            Info("");
        }
    }

    public void ShowPlans(IReadOnlyList<SubnetPlan> plans)
    {
        Info("Reachability of the target subnets from this interface:");
        foreach (SubnetPlan p in plans)
        {
            switch (p.Access)
            {
                case SubnetAccess.OnLink:
                    Info($"    {p.Subnet}: already on-link via {p.ExistingSource} (no change needed)");
                    break;
                case SubnetAccess.NeedsTemporaryAddress:
                    Info($"    {p.Subnet}: not on-link, a temporary address is needed");
                    break;
                default:
                    Info($"    {p.Subnet}: SKIPPED. {p.Reason}");
                    break;
            }
            foreach (string w in p.Warnings) Warn(w);
        }
        Info("");
    }

    public void ExplainChanges(AdapterInfo adapter, IReadOnlyList<SubnetPlan> needTemporary)
    {
        Info("The following temporary configuration changes are planned:");
        Info("");
        foreach (SubnetPlan p in needTemporary)
        {
            Info($"  + Add a secondary IPv4 address (one of {p.Subnet.Host(TargetNetworks.TemporaryHostOctets[0])} .. " +
                 $"{p.Subnet.Host(TargetNetworks.TemporaryHostOctets[^1])}, /{TargetSubnet.PrefixLength}) to '{adapter.Name}'");
        }
        Info("");
        Info("  - The address is temporary (not saved in the persistent configuration) and is removed when");
        Info("    the scan ends, fails, or is cancelled with Ctrl+C.");
        Info("  - Your existing IP address, gateway, DNS and DHCP settings are NOT modified.");
        Info("  - No other network interface is touched.");
        Info("  - Note: changing an IP address cannot create connectivity. The device must be physically");
        Info("    (or through a switch) connected to this adapter's network.");
        Info("");

        List<SubnetPlan> shared = needTemporary.Where(p => p.ConflictingAdapters.Count > 0).ToList();
        if (shared.Count > 0)
        {
            Warn("Another connected adapter is already in a subnet you are about to scan:");
            foreach (SubnetPlan p in shared)
                Info($"    {p.Subnet}: also on {string.Join(", ", p.ConflictingAdapters)}");
            Info("  While the temporary address exists (only during the scan), Windows may send other applications'");
            Info($"  traffic for that subnet out of '{adapter.Name}' instead. That can briefly interrupt connections that");
            Info("  use that subnet on the other adapter. Scan traffic itself stays on the selected adapter, and ping is");
            Info("  not used for these subnets because it cannot be pinned to an adapter.");
            Info("");
        }
    }

    public void ShowCleanup(CleanupReport report, AdapterInfo adapter)
    {
        if (report.Total == 0) return;

        if (report.Succeeded)
        {
            Good($"Cleanup succeeded: {report.Removed} temporary address(es) removed" +
                 (report.AlreadyGone > 0 ? $", {report.AlreadyGone} already gone." : "."));
            return;
        }

        Error($"Cleanup FAILED for {report.Failures.Count} address(es). Your configuration was not fully restored.");
        foreach (CleanupFailure f in report.Failures)
        {
            Info($"    {f.Entry.Address}/{f.Entry.PrefixLength} on '{f.Entry.InterfaceName}': {f.Reason}");
        }
        Info("");
        Info("Manual recovery (run in an elevated PowerShell), or simply restart Windows,");
        Info("or disable and re-enable the adapter:");
        foreach (CleanupFailure f in report.Failures)
        {
            Info($"    Remove-NetIPAddress -InterfaceIndex {f.Entry.InterfaceIndex} -IPAddress {f.Entry.Address} -Confirm:$false");
        }
        Info("This tool will also offer to remove leftovers the next time it starts.");
    }

    public void ShowSuccess(AdapterInfo adapter, Candidate c, IReadOnlyList<HostEvidence> others, int sshPort)
    {
        Info("");
        Info("==========================================");
        Info("   Linux Device Network Discovery");
        Info("==========================================");
        Info("");
        Info($"Selected interface: {adapter.Name}");
        Info($"Target IP address: {c.Host.Address}");
        Info($"MAC address: {FormatMac(c.Host)}");
        Info($"SSH port: {sshPort}");
        Info($"SSH status: {c.Host.Ssh.State}");
        Info($"SSH banner: {c.Host.Ssh.Banner?.Raw}");
        Info($"Assessment: {c.Summary}");
        Info("Evidence:");
        foreach (string r in c.Reasons) Info($"    - {r}");

        if (others.Count > 0)
        {
            Info("");
            Info("Other devices that answered ARP (not SSH candidates):");
            foreach (HostEvidence h in others) Info($"    {h.Address}  {FormatMac(h)}  {DescribeSsh(h)}");
        }

        Info("");
        Good("Discovery completed successfully.");
    }

    public void ShowNoCandidate(AdapterInfo adapter, ScanResult scan, int sshPort)
    {
        Info("");
        Info("==========================================");
        Info("   Linux Device Network Discovery");
        Info("==========================================");
        Info("");
        Info($"Selected interface: {adapter.Name}");
        Error("No SSH-capable device was found.");
        Info("");
        Info($"Probed {scan.ProbedAddresses} addresses: {scan.Responders.Count} answered ARP, {scan.NoReply} did not.");

        if (scan.ArpErrors > 0)
        {
            Warn($"{scan.ArpErrors} ARP probes failed with unexpected errors (first Win32 error code: {scan.FirstArpErrorCode}). " +
                 "Results may be incomplete.");
        }

        if (scan.Responders.Count > 0)
        {
            Info("");
            Info("Devices that answered ARP:");
            foreach (HostEvidence h in scan.Responders)
                Info($"    {h.Address}  {FormatMac(h)}  {DescribeSsh(h)}");
        }

        Info("");
        Info("Possible causes:");
        Info("    - The device is not connected to the network of the selected interface (try another interface).");
        Info("    - The device is powered off or still booting.");
        Info($"    - SSH is not enabled, or it listens on a port other than {sshPort}.");
        Info($"    - The device is in a different subnet than {string.Join(", ", TargetNetworks.All.Select(s => s.Cidr))}.");
        Info("    - A firewall or switch feature (port isolation, client isolation on Wi-Fi) blocks local traffic.");
        Info("    - Another adapter in the same subnet caused the subnet to be skipped.");
    }

    /// <summary>Printed with --verbose: everything the scan saw, to show where a failure happened.</summary>
    public void ShowDiagnostics(ScanResult scan, IReadOnlyList<ScanTarget> targets)
    {
        Info("");
        Info("---- Diagnostics ----");
        foreach (ScanTarget t in targets)
            Info($"Source address for {t.Subnet}: {t.SourceAddress} (ICMP {(t.UseIcmp ? "used" : "skipped")})");
        Info($"ARP: {scan.ProbedAddresses} probed, {scan.Responders.Count} replied, {scan.NoReply} no reply, {scan.ArpErrors} errors");
        foreach (KeyValuePair<int, int> kv in scan.ArpErrorCounts.OrderByDescending(k => k.Value))
            Info($"    Win32 error {kv.Key} x{kv.Value}: {new System.ComponentModel.Win32Exception(kv.Key).Message}");
        foreach (HostEvidence h in scan.Responders)
        {
            Info($"  {h.Address}  MAC {FormatMac(h)}  {DescribeSsh(h)}");
            Info($"      ICMP: {(h.Icmp.Skipped ? "skipped" : h.Icmp.Replied ? $"reply, TTL {h.Icmp.Ttl}" : "no reply")}");
        }
        Info("---------------------");
    }

    // ---------- formatting ----------

    private static string FormatMac(HostEvidence h) =>
        h.Mac is null ? "unknown" : string.Join("-", h.Mac.GetAddressBytes().Select(b => b.ToString("X2", CultureInfo.InvariantCulture)));

    private static string DescribeSsh(HostEvidence h) => h.Ssh.State switch
    {
        PortState.Open when h.Ssh.Banner is not null => $"SSH open: {h.Ssh.Banner.Raw}",
        PortState.Open => $"port open, no SSH banner ({h.Ssh.Detail})",
        PortState.Closed => "SSH port closed",
        PortState.Filtered => "SSH port filtered",
        _ => $"SSH inconclusive ({h.Ssh.Detail})"
    };
}
