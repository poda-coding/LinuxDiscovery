using System.Net;

namespace LinuxDiscovery;

internal sealed record CleanupFailure(JournalEntry Entry, string Reason);

internal sealed record CleanupReport(int Removed, int AlreadyGone, IReadOnlyList<CleanupFailure> Failures)
{
    public bool Succeeded => Failures.Count == 0;
    public int Total => Removed + AlreadyGone + Failures.Count;
}

/// <summary>
/// Owns every temporary configuration change made during one scan. Cleanup is idempotent, thread-safe
/// (it may run from the main thread, a Ctrl+C path, the console-close handler or ProcessExit) and only ever
/// removes addresses this session created. Addresses that already existed are never touched.
/// </summary>
internal sealed class ConfigurationSession : IDisposable
{
    private static readonly TimeSpan DadTimeout = TimeSpan.FromSeconds(6);

    private readonly IAddressConfigurator _configurator;
    private readonly ChangeJournal _journal;
    private readonly Action<string> _log;
    private readonly List<JournalEntry> _created = new();
    private readonly object _gate = new();
    private bool _closed;

    public ConfigurationSession(IAddressConfigurator configurator, ChangeJournal journal, Action<string> log)
    {
        _configurator = configurator;
        _journal = journal;
        _log = log;
        // Last-resort safety net for normal process exit paths.
        AppDomain.CurrentDomain.ProcessExit += OnProcessExit;
    }

    public IReadOnlyList<JournalEntry> CreatedAddresses
    {
        get { lock (_gate) return _created.ToArray(); }
    }

    /// <summary>
    /// Adds one temporary /24 address in <paramref name="subnet"/> to the adapter and returns it once Windows
    /// duplicate address detection has confirmed it is free. Tries several candidate host numbers.
    /// </summary>
    public async Task<IPAddress> AddTemporaryAddressAsync(AdapterInfo adapter, TargetSubnet subnet, CancellationToken ct)
    {
        string? lastProblem = null;

        foreach (byte octet in TargetNetworks.TemporaryHostOctets)
        {
            ct.ThrowIfCancellationRequested();

            IPAddress candidate = subnet.Host(octet);
            if (adapter.Addresses.Any(a => a.Address.Equals(candidate))) continue;

            var entry = new JournalEntry(adapter.Index, adapter.Id, adapter.Name, candidate.ToString(),
                TargetSubnet.PrefixLength, DateTime.UtcNow);

            // Record the intent first: if the process dies right after the change, the next run knows.
            try
            {
                lock (_gate)
                {
                    if (_closed) throw new OperationCanceledException("Session already closed.");
                    _journal.Add(entry);
                }
            }
            catch (IOException ex)
            {
                throw new ConfigurationException($"Cannot write the recovery journal ({_journal.FilePath}): {ex.Message}", ex);
            }
            catch (UnauthorizedAccessException ex)
            {
                throw new ConfigurationException($"Cannot write the recovery journal ({_journal.FilePath}): {ex.Message}", ex);
            }

            AddResult result;
            try
            {
                result = _configurator.Create(adapter.Index, candidate, TargetSubnet.PrefixLength);
            }
            catch
            {
                TryUnjournal(entry);
                throw;
            }

            if (result.Status == AddStatus.AlreadyExists)
            {
                // Not ours: leave the pre-existing address alone and try another candidate.
                TryUnjournal(entry);
                lastProblem = $"{candidate} already exists on the adapter";
                continue;
            }

            if (result.Status != AddStatus.Success)
            {
                TryUnjournal(entry);
                throw new ConfigurationException(
                    $"Could not add temporary address {candidate}/{TargetSubnet.PrefixLength} to '{adapter.Name}': " +
                    $"{result.Message} (Win32 error {result.Win32Error}).");
            }

            // From here on the address exists and is ours: register it before anything else can fail.
            lock (_gate)
            {
                if (_closed)
                {
                    RemoveOne(entry); // cleanup already ran on another thread; undo immediately
                    throw new OperationCanceledException("Session closed while adding an address.");
                }
                _created.Add(entry);
            }

            DadOutcome outcome = await _configurator
                .WaitUntilUsableAsync(adapter.Index, candidate, TargetSubnet.PrefixLength, DadTimeout, ct)
                .ConfigureAwait(false);

            switch (outcome)
            {
                case DadOutcome.Usable:
                    return candidate;

                case DadOutcome.Duplicate:
                    _log($"Address conflict: another device already uses {candidate}. Trying the next candidate...");
                    lastProblem = $"{candidate} is in use by another device";
                    RemoveCreated(entry);
                    continue;

                default:
                    RemoveCreated(entry);
                    throw new ConfigurationException(
                        $"Temporary address {candidate} did not become usable within {DadTimeout.TotalSeconds:0} s. " +
                        "The adapter may be disconnected or the driver may not support secondary addresses.");
            }
        }

        throw new ConfigurationException(
            $"No free temporary address was found in {subnet}" + (lastProblem is null ? "." : $" (last problem: {lastProblem})."));
    }

    /// <summary>Removes every address this session created. Safe to call repeatedly and from any thread.</summary>
    public CleanupReport Cleanup()
    {
        lock (_gate)
        {
            _closed = true;

            int removed = 0, gone = 0;
            var failures = new List<CleanupFailure>();

            foreach (JournalEntry entry in _created.ToArray())
            {
                RemoveResult result = TryRemove(entry);

                switch (result.Status)
                {
                    case RemoveStatus.Removed:
                        removed++;
                        Forget(entry);
                        break;
                    case RemoveStatus.AlreadyGone:
                        gone++;
                        Forget(entry);
                        break;
                    default:
                        // Keep it registered (and journaled) so a later Cleanup() or the next run can retry.
                        failures.Add(new CleanupFailure(entry,
                            $"{result.Message ?? "unknown error"} (Win32 error {result.Win32Error})"));
                        break;
                }
            }

            return new CleanupReport(removed, gone, failures);
        }
    }

    public void Dispose()
    {
        AppDomain.CurrentDomain.ProcessExit -= OnProcessExit;
        Cleanup();
    }

    private void OnProcessExit(object? sender, EventArgs e) => Cleanup();

    // Caller must not hold _gate when calling this from the add path; it takes the lock itself.
    private void RemoveCreated(JournalEntry entry)
    {
        lock (_gate)
        {
            RemoveResult result = TryRemove(entry);
            if (result.Status != RemoveStatus.Failed) Forget(entry);
            else _log($"Warning: could not remove {entry.Address} yet ({result.Message}); it will be retried at cleanup.");
        }
    }

    // Caller must hold _gate.
    private void RemoveOne(JournalEntry entry)
    {
        RemoveResult result = TryRemove(entry);
        if (result.Status != RemoveStatus.Failed)
        {
            TryUnjournal(entry);
        }
    }

    private RemoveResult TryRemove(JournalEntry entry)
    {
        try
        {
            return _configurator.Remove(entry.InterfaceIndex, IPAddress.Parse(entry.Address), entry.PrefixLength);
        }
        catch (Exception ex)
        {
            return new RemoveResult(RemoveStatus.Failed, 0, ex.Message);
        }
    }

    // Caller must hold _gate.
    private void Forget(JournalEntry entry)
    {
        _created.RemoveAll(e => e.InterfaceIndex == entry.InterfaceIndex && e.Address == entry.Address);
        TryUnjournal(entry);
    }

    private void TryUnjournal(JournalEntry entry)
    {
        try
        {
            _journal.Remove(entry);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _log($"Warning: could not update the recovery journal: {ex.Message}");
        }
    }
}
