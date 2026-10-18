using System.Net;

namespace LinuxDiscovery.Tests;

public class ConfigurationSessionTests : IDisposable
{
    private readonly string _journalPath = TestData.TempJournalPath();
    private readonly FakeConfigurator _cfg = new();
    private readonly ChangeJournal _journal;
    private readonly List<string> _log = new();
    private readonly AdapterInfo _adapter = TestData.Adapter("Ethernet", 7, new[] { "192.168.10.25/24" });

    public ConfigurationSessionTests() => _journal = new ChangeJournal(_journalPath);

    public void Dispose()
    {
        if (File.Exists(_journalPath)) File.Delete(_journalPath);
    }

    private ConfigurationSession NewSession() => new(_cfg, _journal, _log.Add);

    [Fact]
    public async Task Adds_a_temporary_address_and_cleanup_removes_it()
    {
        using var session = NewSession();

        IPAddress ip = await session.AddTemporaryAddressAsync(_adapter, TargetNetworks.Subnet1, CancellationToken.None);

        Assert.Equal("192.168.1.231", ip.ToString());
        Assert.Contains("192.168.1.231", _cfg.Present);
        Assert.Single(_journal.Load()); // recorded for crash recovery

        CleanupReport report = session.Cleanup();

        Assert.True(report.Succeeded);
        Assert.Equal(1, report.Removed);
        Assert.Empty(_cfg.Present);
        Assert.Empty(_journal.Load());
    }

    [Fact]
    public async Task Cleanup_is_idempotent()
    {
        using var session = NewSession();
        await session.AddTemporaryAddressAsync(_adapter, TargetNetworks.Subnet0, CancellationToken.None);

        session.Cleanup();
        CleanupReport second = session.Cleanup();

        Assert.Equal(0, second.Total);
    }

    [Fact]
    public async Task Address_conflict_moves_on_to_the_next_candidate_and_removes_the_conflicting_one()
    {
        _cfg.DuplicateOnDad.Add("192.168.1.231");
        using var session = NewSession();

        IPAddress ip = await session.AddTemporaryAddressAsync(_adapter, TargetNetworks.Subnet1, CancellationToken.None);

        Assert.Equal("192.168.1.232", ip.ToString());
        Assert.DoesNotContain("192.168.1.231", _cfg.Present);
    }

    [Fact]
    public async Task Preexisting_address_is_never_removed()
    {
        _cfg.PreExisting.Add("192.168.1.231");
        using var session = NewSession();

        IPAddress ip = await session.AddTemporaryAddressAsync(_adapter, TargetNetworks.Subnet1, CancellationToken.None);
        session.Cleanup();

        Assert.Equal("192.168.1.232", ip.ToString());
        Assert.DoesNotContain("192.168.1.231", _cfg.RemoveCalls);
    }

    [Fact]
    public async Task Failed_removal_is_reported_and_stays_in_the_journal()
    {
        using var session = NewSession();
        await session.AddTemporaryAddressAsync(_adapter, TargetNetworks.Subnet1, CancellationToken.None);
        _cfg.FailRemove.Add("192.168.1.231");

        CleanupReport report = session.Cleanup();

        Assert.False(report.Succeeded);
        Assert.Single(report.Failures);
        Assert.Single(_journal.Load());

        // A later attempt (for example after the problem is fixed) can still succeed.
        _cfg.FailRemove.Clear();
        Assert.True(session.Cleanup().Succeeded);
        Assert.Empty(_journal.Load());
    }

    [Fact]
    public async Task Cancellation_still_allows_cleanup()
    {
        using var session = NewSession();
        using var cts = new CancellationTokenSource();

        await session.AddTemporaryAddressAsync(_adapter, TargetNetworks.Subnet0, CancellationToken.None);
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => session.AddTemporaryAddressAsync(_adapter, TargetNetworks.Subnet1, cts.Token));

        Assert.True(session.Cleanup().Succeeded);
        Assert.Empty(_cfg.Present);
    }

    [Fact]
    public void Journal_ignores_entries_outside_the_target_subnets()
    {
        File.WriteAllText(_journalPath,
            """[{"InterfaceIndex":7,"InterfaceId":"x","InterfaceName":"Ethernet","Address":"10.0.0.5","PrefixLength":24,"CreatedUtc":"2026-01-01T00:00:00Z"}]""");

        Assert.Empty(_journal.Load());
    }
}
