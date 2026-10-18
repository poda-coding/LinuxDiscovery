using System.Net;

namespace LinuxDiscovery;

/// <summary>
/// Handles leftovers from a previous run that was killed or crashed before it could clean up.
/// </summary>
internal static class JournalRecovery
{
    /// <returns>True when nothing is left over (or everything was removed).</returns>
    public static bool Run(ChangeJournal journal, IAddressConfigurator configurator, ConsoleUi ui, bool assumeYes)
    {
        IReadOnlyList<JournalEntry> pending = journal.Load();
        if (pending.Count == 0) return true;

        ui.Warn("A previous run did not finish its cleanup. These temporary addresses were recorded:");
        foreach (JournalEntry e in pending)
            ui.Info($"    {e.Address}/{e.PrefixLength} on '{e.InterfaceName}' (ifIndex {e.InterfaceIndex}, {e.CreatedUtc:u})");

        if (!assumeYes && !ui.AskYesNo("Remove them now?")) return false;

        bool allOk = true;
        foreach (JournalEntry e in pending)
        {
            RemoveResult r = configurator.Remove(e.InterfaceIndex, IPAddress.Parse(e.Address), e.PrefixLength);
            if (r.Status == RemoveStatus.Failed)
            {
                allOk = false;
                ui.Error($"Could not remove {e.Address}: {r.Message}");
                continue;
            }

            journal.Remove(e);
            ui.Info($"    Removed {e.Address} ({(r.Status == RemoveStatus.AlreadyGone ? "was already gone" : "ok")}).");
        }

        return allOk;
    }
}
