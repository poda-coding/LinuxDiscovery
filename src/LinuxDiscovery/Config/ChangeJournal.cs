using System.Net;
using System.Text.Json;

namespace LinuxDiscovery;

/// <summary>One temporary address this tool created (or is about to create).</summary>
internal sealed record JournalEntry(
    int InterfaceIndex,
    string InterfaceId,
    string InterfaceName,
    string Address,
    int PrefixLength,
    DateTime CreatedUtc);

/// <summary>
/// Crash-recovery record of every configuration change. An entry is written BEFORE the change is made
/// and removed only after the change is confirmed reverted, so a killed process leaves a trail that the
/// next run can use. Loaded entries are validated: only addresses inside the target subnets with a
/// /24 prefix are ever honored, so a tampered journal cannot make the tool delete arbitrary addresses.
/// </summary>
internal sealed class ChangeJournal
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private readonly object _gate = new();

    public string FilePath { get; }

    public ChangeJournal(string? filePath = null)
    {
        FilePath = filePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "LinuxDiscovery", "pending-cleanup.json");
    }

    public IReadOnlyList<JournalEntry> Load()
    {
        lock (_gate) return LoadUnsafe();
    }

    public void Add(JournalEntry entry)
    {
        lock (_gate)
        {
            List<JournalEntry> entries = LoadUnsafe();
            if (!entries.Any(e => Same(e, entry))) entries.Add(entry);
            Save(entries);
        }
    }

    public void Remove(JournalEntry entry)
    {
        lock (_gate)
        {
            List<JournalEntry> entries = LoadUnsafe();
            entries.RemoveAll(e => Same(e, entry));
            Save(entries);
        }
    }

    private static bool Same(JournalEntry a, JournalEntry b) =>
        a.InterfaceIndex == b.InterfaceIndex && a.Address == b.Address;

    private static bool IsValid(JournalEntry? e) =>
        e is not null
        && e.InterfaceIndex > 0
        && e.PrefixLength == TargetSubnet.PrefixLength
        && IPAddress.TryParse(e.Address, out IPAddress? ip)
        && TargetNetworks.Find(ip) is not null;

    private List<JournalEntry> LoadUnsafe()
    {
        if (!File.Exists(FilePath)) return new List<JournalEntry>();

        try
        {
            string json = File.ReadAllText(FilePath);
            List<JournalEntry> raw = JsonSerializer.Deserialize<List<JournalEntry>>(json) ?? new List<JournalEntry>();
            return raw.Where(IsValid).ToList();
        }
        catch (JsonException)
        {
            // Unreadable journal: keep it for inspection rather than overwriting it.
            File.Move(FilePath, FilePath + ".corrupt-" + DateTime.UtcNow.Ticks);
            return new List<JournalEntry>();
        }
    }

    private void Save(List<JournalEntry> entries)
    {
        if (entries.Count == 0)
        {
            if (File.Exists(FilePath)) File.Delete(FilePath);
            return;
        }

        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        string temp = FilePath + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(entries, JsonOptions));
        File.Move(temp, FilePath, overwrite: true);
    }
}
