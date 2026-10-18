namespace LinuxDiscovery;

/// <summary>An SSH identification string: SSH-protoversion-softwareversion SP comments (RFC 4253 section 4.2).</summary>
internal sealed record SshBanner(string ProtocolVersion, string SoftwareVersion, string? Comments, string Raw)
{
    /// <summary>Finds the first complete line that is a valid SSH identification string in received data.</summary>
    public static bool TryExtract(string received, out SshBanner? banner)
    {
        banner = null;
        int lastNewline = received.LastIndexOf('\n');
        if (lastNewline < 0) return false; // no complete line yet

        foreach (string line in received[..lastNewline].Split('\n'))
        {
            if (TryParse(line.TrimEnd('\r'), out banner)) return true;
        }

        return false;
    }

    public static bool TryParse(string? line, out SshBanner? banner)
    {
        banner = null;
        if (string.IsNullOrEmpty(line) || line.Length > 255) return false;
        if (!line.StartsWith("SSH-", StringComparison.Ordinal)) return false;
        if (line.Any(char.IsControl)) return false;

        string rest = line[4..];
        string? comments = null;

        int space = rest.IndexOf(' ');
        if (space >= 0)
        {
            comments = rest[(space + 1)..];
            rest = rest[..space];
        }

        int dash = rest.IndexOf('-');
        if (dash <= 0 || dash == rest.Length - 1) return false;

        string protocol = rest[..dash];
        string software = rest[(dash + 1)..];
        if (!protocol.All(c => char.IsAsciiDigit(c) || c == '.')) return false;

        banner = new SshBanner(protocol, software, comments, line);
        return true;
    }
}
