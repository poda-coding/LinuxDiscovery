using System.Globalization;

namespace LinuxDiscovery;

/// <summary>Command-line options. The defaults are fully interactive.</summary>
internal sealed record Options(int? InterfaceIndex, bool AssumeYes, bool IncludeVirtual, bool Verbose, bool ShowHelp, string? Error)
{
    public static string Usage => """
        Usage: LinuxDiscovery [options]

          --interface <ifIndex>   Use this interface (skips the selection prompt)
          --yes                   Apply the planned temporary address changes without asking
                                  (non-interactive mode; changes are still journaled and reverted)
          --include-virtual       Also offer virtual adapters (Hyper-V, VMware, VirtualBox, ...)
          --verbose               Print per-step diagnostics (ARP error codes, every responder, SSH details)
          --help                  Show this help
        """;

    public static Options Parse(string[] args)
    {
        int? index = null;
        bool yes = false, includeVirtual = false, verbose = false, help = false;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i].ToLowerInvariant())
            {
                case "--yes":
                case "-y":
                    yes = true;
                    break;
                case "--include-virtual":
                    includeVirtual = true;
                    break;
                case "--verbose":
                case "-v":
                    verbose = true;
                    break;
                case "--help":
                case "-h":
                case "/?":
                    help = true;
                    break;
                case "--interface":
                    if (i + 1 >= args.Length ||
                        !int.TryParse(args[i + 1], NumberStyles.None, CultureInfo.InvariantCulture, out int n) ||
                        n <= 0)
                    {
                        return new Options(null, false, false, false, false, "--interface requires a positive interface index.");
                    }
                    index = n;
                    i++;
                    break;
                default:
                    return new Options(null, false, false, false, false, $"Unknown argument: {args[i]}");
            }
        }

        return new Options(index, yes, includeVirtual, verbose, help, null);
    }
}
