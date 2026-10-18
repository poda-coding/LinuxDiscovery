# LinuxDiscovery

Windows console tool that finds the IPv4 address of a Linux device when you only know that it is in
`192.168.0.0/24`, `192.168.1.0/24`, `192.168.2.0/24` or `192.168.3.0/24` and that SSH (TCP 22) is enabled.
The scope is the `TargetNetworks.All` list in `src/LinuxDiscovery/Discovery/TargetNetworks.cs`.

It never guesses passwords, never authenticates, and never probes anything outside those two subnets.

## Requirements

* Windows 10 / 11 (x64 or ARM64)
* .NET SDK 10 (LTS) to build. For .NET 8, change `TargetFramework` to `net8.0-windows` in both `.csproj` files.
* Administrator rights (the app manifest asks for them, so Windows shows the UAC prompt at launch)
* No Npcap, no third-party runtime packages

## Build

```powershell
# from the repository root
dotnet build src/LinuxDiscovery -c Release

# optional: run the unit tests (they never touch a real network adapter)
dotnet test tests/LinuxDiscovery.Tests

# optional: one self-contained exe you can copy to another PC
dotnet publish src/LinuxDiscovery -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -o publish
```

Optional solution file: `dotnet new sln -n LinuxDiscovery; dotnet sln add src/LinuxDiscovery tests/LinuxDiscovery.Tests`

## Run

* **Double-click** `LinuxDiscovery.exe`, accept the UAC prompt. The window stays open until you press Enter.
* **From a terminal**: it must be an *elevated* terminal ("Run as administrator").
  `dotnet run` from a non-elevated shell fails with "The requested operation requires elevation"; that is the
  manifest doing its job.

```
LinuxDiscovery.exe [--interface <ifIndex>] [--yes] [--include-virtual] [--verbose] [--help]
```

| Option | Meaning |
| --- | --- |
| `--interface <ifIndex>` | Skip the interface prompt (use the `ifIndex` shown in the list). |
| `--yes` | Non-interactive mode: apply the planned temporary changes without asking. They are still journaled and reverted. |
| `--include-virtual` | Also offer Hyper-V / VMware / VirtualBox / WSL adapters. |
| `--verbose` | Print diagnostics: source address per subnet, ARP error codes, every responder with MAC, SSH details and ICMP result. Use this when a device is not found. |

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Device found |
| 1 | No candidate found |
| 2 | Not running as administrator |
| 3 | No eligible interface (or the requested one is unavailable) |
| 4 | Temporary configuration could not be applied (or every subnet was skipped) |
| 5 | Cancelled by the user (Ctrl+C, "no" at the confirmation, closed input) |
| 6 | Cleanup failed. Manual recovery steps were printed |
| 7 | Connectivity lost during the scan |
| 8 | Another instance is already running |
| 10 | Unexpected error |
| 64 | Bad command line |

## How it works

1. **Enumerate** adapters (managed `NetworkInterface`, no text parsing) and show why unavailable ones are excluded.
2. **Plan**: for each target subnet decide whether the selected adapter is already on-link.
   If not, a temporary `/24` secondary address (`.231` to `.238`) is added through IP Helper
   (`CreateUnicastIpAddressEntry`, with `SkipAsSource` false so that `SendARP` accepts it as source). Existing address, gateway, DNS and DHCP are never modified.
   If another connected adapter is already in one of the subnets, the tool warns you and asks for confirmation
   (see "Safety" below) instead of skipping it. A subnet is only skipped when the selected adapter has a
   longer-prefix address (for example a /28) that overlaps it.
3. **Conflict check**: after adding, Windows duplicate address detection is awaited. On a conflict the
   address is removed and the next candidate is tried.
4. **Sweep**: ARP request for each of the 1016 addresses (4 x 254) via `SendARP`, with the local address as
   source so traffic is pinned to the chosen adapter. ARP is answered below the host firewall, so ping/iptables
   do not hide a device.
5. **SSH check** (only on ARP responders): TCP connect to port 22 from the pinned source address, then read
   the SSH identification string. States are reported as open / closed (refused) / filtered (timeout) / inconclusive.
   ICMP echo is diagnostic only (TTL hint); it is never required, and it is not used on subnets shared with
   another adapter because ping cannot be pinned to an adapter.
6. **Identify**: a candidate needs ARP reply + open port + valid SSH banner. "Linux likely" requires the banner to
   name a distribution (Ubuntu, Debian, ...). Anything else is reported as "SSH server, OS not confirmed".
7. **Cleanup**: always runs (success, error, Ctrl+C, closing the window, logoff, normal process exit) and reports the result.

## Safety, journal and limitations

* Before each change, an entry is written to `%ProgramData%\LinuxDiscovery\pending-cleanup.json` and removed only after
  the address is confirmed removed. Entries outside the target subnets are ignored when loading.
* **If the process is killed (Task Manager, power loss, BSOD) no code can run.** The temporary address
  is not removed at that moment. Next start the tool detects the journal and offers to remove it. The addresses
  are created without a persistent entry, so a reboot, or disabling and re-enabling the adapter, should also clear
  them; confirm this once on your machine (see test checklist). Manual removal:
  `Remove-NetIPAddress -InterfaceIndex <n> -IPAddress 192.168.1.231 -Confirm:$false`
* Address-conflict detection cannot be guaranteed: a sleeping or late-booting device with the same address
  can appear later.
* **Other adapters in the same subnet.** The selected adapter is scanned regardless of what other adapters have.
  While the temporary address exists, Windows has two on-link routes for that subnet and may send other
  applications' traffic for it out of the selected adapter. This lasts only for the scan, and the tool tells you
  which adapter is affected before changing anything. Scan traffic itself is pinned to the selected adapter.
* A secondary address cannot create connectivity. If the adapter is not on the same physical network
  (cable/switch/Wi-Fi) as the device, nothing will be found.
* Wi-Fi with client isolation, managed switches with port isolation, or a Linux box with unusual
  `arp_ignore` / `arp_filter` settings can hide hosts from ARP.
* Only IPv4 and TCP port 22 are checked.

## Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| "requires elevation" when launching | Start from an elevated terminal or double-click the exe. |
| Warning "Another connected adapter is already in a subnet" | Expected when Wi-Fi and Ethernet share a subnet. Harmless unless that other adapter is actively using the subnet; disconnect it for the cleanest result. |
| Subnet "SKIPPED ... longer prefix" | The selected adapter has e.g. a /28 inside the subnet; a temporary /24 would overlap it. |
| "Access denied" adding the address | Not elevated, or a policy/VPN agent locks the adapter. |
| "did not become usable" | Adapter disconnected, or the driver rejects secondary addresses (some USB/virtual NICs). |
| Many ARP probes with "unexpected error" | A virtual/filter driver interferes with `SendARP`; try another adapter or `--include-virtual` off. |
| Device found by ARP but SSH "closed"/"filtered" | SSH on another port, or a firewall on the device. |
| "Another instance is already running" | Close the other window, or wait for it to finish. |

## Test checklist

Automated (no real adapter touched): `dotnet test tests/LinuxDiscovery.Tests` covers banner parsing, classification
(ping blocked / SSH closed / several servers / none), reachability planning for each address situation, address
conflicts, failed cleanup, cancellation and idempotent cleanup, and journal validation.

Manual (needs a real adapter and device):

- [ ] Adapter in 192.168.1.x: the other three subnets (0, 2, 3) get a temporary address, 192.168.1.0/24 does not
- [ ] Adapter in 192.168.3.x: only 0, 1 and 2 get a temporary address
- [ ] Adapter in 192.168.10.x: all four get one; original address/gateway/DNS unchanged afterwards (`ipconfig /all` before and after)
- [ ] Wi-Fi in 192.168.1.x and Ethernet selected: warning shown, scan still runs on Ethernet, no ICMP on that subnet; check `Get-NetRoute -DestinationPrefix 192.168.1.0/24` during and after the scan
- [ ] Adapter with no IPv4 / link-local only
- [ ] Disconnected adapter is listed as unavailable with the reason
- [ ] Linux device with ping blocked (`iptables -A INPUT -p icmp --icmp-type echo-request -j DROP`) is still found
- [ ] Device answering ping but with sshd stopped is reported as "SSH port closed", not as a candidate
- [ ] Two SSH servers: you get the numbered choice
- [ ] No device connected: summary with causes, retry menu
- [ ] Give another PC the temporary address (for example `192.168.1.231`): conflict detected, next address used
- [ ] Not elevated: manifest prompt / clear message
- [ ] Ctrl+C mid-scan: addresses removed, exit code 5
- [ ] Close the console window mid-scan: `Get-NetIPAddress -IPAddress 192.168.*.23?` shows nothing afterwards
- [ ] Kill the process in Task Manager, then start again: leftover detected and removable; check whether a reboot also clears it
- [ ] Pull the cable mid-scan: exit code 7, cleanup still reported
- [ ] While the tool is running: `Get-NetIPAddress -PolicyStore PersistentStore` does not list the temporary address
