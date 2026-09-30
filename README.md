# windisablenud: LocalSubnetGuard

A small Windows service that **disables Neighbor Unreachability Detection (NUD)** on network adapters
that have no default gateway. Traffic for their directly-connected subnets then stays on them instead
of failing over to the default gateway on another adapter.

## The problem

Take a PC with two adapters:

| Adapter    | Subnet          | Default gateway |
|------------|-----------------|-----------------|
| Ethernet   | 192.168.1.0/24  | 192.168.1.1     |
| Ethernet 2 | 10.1.1.0/24     | none (lab, PLC network, SAN, ...) |

When a device on `10.1.1.0/24` stops answering ARP or Neighbor Discovery for a few seconds (power cycle,
switch reboot, busy embedded stack), NUD marks it **Unreachable**. Windows then treats the on-link route
as unusable and sends traffic for that address to the next best route, the default gateway on `Ethernet`.
The packets leak onto the wrong network. Connections break, and they often stay broken after the device
comes back, because Windows keeps using the cached path.

## What it does

The service acts on every connected adapter that has **no default gateway**, checked separately for
IPv4 and IPv6:

1. **NUD off.** Neighbor Unreachability Detection is turned off on the adapter (the same setting as
   `netsh interface ipv4 set interface <adapter> nud=disabled`). Its neighbors are not marked Unreachable,
   so Windows never moves their traffic to the gateway.
2. **Hold (backstop).** If a neighbor on that adapter is marked Unreachable anyway, its entry is deleted
   and the path cache is flushed. Windows re-resolves the address on the local adapter instead of
   re-routing it. The service checks every 250 ms by default and logs when the neighbor answers again.

Nothing is blocked and no network is remembered: the service follows the live configuration, re-checking
on every address change and every 5 seconds. If an adapter gains a default gateway, NUD is turned back on
there right away. The only thing saved is the list of adapters the service turned NUD off on
(`%ProgramData%\LocalSubnetGuard\state.txt`), so `uninstall` can turn it back on.

## Usage

Build with `build.cmd`, or download the exe from the CI artifacts. Then, from an elevated prompt:

```
LocalSubnetGuard.exe install [intervalMs]   install + start the service (default 250 ms)
LocalSubnetGuard.exe uninstall              remove the service and turn NUD back on
LocalSubnetGuard.exe run [intervalMs]       run in this console; NUD is turned back on at exit
LocalSubnetGuard.exe status                 show adapters, NUD settings and neighbors
```

`install` copies the exe to `%ProgramFiles%\LocalSubnetGuard` and registers an auto-start service that
restarts on failure. It also removes leftovers of earlier versions: the PowerShell scheduled task, and
Windows Firewall rules in the `LocalSubnetGuard` group. Stopping the service leaves NUD off.
`status` works without elevation.

The log is at `%ProgramData%\LocalSubnetGuard\LocalSubnetGuard.log` and rotates at 1 MB. Only SYSTEM and
Administrators can write to that folder.

## Things to know

- **Uninstall turns NUD back on** only on adapters that are present at the time. For an absent adapter,
  the log prints the `netsh` command to run later.
- **Some adapters and addresses are ignored:** loopback, transition tunnels (Teredo, 6to4, ISATAP,
  IP-HTTPS), link-local addresses and host-only prefixes (IPv4 /32, IPv6 /128). An adapter whose only
  IPv6 addresses are DHCPv6 /128s therefore keeps IPv6 NUD on.

## Development

- One source file, [LocalSubnetGuard.cs](LocalSubnetGuard.cs), written in C# 5 so it compiles with the
  `csc.exe` built into Windows (.NET Framework 4.x). No SDK is needed.
- `build.cmd` builds `bin\LocalSubnetGuard.exe` and runs the tests in [tests/Tests.cs](tests/Tests.cs).
  They cover which adapters get NUD off, the hold/release tracker, state round-tripping, and a read-only
  check of the native struct layouts.
- GitHub Actions runs the same script on every push and uploads the exe as an artifact.
