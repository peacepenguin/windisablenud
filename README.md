# windisablenud: LocalSubnetGuard

A small Windows service that works around **Neighbor Unreachability Detection (NUD) failover**, so
traffic for a directly-connected subnet stays on its own network adapter and never leaks out the
default gateway.

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

NUD itself cannot be turned off. `netsh interface ipv4 set interface` lists a `nud` parameter, but
setting it to `disabled` always fails with "The parameter is incorrect".

## What it does

The service watches the neighbor table of every connected adapter that has **no default gateway**,
checked separately for IPv4 and IPv6. When a neighbor in one of that adapter's subnets is marked
Unreachable, the service deletes the entry and flushes the path cache. Windows then re-resolves the
address on the local adapter instead of re-routing it to the gateway. The service keeps doing this
until the neighbor answers again, and logs when a device is held and when it comes back.

It checks every 250 ms by default. The set of protected subnets follows the live network configuration,
re-checked on every address change and every 5 seconds. Nothing is blocked, no setting is changed and no
network is remembered. The only thing written to disk is the log.

Between a neighbor being marked Unreachable and the next check, some traffic can still go out the
gateway: up to one interval (250 ms by default).

## Usage

Build with `build.cmd`, or download the exe from the CI artifacts. Then, from an elevated prompt:

```
LocalSubnetGuard.exe install [intervalMs]   install + start the service (default 250 ms)
LocalSubnetGuard.exe uninstall              stop + remove the service
LocalSubnetGuard.exe run [intervalMs]       run in this console (Ctrl+C to stop)
LocalSubnetGuard.exe status                 show adapters, protected subnets and their neighbors
```

`install` copies the exe to `%ProgramFiles%\LocalSubnetGuard` and registers an auto-start service that
restarts on failure. It also removes leftovers of earlier versions: the PowerShell scheduled task,
Windows Firewall rules in the `LocalSubnetGuard` group, and the old state file. `status` works without
elevation.

The log is at `%ProgramData%\LocalSubnetGuard\LocalSubnetGuard.log` and rotates at 1 MB. Only SYSTEM and
Administrators can write to that folder.

## Things to know

Some adapters and addresses are ignored: loopback, transition tunnels (Teredo, 6to4, ISATAP, IP-HTTPS),
link-local addresses and host-only prefixes (IPv4 /32, IPv6 /128). An adapter whose only IPv6 addresses
are DHCPv6 /128s therefore has no protected IPv6 subnet.

## Development

- One source file, [LocalSubnetGuard.cs](LocalSubnetGuard.cs), written in C# 5 so it compiles with the
  `csc.exe` built into Windows (.NET Framework 4.x). No SDK is needed.
- `build.cmd` builds `bin\LocalSubnetGuard.exe` and runs the tests in [tests/Tests.cs](tests/Tests.cs).
  They cover which subnets are protected, the hold/release tracker, address handling, and a read-only
  check of the neighbor-table layout.
- GitHub Actions runs the same script on every push and uploads the exe as an artifact.
