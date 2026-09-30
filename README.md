# windisablenud: LocalSubnetGuard

A small Windows service that works around **Neighbor Unreachability Detection (NUD) failover**, so
traffic for a directly-connected subnet stays on its own network adapter and reduces leaks out the
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

The service acts on every connected adapter that has **no default gateway**, checked separately for
IPv4 and IPv6, in three layers:

1. **Slow NUD down.** NUD's timers can be changed even though NUD can't be turned off. By default
   Windows probes a neighbor 3 times, 1 s apart, and marks it Unreachable if none of the probes is
   answered, so about 3 s of silence is enough to trigger failover. The service sets
   `retransmittime=10000` and `basereachabletime=120000` on the adapter, so a neighbor has to be silent
   for about 30 s, and is probed far less often. Short outages such as a device reboot or a switch
   restart then never cause failover at all. The change is made with `netsh ... store=active`, so a reboot
   always resets it, and the original values are put back when the service stops or the adapter gains a
   default gateway.
2. **Reset before NUD gives up.** While Windows is still resolving a neighbor (state Incomplete) or
   probing it (state Probe), its packets wait on the local adapter. Only when the countdown runs out,
   after about 3 × the retransmit time, is the neighbor marked Unreachable and its traffic re-routed.
   So when a neighbor has been in one of those states for 1.5 × the retransmit time (15 s with the
   lengthened timers), the service deletes its entry. Windows starts a fresh countdown on the next packet,
   so a device that stays down, even for hours, is never marked Unreachable and its traffic never goes to
   the gateway. It is found again as soon as it answers.
3. **Hold (backstop).** If a neighbor is marked Unreachable anyway, the service deletes the entry and
   flushes the path cache. Windows then re-resolves the address on the local adapter instead of
   re-routing it to the gateway.

The service checks the neighbor table every 250 ms by default, and logs when a device stops answering
and when it comes back. The set of protected adapters follows the live network configuration, re-checked
on every address change and every 5 seconds. Nothing is blocked and no network is remembered. The only
thing written to disk is the log.

Traffic can only leak if layer 3 is ever needed: up to one interval (250 ms by default) between a
neighbor being marked Unreachable and the next check. Layer 2 acts halfway through the countdown, so
that should not happen. The log says `was marked Unreachable` if it ever does.

Layer 2 relies on Windows not re-routing traffic while a neighbor is still Incomplete or in Probe. That
is how NUD failover appears to work (it is triggered by the Unreachable state), but it has not been
verified with a packet capture yet.

Costs on the protected adapters:

- A device that is really gone is never declared unreachable while traffic to it continues, so
  connections to it time out instead of failing with "host unreachable".
- The same goes for addresses that never existed. Scanning the subnet logs one line per address that
  does not answer.
- If a device is replaced by one with a different MAC address but the same IP, and the new one does
  not announce itself, traffic can go to the old MAC for up to about 30 s.
- A lost ARP or Neighbor Discovery request for a new address is retried after 10 s instead of 1 s.
- On IPv6, duplicate address detection waits one retransmit time, so a new IPv6 address on the adapter
  takes about 10 s to become usable.

## Usage

Build with `build.cmd`, or download the exe from the CI artifacts. Then, from an elevated prompt:

```
LocalSubnetGuard.exe install [intervalMs]   install + start the service (default 250 ms)
LocalSubnetGuard.exe uninstall              stop + remove the service (restores the NUD timers)
LocalSubnetGuard.exe run [intervalMs]       run in this console (Ctrl+C to stop and restore the timers)
LocalSubnetGuard.exe status                 show adapters, protected subnets, NUD timers and neighbors
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
