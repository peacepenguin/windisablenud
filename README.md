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

0. **Block the leak (Windows Filtering Platform).** For each protected subnet the service installs a WFP
   filter at the outbound IP-packet layer that drops any packet to that subnet leaving through *any other*
   adapter (loopback excepted). Unlike firewall rules this sees every packet, after routing, so whatever
   NUD does to the routing table, nothing for the lab subnet can reach the default gateway. The filters
   live in a dynamic WFP session: if the service or its process dies for any reason, Windows removes them,
   so a crash can never leave a subnet blocked. They follow the live configuration and are re-checked
   every 5 s (and reinstalled if the Base Filtering Engine restarts). If another connected adapter also
   has an address in the same range, traffic may legitimately use either, so that subnet is not blocked
   (a warning is logged). The service depends on the Base Filtering Engine (`BFE`).

   The two layers below keep the connection *working* (device re-resolved on the right adapter); this
   one guarantees it can't *leak*.

1. **Slow NUD down (optional, `slowtimers`).** Off by default: with the WFP block in place a leak is
   impossible, and long timers make Windows wait up to 10 s before asking again for a device that comes
   back. Existing lengthened timers are restored to the defaults at startup. When enabled, NUD's timers can be changed even though NUD can't be turned off. By default
   Windows probes a neighbor 3 times, 1 s apart, and marks it Unreachable if none of the probes is
   answered, so about 3 s of silence is enough to trigger failover. The service sets
   `retransmittime=10000` and `basereachabletime=120000` on the adapter, so a neighbor has to be silent
   for about 30 s, and is probed far less often. Short outages such as a device reboot or a switch
   restart then never cause failover at all. The change is made with `netsh ... store=active`, so a reboot
   always resets it, and the original values are put back when the service stops or the adapter gains a
   default gateway.
2. **Hold, fast.** When a neighbor is marked Unreachable, the service deletes the entry and flushes the
   path cache. Windows then re-resolves the address on the local adapter instead of re-routing it to the
   gateway. Unreachable only ever follows a failing probe (state Probe) or lookup (state Incomplete), so
   while any protected neighbor is in one of those states the service checks every 100 ms instead of
   every 500 ms. It catches the Unreachable within about 100 ms, and resets an entry that stays in Incomplete for more than 5 s or
   Probe for more than 12 s (stuck: seen about once in 20-50 cycles). (The WFP block, not this speed, is what prevents leaks.)

The Unreachable itself can't be prevented. Deleting an entry while it is in Probe or Incomplete, to
restart the countdown, makes Windows mark the neighbor Unreachable immediately (seen in traces), so the
service never does that.

What to expect when a device stops answering:

- **Outages shorter than about 30 s** (device reboot, switch restart) never reach Unreachable, so no
  traffic leaves via the gateway.
- **Longer outages** reach Unreachable once, about 30 s after probing starts. Traffic can go out the
  gateway for the ~100 ms until the hold catches it. After that, Windows keeps looking the device up
  (state Incomplete) for as long as traffic continues. In traces this lasted without another Unreachable,
  and the device was found again as soon as it answered.

The service logs when a device stops answering, when it is held and when it comes back. `run trace` also
logs every state change of the protected neighbors. The set of protected adapters follows the live network
configuration, re-checked on every address change and every 5 seconds. Nothing is blocked and no network
is remembered. The only thing written to disk is the log.

Costs on the protected adapters:

- If a device is replaced by one with a different MAC address but the same IP, and the new one does
  not announce itself, traffic can go to the old MAC for up to about 30 s.
- A lost ARP or Neighbor Discovery request for a new address is retried after 10 s instead of 1 s.
- On IPv6, duplicate address detection waits one retransmit time, so a new IPv6 address on the adapter
  takes about 10 s to become usable.

## Usage

Build with `build.cmd`, or download the exe from the CI artifacts. Then, from an elevated prompt:

```
LocalSubnetGuard.exe install [intervalMs] [slowtimers]
                                            install + start the service (default 500 ms)
LocalSubnetGuard.exe uninstall              stop + remove the service (restores the NUD timers)
LocalSubnetGuard.exe run [intervalMs] [trace] [slowtimers]
                                            run in this console (Ctrl+C to stop and restore the timers);
                                            'trace' also logs every state change of protected neighbors
LocalSubnetGuard.exe wfptest <cidr> on|except <adapter>
                                            diagnostic: install one WFP block filter until Enter
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
