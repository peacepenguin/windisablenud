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

0. **Block the leak (Windows Filtering Platform; `wfpblock=yes`, off by default).** For each protected subnet the service installs a WFP
   filter at the outbound IP-packet layer that drops any packet to that subnet leaving through *any other*
   adapter (loopback excepted). Unlike firewall rules this sees every packet, after routing, so whatever
   NUD does to the routing table, nothing for the lab subnet can reach the default gateway. The filters
   live in a dynamic WFP session: if the service or its process dies for any reason, Windows removes them,
   so a crash can never leave a subnet blocked. They follow the live configuration and are re-checked
   every 5 s (and reinstalled if the Base Filtering Engine restarts). If another connected adapter also
   has an address in the same range, traffic may legitimately use either, so that subnet is not blocked
   (a warning is logged). The service depends on the Base Filtering Engine (`BFE`).

   The layers below keep the connection *working* (device re-resolved on the right adapter); this
   one guarantees it can't *leak*, whatever Windows decides.

1. **Clear failing neighbors.** Windows marks a neighbor Unreachable after about 3 s of failed lookups and
   then routes its traffic to the default gateway. Once a second the service reads the neighbor table and,
   for neighbors in the protected subnets:
   - deletes entries that stay **Incomplete** for 2 s (`deleteincomplete`, on by default). Windows normally
     gives up after about 3 s, so the neighbor never reaches Unreachable and nothing is re-routed; the
     deleted entry is re-created by the next packet and the lookup restarts. An entry also sometimes stays
     Incomplete without sending anything, so a device that comes back is never found (seen in traces); this
     fixes that too;
   - deletes entries that stay in **Probe** for more than 12 s (normally 4-8 s; same setting);
   - deletes entries marked **Unreachable** (`deleteunreachable`, off by default) and flushes the global
     path cache (`pathflush`, off by default). Not generally helpful on current builds of Windows, because
     the first bullet keeps the neighbor from getting there. One Unreachable per outage can still slip
     through, when the Probe phase ends in Unreachable before there is an Incomplete entry to delete.

   A device that returns is found again on the next lookup, typically within a second of its link coming up.
   The log says once per outage when a device stops answering, and when it is back.
2. **Slow NUD down (optional, `slowtimers`).** Off by default: long timers make Windows wait up to 10 s
   before asking again for a device that comes back. Existing lengthened timers are restored to the
   defaults at startup. When enabled, the NUD timers are lengthened (NUD itself can't be turned off): by
   default Windows probes a neighbor 3 times, 1 s apart, so about 3 s of silence triggers failover;
   `retransmittime=10000` and `basereachabletime=120000` make that about 30 s. The change uses
   `netsh ... store=active`, so a reboot resets it, and the originals are put back when the service stops
   or the adapter gains a default gateway.

`run trace` also logs every state change of the protected neighbors. The set of protected adapters follows
the live network configuration, re-checked on every address change and every 5 seconds. No network is
remembered. The only thing written to disk is the log.

Costs on the protected adapters:

- If a device is replaced by one with a different MAC address but the same IP, and the new one does
  not announce itself, traffic can go to the old MAC for up to about 30 s.
- A lost ARP or Neighbor Discovery request for a new address is retried after 10 s instead of 1 s.
- On IPv6, duplicate address detection waits one retransmit time, so a new IPv6 address on the adapter
  takes about 10 s to become usable.

## Settings

`C:\ProgramData\LocalSubnetGuard\LocalSubnetGuard.conf` is created on first start and re-read every few
seconds, so changes need no restart. Only SYSTEM and Administrators can write to it. Each setting is one
action and works on its own.

```
wfpblock=no           # WFP filters: drop packets for a protected subnet leaving through another adapter
deleteincomplete=yes  # delete entries stuck in Incomplete (2 s) or Probe (12 s) so the lookup restarts
deleteunreachable=no  # delete entries Windows has marked Unreachable so the lookup restarts
pathflush=no          # flush the path cache when a neighbor is seen Unreachable (global: every adapter)
```

Those are the defaults. Deleting the Incomplete entries early keeps a neighbor from ever reaching
Unreachable, so nothing is re-routed to the default gateway and no packet leaves. That makes
`deleteunreachable` and `pathflush` not generally helpful on current builds of Windows. `wfpblock=yes` is
the safety net underneath: it drops a packet that would leave through the wrong adapter, whatever Windows
decides. It can run alone (pings to a failed device then show "General failure" until Windows retries the
device itself) or together with the delete settings.

The old `deleteflush` name still works: it sets the last three, and a file that still uses it is converted
to the new format once at start (your values are kept; the old file is saved as
`LocalSubnetGuard.conf.old`).

`status` shows the current values and the log says when they change.

## Usage

Build with `build.cmd`, or download the exe from the CI artifacts. Then, from an elevated prompt:

```
LocalSubnetGuard.exe install [intervalMs] [slowtimers]
                                            install + start the service (default 1000 ms)
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
