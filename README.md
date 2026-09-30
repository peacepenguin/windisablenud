# windisablenud: LocalSubnetGuard

A small Windows service that stops **Neighbor Unreachability Detection (NUD) failover**, so traffic
for a directly-connected subnet stays on its own network adapter and never leaks out the default gateway.

## The problem

Take a PC with two NICs:

| NIC        | Subnet          | Default gateway |
|------------|-----------------|-----------------|
| Ethernet   | 192.168.1.0/24  | 192.168.1.1     |
| Ethernet 2 | 10.1.1.0/24     | none (lab, PLC network, SAN, ...) |

When a device on `10.1.1.0/24` stops answering ARP or Neighbor Discovery for a few seconds (power cycle,
switch reboot, busy embedded stack), NUD marks it **Unreachable**. Windows then treats the on-link route
as unusable and sends traffic for that address to the next best route, the default gateway on `Ethernet`.
The packets leak onto the wrong network. Connections break, and they often stay broken after the device
comes back, because Windows keeps using the cached path.

## What it does

LocalSubnetGuard treats the connected subnets of every NIC that has **no default gateway** as protected.
It protects IPv4 and IPv6 separately, and applies three layers:

1. **NUD off.** Neighbor Unreachability Detection is disabled on each protected NIC (the same setting as
   `netsh interface ipv4 set interface <nic> nud=disabled`). Its neighbors are then not marked
   Unreachable in the first place.
2. **Hold.** If a neighbor in a protected subnet is marked Unreachable anyway, its entry is deleted and
   the path cache is flushed. Windows re-resolves the address on the local NIC instead of re-routing it.
   The tool checks every 250 ms by default and logs when the neighbor answers again.
3. **Firewall.** Each default-gateway NIC gets an outbound block rule for the protected subnets, so
   nothing that slips past layers 1 and 2 can go out through the gateway.

Protected subnets and gateway NICs are learned automatically and remembered in
`%ProgramData%\LocalSubnetGuard\state.txt`. Protection therefore survives reboots, service restarts and
an unplugged lab adapter. Stopping the service leaves the protection in place; `uninstall` removes it.

A remembered subnet is **suspended** while it overlaps a subnet connected on a different NIC. For example,
a laptop joins Wi-Fi that happens to use the same range as the lab. It becomes active again once the
overlap goes away.

## Usage

Build with `build.cmd`, or download the exe from the CI artifacts. Then, from an elevated prompt:

```
LocalSubnetGuard.exe install [intervalMs]   install + start the service (default 250 ms)
LocalSubnetGuard.exe uninstall              remove the service and all protection
LocalSubnetGuard.exe run [intervalMs]       run in this console; protection is removed on exit
LocalSubnetGuard.exe status                 show interfaces, protected subnets, NUD, rules, neighbors
LocalSubnetGuard.exe forget <cidr>|all      stop protecting a remembered subnet (or all of them)
```

`install` copies the exe to `%ProgramFiles%\LocalSubnetGuard` and registers an auto-start service that
restarts on failure. It also removes the older PowerShell scheduled task of the same name if one exists.
`status` works without elevation.

The log is at `%ProgramData%\LocalSubnetGuard\LocalSubnetGuard.log` and rotates at 1 MB. Only SYSTEM and
Administrators can write to that folder.

## Things to know

- **Remembered subnets stay blocked on gateway NICs.** Suppose you remove a lab network for good, or
  later need to reach that range through a gateway (such as over a VPN). Run
  `LocalSubnetGuard.exe forget <cidr>` to drop it.
- **The Windows Firewall must be on**, and Group Policy must allow local rules, for layer 3 to work.
  `status` and the log warn when it isn't.
- **Uninstall re-enables NUD** only on NICs that are present at the time. For an absent NIC, the log
  prints the `netsh` command to run later.
- **Some interfaces are ignored:** loopback, transition tunnels (Teredo, 6to4, ISATAP, IP-HTTPS),
  link-local addresses and host-only prefixes (IPv4 /32, IPv6 /128). A DHCPv6-only LAN whose addresses
  are /128 is therefore not detected from its addresses.

## Development

- One source file, [LocalSubnetGuard.cs](LocalSubnetGuard.cs), written in C# 5 so it compiles with the
  `csc.exe` built into Windows (.NET Framework 4.x). No SDK is needed.
- `build.cmd` builds `bin\LocalSubnetGuard.exe` and runs the tests in [tests/Tests.cs](tests/Tests.cs).
  They cover the planning logic (learning, suspension, rule contents), the hold/release tracker, state
  round-tripping, and a read-only check of the native struct layouts.
- GitHub Actions runs the same script on every push and uploads the exe as an artifact.
