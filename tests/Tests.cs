// Unit tests for LocalSubnetGuard. build.cmd compiles them together with LocalSubnetGuard.cs:
//   csc /main:LocalSubnetGuard.Tests.Runner ... LocalSubnetGuard.cs tests\Tests.cs
// Every static method whose name starts with "Test" is run. Only TestNativeLayouts touches the machine (read-only).

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;

namespace LocalSubnetGuard.Tests
{
    static class Runner
    {
        static int Main()
        {
            int passed = 0, failed = 0;
            foreach (var m in typeof(Runner).GetMethods(BindingFlags.NonPublic | BindingFlags.Static).Where(m => m.Name.StartsWith("Test")))
            {
                try { m.Invoke(null, null); passed++; }
                catch (TargetInvocationException ex) { failed++; Console.WriteLine("FAIL {0}: {1}", m.Name, ex.InnerException.Message); }
            }
            Console.WriteLine("{0} passed, {1} failed", passed, failed);
            return failed == 0 ? 0 : 1;
        }

        // ---------------------------------------------------------------- helpers
        static void True(bool c, string what) { if (!c) throw new Exception(what); }
        static void Eq<T>(T expected, T actual, string what)
        {
            if (!Equals(expected, actual)) throw new Exception(string.Format("{0}: expected <{1}>, got <{2}>", what, expected, actual));
        }
        static Prefix P(string s) { Prefix p; if (!Prefix.TryParse(s, out p)) throw new Exception("bad prefix " + s); return p; }
        static byte[] A(string s) { return IPAddress.Parse(s).GetAddressBytes(); }
        static readonly List<string> NoLog = new List<string>();

        static NicInfo Nic(int index, string name, bool gw4, bool gw6, params string[] prefixes)
        {
            return new NicInfo { Id = "{" + index + "}", Name = name, Up = true, Gw4 = gw4, Gw6 = gw6, Index4 = index, Index6 = index,
                                 Prefixes = prefixes.Select(P).ToList() };
        }
        static NetSnapshot Snap(params NicInfo[] nics) { return new NetSnapshot { Nics = nics.ToList() }; }
        static State Learned(NetSnapshot snap) { var st = new State(); Planner.Learn(st, snap, s => { }); return st; }
        static string Cidrs(IEnumerable<ProtectedSubnet> s) { return string.Join(",", s.Select(x => x.Prefix.ToString()).OrderBy(x => x)); }

        // Typical laptop: Wi-Fi with the default gateway, plus a lab NIC with no gateway.
        static NicInfo Wifi() { return Nic(1, "Wi-Fi", true, true, "192.168.1.0/24", "2001:db8:1::/64"); }
        static NicInfo Lab() { return Nic(2, "Lab NIC", false, false, "192.168.50.0/24", "fd00:50::/64"); }

        // ---------------------------------------------------------------- Prefix
        static void TestPrefixParseAndFormat()
        {
            Eq("192.168.50.0/24", P("192.168.50.7/24").ToString(), "v4 masked");
            Eq("10.0.0.0/8", P("10.1.2.3/8").ToString(), "v4 /8");
            Eq("172.16.0.0/12", P("172.31.255.1/12").ToString(), "v4 non-octet boundary");
            Eq("fd00:1:2:3::/64", P("fd00:1:2:3::5/64").ToString(), "v6 masked");
            Prefix p;
            True(!Prefix.TryParse("10.0.0.0/33", out p), "v4 /33 rejected");
            True(!Prefix.TryParse("10.0.0.0", out p), "missing length rejected");
            True(!Prefix.TryParse("fd00::/129", out p), "v6 /129 rejected");
            True(P("192.168.50.9/24").Equals(P("192.168.50.0/24")), "equality ignores host bits");
        }

        static void TestContainsAndOverlaps()
        {
            True(P("192.168.50.0/24").Contains(A("192.168.50.200")), "v4 contains");
            True(!P("192.168.50.0/24").Contains(A("192.168.51.1")), "v4 not contains");
            True(P("172.16.0.0/12").Contains(A("172.31.0.1")) && !P("172.16.0.0/12").Contains(A("172.32.0.1")), "v4 /12 boundary");
            True(P("fd00:50::/64").Contains(A("fd00:50::1234")), "v6 contains");
            True(!P("fd00:50::/64").Contains(A("fd00:51::1")), "v6 not contains");
            True(!P("0.0.0.0/8").Contains(A("::1")), "family mismatch never contains");
            True(P("10.0.0.0/16").Overlaps(P("10.0.5.0/24")) && P("10.0.5.0/24").Overlaps(P("10.0.0.0/16")), "overlap both ways");
            True(!P("10.0.0.0/24").Overlaps(P("10.0.1.0/24")), "disjoint");
            True(!P("10.0.0.0/8").Overlaps(P("a00::/8")), "different families never overlap");
        }

        static void TestInterfaceAddressFilter()
        {
            Eq("192.168.50.0/24", Prefix.OfInterfaceAddress(IPAddress.Parse("192.168.50.10"), 24).ToString(), "normal v4");
            Eq("10.0.0.0/31", Prefix.OfInterfaceAddress(IPAddress.Parse("10.0.0.1"), 31).ToString(), "/31 point-to-point kept");
            True(Prefix.OfInterfaceAddress(IPAddress.Parse("169.254.3.4"), 16) == null, "v4 link-local");
            True(Prefix.OfInterfaceAddress(IPAddress.Parse("127.0.0.1"), 8) == null, "v4 loopback");
            True(Prefix.OfInterfaceAddress(IPAddress.Parse("10.0.0.1"), 32) == null, "v4 host prefix");
            True(Prefix.OfInterfaceAddress(IPAddress.Parse("10.0.0.1"), 4) == null, "v4 huge prefix");
            Eq("fd00:50::/64", Prefix.OfInterfaceAddress(IPAddress.Parse("fd00:50::10"), 64).ToString(), "normal v6");
            True(Prefix.OfInterfaceAddress(IPAddress.Parse("fe80::1"), 64) == null, "v6 link-local");
            True(Prefix.OfInterfaceAddress(IPAddress.Parse("::1"), 128) == null, "v6 loopback");
            True(Prefix.OfInterfaceAddress(IPAddress.Parse("2001:db8::5"), 128) == null, "v6 host prefix");
        }

        // ---------------------------------------------------------------- State
        static void TestStateRoundTrip()
        {
            var st = new State();
            st.Subnets.Add(new ProtectedSubnet { Prefix = P("192.168.50.0/24"), NicId = "{A}", NicName = "Ethernet 2 (lab)" });
            st.Subnets.Add(new ProtectedSubnet { Prefix = P("fd00:50::/64"), NicId = "{A}", NicName = "Ethernet 2 (lab)" });
            st.Gateways.Add(new NicRef { NicId = "{B}", NicName = "Wi-Fi" });
            st.Nud.Add(new NudRecord { NicId = "{A}", NicName = "Ethernet 2 (lab)", Family = AddressFamily.InterNetworkV6 });
            var back = State.Parse(st.Serialize() + "garbage line\nsubnet not-a-prefix {X} x\n");
            Eq(st.Serialize(), back.Serialize(), "round trip, bad lines ignored");
            Eq("Ethernet 2 (lab)", back.Subnets[0].NicName, "names with spaces");
            Eq(AddressFamily.InterNetworkV6, back.Nud[0].Family, "nud family");
        }

        // ---------------------------------------------------------------- Planner.Learn
        static void TestLearnProtectsOnlyNonGatewaySubnets()
        {
            var st = Learned(Snap(Wifi(), Lab()));
            Eq("192.168.50.0/24,fd00:50::/64", Cidrs(st.Subnets), "lab subnets learned, Wi-Fi's not");
            Eq("Wi-Fi", string.Join(",", st.Gateways.Select(g => g.NicName)), "gateway NIC recorded");
        }

        static void TestLearnIsPerFamily()
        {
            // The lab LAN has an IPv6 router but no IPv4 gateway: only its IPv4 subnet is protected.
            var lab = Nic(2, "Lab NIC", false, true, "192.168.50.0/24", "2001:db8:50::/64");
            var st = Learned(Snap(Wifi(), lab));
            Eq("192.168.50.0/24", Cidrs(st.Subnets), "only the gateway-less family");
            True(st.Gateways.Any(g => g.NicName == "Lab NIC"), "an IPv6-gateway NIC is a gateway NIC");
        }

        static void TestLearnSkipsSubnetsOverlappingAGatewayLan()
        {
            var wifi = Nic(1, "Wi-Fi", true, false, "10.0.5.0/24");
            var lab = Nic(2, "Lab NIC", false, false, "10.0.0.0/16");
            Eq("", Cidrs(Learned(Snap(wifi, lab)).Subnets), "10.0.0.0/16 would block Wi-Fi's own LAN");
        }

        static void TestLearnIsIdempotent()
        {
            var snap = Snap(Wifi(), Lab());
            var st = Learned(snap);
            True(!Planner.Learn(st, snap, s => { }), "second pass changes nothing");
        }

        static void TestOwnerDoesNotFlapWhenOnTwoNics()
        {
            var a = Nic(2, "Lab A", false, false, "192.168.50.0/24");
            var b = Nic(3, "Lab B", false, false, "192.168.50.0/24");
            var st = Learned(Snap(Wifi(), a, b));
            string owner = st.Subnets.Single().NicName;
            True(!Planner.Learn(st, Snap(Wifi(), a, b), s => { }), "stable while on both NICs");
            var survivor = owner == "Lab A" ? b : a;
            True(Planner.Learn(st, Snap(Wifi(), survivor), s => { }), "moves when the owner disconnects");
            Eq(survivor.Name, st.Subnets.Single().NicName, "new owner");
        }

        static void TestRenamesAreFollowed()
        {
            var st = Learned(Snap(Wifi(), Lab()));
            st.Nud.Add(new NudRecord { NicId = "{2}", NicName = "Lab NIC", Family = AddressFamily.InterNetwork });
            var renamed = Lab(); renamed.Name = "Bench";
            var wifi = Wifi(); wifi.Name = "WLAN";
            True(Planner.Learn(st, Snap(wifi, renamed), s => { }), "rename detected");
            True(st.Subnets.All(s => s.NicName == "Bench") && st.Nud[0].NicName == "Bench", "subnet and NUD records renamed");
            Eq("WLAN", st.Gateways.Single().NicName, "gateway renamed");
        }

        // ---------------------------------------------------------------- Planner.Build
        static void TestPlanBlocksHoldsAndDisablesNud()
        {
            var snap = Snap(Wifi(), Lab());
            var plan = Planner.Build(Learned(snap), snap);
            Eq("Wi-Fi", string.Join(",", plan.Rules.Keys), "one rule, on the gateway NIC");
            Eq("192.168.50.0/24,fd00:50::/64", string.Join(",", plan.Rules["Wi-Fi"].OrderBy(x => x)), "rule blocks both families");
            Eq(2, plan.Held.Count, "both subnets held");
            True(plan.Held.All(h => h.IfIndex == 2), "held on the lab NIC");
            Eq("IPv4,IPv6", string.Join(",", plan.Nud.Select(t => Net.FamilyName(t.Family)).OrderBy(x => x)), "NUD off for both families");
            True(plan.Nud.All(t => t.NicName == "Lab NIC" && t.IfIndex == 2), "NUD off on the lab NIC only");
        }

        static void TestProtectionSurvivesUnpluggedNic()
        {
            var st = Learned(Snap(Wifi(), Lab()));
            var plan = Planner.Build(st, Snap(Wifi())); // lab NIC gone (USB adapter unplugged, or before it is up at boot)
            Eq(2, plan.Rules["Wi-Fi"].Count, "still blocked on Wi-Fi");
            Eq(0, plan.Held.Count, "nothing to hold");
            Eq(0, plan.Nud.Count, "no NUD target while the NIC is absent");
        }

        static void TestStickyGatewayKeepsRuleWhileGatewayIsMissing()
        {
            var st = Learned(Snap(Wifi(), Lab()));
            var wifiNoGw = Wifi(); wifiNoGw.Gw4 = wifiNoGw.Gw6 = false; // e.g. mid-reconnect
            var plan = Planner.Build(st, Snap(wifiNoGw, Lab()));
            True(plan.Rules.ContainsKey("Wi-Fi"), "rule kept");
        }

        static void TestSuspendedWhileAnotherNicOverlaps()
        {
            var st = Learned(Snap(Wifi(), Lab()));
            var coffeeShop = Nic(1, "Wi-Fi", true, false, "192.168.50.0/24"); // same subnet as the lab, behind the gateway
            var plan = Planner.Build(st, Snap(coffeeShop));
            Eq(1, plan.Suspended.Count, "lab IPv4 subnet suspended");
            True(plan.Suspended.Values.Single().Contains("Wi-Fi"), "reason names the NIC");
            Eq("fd00:50::/64", string.Join(",", plan.Rules["Wi-Fi"]), "only the non-overlapping subnet blocked");
        }

        static void TestRuleExcludesTheGatewayNicsOwnSubnets()
        {
            var st = Learned(Snap(Wifi(), Lab()));
            var labWithRouter = Lab(); labWithRouter.Gw4 = true; // the lab LAN later gets a router
            Planner.Learn(st, Snap(Wifi(), labWithRouter), s => { });
            var plan = Planner.Build(st, Snap(Wifi(), labWithRouter));
            True(!plan.Rules.ContainsKey("Lab NIC"), "no rule blocks a NIC's own subnets (and never an empty rule)");
            Eq(2, plan.Rules["Wi-Fi"].Count, "Wi-Fi still blocks them");
        }

        // ---------------------------------------------------------------- HoldTracker
        static NeighborRow Row(string ip, int ifIndex, NeighborState s) { return new NeighborRow { Addr = A(ip), IfIndex = ifIndex, State = s }; }

        static void TestHoldTrackerHoldsAndReleases()
        {
            var held = new List<HeldSubnet> { new HeldSubnet { Prefix = P("192.168.50.0/24"), IfIndex = 2, NicName = "Lab NIC" } };
            Func<NeighborRow, string> match = r => { var h = Planner.Match(held, r); return h == null ? null : h.NicName; };
            var log = new List<string>();
            var t = new HoldTracker();
            var t0 = new DateTime(2026, 1, 1);

            var rows = new List<NeighborRow> {
                Row("192.168.50.9", 2, NeighborState.Unreachable),
                Row("192.168.1.9", 1, NeighborState.Unreachable),   // not protected
                Row("192.168.50.10", 3, NeighborState.Unreachable), // right subnet, wrong NIC
                Row("192.168.50.11", 2, NeighborState.Reachable) };
            Eq("0", string.Join(",", t.Decide(rows, match, t0, log.Add)), "only the protected Unreachable entry is deleted");
            Eq(1, log.Count, "hold logged once");

            t.Decide(new List<NeighborRow> { Row("192.168.50.9", 2, NeighborState.Unreachable) }, match, t0.AddSeconds(3), log.Add);
            Eq(1, log.Count, "re-hold is not logged again");

            Eq(0, t.Decide(new List<NeighborRow> { Row("192.168.50.9", 2, NeighborState.Incomplete) }, match, t0.AddSeconds(4), log.Add).Count, "Incomplete is left to resolve");
            Eq(0, t.Decide(new List<NeighborRow> { Row("192.168.50.9", 2, NeighborState.Delay) }, match, t0.AddSeconds(5), log.Add).Count, "Delay is not deleted");
            Eq(1, t.Count, "Delay is not a release");

            t.Decide(new List<NeighborRow> { Row("192.168.50.9", 2, NeighborState.Reachable) }, match, t0.AddSeconds(6), log.Add);
            Eq(0, t.Count, "released when Reachable");
            True(log.Last().Contains("answered") && log.Last().Contains("held 2 time(s)"), "release logged: " + log.Last());
        }

        static void TestHoldTrackerExpiresWithoutFlushingForever()
        {
            var held = new List<HeldSubnet> { new HeldSubnet { Prefix = P("fd00:50::/64"), IfIndex = 2, NicName = "Lab NIC" } };
            Func<NeighborRow, string> match = r => { var h = Planner.Match(held, r); return h == null ? null : h.NicName; };
            var log = new List<string>();
            var t = new HoldTracker();
            var t0 = new DateTime(2026, 1, 1);

            t.Decide(new List<NeighborRow> { Row("fd00:50::9", 2, NeighborState.Unreachable) }, match, t0, log.Add);
            Eq(0, t.Decide(new List<NeighborRow>(), match, t0.AddSeconds(30), log.Add).Count, "entry gone: nothing to delete, so no flush");
            Eq(1, t.Count, "still tracked within expiry");
            t.Decide(new List<NeighborRow>(), match, t0 + HoldTracker.Expiry + TimeSpan.FromSeconds(1), log.Add);
            Eq(0, t.Count, "dropped after expiry");
            True(log.Last().Contains("fd00:50::9") && log.Last().Contains("no longer tracking"), "expiry logged: " + log.Last());
        }

        // ---------------------------------------------------------------- native layouts (read-only)
        static void TestNativeLayouts()
        {
            // Loopback has NUD disabled on every Windows install; the other connected NICs have a readable value.
            Eq(false, Nud.Get(AddressFamily.InterNetwork, NetworkInterface.LoopbackInterfaceIndex), "IPv4 loopback NUD");
            Eq(false, Nud.Get(AddressFamily.InterNetworkV6, NetworkInterface.IPv6LoopbackInterfaceIndex), "IPv6 loopback NUD");
            foreach (var n in Net.Snapshot().Nics.Where(n => n.Up && n.Index4 >= 0))
                True(Nud.Get(AddressFamily.InterNetwork, n.Index4) != null, "NUD readable on " + n.Name);

            foreach (var fam in Net.Families)
            {
                int len = fam == AddressFamily.InterNetwork ? 4 : 16;
                var rows = Neighbors.Read(fam);
                True(rows.All(r => r.Addr.Length == len && r.IfIndex > 0 && (int)r.State >= 0 && (int)r.State <= 6),
                    Net.FamilyName(fam) + " neighbor rows parse");
            }
        }
    }
}
