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

        static NicInfo Nic(int index, string name, bool gw4, bool gw6, params string[] prefixes)
        {
            return new NicInfo { Id = "{" + index + "}", Name = name, Up = true, Gw4 = gw4, Gw6 = gw6, Index4 = index, Index6 = index,
                                 Prefixes = prefixes.Select(P).ToList() };
        }
        static List<HeldSubnet> Build(params NicInfo[] nics) { return Planner.Build(new NetSnapshot { Nics = nics.ToList() }); }
        static string Held(List<HeldSubnet> held) { return string.Join(",", held.Select(h => h.Prefix + " on " + h.NicName).OrderBy(x => x)); }

        // Typical PC: an adapter with the default gateway, plus a lab adapter with none.
        static NicInfo Wan() { return Nic(1, "Ethernet", true, true, "192.168.1.0/24", "2001:db8:1::/64"); }
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

        static void TestContains()
        {
            True(P("192.168.50.0/24").Contains(A("192.168.50.200")), "v4 contains");
            True(!P("192.168.50.0/24").Contains(A("192.168.51.1")), "v4 not contains");
            True(P("172.16.0.0/12").Contains(A("172.31.0.1")) && !P("172.16.0.0/12").Contains(A("172.32.0.1")), "v4 /12 boundary");
            True(P("fd00:50::/64").Contains(A("fd00:50::1234")), "v6 contains");
            True(!P("fd00:50::/64").Contains(A("fd00:51::1")), "v6 not contains");
            True(!P("0.0.0.0/8").Contains(A("::1")), "family mismatch never contains");
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

        // ---------------------------------------------------------------- Planner
        static void TestOnlyAdaptersWithoutGatewayAreProtected()
        {
            var held = Build(Wan(), Lab());
            Eq("192.168.50.0/24 on Lab NIC,fd00:50::/64 on Lab NIC", Held(held), "lab subnets only");
            True(held.All(h => h.IfIndex == 2 && h.NicId == "{2}"), "on the lab adapter");
        }

        static void TestGatewayIsCheckedPerFamily()
        {
            // The lab LAN has an IPv6 router but no IPv4 gateway: only its IPv4 subnet is protected.
            Eq("192.168.50.0/24 on Lab NIC", Held(Build(Wan(), Nic(2, "Lab NIC", false, true, "192.168.50.0/24", "2001:db8:50::/64"))), "per family");
        }

        static void TestAdapterThatGainsAGatewayIsNotProtected()
        {
            var lab = Lab(); lab.Gw4 = lab.Gw6 = true;
            Eq("", Held(Build(Wan(), lab)), "nothing left to protect");
        }

        static void TestDisconnectedAdapterIsNotProtected()
        {
            var lab = Lab(); lab.Up = false;
            Eq("", Held(Build(Wan(), lab)), "follows the live configuration");
        }

        static void TestOverlaps()
        {
            True(P("10.0.0.0/8").Overlaps(P("10.1.1.0/24")) && P("10.1.1.0/24").Overlaps(P("10.0.0.0/8")), "contained");
            True(P("10.1.1.0/24").Overlaps(P("10.1.1.0/24")), "same");
            True(!P("10.1.1.0/24").Overlaps(P("10.1.2.0/24")), "disjoint");
            True(!P("10.1.1.0/24").Overlaps(P("fd00::/64")), "family mismatch");
        }

        static string Blockable(out string ambiguous, params NicInfo[] nics)
        {
            var snap = new NetSnapshot { Nics = nics.ToList() };
            var amb = new List<HeldSubnet>();
            var ok = Planner.Blockable(snap, Planner.Build(snap), amb);
            ambiguous = Held(amb);
            return Held(ok);
        }

        static void TestBlocksCoverProtectedSubnets()
        {
            string amb;
            Eq("192.168.50.0/24 on Lab NIC,fd00:50::/64 on Lab NIC", Blockable(out amb, Wan(), Lab()), "lab subnets blocked");
            Eq("", amb, "none ambiguous");
            Eq("", Blockable(out amb, Wan()), "no gateway-less adapter, no blocks");
        }

        static void TestOverlappingSubnetIsNotBlocked()
        {
            string amb;
            // The other adapter also has an address in 192.168.50.0/24: traffic may legitimately use either.
            var wan = Nic(1, "Ethernet", true, true, "192.168.50.0/24");
            Eq("fd00:50::/64 on Lab NIC", Blockable(out amb, wan, Lab()), "only the unique subnet is blocked");
            Eq("192.168.50.0/24 on Lab NIC", amb, "overlap reported");
            // A disconnected adapter's addresses do not count.
            wan.Up = false;
            Eq("192.168.50.0/24 on Lab NIC,fd00:50::/64 on Lab NIC", Blockable(out amb, wan, Lab()), "down adapter ignored");
        }

        // ---------------------------------------------------------------- HoldTracker
        static NeighborRow Row(string ip, int ifIndex, NeighborState s) { return new NeighborRow { Addr = A(ip), IfIndex = ifIndex, State = s }; }

        static Func<NeighborRow, HeldSubnet> LabMatch(string prefix)
        {
            var held = new List<HeldSubnet> { new HeldSubnet { Prefix = P(prefix), IfIndex = 2, NicId = "{2}", NicName = "Lab NIC" } };
            return r => Planner.Match(held, r);
        }
        static HoldTracker.Decision Pass(HoldTracker t, Func<NeighborRow, HeldSubnet> match, DateTime now, List<string> log, params NeighborRow[] rows)
        {
            return t.Decide(rows.ToList(), match, now, log.Add);
        }

        // The sequence from a real trace: Probe, Unreachable, a lookup (Incomplete) that lasts while the device
        // is down, and the answer when it is back. Nothing but Unreachable is ever deleted.
        static void TestFailingNeighborIsWatchedAndHeld()
        {
            var match = LabMatch("192.168.50.0/24");
            var log = new List<string>();
            var t = new HoldTracker();
            var t0 = new DateTime(2026, 1, 1);

            var d = Pass(t, match, t0, log, Row("192.168.50.9", 2, NeighborState.Probe));
            True(d.Delete.Count == 0 && !d.Flush, "Probe: delete nothing");
            True(log.Single().Contains("watching it") && log.Single().Contains("Probe"), "logged: " + log.Single());

            d = Pass(t, match, t0.AddSeconds(9), log, Row("192.168.50.9", 2, NeighborState.Probe));
            True(d.Delete.Count == 0 && !d.Flush, "A normal Probe is never deleted");

            d = Pass(t, match, t0.AddSeconds(30), log, Row("192.168.50.9", 2, NeighborState.Unreachable));
            Eq("0", string.Join(",", d.Delete), "Unreachable is held");
            True(d.Flush, "path cache flushed");
            True(log.Last().Contains("marked Unreachable"), "logged: " + log.Last());

            for (int s = 31; s <= 32; s++)
            {
                d = Pass(t, match, t0.AddSeconds(s), log, Row("192.168.50.9", 2, NeighborState.Incomplete));
                True(d.Delete.Count == 0, "a fresh Incomplete is left alone (" + s + " s)");
            }
            for (int i = 0; i < 5; i++)
                Pass(t, match, t0.AddSeconds(32.1 + i * 0.016), log, Row("192.168.50.9", 2, NeighborState.Unreachable));
            Eq(2, log.Count, "no more log lines while it is down, even if Unreachable keeps coming back");

            d = Pass(t, match, t0.AddSeconds(95), log, Row("192.168.50.9", 2, NeighborState.Reachable));
            Eq(0, t.Count, "released when it answers");
            True(log.Last().Contains("answered") && log.Last().Contains("cleared 6 time(s)"),"release logged: " + log.Last());
        }

        static void TestStuckNeighborIsReset()
        {
            var match = LabMatch("192.168.50.0/24");
            var log = new List<string>();
            var t = new HoldTracker();
            var t0 = new DateTime(2026, 1, 1);
            Pass(t, match, t0, log, Row("192.168.50.9", 2, NeighborState.Incomplete));
            var d = Pass(t, match, t0.AddSeconds(1), log, Row("192.168.50.9", 2, NeighborState.Incomplete));
            True(d.Delete.Count == 0 && !d.Flush, "not stuck yet");
            d = Pass(t, match, t0.AddSeconds(2.5), log, Row("192.168.50.9", 2, NeighborState.Incomplete));
            True(d.Delete.Count == 1 && d.Flush, "stuck: entry deleted and path cache flushed");
            True(log.Last().Contains("clearing its entry"), "logged: " + log.Last());
            d = Pass(t, match, t0.AddSeconds(3.5), log, Row("192.168.50.9", 2, NeighborState.Incomplete));
            True(d.Delete.Count == 0, "the countdown restarts after a reset");
        }

        static void TestOnlyProtectedNeighborsCount()
        {
            var match = LabMatch("192.168.50.0/24");
            var log = new List<string>();
            var t = new HoldTracker();
            var d = Pass(t, match, new DateTime(2026, 1, 1), log,
                Row("192.168.1.9", 1, NeighborState.Unreachable),   // not protected
                Row("192.168.50.10", 3, NeighborState.Unreachable), // right subnet, wrong adapter
                Row("192.168.50.11", 2, NeighborState.Reachable),
                Row("192.168.50.12", 2, NeighborState.Delay),       // Delay does not fail by itself
                Row("192.168.50.13", 2, NeighborState.Stale));
            True(d.Delete.Count == 0 && !d.Flush && log.Count == 0 && t.Count == 0, "nothing to do");
        }

        static void TestEpisodeExpiresWithoutTraffic()
        {
            var match = LabMatch("fd00:50::/64");
            var log = new List<string>();
            var t = new HoldTracker();
            var t0 = new DateTime(2026, 1, 1);

            Pass(t, match, t0, log, Row("fd00:50::9", 2, NeighborState.Unreachable)); // held; nothing sends to it again
            AssertIdle(Pass(t, match, t0.AddSeconds(30), log));
            Eq(1, t.Count, "still tracked within expiry");
            Pass(t, match, t0 + HoldTracker.Expiry + TimeSpan.FromSeconds(1), log);
            Eq(0, t.Count, "dropped after expiry");
            True(log.Last().Contains("fd00:50::9") && log.Last().Contains("no longer tracking"), "expiry logged: " + log.Last());
        }
        static void AssertIdle(HoldTracker.Decision d) { True(d.Delete.Count == 0, "entry gone: nothing to do"); }

        // ---------------------------------------------------------------- native layouts (read-only)
        static void TestNativeLayouts()
        {
            // Every connected adapter has readable NUD timers in a sane range (loopback included).
            int b, rt;
            True(NudTimers.Get(AddressFamily.InterNetwork, NetworkInterface.LoopbackInterfaceIndex, out b, out rt), "loopback timers readable");
            foreach (var n in Net.Snapshot().Nics.Where(n => n.Up && n.Index4 >= 0))
                True(NudTimers.Get(AddressFamily.InterNetwork, n.Index4, out b, out rt) && b >= 1000 && b <= 3600000 && rt >= 100 && rt <= 60000,
                    string.Format("timers on {0}: {1} / {2}", n.Name, b, rt));

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
