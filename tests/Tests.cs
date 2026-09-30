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

        // ---------------------------------------------------------------- HoldTracker
        static NeighborRow Row(string ip, int ifIndex, NeighborState s) { return new NeighborRow { Addr = A(ip), IfIndex = ifIndex, State = s }; }

        // Lab subnet with the lengthened timers: RetransmitTime 10 s, so entries are reset after 15 s.
        static Func<NeighborRow, HeldSubnet> LabMatch(string prefix)
        {
            var h = new HeldSubnet { Prefix = P(prefix), IfIndex = 2, NicId = "{2}", NicName = "Lab NIC" };
            h.SetResetAfter(10000);
            var held = new List<HeldSubnet> { h };
            return r => Planner.Match(held, r);
        }
        static HoldTracker.Decision Pass(HoldTracker t, Func<NeighborRow, HeldSubnet> match, DateTime now, List<string> log, params NeighborRow[] rows)
        {
            return t.Decide(rows.ToList(), match, now, log.Add);
        }

        static void TestResetBeforeNudGivesUp()
        {
            var match = LabMatch("192.168.50.0/24");
            var log = new List<string>();
            var t = new HoldTracker();
            var t0 = new DateTime(2026, 1, 1);
            var dead = Row("192.168.50.9", 2, NeighborState.Incomplete);

            Eq(0, Pass(t, match, t0, log, dead).Delete.Count, "just started resolving");
            Eq(0, Pass(t, match, t0.AddSeconds(14.9), log, dead).Delete.Count, "still within half the budget");
            var d = Pass(t, match, t0.AddSeconds(15), log, dead);
            Eq("0", string.Join(",", d.Delete), "reset at 1.5 x RetransmitTime");
            True(!d.Flush, "never reached Unreachable, so no path-cache flush");
            True(log.Single().Contains("resetting"), "reset logged: " + log.Single());

            // Windows re-creates the entry on the next packet: a fresh countdown, and no new log line.
            Eq(0, Pass(t, match, t0.AddSeconds(16), log, dead).Delete.Count, "new countdown");
            Eq(0, Pass(t, match, t0.AddSeconds(30), log, dead).Delete.Count, "14 s into the new countdown");
            Eq(1, Pass(t, match, t0.AddSeconds(31), log, dead).Delete.Count, "reset again");
            Eq(1, log.Count, "one log line per episode");

            Pass(t, match, t0.AddSeconds(35), log, Row("192.168.50.9", 2, NeighborState.Reachable));
            Eq(0, t.Count, "released when it answers");
            True(log.Last().Contains("answered") && log.Last().Contains("reset 2, held 0"), "release logged: " + log.Last());
        }

        static void TestProbeIsResetButDelayIsNot()
        {
            var match = LabMatch("192.168.50.0/24");
            var log = new List<string>();
            var t = new HoldTracker();
            var t0 = new DateTime(2026, 1, 1);

            Pass(t, match, t0, log, Row("192.168.50.9", 2, NeighborState.Delay));
            Eq(0, Pass(t, match, t0.AddSeconds(20), log, Row("192.168.50.9", 2, NeighborState.Delay)).Delete.Count, "Delay never counts down");
            Pass(t, match, t0.AddSeconds(21), log, Row("192.168.50.9", 2, NeighborState.Probe));
            Eq(1, Pass(t, match, t0.AddSeconds(36), log, Row("192.168.50.9", 2, NeighborState.Probe)).Delete.Count, "Probe is reset like Incomplete");
        }

        static void TestCountdownRestartsWhenNeighborRecovers()
        {
            var match = LabMatch("192.168.50.0/24");
            var log = new List<string>();
            var t = new HoldTracker();
            var t0 = new DateTime(2026, 1, 1);

            Pass(t, match, t0, log, Row("192.168.50.9", 2, NeighborState.Probe));
            Pass(t, match, t0.AddSeconds(10), log, Row("192.168.50.9", 2, NeighborState.Reachable));
            Pass(t, match, t0.AddSeconds(11), log, Row("192.168.50.9", 2, NeighborState.Probe));
            Eq(0, Pass(t, match, t0.AddSeconds(20), log, Row("192.168.50.9", 2, NeighborState.Probe)).Delete.Count, "counted from the new Probe, not the old one");
            Eq(0, log.Count, "nothing to report");
        }

        static void TestUnreachableIsHeldAsBackstop()
        {
            var match = LabMatch("192.168.50.0/24");
            var log = new List<string>();
            var t = new HoldTracker();
            var t0 = new DateTime(2026, 1, 1);

            var d = Pass(t, match, t0, log,
                Row("192.168.50.9", 2, NeighborState.Unreachable),
                Row("192.168.1.9", 1, NeighborState.Unreachable),   // not protected
                Row("192.168.50.10", 3, NeighborState.Unreachable), // right subnet, wrong adapter
                Row("192.168.50.11", 2, NeighborState.Reachable));
            Eq("0", string.Join(",", d.Delete), "only the protected Unreachable entry is deleted");
            True(d.Flush, "path cache flushed: it may already point at the gateway");
            True(log.Single().Contains("marked Unreachable"), "logged: " + log.Single());

            Pass(t, match, t0.AddSeconds(5), log, Row("192.168.50.9", 2, NeighborState.Stale));
            True(log.Last().Contains("answered") && log.Last().Contains("held 1"), "release logged: " + log.Last());
        }

        static void TestEpisodeExpiresWithoutTraffic()
        {
            var match = LabMatch("fd00:50::/64");
            var log = new List<string>();
            var t = new HoldTracker();
            var t0 = new DateTime(2026, 1, 1);

            Pass(t, match, t0, log, Row("fd00:50::9", 2, NeighborState.Incomplete));
            Pass(t, match, t0.AddSeconds(15), log, Row("fd00:50::9", 2, NeighborState.Incomplete)); // reset; nothing sends to it again
            Eq(0, Pass(t, match, t0.AddSeconds(30), log).Delete.Count, "entry gone: nothing to delete");
            Eq(1, t.Count, "still tracked within expiry");
            Pass(t, match, t0.AddSeconds(15) + HoldTracker.Expiry + TimeSpan.FromSeconds(1), log);
            Eq(0, t.Count, "dropped after expiry");
            True(log.Last().Contains("fd00:50::9") && log.Last().Contains("no longer tracking"), "expiry logged: " + log.Last());
        }

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
