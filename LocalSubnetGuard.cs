// LocalSubnetGuard - works around Neighbor Unreachability Detection (NUD) failover, so traffic for
// directly-connected subnets stays on their adapter instead of leaking to the default gateway.
//
// Windows treats an on-link destination whose neighbor entry is Unreachable as unroutable on that
// adapter and sends it to the next best route - normally the default gateway on another adapter.
// NUD itself cannot be turned off: netsh lists a 'nud' interface parameter, but setting it to
// disabled fails with "The parameter is incorrect". So instead, for every connected adapter without
// a default gateway (checked per address family, IPv4 and IPv6):
//
//  1. Slow NUD  its NUD timers are lengthened (base reachable time 120 s, retransmit time 10 s, in the
//               active store only, so a reboot resets them), so a neighbor that goes quiet for less than
//               about 30 s is never marked Unreachable. The original values are put back when the
//               service stops or the adapter gains a default gateway.
//  2. Hold      a neighbor in one of the adapter's subnets that is marked Unreachable anyway has its
//               entry deleted and the path cache flushed, so Windows re-resolves it on the local adapter
//               instead of re-routing it. While a neighbor is failing (Probe or Incomplete) the neighbor
//               table is polled every 100 ms instead of every interval, so this happens within ~100 ms.
//               Unreachable itself cannot be prevented: deleting an entry that is in Probe or Incomplete
//               makes Windows mark it Unreachable at once.
//
// Everything follows the live network configuration; nothing is blocked or remembered.
//
// Build: build.cmd (uses the .NET Framework 4.x csc.exe that ships with Windows).
//
// Usage (elevated, except status):
//   LocalSubnetGuard.exe install [intervalMs] [slowtimers]   install + start as a Windows service (default 500 ms)
//   LocalSubnetGuard.exe uninstall              stop + remove the service (restores the NUD timers)
//   LocalSubnetGuard.exe run [intervalMs] [trace]
//                                               run in this console (Ctrl+C to stop and restore the timers);
//                                               'trace' also logs every state change of protected neighbors
//   LocalSubnetGuard.exe status                 show adapters, protected subnets, NUD timers and neighbors

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Threading;

namespace LocalSubnetGuard
{
    static class Program
    {
        public const string ServiceName = "LocalSubnetGuard";
        public const int DefaultIntervalMs = 500;

        static int Main(string[] args)
        {
            int rc = Run(args);
            Log.Flush();
            return rc;
        }

        static int Run(string[] args)
        {
            string cmd = args.Length > 0 ? args[0].ToLowerInvariant().TrimStart('-', '/') : "help";
            int interval;
            switch (cmd)
            {
                case "service":
                    ServiceBase.Run(new GuardService(ParseInterval(args, out interval) ? interval : DefaultIntervalMs, HasFlag(args, "slowtimers")));
                    return 0;
                case "status":
                    return Status();
                case "install":
                case "run":
                {
                    bool trace = cmd == "run" && HasFlag(args, "trace"), slow = HasFlag(args, "slowtimers");
                    var rest = args.Where(a => !a.Equals("trace", StringComparison.OrdinalIgnoreCase) && !a.Equals("slowtimers", StringComparison.OrdinalIgnoreCase)).ToArray();
                    if (!ParseInterval(rest, out interval)) { Console.Error.WriteLine("intervalMs must be 50-60000."); return 1; }
                    if (!IsAdmin()) return NotAdmin();
                    return cmd == "install" ? Setup.Install(interval, slow) : RunConsole(interval, trace, slow);
                }
                case "uninstall":
                    if (!IsAdmin()) return NotAdmin();
                    return Setup.Uninstall();
                case "wfptest":
                    if (!IsAdmin()) return NotAdmin();
                    return WfpTest(args);
                case "help": case "h": case "?":
                    Help(); return 0;
                default:
                    Help(); return 1;
            }
        }

        static bool HasFlag(string[] args, string flag)
        {
            return args.Skip(1).Any(a => a.Equals(flag, StringComparison.OrdinalIgnoreCase));
        }

        // The optional interval is always args[1].
        static bool ParseInterval(string[] args, out int v)
        {
            v = DefaultIntervalMs;
            if (args.Length < 2) return true;
            return int.TryParse(args[1], out v) && v >= 50 && v <= 60000;
        }

        static bool IsAdmin()
        {
            return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        }

        static int NotAdmin()
        {
            Console.Error.WriteLine("Run this from an elevated (Administrator) prompt.");
            return 5;
        }

        static void Help()
        {
            Console.WriteLine(
@"LocalSubnetGuard - keep connected-subnet traffic on its adapter (works around NUD failover)

  LocalSubnetGuard.exe install [intervalMs] [slowtimers]   install + start the service (default 500 ms)
  LocalSubnetGuard.exe uninstall              stop + remove the service (restores the NUD timers)
  LocalSubnetGuard.exe run [intervalMs] [trace]
                                              run in this console (Ctrl+C to stop and restore the timers);
                                              'trace' also logs every state change of protected neighbors
  LocalSubnetGuard.exe status                 show adapters, protected subnets, NUD timers and neighbors
  LocalSubnetGuard.exe wfptest <cidr> on|except <adapter>
                                              diagnostic: block outbound packets to <cidr> leaving through
                                              <adapter> (on) or any other adapter (except), until Enter

Log: " + Log.PathName);
        }

        static int RunConsole(int intervalMs, bool trace, bool slowTimers)
        {
            if (Setup.ServiceRunning())
            {
                Console.Error.WriteLine("The {0} service is running; stop it first (sc stop {0}).", ServiceName);
                return 1;
            }
            Log.Echo = true;
            var g = new Guard(intervalMs) { Trace = trace, SlowTimers = slowTimers };
            var done = new ManualResetEvent(false);
            Console.CancelKeyPress += (s, e) => { e.Cancel = true; done.Set(); };
            g.Start();
            Log.Write("Running in console. Ctrl+C to stop.");
            done.WaitOne();
            g.Stop(true);
            return 0;
        }

        // Diagnostic: adds one WFP block filter until Enter is pressed (or the process ends in any way).
        static int WfpTest(string[] args)
        {
            Prefix p;
            if (args.Length != 4 || !Prefix.TryParse(args[1], out p) || (args[2] != "on" && args[2] != "except"))
            {
                Console.Error.WriteLine("Usage: LocalSubnetGuard.exe wfptest <cidr> on|except <adapter name>");
                return 1;
            }
            bool except = args[2] == "except";
            var nics = Net.Snapshot().Nics;
            var nic = nics.FirstOrDefault(n => n.Name.Equals(args[3], StringComparison.OrdinalIgnoreCase));
            if (nic == null || nic.Index(p.Family) < 0)
            {
                Console.Error.WriteLine("No adapter '{0}' with {1}. Adapters: {2}", args[3], Net.FamilyName(p.Family),
                    string.Join(", ", nics.Select(n => "'" + n.Name + "'")));
                return 1;
            }
            try
            {
                using (var wfp = Wfp.Open())
                {
                    Console.WriteLine("Layer OK: {0}", wfp.CheckLayer(p.Family));
                    string what = except ? string.Format("to {0} leaving through any adapter except '{1}' (loopback allowed)", p, nic.Name)
                                         : string.Format("to {0} leaving through '{1}'", p, nic.Name);
                    ulong id = wfp.AddBlock(p, Wfp.LuidOf(nic.Index(p.Family)), except, "LocalSubnetGuard wfptest");
                    Console.WriteLine("Blocking outbound packets {0} (filter id {1}).", what, id);
                    Console.WriteLine("Press Enter to remove it. Ctrl+C or closing the window removes it too.");
                    Console.ReadLine();
                }
                Console.WriteLine("Filter removed.");
                return 0;
            }
            catch (InvalidOperationException ex)
            {
                Console.Error.WriteLine("WFP: " + ex.Message);
                return 1;
            }
        }

        static int Status()
        {
            var snap = Net.Snapshot();
            var held = Planner.Build(snap);

            Console.WriteLine("Connected adapters:");
            foreach (var n in snap.Nics.Where(n => n.Up))
            {
                string gw = n.Gw4 && n.Gw6 ? "IPv4+IPv6" : n.Gw4 ? "IPv4" : n.Gw6 ? "IPv6" : "none";
                Console.WriteLine("  [{0}] {1}  (default gateway: {2})  {3}", n.Index4 >= 0 ? n.Index4 : n.Index6, n.Name, gw,
                    n.Prefixes.Count == 0 ? "-" : string.Join(", ", n.Prefixes));
            }

            Console.WriteLine("Protected subnets (neighbors marked Unreachable are held on the adapter):");
            if (held.Count == 0) Console.WriteLine("  (none: every connected adapter has a default gateway)");
            foreach (var h in held)
            {
                int b, r;
                string timers = !NudTimers.Get(h.Prefix.Family, h.IfIndex, out b, out r) ? "unknown"
                    : string.Format("base reachable {0} ms, retransmit {1} ms{2}", b, r, NudTimers.IsTuned(b, r) ? " (lengthened)" : "");
                Console.WriteLine("  {0,-22} on [{1}] {2}  NUD timers: {3}", h.Prefix, h.IfIndex, h.NicName, timers);
            }

            Console.WriteLine("Neighbors in protected subnets:");
            foreach (var fam in Net.Families)
                foreach (var n in Neighbors.Read(fam))
                    if (Planner.Match(held, n) != null)
                        Console.WriteLine("  {0,-28} [{1}] {2}", n.Address, n.IfIndex, n.State);

            if (Setup.ServiceExists())
                using (var sc = new ServiceController(ServiceName)) Console.WriteLine("Service: " + sc.Status);
            else
                Console.WriteLine("Service: not installed");
            return 0;
        }
    }

    // ------------------------------------------------------------------ service
    class GuardService : ServiceBase
    {
        readonly Guard _g;
        public GuardService(int intervalMs, bool slowTimers)
        {
            ServiceName = Program.ServiceName;
            CanStop = true;
            CanShutdown = true;
            _g = new Guard(intervalMs) { SlowTimers = slowTimers };
        }
        protected override void OnStart(string[] args) { _g.Start(); }
        protected override void OnStop() { _g.Stop(true); }
        protected override void OnShutdown() { _g.Stop(false); } // the active-store timers reset at reboot anyway
    }

    // ------------------------------------------------------------------ core loop
    class Guard
    {
        class Tuned { public string NicId, NicName; public AddressFamily Family; public int OrigBase, OrigRetransmit; }

        const int FastIntervalMs = 100; // poll interval while a protected neighbor is failing

        readonly int _intervalMs;
        readonly HoldTracker _hold4 = new HoldTracker(), _hold6 = new HoldTracker();
        readonly Dictionary<string, Tuned> _tuned = new Dictionary<string, Tuned>(); // adapter id|family -> original timers
        readonly HashSet<string> _tuneFailures = new HashSet<string>();
        readonly Dictionary<string, NeighborState> _traced = new Dictionary<string, NeighborState>(); // trace: last state seen
        volatile List<HeldSubnet> _held = new List<HeldSubnet>();
        string _lastSig;

        // WFP block filters, one per protected subnet (key: prefix|adapter LUID). The dynamic session removes them
        // by itself if this process dies, so a crash can never leave a subnet blocked.
        Wfp _wfp;
        readonly Dictionary<string, ulong> _filters = new Dictionary<string, ulong>();
        string _wfpError, _lastAmbiguous = "";

        public bool SlowTimers; // lengthen the NUD timers on protected adapters (off by default)
        public bool Trace; // log every state change of protected neighbors, and every entry deleted
        volatile bool _refresh = true;
        Thread _thread, _configThread; // the hold loop must never wait for the (slower) configuration refresh
        readonly ManualResetEvent _stop = new ManualResetEvent(false);

        public Guard(int intervalMs) { _intervalMs = intervalMs; }

        public void Start()
        {
            Log.Write(string.Format("Starting (interval {0} ms).", _intervalMs));
            DataDir.Secure();
            Legacy.Cleanup();
            NetworkChange.NetworkAddressChanged += OnNetChange;
            NetworkChange.NetworkAvailabilityChanged += OnNetAvailability;
            _thread = new Thread(Loop) { IsBackground = true, Name = "LocalSubnetGuard" };
            _configThread = new Thread(ConfigLoop) { IsBackground = true, Name = "LocalSubnetGuard-config" };
            _thread.Start();
            _configThread.Start();
        }

        // With restoreTimers, NUD timers go back to their original values on every adapter still present.
        public void Stop(bool restoreTimers)
        {
            NetworkChange.NetworkAddressChanged -= OnNetChange;
            NetworkChange.NetworkAvailabilityChanged -= OnNetAvailability;
            _stop.Set();
            if (_thread != null) _thread.Join(5000);
            if (_configThread != null) _configThread.Join(5000);
            DropWfp();
            if (restoreTimers)
            {
                var snap = Net.Snapshot();
                foreach (var t in _tuned.Values)
                {
                    var nic = snap.Find(t.NicId);
                    if (nic != null && nic.Index(t.Family) >= 0) RestoreTimers(t, nic.Index(t.Family));
                }
                _tuned.Clear();
            }
            Log.Write("Stopped.");
        }

        void OnNetChange(object s, EventArgs e) { _refresh = true; }
        void OnNetAvailability(object s, NetworkAvailabilityEventArgs e) { _refresh = true; }

        // Hold loop: only reads the neighbor table and deletes failing entries. It never waits for anything slow.
        void Loop()
        {
            while (!_stop.WaitOne(0))
            {
                bool urgent = false;
                var sw = Stopwatch.StartNew();
                try { urgent = Tick(); }
                catch (Exception ex) { Log.Write("ERROR: " + ex.Message); }
                if (sw.ElapsedMilliseconds > 500) Log.Write(string.Format("WARNING: a hold pass took {0} ms", sw.ElapsedMilliseconds));
                _stop.WaitOne(urgent ? Math.Min(FastIntervalMs, _intervalMs) : _intervalMs);
            }
        }

        // Configuration loop: follows the live network configuration (adapters, NUD timers, WFP filters) on every
        // network change and every 5 seconds. It can be slow (netsh, WFP, adapter enumeration) without delaying the hold.
        void ConfigLoop()
        {
            while (!_stop.WaitOne(0))
            {
                _refresh = false;
                var sw = Stopwatch.StartNew();
                try { Refresh(); }
                catch (Exception ex) { Log.Write("ERROR: " + ex.Message); }
                if (sw.ElapsedMilliseconds > 1000) Log.Write(string.Format("WARNING: a configuration refresh took {0} ms", sw.ElapsedMilliseconds));
                for (int i = 0; i < 50 && !_refresh && !_stop.WaitOne(100); i++) { }
            }
        }

        void Refresh()
        {
            var snap = Net.Snapshot();
            var held = Planner.Build(snap);
            ApplyTimers(snap, held);
            ApplyBlocks(snap, held);
            string sig = string.Join(", ", held.Select(h =>
            {
                int b, r;
                return string.Format("{0} on '{1}' (NUD timers {2})", h.Prefix, h.NicName,
                    NudTimers.Get(h.Prefix.Family, h.IfIndex, out b, out r) ? string.Format("{0} / {1} ms", b, r) : "unknown");
            }));
            if (sig != _lastSig)
            {
                _lastSig = sig;
                Log.Write(sig == "" ? "Nothing to protect: every connected adapter has a default gateway." : "Protecting " + sig + ".");
            }
            _held = held;
        }

        void DropWfp()
        {
            _filters.Clear();
            if (_wfp != null) { _wfp.Dispose(); _wfp = null; }
        }

        // Makes the WFP filters match the protected subnets: each one gets a filter that drops outbound packets
        // to it that would leave through any adapter but its own. Even while NUD has a neighbor Unreachable,
        // nothing for the subnet can leak to the default gateway. Runs on every refresh, so it also repairs
        // filters lost to a Base Filtering Engine restart.
        void ApplyBlocks(NetSnapshot snap, List<HeldSubnet> held)
        {
            var ambiguous = new List<HeldSubnet>();
            var want = new Dictionary<string, HeldSubnet>();
            foreach (var h in Planner.Blockable(snap, held, ambiguous))
            {
                try { want[h.Prefix + "|" + Wfp.LuidOf(h.IfIndex)] = h; }
                catch (InvalidOperationException ex) { Log.Write("ERROR: " + ex.Message); }
            }
            string amb = string.Join(", ", ambiguous.Select(h => h.Prefix + " on '" + h.NicName + "'"));
            if (amb != _lastAmbiguous)
            {
                _lastAmbiguous = amb;
                if (amb != "") Log.Write("WARNING: not blocking " + amb + ": another connected adapter has an address in the same range.");
            }

            try
            {
                if (_wfp != null && _filters.Values.Any(id => !_wfp.Exists(id)))
                {
                    Log.Write("WARNING: the WFP filters disappeared (Base Filtering Engine restarted?); reinstalling them.");
                    DropWfp();
                }
                if (want.Count == 0 && _wfp == null) { _wfpError = null; return; }
                if (_wfp == null) _wfp = Wfp.Open();
                _wfpError = null;

                foreach (var key in _filters.Keys.ToList())
                    if (!want.ContainsKey(key))
                    {
                        _wfp.Remove(_filters[key]);
                        _filters.Remove(key);
                        Log.Write("Unblocked " + key.Substring(0, key.IndexOf('|')) + ".");
                    }
                foreach (var kv in want)
                {
                    if (_filters.ContainsKey(kv.Key)) continue;
                    var h = kv.Value;
                    _filters[kv.Key] = _wfp.AddBlock(h.Prefix, Wfp.LuidOf(h.IfIndex), true, "LocalSubnetGuard " + h.Prefix);
                    Log.Write(string.Format("Blocking {0} from leaving through any adapter but '{1}'.", h.Prefix, h.NicName));
                }
                if (want.Count == 0) DropWfp();
            }
            catch (InvalidOperationException ex)
            {
                DropWfp(); // reopen from scratch on the next refresh
                if (ex.Message != _wfpError) { _wfpError = ex.Message; Log.Write("ERROR: WFP block failed: " + ex.Message + " (will retry)"); }
            }
        }

        // Lengthens the NUD timers of every protected (adapter, family), and puts the originals back on
        // adapters that no longer qualify. Adapters that are not present keep their entry until they return.
        void ApplyTimers(NetSnapshot snap, List<HeldSubnet> held)
        {
            var groups = held.GroupBy(h => h.NicId + "|" + Net.FamilyName(h.Prefix.Family)).ToDictionary(g => g.Key, g => g.First());
            if (!SlowTimers)
            {
                // Lengthened timers make Windows wait up to 10 s before asking again for a device that comes
                // back, so leave them at their defaults - and undo them if an earlier run left them lengthened.
                foreach (var h in groups.Values)
                {
                    int b, r;
                    if (NudTimers.Get(h.Prefix.Family, h.IfIndex, out b, out r) && NudTimers.IsTuned(b, r))
                        RestoreTimers(new Tuned { NicName = h.NicName, Family = h.Prefix.Family,
                            OrigBase = NudTimers.DefaultBaseReachableMs, OrigRetransmit = NudTimers.DefaultRetransmitMs }, h.IfIndex);
                }
            }
            var targets = SlowTimers ? groups : new Dictionary<string, HeldSubnet>();
            foreach (var kv in targets)
            {
                var h = kv.Value;
                var fam = h.Prefix.Family;
                int b, r;
                if (!NudTimers.Get(fam, h.IfIndex, out b, out r)) continue;
                if (!_tuned.ContainsKey(kv.Key))
                {
                    // Already at our values means an earlier run was not stopped cleanly: its originals are unknown,
                    // so assume the Windows defaults.
                    bool leftover = NudTimers.IsTuned(b, r);
                    _tuned[kv.Key] = new Tuned { NicId = h.NicId, NicName = h.NicName, Family = fam,
                        OrigBase = leftover ? NudTimers.DefaultBaseReachableMs : b, OrigRetransmit = leftover ? NudTimers.DefaultRetransmitMs : r };
                }
                if (NudTimers.IsTuned(b, r)) continue;

                string err = NudTimers.Set(fam, h.IfIndex, NudTimers.TunedBaseReachableMs, NudTimers.TunedRetransmitMs);
                if (err == null)
                {
                    _tuneFailures.Remove(kv.Key);
                    Log.Write(string.Format("NUD timers on '{0}' ({1}) lengthened to base reachable {2} ms, retransmit {3} ms (were {4} / {5} ms).",
                        h.NicName, Net.FamilyName(fam), NudTimers.TunedBaseReachableMs, NudTimers.TunedRetransmitMs, b, r));
                }
                else if (_tuneFailures.Add(kv.Key))
                    Log.Write(string.Format("ERROR: could not lengthen NUD timers on '{0}' ({1}): {2}", h.NicName, Net.FamilyName(fam), err));
            }
            foreach (var key in _tuned.Keys.ToList())
            {
                if (targets.ContainsKey(key)) continue;
                var t = _tuned[key];
                var nic = snap.Find(t.NicId);
                if (nic == null || nic.Index(t.Family) < 0) continue;
                RestoreTimers(t, nic.Index(t.Family));
                _tuned.Remove(key);
            }
        }

        static void RestoreTimers(Tuned t, int ifIndex)
        {
            string err = NudTimers.Set(t.Family, ifIndex, t.OrigBase, t.OrigRetransmit);
            Log.Write(err == null
                ? string.Format("NUD timers on '{0}' ({1}) restored to base reachable {2} ms, retransmit {3} ms.", t.NicName, Net.FamilyName(t.Family), t.OrigBase, t.OrigRetransmit)
                : string.Format("ERROR: could not restore NUD timers on '{0}' ({1}): {2}", t.NicName, Net.FamilyName(t.Family), err));
        }

        // Returns true while a protected neighbor is failing (Probe, Incomplete or Unreachable), so the loop
        // polls fast and catches it being marked Unreachable within FastIntervalMs.
        bool Tick()
        {
            var all = _held;
            bool urgent = false;
            foreach (var fam in Net.Families)
            {
                var held = all.Where(h => h.Prefix.Family == fam).ToList();
                var tracker = fam == AddressFamily.InterNetwork ? _hold4 : _hold6;
                if (held.Count == 0 && tracker.Count == 0) continue;
                bool flush = false;
                var rows = Neighbors.Scan(fam, table =>
                {
                    var d = tracker.Decide(table, r => Planner.Match(held, r), DateTime.UtcNow, Log.Write);
                    flush = d.Flush;
                    if (d.Urgent) urgent = true;
                    return d.Delete;
                }, (r, rc) =>
                {
                    if (rc != 0) Log.Write(string.Format("ERROR: could not delete the neighbor entry for {0} ({1}): error {2}", r.Address, r.State, rc));
                    else if (Trace) Log.Write(string.Format("trace: deleted {0} [{1}] ({2})", r.Address, r.IfIndex, r.State));
                });
                if (flush)
                {
                    int rc = Neighbors.FlushPathCache(fam);
                    if (Trace || rc != 0) Log.Write(string.Format("{0}flushed the {1} path cache (result {2})", rc == 0 ? "trace: " : "ERROR: ", Net.FamilyName(fam), rc));
                }
                if (Trace) TraceStates(rows.Where(r => Planner.Match(held, r) != null), fam);
            }
            return urgent;
        }

        // Logs each state change of a protected neighbor (as read at the start of this pass).
        void TraceStates(IEnumerable<NeighborRow> rows, AddressFamily fam)
        {
            var seen = new HashSet<string>();
            foreach (var r in rows)
            {
                seen.Add(r.Key);
                NeighborState last;
                bool known = _traced.TryGetValue(r.Key, out last);
                if (!known || last != r.State)
                    Log.Write(string.Format("trace: {0} [{1}] {2} -> {3}", r.Address, r.IfIndex, known ? last.ToString() : "(new)", r.State));
                _traced[r.Key] = r.State;
            }
            bool v6 = fam == AddressFamily.InterNetworkV6; // only IPv6 keys contain ':'
            foreach (var key in _traced.Keys.Where(k => !seen.Contains(k) && k.Contains(':') == v6).ToList())
            {
                Log.Write(string.Format("trace: {0} {1} -> (gone)", key, _traced[key]));
                _traced.Remove(key);
            }
        }
    }

    // Catches NUD giving up on a neighbor in a protected subnet. Windows marks a neighbor Unreachable after
    // about 3 x RetransmitTime of unanswered probes (state Probe) or solicitations (state Incomplete), and
    // from then on routes its traffic to the default gateway. That cannot be prevented: deleting an entry in
    // Probe or Incomplete makes Windows mark it Unreachable at once (seen in traces). So while a protected
    // neighbor is in one of those states the caller polls fast (Decision.Urgent), and the moment one is
    // marked Unreachable its entry is deleted and the caller flushes the path cache, so Windows re-resolves
    // it on the local adapter. An episode ends when the neighbor answers, or after Expiry without it being
    // seen in Probe, Incomplete or Unreachable (no more traffic to it).
    class HoldTracker
    {
        class Episode { public string Nic; public DateTime Since, LastSeen; public int Holds; public NeighborState State = (NeighborState)(-1); public DateTime StateSince; }

        public class Decision { public List<int> Delete = new List<int>(); public bool Flush, Urgent; }

        public static readonly TimeSpan Expiry = TimeSpan.FromSeconds(60);
        // Windows leaves Incomplete after ~3 s and Probe after at most ~8 s. A neighbor that stays in either far
        // longer is stuck (traces showed it staying Incomplete while traffic leaked to the blocked gateway):
        // its entry is deleted so resolution starts over.
        public static readonly TimeSpan StuckAfterIncomplete = TimeSpan.FromSeconds(5), StuckAfterProbe = TimeSpan.FromSeconds(12);
        readonly Dictionary<string, Episode> _episodes = new Dictionary<string, Episode>();

        public int Count { get { return _episodes.Count; } }

        public Decision Decide(IList<NeighborRow> rows, Func<NeighborRow, HeldSubnet> protecting, DateTime now, Action<string> log)
        {
            var d = new Decision();
            for (int i = 0; i < rows.Count; i++)
            {
                var r = rows[i];
                var h = protecting(r);
                if (h == null) continue;
                if (r.State == NeighborState.Probe || r.State == NeighborState.Incomplete)
                {
                    d.Urgent = true;
                    var e = Touch(r, h, now, log, "{0} is not answering on '{1}' ({2}) - watching it closely");
                    if (e.State != r.State) { e.State = r.State; e.StateSince = now; }
                    else if (now - e.StateSince > (r.State == NeighborState.Incomplete ? StuckAfterIncomplete : StuckAfterProbe))
                    {
                        d.Delete.Add(i);
                        d.Flush = true;
                        log(string.Format("{0} has been in state {1} on '{2}' for {3:0}s - resetting its entry", r.Address, r.State, h.NicName, (now - e.StateSince).TotalSeconds));
                        e.StateSince = now;
                    }
                }
                else if (r.State == NeighborState.Unreachable)
                {
                    d.Delete.Add(i);
                    d.Flush = true;
                    d.Urgent = true;
                    var e = Touch(r, h, now, log, null);
                    if (e.State != r.State) { e.State = r.State; e.StateSince = now; }
                    // Windows re-creates the entry as Unreachable while traffic continues: log only the first hold.
                    if (e.Holds++ == 0)
                        log(string.Format("{0} was marked Unreachable on '{1}' - holding it on the local adapter (repeats are not logged)", r.Address, h.NicName));
                }
                else if (r.State == NeighborState.Reachable || r.State == NeighborState.Stale || r.State == NeighborState.Permanent)
                {
                    Episode e;
                    if (_episodes.TryGetValue(r.Key, out e))
                    {
                        log(string.Format("{0} answered on '{1}' ({2}) after {3:0.0}s, held {4} time(s)",
                            r.Address, e.Nic, r.State, (now - e.Since).TotalSeconds, e.Holds));
                        _episodes.Remove(r.Key);
                    }
                }
            }
            foreach (var kv in _episodes.Where(kv => now - kv.Value.LastSeen > Expiry).ToList())
            {
                log(string.Format("{0} on '{1}' has had no traffic for {2:0}s; no longer tracking it",
                    kv.Key.Substring(0, kv.Key.IndexOf('%')), kv.Value.Nic, Expiry.TotalSeconds));
                _episodes.Remove(kv.Key);
            }
            return d;
        }

        // Starts an episode (logging firstMessage, if any, formatted with address, adapter and state) or continues it.
        Episode Touch(NeighborRow r, HeldSubnet h, DateTime now, Action<string> log, string firstMessage)
        {
            Episode e;
            if (!_episodes.TryGetValue(r.Key, out e))
            {
                _episodes[r.Key] = e = new Episode { Nic = h.NicName, Since = now };
                if (firstMessage != null) log(string.Format(firstMessage, r.Address, h.NicName, r.State));
            }
            e.LastSeen = now;
            return e;
        }
    }

    // ------------------------------------------------------------------ planning (pure; unit tested)
    class HeldSubnet { public Prefix Prefix; public int IfIndex; public string NicId, NicName; }

    static class Planner
    {
        // The connected subnets of every connected adapter without a default gateway for that family.
        // Built from the live configuration only.
        public static List<HeldSubnet> Build(NetSnapshot snap)
        {
            var held = new List<HeldSubnet>();
            foreach (var n in snap.Nics.Where(n => n.Up))
                foreach (var p in n.Prefixes)
                {
                    int idx = n.Index(p.Family);
                    if (idx >= 0 && !n.HasGateway(p.Family))
                        held.Add(new HeldSubnet { Prefix = p, IfIndex = idx, NicId = n.Id, NicName = n.Name });
                }
            return held;
        }

        // The protected subnets that can safely get a "never leave through another adapter" block: those that
        // no other connected adapter also has an address in. Where subnets overlap, traffic legitimately
        // leaves through either adapter, so those are only skipped (and returned in `ambiguous`).
        public static List<HeldSubnet> Blockable(NetSnapshot snap, List<HeldSubnet> held, List<HeldSubnet> ambiguous)
        {
            var ok = new List<HeldSubnet>();
            foreach (var h in held)
            {
                bool overlap = snap.Nics.Any(n => n.Up && !string.Equals(n.Id, h.NicId, StringComparison.OrdinalIgnoreCase) &&
                                                  n.Prefixes.Any(p => p.Overlaps(h.Prefix)));
                (overlap ? ambiguous : ok).Add(h);
            }
            return ok;
        }

        public static HeldSubnet Match(IEnumerable<HeldSubnet> held, NeighborRow n)
        {
            return held.FirstOrDefault(h => h.IfIndex == n.IfIndex && h.Prefix.Contains(n.Addr));
        }
    }

    // ------------------------------------------------------------------ addresses and network discovery
    class Prefix : IEquatable<Prefix>
    {
        readonly byte[] _net;
        public readonly int Length;

        public Prefix(byte[] addr, int length)
        {
            Length = length;
            _net = (byte[])addr.Clone();
            for (int i = 0; i < _net.Length; i++)
                _net[i] &= (byte)(0xFF00 >> Math.Max(0, Math.Min(8, length - i * 8)));
        }

        public AddressFamily Family { get { return _net.Length == 4 ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6; } }
        public byte[] NetworkBytes { get { return (byte[])_net.Clone(); } }

        // True if the two prefixes share any address (one contains the other).
        public bool Overlaps(Prefix o)
        {
            if (o._net.Length != _net.Length) return false;
            return Length <= o.Length ? Contains(o._net) : o.Contains(_net);
        }

        public bool Contains(byte[] addr)
        {
            if (addr.Length != _net.Length) return false;
            for (int i = 0, bits = Length; bits > 0; i++, bits -= 8)
                if (((addr[i] ^ _net[i]) & (0xFF00 >> Math.Min(8, bits))) != 0) return false;
            return true;
        }

        public override string ToString() { return new IPAddress(_net) + "/" + Length; }
        public bool Equals(Prefix o) { return (object)o != null && o.Length == Length && o._net.SequenceEqual(_net); }
        public override bool Equals(object o) { return Equals(o as Prefix); }
        public override int GetHashCode() { return ToString().GetHashCode(); }

        public static bool TryParse(string s, out Prefix p)
        {
            p = null;
            int slash = s.IndexOf('/'), len;
            IPAddress a;
            if (slash < 0 || !IPAddress.TryParse(s.Substring(0, slash), out a) || !int.TryParse(s.Substring(slash + 1), out len)) return false;
            byte[] b = a.GetAddressBytes();
            if (len < 0 || len > b.Length * 8) return false;
            p = new Prefix(b, len);
            return true;
        }

        // The connected subnet of an interface address, or null for addresses that are never protected:
        // loopback, link-local, multicast, host-only prefixes and very large prefixes.
        public static Prefix OfInterfaceAddress(IPAddress a, int len)
        {
            byte[] b = a.GetAddressBytes();
            if (a.AddressFamily == AddressFamily.InterNetwork)
            {
                if (b[0] == 127 || (b[0] == 169 && b[1] == 254) || len < 8 || len > 31) return null;
            }
            else if (a.AddressFamily == AddressFamily.InterNetworkV6)
            {
                if (IPAddress.IsLoopback(a) || a.IsIPv6LinkLocal || a.IsIPv6SiteLocal || a.IsIPv6Multicast ||
                    a.IsIPv4MappedToIPv6 || len < 16 || len > 127) return null;
            }
            else return null;
            return new Prefix(b, len);
        }
    }

    class NicInfo
    {
        public string Id, Name;
        public bool Up, Gw4, Gw6;
        public int Index4 = -1, Index6 = -1; // -1: protocol not bound
        public List<Prefix> Prefixes = new List<Prefix>(); // only filled while Up

        public int Index(AddressFamily f) { return f == AddressFamily.InterNetwork ? Index4 : Index6; }
        public bool HasGateway(AddressFamily f) { return f == AddressFamily.InterNetwork ? Gw4 : Gw6; }
    }

    class NetSnapshot
    {
        public List<NicInfo> Nics = new List<NicInfo>();
        public NicInfo Find(string id) { return Nics.FirstOrDefault(n => string.Equals(n.Id, id, StringComparison.OrdinalIgnoreCase)); }
    }

    static class Net
    {
        public static readonly AddressFamily[] Families = { AddressFamily.InterNetwork, AddressFamily.InterNetworkV6 };

        public static ushort Af(AddressFamily f) { return (ushort)(f == AddressFamily.InterNetwork ? 2 : 23); } // AF_INET, AF_INET6
        public static string FamilyName(AddressFamily f) { return f == AddressFamily.InterNetwork ? "IPv4" : "IPv6"; }

        // Every adapter except loopback and transition tunnels (Teredo, 6to4, ISATAP, IP-HTTPS).
        public static NetSnapshot Snapshot()
        {
            var snap = new NetSnapshot();
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback || nic.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;
                IPInterfaceProperties p;
                try { p = nic.GetIPProperties(); } catch { continue; }
                var n = new NicInfo { Id = nic.Id, Name = nic.Name, Up = nic.OperationalStatus == OperationalStatus.Up };
                try { var v4 = p.GetIPv4Properties(); if (v4 != null) n.Index4 = v4.Index; } catch { }
                try { var v6 = p.GetIPv6Properties(); if (v6 != null) n.Index6 = v6.Index; } catch { }
                if (n.Index4 < 0 && n.Index6 < 0) continue;

                if (n.Up)
                {
                    foreach (var g in p.GatewayAddresses)
                    {
                        if (g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any)) n.Gw4 = true;
                        if (g.Address.AddressFamily == AddressFamily.InterNetworkV6 && !g.Address.Equals(IPAddress.IPv6Any)) n.Gw6 = true;
                    }
                    foreach (var ua in p.UnicastAddresses)
                    {
                        if (ua.DuplicateAddressDetectionState == DuplicateAddressDetectionState.Duplicate) continue;
                        var pre = Prefix.OfInterfaceAddress(ua.Address, ua.PrefixLength);
                        if (pre != null && !n.Prefixes.Contains(pre)) n.Prefixes.Add(pre);
                    }
                }
                snap.Nics.Add(n);
            }
            return snap;
        }
    }

    // ------------------------------------------------------------------ NUD timers
    // Windows marks a neighbor Unreachable after its unicast probes (sent RetransmitTime apart) go
    // unanswered. Lengthening RetransmitTime and BaseReachableTime means a neighbor has to be silent for
    // much longer - and is probed much less often - before that happens.
    static class NudTimers
    {
        public const int TunedBaseReachableMs = 120000, TunedRetransmitMs = 10000;
        public const int DefaultBaseReachableMs = 30000, DefaultRetransmitMs = 1000;

        // MIB_IPINTERFACE_ROW (168 bytes): Family @0, InterfaceLuid @8, InterfaceIndex @16, ...,
        //   BaseReachableTime @60, RetransmitTime @64, ...
        const int RowSize = 168, OffIndex = 16, OffBaseReachable = 60, OffRetransmit = 64;

        [DllImport("iphlpapi.dll")] static extern void InitializeIpInterfaceEntry(IntPtr row);
        [DllImport("iphlpapi.dll")] static extern int GetIpInterfaceEntry(IntPtr row);

        public static bool IsTuned(int baseReachable, int retransmit)
        {
            return baseReachable == TunedBaseReachableMs && retransmit == TunedRetransmitMs;
        }

        public static bool Get(AddressFamily f, int ifIndex, out int baseReachable, out int retransmit)
        {
            baseReachable = retransmit = 0;
            IntPtr row = Marshal.AllocHGlobal(RowSize);
            try
            {
                InitializeIpInterfaceEntry(row);
                Marshal.WriteInt16(row, 0, (short)Net.Af(f));
                Marshal.WriteInt32(row, OffIndex, ifIndex);
                if (GetIpInterfaceEntry(row) != 0) return false;
                baseReachable = Marshal.ReadInt32(row, OffBaseReachable);
                retransmit = Marshal.ReadInt32(row, OffRetransmit);
                return true;
            }
            finally { Marshal.FreeHGlobal(row); }
        }

        // Sets both timers in the active store only (they reset at reboot) and reads them back.
        // Returns null on success, else what went wrong.
        public static string Set(AddressFamily f, int ifIndex, int baseReachable, int retransmit)
        {
            string output;
            int rc = Setup.Run("netsh.exe", string.Format("interface {0} set interface {1} basereachabletime={2} retransmittime={3} store=active",
                Net.FamilyName(f).ToLowerInvariant(), ifIndex, baseReachable, retransmit), out output);
            if (rc != 0) return string.Format("netsh exit {0}: {1}", rc, output.Trim());
            int b, r;
            if (!Get(f, ifIndex, out b, out r) || b != baseReachable || r != retransmit)
                return string.Format("netsh reported success but the timers are {0} / {1} ms", b, r);
            return null;
        }
    }

    // ------------------------------------------------------------------ Windows Filtering Platform
    // Outbound block filters at the OUTBOUND_IPPACKET layers: they see every packet (not just the first of a
    // connection, like firewall rules), after routing, so the adapter a packet leaves through is known. They
    // are added in a dynamic session, so the Base Filtering Engine removes them by itself when the engine
    // handle is closed or this process exits for any reason - they can never outlive the program.
    sealed class Wfp : IDisposable
    {
        static readonly Guid LayerOutboundIpPacketV4 = new Guid("1e5c9fae-8a84-4135-a331-950b54229ecd");
        static readonly Guid LayerOutboundIpPacketV6 = new Guid("a3b3ab6b-3564-488c-9117-f34e82142763");
        static readonly Guid CondIpRemoteAddress = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
        static readonly Guid CondIpLocalInterface = new Guid("4cd62a49-59c3-4969-b7f3-bda5d32890a4");
        static readonly Guid CondFlags = new Guid("632ce23b-5167-435c-86d7-e903684aa80c");
        static readonly Guid SubLayerKey = new Guid("dde24a5d-af73-4e90-b7e9-a8a8b7173dbd"); // ours

        const uint RpcAuthnDefault = 0xFFFFFFFF, SessionFlagDynamic = 1;
        const uint FwpEmpty = 0, FwpUint32 = 3, FwpUint64 = 4, FwpV4AddrMask = 0x100, FwpV6AddrMask = 0x101;
        const uint MatchEqual = 0, MatchFlagsNoneSet = 8, MatchNotEqual = 10;
        const uint ActionBlock = 0x1001;           // FWP_ACTION_BLOCK (0x1 | FWP_ACTION_FLAG_TERMINATING)
        const uint ConditionFlagIsLoopback = 1;    // FWP_CONDITION_FLAG_IS_LOOPBACK

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct DisplayData { public string Name; public string Description; }
        [StructLayout(LayoutKind.Sequential)] struct ByteBlob { public uint Size; public IntPtr Data; }
        [StructLayout(LayoutKind.Sequential)] struct Value { public uint Type; public ulong Data; } // FWP_VALUE0 / FWP_CONDITION_VALUE0
        [StructLayout(LayoutKind.Sequential)] struct Condition { public Guid FieldKey; public uint MatchType; public Value ConditionValue; }
        [StructLayout(LayoutKind.Sequential)] struct Action { public uint Type; public Guid FilterType; }

        [StructLayout(LayoutKind.Sequential)]
        struct Session
        {
            public Guid SessionKey; public DisplayData DisplayData; public uint Flags; public uint TxnWaitTimeoutInMSec;
            public uint ProcessId; public IntPtr Sid; public IntPtr Username; public int KernelMode;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SubLayer
        {
            public Guid SubLayerKey; public DisplayData DisplayData; public uint Flags; public IntPtr ProviderKey;
            public ByteBlob ProviderData; public ushort Weight;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct Filter
        {
            public Guid FilterKey; public DisplayData DisplayData; public uint Flags; public IntPtr ProviderKey;
            public ByteBlob ProviderData; public Guid LayerKey; public Guid SubLayerKey; public Value Weight;
            public uint NumFilterConditions; public IntPtr FilterCondition; public Action Action;
            public ulong ProviderContext, ProviderContextHigh; // union { UINT64 rawContext; GUID providerContextKey; }
            public IntPtr Reserved; public ulong FilterId; public Value EffectiveWeight;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct Layer
        {
            public Guid LayerKey; public IntPtr Name, Description; public uint Flags; public uint NumFields;
            public IntPtr Field; public Guid DefaultSubLayerKey; public ushort LayerId;
        }
        [StructLayout(LayoutKind.Sequential)] struct Field { public IntPtr FieldKey; public uint Type; public uint DataType; }

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
        static extern uint FwpmEngineOpen0(string serverName, uint authnService, IntPtr authIdentity, ref Session session, out IntPtr engine);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr engine);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerAdd0(IntPtr engine, ref SubLayer subLayer, IntPtr sd);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterAdd0(IntPtr engine, ref Filter filter, IntPtr sd, out ulong id);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDeleteById0(IntPtr engine, ulong id);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterGetById0(IntPtr engine, ulong id, out IntPtr filter);
        [DllImport("fwpuclnt.dll")] static extern uint FwpmLayerGetByKey0(IntPtr engine, ref Guid key, out IntPtr layer);
        [DllImport("fwpuclnt.dll")] static extern void FwpmFreeMemory0(ref IntPtr p);
        [DllImport("iphlpapi.dll")] static extern int ConvertInterfaceIndexToLuid(uint ifIndex, out ulong luid);

        IntPtr _engine;

        Wfp(IntPtr engine) { _engine = engine; }

        public static Wfp Open()
        {
            var session = new Session { DisplayData = new DisplayData { Name = "LocalSubnetGuard" }, Flags = SessionFlagDynamic };
            IntPtr engine;
            Check(FwpmEngineOpen0(null, RpcAuthnDefault, IntPtr.Zero, ref session, out engine), "open the filtering engine");
            var wfp = new Wfp(engine);
            var sub = new SubLayer { SubLayerKey = SubLayerKey, Weight = 0xFFFF,
                DisplayData = new DisplayData { Name = "LocalSubnetGuard", Description = "Keeps connected-subnet traffic on its adapter." } };
            try { Check(FwpmSubLayerAdd0(engine, ref sub, IntPtr.Zero), "add the sublayer"); }
            catch { wfp.Dispose(); throw; }
            return wfp;
        }

        static Guid LayerFor(AddressFamily f) { return f == AddressFamily.InterNetwork ? LayerOutboundIpPacketV4 : LayerOutboundIpPacketV6; }

        // Confirms the outbound IP packet layer for a family exists and has every field the filters use.
        // Returns the layer's display name; throws with the details if not.
        public string CheckLayer(AddressFamily f)
        {
            Guid key = LayerFor(f);
            IntPtr p;
            Check(FwpmLayerGetByKey0(_engine, ref key, out p), "find the " + Net.FamilyName(f) + " outbound IP packet layer " + key);
            try
            {
                var layer = (Layer)Marshal.PtrToStructure(p, typeof(Layer));
                var fields = new HashSet<Guid>();
                int size = Marshal.SizeOf(typeof(Field));
                for (int i = 0; i < layer.NumFields; i++)
                {
                    var fld = (Field)Marshal.PtrToStructure(new IntPtr(layer.Field.ToInt64() + (long)i * size), typeof(Field));
                    fields.Add((Guid)Marshal.PtrToStructure(fld.FieldKey, typeof(Guid)));
                }
                foreach (var need in new[] { CondIpRemoteAddress, CondIpLocalInterface, CondFlags })
                    if (!fields.Contains(need)) throw new InvalidOperationException("layer " + key + " has no field " + need);
                return Marshal.PtrToStringUni(layer.Name);
            }
            finally { FwpmFreeMemory0(ref p); }
        }

        // Blocks outbound packets to `remote` that leave through the adapter with this LUID (except = false),
        // or through any adapter but that one (except = true; loopback traffic, e.g. to this PC's own address,
        // is never blocked). Returns the filter id.
        public ulong AddBlock(Prefix remote, ulong ifLuid, bool except, string name)
        {
            var mem = new List<IntPtr>();
            try
            {
                byte[] net = remote.NetworkBytes;
                IntPtr addr;
                uint addrType;
                if (remote.Family == AddressFamily.InterNetwork)
                {
                    addr = Alloc(mem, 8); // FWP_V4_ADDR_AND_MASK { UINT32 addr; UINT32 mask; } in host byte order
                    Marshal.WriteInt32(addr, 0, (int)((uint)net[0] << 24 | (uint)net[1] << 16 | (uint)net[2] << 8 | net[3]));
                    Marshal.WriteInt32(addr, 4, (int)Subnet4Mask(remote.Length));
                    addrType = FwpV4AddrMask;
                }
                else
                {
                    addr = Alloc(mem, 17); // FWP_V6_ADDR_AND_MASK { UINT8 addr[16]; UINT8 prefixLength; }
                    Marshal.Copy(net, 0, addr, 16);
                    Marshal.WriteByte(addr, 16, (byte)remote.Length);
                    addrType = FwpV6AddrMask;
                }
                IntPtr luid = Alloc(mem, 8);
                Marshal.WriteInt64(luid, (long)ifLuid);

                var conds = new List<Condition>
                {
                    new Condition { FieldKey = CondIpRemoteAddress, MatchType = MatchEqual, ConditionValue = new Value { Type = addrType, Data = (ulong)addr.ToInt64() } },
                    new Condition { FieldKey = CondIpLocalInterface, MatchType = except ? MatchNotEqual : MatchEqual, ConditionValue = new Value { Type = FwpUint64, Data = (ulong)luid.ToInt64() } },
                };
                if (except)
                    conds.Add(new Condition { FieldKey = CondFlags, MatchType = MatchFlagsNoneSet, ConditionValue = new Value { Type = FwpUint32, Data = ConditionFlagIsLoopback } });

                int size = Marshal.SizeOf(typeof(Condition));
                IntPtr arr = Alloc(mem, size * conds.Count);
                for (int i = 0; i < conds.Count; i++) Marshal.StructureToPtr(conds[i], new IntPtr(arr.ToInt64() + (long)i * size), false);

                var filter = new Filter
                {
                    FilterKey = Guid.NewGuid(),
                    DisplayData = new DisplayData { Name = name, Description = "Managed by LocalSubnetGuard; removed when it stops." },
                    LayerKey = LayerFor(remote.Family),
                    SubLayerKey = SubLayerKey,
                    Weight = new Value { Type = FwpEmpty },
                    NumFilterConditions = (uint)conds.Count,
                    FilterCondition = arr,
                    Action = new Action { Type = ActionBlock },
                };
                ulong id;
                Check(FwpmFilterAdd0(_engine, ref filter, IntPtr.Zero, out id), "add the filter");
                return id;
            }
            finally { foreach (var p in mem) Marshal.FreeHGlobal(p); }
        }

        // True if the filter is still installed. False if it is gone or the engine no longer answers
        // (e.g. the Base Filtering Engine was restarted, which drops every dynamic filter).
        public bool Exists(ulong id)
        {
            IntPtr p;
            if (FwpmFilterGetById0(_engine, id, out p) != 0) return false;
            FwpmFreeMemory0(ref p);
            return true;
        }

        public void Remove(ulong id) { Check(FwpmFilterDeleteById0(_engine, id), "remove filter " + id); }

        static uint Subnet4Mask(int len) { return len == 0 ? 0u : uint.MaxValue << (32 - len); }

        static IntPtr Alloc(List<IntPtr> mem, int size)
        {
            IntPtr p = Marshal.AllocHGlobal(size);
            for (int i = 0; i < size; i++) Marshal.WriteByte(p, i, 0);
            mem.Add(p);
            return p;
        }

        public static ulong LuidOf(int ifIndex)
        {
            ulong luid;
            int rc = ConvertInterfaceIndexToLuid((uint)ifIndex, out luid);
            if (rc != 0) throw new InvalidOperationException(string.Format("could not get the LUID of interface {0}: error {1}", ifIndex, rc));
            return luid;
        }

        static void Check(uint rc, string what)
        {
            if (rc != 0) throw new InvalidOperationException(string.Format("could not {0}: error 0x{1:X8}", what, rc));
        }

        // Closing the dynamic session's engine handle removes everything it added.
        public void Dispose()
        {
            if (_engine != IntPtr.Zero) { FwpmEngineClose0(_engine); _engine = IntPtr.Zero; }
        }
    }

    // ------------------------------------------------------------------ neighbor table (IP Helper)
    enum NeighborState { Unreachable = 0, Incomplete = 1, Probe = 2, Delay = 3, Stale = 4, Reachable = 5, Permanent = 6 }

    class NeighborRow
    {
        public byte[] Addr; public int IfIndex; public NeighborState State;
        public string Address { get { return new IPAddress(Addr).ToString(); } }
        public string Key { get { return Address + "%" + IfIndex; } }
    }

    static class Neighbors
    {
        // MIB_IPNET_TABLE2: ULONG NumEntries; (pad) MIB_IPNET_ROW2 Table[] at offset 8
        // MIB_IPNET_ROW2 (88 bytes): SOCKADDR_INET Address @0 (28), InterfaceIndex @28, InterfaceLuid @32,
        //   PhysicalAddress[32] @40, PhysicalAddressLength @72, State @76, Flags @80, ReachabilityTime @84
        // SOCKADDR_IN: family @0, port @2, addr @4 (4 bytes). SOCKADDR_IN6: family @0, port @2, flowinfo @4, addr @8 (16 bytes).
        const int TableOffset = 8, RowSize = 88, OffIndex = 28, OffState = 76;

        [DllImport("iphlpapi.dll")] static extern int GetIpNetTable2(ushort family, out IntPtr table);
        [DllImport("iphlpapi.dll")] static extern void FreeMibTable(IntPtr memory);
        [DllImport("iphlpapi.dll")] static extern int DeleteIpNetEntry2(IntPtr row);
        [DllImport("iphlpapi.dll")] static extern int FlushIpPathTable(ushort family);

        public static List<NeighborRow> Read(AddressFamily f) { return Scan(f, null, null); }

        // Reads the neighbor table; the entries whose indices `pick` returns are deleted (never Permanent ones),
        // and `deleted` is told each one's Win32 result.
        public static List<NeighborRow> Scan(AddressFamily f, Func<List<NeighborRow>, IEnumerable<int>> pick, Action<NeighborRow, int> deleted)
        {
            var rows = new List<NeighborRow>();
            var ptrs = new List<IntPtr>();
            ushort af = Net.Af(f);
            int addrOff = af == 2 ? 4 : 8, addrLen = af == 2 ? 4 : 16;
            IntPtr t;
            if (GetIpNetTable2(af, out t) != 0) return rows;
            try
            {
                int n = Marshal.ReadInt32(t);
                for (int i = 0; i < n; i++)
                {
                    IntPtr row = new IntPtr(t.ToInt64() + TableOffset + (long)i * RowSize);
                    if ((ushort)Marshal.ReadInt16(row, 0) != af) continue;
                    var addr = new byte[addrLen];
                    Marshal.Copy(IntPtr.Add(row, addrOff), addr, 0, addrLen);
                    rows.Add(new NeighborRow { Addr = addr, IfIndex = Marshal.ReadInt32(row, OffIndex), State = (NeighborState)Marshal.ReadInt32(row, OffState) });
                    ptrs.Add(row);
                }
                if (pick != null)
                    foreach (int i in pick(rows))
                        if (rows[i].State != NeighborState.Permanent)
                        {
                            int rc = DeleteIpNetEntry2(ptrs[i]);
                            if (deleted != null) deleted(rows[i], rc);
                        }
            }
            finally { FreeMibTable(t); }
            return rows;
        }

        public static int FlushPathCache(AddressFamily f) { return FlushIpPathTable(Net.Af(f)); }
    }

    // ------------------------------------------------------------------ cleanup of earlier versions
    static class Legacy
    {
        const string FirewallGroup = "LocalSubnetGuard";

        // Earlier versions added outbound Windows Firewall block rules and kept a state file; remove both.
        public static void Cleanup()
        {
            try
            {
                dynamic pol = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
                var names = new List<string>();
                foreach (dynamic r in pol.Rules)
                {
                    string g = null;
                    try { g = r.Grouping; } catch { }
                    if (g == FirewallGroup) names.Add((string)r.Name);
                }
                foreach (var name in names) pol.Rules.Remove(name);
                if (names.Count > 0) Log.Write(string.Format("Removed {0} firewall rule(s) left by an earlier version.", names.Count));
            }
            catch (Exception ex) { Log.Write("WARNING: could not check for old firewall rules: " + ex.Message); }
            try { File.Delete(Path.Combine(DataDir.Location, "state.txt")); } catch { }
        }
    }

    // ------------------------------------------------------------------ install / uninstall
    static class Setup
    {
        static string InstallDir { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "LocalSubnetGuard"); } }

        // Runs a tool and returns its exit code. Its output is shown if it fails (unless showFailure is false).
        static int Run(string file, string args, bool showFailure = true)
        {
            string output;
            int rc = Run(file, args, out output);
            if (rc != 0 && showFailure)
                Console.Error.WriteLine("{0} {1} failed (exit {2}):{3}{4}", file, args, rc, Environment.NewLine, output.Trim());
            return rc;
        }

        public static int Run(string file, string args, out string output)
        {
            var psi = new ProcessStartInfo(file, args) { UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true };
            using (var p = Process.Start(psi))
            {
                var err = p.StandardError.ReadToEndAsync(); // read both streams concurrently so neither can fill up and block
                output = p.StandardOutput.ReadToEnd() + err.Result;
                p.WaitForExit();
                return p.ExitCode;
            }
        }

        public static bool ServiceExists()
        {
            return ServiceController.GetServices().Any(s => s.ServiceName.Equals(Program.ServiceName, StringComparison.OrdinalIgnoreCase));
        }

        public static bool ServiceRunning()
        {
            if (!ServiceExists()) return false;
            using (var sc = new ServiceController(Program.ServiceName)) return sc.Status != ServiceControllerStatus.Stopped;
        }

        static void StopService()
        {
            if (!ServiceExists()) return;
            using (var sc = new ServiceController(Program.ServiceName))
            {
                if (sc.Status != ServiceControllerStatus.Stopped)
                {
                    try { sc.Stop(); sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20)); } catch { }
                }
            }
        }

        // The service process can hold the exe for a moment after it reports Stopped.
        static void CopyWithRetry(string src, string dst)
        {
            for (int i = 0; ; i++)
            {
                try { File.Copy(src, dst, true); return; }
                catch (IOException) { if (i >= 20) throw; Thread.Sleep(500); }
            }
        }

        public static int Install(int intervalMs, bool slowTimers)
        {
            // Retire the earlier PowerShell implementation (a scheduled task of the same name) if it is still installed.
            if (Run("schtasks.exe", "/Query /TN LocalSubnetGuard", false) == 0)
            {
                Run("schtasks.exe", "/End /TN LocalSubnetGuard", false);
                Run("schtasks.exe", "/Delete /TN LocalSubnetGuard /F");
                Console.WriteLine("Removed old PowerShell scheduled task 'LocalSubnetGuard'.");
            }

            StopService();
            DataDir.Secure();
            Directory.CreateDirectory(InstallDir);
            string src = Assembly.GetExecutingAssembly().Location;
            string dst = Path.Combine(InstallDir, "LocalSubnetGuard.exe");
            if (!string.Equals(Path.GetFullPath(src), Path.GetFullPath(dst), StringComparison.OrdinalIgnoreCase))
                CopyWithRetry(src, dst);

            string bin = "\\\"" + dst + "\\\" service " + intervalMs + (slowTimers ? " slowtimers" : "");
            int rc = ServiceExists()
                ? Run("sc.exe", "config " + Program.ServiceName + " binPath= \"" + bin + "\" start= auto depend= BFE")
                : Run("sc.exe", "create " + Program.ServiceName + " binPath= \"" + bin + "\" start= auto depend= BFE DisplayName= \"Local Subnet Guard\"");
            if (rc != 0) return 1;

            Run("sc.exe", "description " + Program.ServiceName + " \"Keeps connected-subnet traffic on its adapter; works around NUD failover to the default gateway.\"");
            Run("sc.exe", "failure " + Program.ServiceName + " reset= 86400 actions= restart/5000/restart/5000/restart/5000");

            using (var sc = new ServiceController(Program.ServiceName))
            {
                sc.Start();
                sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(20));
            }
            Console.WriteLine("Installed to " + dst + " and started (interval " + intervalMs + " ms).");
            Console.WriteLine("Log: " + Log.PathName);
            return 0;
        }

        public static int Uninstall()
        {
            StopService();
            if (ServiceExists() && Run("sc.exe", "delete " + Program.ServiceName) != 0) return 1;
            Log.Echo = true;
            Legacy.Cleanup();
            Console.WriteLine("Service removed. (" + InstallDir + " left in place.)");
            return 0;
        }
    }

    // ------------------------------------------------------------------ %ProgramData%\LocalSubnetGuard (log)
    static class DataDir
    {
        public static string Location
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "LocalSubnetGuard"); }
        }

        // SYSTEM and Administrators get full control, Users read-only, so non-admins cannot tamper with the log.
        public static void Secure()
        {
            try
            {
                Directory.CreateDirectory(Location);
                var sec = new DirectorySecurity();
                sec.SetAccessRuleProtection(true, false);
                foreach (var ace in new[] {
                    new { Sid = WellKnownSidType.LocalSystemSid, Rights = FileSystemRights.FullControl },
                    new { Sid = WellKnownSidType.BuiltinAdministratorsSid, Rights = FileSystemRights.FullControl },
                    new { Sid = WellKnownSidType.BuiltinUsersSid, Rights = FileSystemRights.ReadAndExecute } })
                    sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(ace.Sid, null), ace.Rights,
                        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                Directory.SetAccessControl(Location, sec);
            }
            catch (Exception ex) { Log.Write("WARNING: could not secure " + Location + ": " + ex.Message); }
        }
    }

    // ------------------------------------------------------------------ logging
    // Writes happen on a background thread, so a blocked console (e.g. text selected in a QuickEdit window)
    // or a slow disk can never stall the guard.
    static class Log
    {
        public static bool Echo;
        static readonly object _lock = new object();
        static readonly System.Collections.Concurrent.BlockingCollection<string> _queue = new System.Collections.Concurrent.BlockingCollection<string>();
        static Thread _writer;
        public static string PathName { get { return Path.Combine(DataDir.Location, "LocalSubnetGuard.log"); } }

        public static void Write(string msg)
        {
            string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff") + "  " + msg;
            lock (_lock)
            {
                if (_writer == null)
                {
                    _writer = new Thread(Drain) { IsBackground = true, Name = "LocalSubnetGuard-log" };
                    _writer.Start();
                }
            }
            try { _queue.Add(line); } catch (InvalidOperationException) { } // already shut down
        }

        // Waits (briefly) for queued lines to be written; call before the process exits.
        public static void Flush()
        {
            Thread w;
            lock (_lock) { w = _writer; }
            if (w == null) return;
            try { _queue.CompleteAdding(); } catch { }
            w.Join(2000);
        }

        static void Drain()
        {
            foreach (var line in _queue.GetConsumingEnumerable())
            {
                if (Echo) { try { Console.WriteLine(line); } catch { } }
                try
                {
                    Directory.CreateDirectory(DataDir.Location);
                    var fi = new FileInfo(PathName);
                    if (fi.Exists && fi.Length > 1024 * 1024)
                    {
                        string old = PathName + ".1";
                        if (File.Exists(old)) File.Delete(old);
                        File.Move(PathName, old);
                    }
                    File.AppendAllText(PathName, line + Environment.NewLine);
                }
                catch { }
            }
        }
    }
}
