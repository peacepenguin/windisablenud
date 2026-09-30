// LocalSubnetGuard - works around Neighbor Unreachability Detection (NUD) failover, so traffic for
// directly-connected subnets stays on their adapter instead of leaking to the default gateway.
//
// Windows treats an on-link destination whose neighbor entry is Unreachable as unroutable on that
// adapter and sends it to the next best route - normally the default gateway on another adapter.
// NUD itself cannot be turned off: netsh lists a 'nud' interface parameter, but setting it to
// disabled fails with "The parameter is incorrect". So instead, for every connected adapter without
// a default gateway (checked per address family, IPv4 and IPv6), this service watches the neighbor
// table: when a neighbor in one of the adapter's subnets is marked Unreachable, its entry is deleted
// and the path cache flushed, so Windows re-resolves it on the local adapter instead of re-routing it.
// It keeps doing that until the neighbor answers again.
//
// Everything follows the live network configuration; nothing is blocked, changed or remembered.
//
// Build: build.cmd (uses the .NET Framework 4.x csc.exe that ships with Windows).
//
// Usage (elevated, except status):
//   LocalSubnetGuard.exe install [intervalMs]   install + start as a Windows service (default 250 ms)
//   LocalSubnetGuard.exe uninstall              stop + remove the service
//   LocalSubnetGuard.exe run [intervalMs]       run in this console (Ctrl+C to stop)
//   LocalSubnetGuard.exe status                 show adapters, protected subnets and their neighbors

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
        public const int DefaultIntervalMs = 250;

        static int Main(string[] args)
        {
            string cmd = args.Length > 0 ? args[0].ToLowerInvariant().TrimStart('-', '/') : "help";
            int interval;
            switch (cmd)
            {
                case "service":
                    ServiceBase.Run(new GuardService(ParseInterval(args, out interval) ? interval : DefaultIntervalMs));
                    return 0;
                case "status":
                    return Status();
                case "install":
                case "run":
                    if (!ParseInterval(args, out interval)) { Console.Error.WriteLine("intervalMs must be 50-60000."); return 1; }
                    if (!IsAdmin()) return NotAdmin();
                    return cmd == "install" ? Setup.Install(interval) : RunConsole(interval);
                case "uninstall":
                    if (!IsAdmin()) return NotAdmin();
                    return Setup.Uninstall();
                case "help": case "h": case "?":
                    Help(); return 0;
                default:
                    Help(); return 1;
            }
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

  LocalSubnetGuard.exe install [intervalMs]   install + start the service (default 250 ms)
  LocalSubnetGuard.exe uninstall              stop + remove the service
  LocalSubnetGuard.exe run [intervalMs]       run in this console (Ctrl+C to stop)
  LocalSubnetGuard.exe status                 show adapters, protected subnets and their neighbors

Log: " + Log.PathName);
        }

        static int RunConsole(int intervalMs)
        {
            if (Setup.ServiceRunning())
            {
                Console.Error.WriteLine("The {0} service is running; stop it first (sc stop {0}).", ServiceName);
                return 1;
            }
            Log.Echo = true;
            var g = new Guard(intervalMs);
            var done = new ManualResetEvent(false);
            Console.CancelKeyPress += (s, e) => { e.Cancel = true; done.Set(); };
            g.Start();
            Log.Write("Running in console. Ctrl+C to stop.");
            done.WaitOne();
            g.Stop();
            return 0;
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

            Console.WriteLine("Protected subnets (Unreachable neighbors are held on the adapter):");
            if (held.Count == 0) Console.WriteLine("  (none: every connected adapter has a default gateway)");
            foreach (var h in held) Console.WriteLine("  {0,-22} on [{1}] {2}", h.Prefix, h.IfIndex, h.NicName);

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
        public GuardService(int intervalMs)
        {
            ServiceName = Program.ServiceName;
            CanStop = true;
            CanShutdown = true;
            _g = new Guard(intervalMs);
        }
        protected override void OnStart(string[] args) { _g.Start(); }
        protected override void OnStop() { _g.Stop(); }
        protected override void OnShutdown() { _g.Stop(); }
    }

    // ------------------------------------------------------------------ core loop
    class Guard
    {
        readonly int _intervalMs;
        readonly HoldTracker _hold4 = new HoldTracker(), _hold6 = new HoldTracker();
        List<HeldSubnet> _held = new List<HeldSubnet>();
        string _lastSig;
        volatile bool _refresh = true;
        DateTime _nextRefresh = DateTime.MinValue;
        Thread _thread;
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
            _thread.Start();
        }

        public void Stop()
        {
            NetworkChange.NetworkAddressChanged -= OnNetChange;
            NetworkChange.NetworkAvailabilityChanged -= OnNetAvailability;
            _stop.Set();
            if (_thread != null) _thread.Join(5000);
            Log.Write("Stopped.");
        }

        void OnNetChange(object s, EventArgs e) { _refresh = true; }
        void OnNetAvailability(object s, NetworkAvailabilityEventArgs e) { _refresh = true; }

        void Loop()
        {
            while (!_stop.WaitOne(0))
            {
                try
                {
                    if (_refresh || DateTime.UtcNow >= _nextRefresh)
                    {
                        _refresh = false;
                        _nextRefresh = DateTime.UtcNow.AddSeconds(5);
                        Refresh();
                    }
                    Tick();
                }
                catch (Exception ex) { Log.Write("ERROR: " + ex.Message); }
                _stop.WaitOne(_intervalMs);
            }
        }

        void Refresh()
        {
            var held = Planner.Build(Net.Snapshot());
            string sig = string.Join(", ", held.Select(h => h.Prefix + " on '" + h.NicName + "'"));
            if (sig != _lastSig)
            {
                _lastSig = sig;
                Log.Write(sig == "" ? "Nothing to protect: every connected adapter has a default gateway." : "Protecting " + sig + ".");
            }
            _held = held;
        }

        void Tick()
        {
            var all = _held;
            foreach (var fam in Net.Families)
            {
                var held = all.Where(h => h.Prefix.Family == fam).ToList();
                var tracker = fam == AddressFamily.InterNetwork ? _hold4 : _hold6;
                if (held.Count == 0 && tracker.Count == 0) continue;
                int deleted = 0;
                Neighbors.Scan(fam, rows =>
                {
                    var del = tracker.Decide(rows, r => { var h = Planner.Match(held, r); return h == null ? null : h.NicName; },
                                             DateTime.UtcNow, Log.Write);
                    deleted = del.Count;
                    return del;
                });
                if (deleted > 0) Neighbors.FlushPathCache(fam);
            }
        }
    }

    // Tracks neighbors in protected subnets that NUD marked Unreachable. Each pass it returns the
    // entries to delete; a neighbor is released when it answers again, and forgotten once it has not
    // been marked Unreachable for Expiry (no more traffic to it).
    class HoldTracker
    {
        class Entry { public string Nic; public DateTime Since, LastHeld; public int Holds; }

        public static readonly TimeSpan Expiry = TimeSpan.FromSeconds(60);
        readonly Dictionary<string, Entry> _held = new Dictionary<string, Entry>();

        public int Count { get { return _held.Count; } }

        public List<int> Decide(IList<NeighborRow> rows, Func<NeighborRow, string> protectingNic, DateTime now, Action<string> log)
        {
            var delete = new List<int>();
            for (int i = 0; i < rows.Count; i++)
            {
                var r = rows[i];
                string nic = protectingNic(r);
                if (nic == null) continue;
                Entry e;
                _held.TryGetValue(r.Key, out e);
                if (r.State == NeighborState.Unreachable)
                {
                    if (e == null)
                    {
                        _held[r.Key] = e = new Entry { Nic = nic, Since = now };
                        log(string.Format("{0} marked Unreachable on '{1}' - holding it on the local adapter", r.Address, nic));
                    }
                    e.LastHeld = now;
                    e.Holds++;
                    delete.Add(i);
                }
                else if (e != null && (r.State == NeighborState.Reachable || r.State == NeighborState.Stale || r.State == NeighborState.Permanent))
                {
                    log(string.Format("{0} answered on '{1}' ({2}) after {3:0.0}s, held {4} time(s)",
                        r.Address, e.Nic, r.State, (now - e.Since).TotalSeconds, e.Holds));
                    _held.Remove(r.Key);
                }
            }
            foreach (var kv in _held.Where(kv => now - kv.Value.LastHeld > Expiry).ToList())
            {
                log(string.Format("{0} on '{1}' has had no traffic for {2:0}s; no longer tracking it",
                    kv.Key.Substring(0, kv.Key.IndexOf('%')), kv.Value.Nic, Expiry.TotalSeconds));
                _held.Remove(kv.Key);
            }
            return delete;
        }
    }

    // ------------------------------------------------------------------ planning (pure; unit tested)
    class HeldSubnet { public Prefix Prefix; public int IfIndex; public string NicName; }

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
                        held.Add(new HeldSubnet { Prefix = p, IfIndex = idx, NicName = n.Name });
                }
            return held;
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

        public static List<NeighborRow> Read(AddressFamily f) { return Scan(f, null); }

        // Reads the neighbor table; the entries whose indices `pick` returns are deleted (never Permanent ones).
        public static List<NeighborRow> Scan(AddressFamily f, Func<List<NeighborRow>, IEnumerable<int>> pick)
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
                        if (rows[i].State != NeighborState.Permanent) DeleteIpNetEntry2(ptrs[i]);
            }
            finally { FreeMibTable(t); }
            return rows;
        }

        public static void FlushPathCache(AddressFamily f) { FlushIpPathTable(Net.Af(f)); }
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
            var psi = new ProcessStartInfo(file, args) { UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true };
            using (var p = Process.Start(psi))
            {
                var err = p.StandardError.ReadToEndAsync(); // read both streams concurrently so neither can fill up and block
                string output = p.StandardOutput.ReadToEnd() + err.Result;
                p.WaitForExit();
                if (p.ExitCode != 0 && showFailure)
                    Console.Error.WriteLine("{0} {1} failed (exit {2}):{3}{4}", file, args, p.ExitCode, Environment.NewLine, output.Trim());
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

        public static int Install(int intervalMs)
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

            string bin = "\\\"" + dst + "\\\" service " + intervalMs;
            int rc = ServiceExists()
                ? Run("sc.exe", "config " + Program.ServiceName + " binPath= \"" + bin + "\" start= auto")
                : Run("sc.exe", "create " + Program.ServiceName + " binPath= \"" + bin + "\" start= auto DisplayName= \"Local Subnet Guard\"");
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
    static class Log
    {
        public static bool Echo;
        static readonly object _lock = new object();
        public static string PathName { get { return Path.Combine(DataDir.Location, "LocalSubnetGuard.log"); } }

        public static void Write(string msg)
        {
            string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff") + "  " + msg;
            if (Echo) Console.WriteLine(line);
            lock (_lock)
            {
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
