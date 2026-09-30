// LocalSubnetGuard - keeps traffic for directly-connected subnets on their local NIC.
//
//  * Finds NIC(s) that have an IPv4 default gateway.
//  * Collects the connected IPv4 subnets of every other NIC (sticky for the life of the process).
//  * Adds an outbound Windows Firewall block rule on the gateway NIC(s) for those subnets.
//  * When NUD marks a neighbor in a protected subnet Unreachable, it keeps deleting that
//    neighbor entry and flushing the IPv4 path (destination) cache every tick, so Windows never
//    re-routes the address to the default gateway. When the neighbor answers ARP again, it is released.
//
// Build (.NET Framework 4.x, ships with Windows 11):
//   csc /target:exe /out:LocalSubnetGuard.exe /r:System.ServiceProcess.dll /r:Microsoft.CSharp.dll LocalSubnetGuard.cs
//
// Usage (elevated):
//   LocalSubnetGuard.exe install [intervalMs]   install + start as a Windows service (default 250 ms)
//   LocalSubnetGuard.exe uninstall              stop + remove service and its firewall rules
//   LocalSubnetGuard.exe run [intervalMs]       run in this console (Ctrl+C to stop)
//   LocalSubnetGuard.exe status                 show gateway NICs, protected subnets, rules, neighbors

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
            if (!Environment.UserInteractive)
            {
                ServiceBase.Run(new GuardService(ParseInterval(args, 0)));
                return 0;
            }

            string cmd = args.Length > 0 ? args[0].ToLowerInvariant().TrimStart('-', '/') : "help";
            if (cmd == "help" || cmd == "?" || cmd == "h") { Help(); return 0; }

            if (!IsAdmin()) { Console.Error.WriteLine("Run this from an elevated (Administrator) prompt."); return 5; }

            switch (cmd)
            {
                case "install":   return Setup.Install(ParseInterval(args, 1));
                case "uninstall": return Setup.Uninstall();
                case "run":       return RunConsole(ParseInterval(args, 1));
                case "status":    return Status();
                default: Help(); return 1;
            }
        }

        static int ParseInterval(string[] args, int pos)
        {
            int v;
            if (args.Length > pos && int.TryParse(args[pos], out v) && v >= 50 && v <= 60000) return v;
            return DefaultIntervalMs;
        }

        static bool IsAdmin()
        {
            return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        }

        static void Help()
        {
            Console.WriteLine(
@"LocalSubnetGuard - keep connected-subnet traffic on its local NIC (defeats NUD failover)

  LocalSubnetGuard.exe install [intervalMs]   install + start service (default 250 ms)
  LocalSubnetGuard.exe uninstall              remove service and its firewall rules
  LocalSubnetGuard.exe run [intervalMs]       run in console (Ctrl+C to stop)
  LocalSubnetGuard.exe status                 show current state

Log: " + Log.PathName);
        }

        static int RunConsole(int intervalMs)
        {
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
            Console.WriteLine("Gateway NIC(s):");
            foreach (var kv in snap.Gateways) Console.WriteLine("  [{0}] {1}", kv.Key, kv.Value);
            Console.WriteLine("Protected subnets (currently connected on other NICs):");
            foreach (var s in snap.Others) Console.WriteLine("  {0}  on [{1}] {2}", s.Cidr, s.IfIndex, s.IfName);
            Console.WriteLine("Firewall rules (group '{0}'):", Firewall.Group);
            foreach (var r in Firewall.Describe()) Console.WriteLine("  " + r);
            Console.WriteLine("IPv4 neighbors in protected subnets:");
            foreach (var n in Neighbors.Read())
                if (snap.Others.Any(s => s.IfIndex == n.IfIndex && s.Contains(n.Ip)))
                    Console.WriteLine("  {0,-15} [{1}] {2}", Net.ToStr(n.Ip), n.IfIndex, n.State);
            try
            {
                using (var sc = new ServiceController(ServiceName))
                    Console.WriteLine("Service: " + sc.Status);
            }
            catch { Console.WriteLine("Service: not installed"); }
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

    // ------------------------------------------------------------------ core logic
    class Guard
    {
        class WatchEntry { public string Alias; public DateTime Since; }

        readonly int _intervalMs;
        readonly Dictionary<string, Subnet> _protected = new Dictionary<string, Subnet>(); // sticky
        readonly Dictionary<string, WatchEntry> _watch = new Dictionary<string, WatchEntry>(); // key ip|ifIndex
        HashSet<int> _gwIdx = new HashSet<int>();
        string _lastSig = null;
        volatile bool _refresh = true;
        DateTime _nextRefresh = DateTime.MinValue;
        Thread _thread;
        readonly ManualResetEvent _stop = new ManualResetEvent(false);

        public Guard(int intervalMs) { _intervalMs = intervalMs; }

        public void Start()
        {
            Log.Write(string.Format("Starting (interval {0} ms).", _intervalMs));
            NetworkChange.NetworkAddressChanged += OnNetChange;
            NetworkChange.NetworkAvailabilityChanged += OnNetChange2;
            _thread = new Thread(Loop) { IsBackground = true, Name = "LocalSubnetGuard" };
            _thread.Start();
        }

        public void Stop()
        {
            NetworkChange.NetworkAddressChanged -= OnNetChange;
            NetworkChange.NetworkAvailabilityChanged -= OnNetChange2;
            _stop.Set();
            if (_thread != null) _thread.Join(5000);
            try { Firewall.RemoveAll(); } catch (Exception ex) { Log.Write("Rule cleanup failed: " + ex.Message); }
            Log.Write("Stopped; firewall rules removed.");
        }

        void OnNetChange(object s, EventArgs e) { _refresh = true; }
        void OnNetChange2(object s, NetworkAvailabilityEventArgs e) { _refresh = true; }

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
                        RefreshTopology();
                    }
                    Tick();
                }
                catch (Exception ex) { Log.Write("ERROR: " + ex.Message); }
                _stop.WaitOne(_intervalMs);
            }
        }

        void RefreshTopology()
        {
            var snap = Net.Snapshot();
            _gwIdx = new HashSet<int>(snap.Gateways.Keys);

            foreach (var s in snap.Others) _protected[s.Cidr] = s;
            var gwCidrs = new HashSet<string>(snap.GatewaySubnets.Select(s => s.Cidr));
            foreach (var c in _protected.Keys.ToList())
                if (gwCidrs.Contains(c) || _gwIdx.Contains(_protected[c].IfIndex)) _protected.Remove(c);

            var subnets = _protected.Keys.OrderBy(k => k).ToList();
            string sig = string.Join(",", snap.Gateways.OrderBy(k => k.Key).Select(k => k.Key + "=" + k.Value))
                         + "|" + string.Join(",", subnets);
            if (sig == _lastSig) return;
            _lastSig = sig;

            Firewall.RemoveAll();
            if (snap.Gateways.Count == 0) { Log.Write("No default-gateway NIC; no rules."); return; }
            if (subnets.Count == 0) { Log.Write("No other connected subnets; no rules."); return; }
            foreach (var gw in snap.Gateways.Values)
            {
                Firewall.AddBlock(gw, subnets);
                Log.Write(string.Format("Rule: block outbound on '{0}' -> {1}", gw, string.Join(", ", subnets)));
            }
            Firewall.WarnIfDisabled();
        }

        void Tick()
        {
            if (_protected.Count == 0) return;
            var subnets = _protected.Values.ToList();
            var rows = Neighbors.Read();
            bool flush = false;

            // 1. new NUD casualties
            foreach (var n in rows)
            {
                if (n.State != NeighborState.Unreachable || _gwIdx.Contains(n.IfIndex)) continue;
                string key = n.Ip + "|" + n.IfIndex;
                if (_watch.ContainsKey(key)) continue;
                var sn = subnets.FirstOrDefault(s => s.IfIndex == n.IfIndex && s.Contains(n.Ip));
                if (sn == null) continue;
                _watch[key] = new WatchEntry { Alias = sn.IfName, Since = DateTime.UtcNow };
                Log.Write(string.Format("{0} marked Unreachable on '{1}' - holding it on the local NIC", Net.ToStr(n.Ip), sn.IfName));
            }
            if (_watch.Count == 0) return;

            // 2. hold / release watched neighbors
            foreach (var key in _watch.Keys.ToList())
            {
                var parts = key.Split('|');
                uint ip = uint.Parse(parts[0]);
                int idx = int.Parse(parts[1]);
                var w = _watch[key];
                var n = rows.FirstOrDefault(r => r.Ip == ip && r.IfIndex == idx);

                if (n != null && (n.State == NeighborState.Reachable || n.State == NeighborState.Stale ||
                                  n.State == NeighborState.Delay || n.State == NeighborState.Probe ||
                                  n.State == NeighborState.Permanent))
                {
                    Log.Write(string.Format("{0} answered on '{1}' ({2}) after {3:0.0}s - back on local NIC",
                        Net.ToStr(ip), w.Alias, n.State, (DateTime.UtcNow - w.Since).TotalSeconds));
                    _watch.Remove(key);
                    flush = true;
                    continue;
                }
                if (n != null) Neighbors.Delete(ip, idx);
                flush = true;
            }
            if (flush) Neighbors.FlushPathCache();
        }
    }

    // ------------------------------------------------------------------ network discovery
    class Subnet
    {
        public uint Net; public int Len; public string Cidr; public int IfIndex; public string IfName;
        public bool Contains(uint ip) { return (ip & Mask(Len)) == Net; }
        public static uint Mask(int len) { return len <= 0 ? 0u : (uint)(0xFFFFFFFFUL << (32 - len)); }
    }

    class NetSnapshot
    {
        public Dictionary<int, string> Gateways = new Dictionary<int, string>();
        public List<Subnet> GatewaySubnets = new List<Subnet>();
        public List<Subnet> Others = new List<Subnet>();
    }

    static class Net
    {
        public static uint ToUInt(IPAddress a)
        {
            var b = a.GetAddressBytes();
            return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        }
        public static string ToStr(uint ip)
        {
            return string.Format("{0}.{1}.{2}.{3}", ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
        }

        public static NetSnapshot Snapshot()
        {
            var snap = new NetSnapshot();
            var all = new List<Subnet>();
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                IPInterfaceProperties p; IPv4InterfaceProperties v4;
                try { p = nic.GetIPProperties(); v4 = p.GetIPv4Properties(); } catch { continue; }
                if (v4 == null) continue;

                bool hasGw = nic.OperationalStatus == OperationalStatus.Up &&
                    p.GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork &&
                                                !g.Address.Equals(IPAddress.Any));
                if (hasGw) snap.Gateways[v4.Index] = nic.Name;

                foreach (var ua in p.UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    uint ip = ToUInt(ua.Address);
                    if ((ip >> 16) == 0xA9FE || (ip >> 24) == 127) continue; // 169.254/16, 127/8
                    int len = ua.PrefixLength;
                    if (len < 8 || len > 30) continue;
                    uint net = ip & Subnet.Mask(len);
                    var s = new Subnet { Net = net, Len = len, Cidr = ToStr(net) + "/" + len, IfIndex = v4.Index, IfName = nic.Name };
                    (hasGw ? snap.GatewaySubnets : all).Add(s);
                }
            }
            var gwC = new HashSet<string>(snap.GatewaySubnets.Select(s => s.Cidr));
            snap.Others = all.Where(s => !gwC.Contains(s.Cidr) && !snap.Gateways.ContainsKey(s.IfIndex)).ToList();
            return snap;
        }
    }

    // ------------------------------------------------------------------ neighbor table (IP Helper)
    enum NeighborState { Unreachable = 0, Incomplete = 1, Probe = 2, Delay = 3, Stale = 4, Reachable = 5, Permanent = 6 }

    class NeighborRow { public uint Ip; public int IfIndex; public NeighborState State; }

    static class Neighbors
    {
        const ushort AF_INET = 2;
        // MIB_IPNET_TABLE2: ULONG NumEntries; (pad) MIB_IPNET_ROW2 Table[] at offset 8
        // MIB_IPNET_ROW2 (88 bytes): SOCKADDR_INET Address @0 (28), InterfaceIndex @28, InterfaceLuid @32,
        //   PhysicalAddress[32] @40, PhysicalAddressLength @72, State @76, Flags @80, ReachabilityTime @84
        const int TableOffset = 8, RowSize = 88, OffIndex = 28, OffState = 76;

        [DllImport("iphlpapi.dll")] static extern int GetIpNetTable2(ushort family, out IntPtr table);
        [DllImport("iphlpapi.dll")] static extern void FreeMibTable(IntPtr memory);
        [DllImport("iphlpapi.dll")] static extern int DeleteIpNetEntry2(IntPtr row);
        [DllImport("iphlpapi.dll")] static extern int FlushIpPathTable(ushort family);

        static uint RowIp(IntPtr row)
        {
            // SOCKADDR_IN: family @0, port @2, addr @4 (network byte order)
            return ((uint)Marshal.ReadByte(row, 4) << 24) | ((uint)Marshal.ReadByte(row, 5) << 16) |
                   ((uint)Marshal.ReadByte(row, 6) << 8) | Marshal.ReadByte(row, 7);
        }

        public static List<NeighborRow> Read()
        {
            var list = new List<NeighborRow>();
            IntPtr t;
            if (GetIpNetTable2(AF_INET, out t) != 0) return list;
            try
            {
                int n = Marshal.ReadInt32(t);
                for (int i = 0; i < n; i++)
                {
                    IntPtr row = new IntPtr(t.ToInt64() + TableOffset + (long)i * RowSize);
                    if ((ushort)Marshal.ReadInt16(row, 0) != AF_INET) continue;
                    list.Add(new NeighborRow
                    {
                        Ip = RowIp(row),
                        IfIndex = Marshal.ReadInt32(row, OffIndex),
                        State = (NeighborState)Marshal.ReadInt32(row, OffState)
                    });
                }
            }
            finally { FreeMibTable(t); }
            return list;
        }

        public static void Delete(uint ip, int ifIndex)
        {
            IntPtr t;
            if (GetIpNetTable2(AF_INET, out t) != 0) return;
            try
            {
                int n = Marshal.ReadInt32(t);
                for (int i = 0; i < n; i++)
                {
                    IntPtr row = new IntPtr(t.ToInt64() + TableOffset + (long)i * RowSize);
                    if ((ushort)Marshal.ReadInt16(row, 0) != AF_INET) continue;
                    if (RowIp(row) == ip && Marshal.ReadInt32(row, OffIndex) == ifIndex &&
                        (NeighborState)Marshal.ReadInt32(row, OffState) != NeighborState.Permanent)
                        DeleteIpNetEntry2(row);
                }
            }
            finally { FreeMibTable(t); }
        }

        public static void FlushPathCache() { FlushIpPathTable(AF_INET); }
    }

    // ------------------------------------------------------------------ Windows Firewall (COM)
    static class Firewall
    {
        public const string Group = "LocalSubnetGuard";
        const int DirOut = 2, ActionBlock = 0, ProtoAny = 256, ProfilesAll = 0x7FFFFFFF;

        static dynamic Policy() { return Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2")); }

        static List<dynamic> OurRules(dynamic pol)
        {
            var list = new List<dynamic>();
            foreach (dynamic r in pol.Rules)
            {
                string g = null;
                try { g = r.Grouping; } catch { }
                if (g == Group) list.Add(r);
            }
            return list;
        }

        public static void RemoveAll()
        {
            dynamic pol = Policy();
            foreach (dynamic r in OurRules(pol))
            {
                try { pol.Rules.Remove((string)r.Name); } catch { }
            }
        }

        public static void AddBlock(string interfaceName, IList<string> cidrs)
        {
            dynamic pol = Policy();
            dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
            rule.Name = Group + " - block local subnets on '" + interfaceName + "'";
            rule.Description = "Managed by LocalSubnetGuard. Rebuilt automatically; do not edit.";
            rule.Grouping = Group;
            rule.Direction = DirOut;
            rule.Action = ActionBlock;
            rule.Protocol = ProtoAny;
            rule.RemoteAddresses = string.Join(",", cidrs);
            rule.Interfaces = new object[] { interfaceName };
            rule.Profiles = ProfilesAll;
            rule.Enabled = true;
            pol.Rules.Add(rule);
        }

        public static IEnumerable<string> Describe()
        {
            dynamic pol = Policy();
            var outp = new List<string>();
            foreach (dynamic r in OurRules(pol))
            {
                string ifs = "";
                try { object[] a = r.Interfaces; if (a != null) ifs = string.Join(", ", a.Select(x => x.ToString())); } catch { }
                outp.Add(string.Format("{0}  [interface: {1}] [remote: {2}] [enabled: {3}]",
                    (string)r.Name, ifs == "" ? "ANY" : ifs, (string)r.RemoteAddresses, (bool)r.Enabled));
            }
            if (outp.Count == 0) outp.Add("(none)");
            return outp;
        }

        public static void WarnIfDisabled()
        {
            object pol = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            Type t = pol.GetType();
            int current = (int)t.InvokeMember("CurrentProfileTypes", BindingFlags.GetProperty, null, pol, null);
            foreach (var p in new[] { new { Bit = 1, Name = "Domain" }, new { Bit = 2, Name = "Private" }, new { Bit = 4, Name = "Public" } })
            {
                if ((current & p.Bit) == 0) continue;
                bool on = (bool)t.InvokeMember("FirewallEnabled", BindingFlags.GetProperty, null, pol, new object[] { p.Bit });
                if (!on) Log.Write("WARNING: Windows Firewall " + p.Name + " profile is OFF - block rules have no effect.");
            }
        }
    }

    // ------------------------------------------------------------------ install / uninstall
    static class Setup
    {
        static string InstallDir { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "LocalSubnetGuard"); } }

        static int Run(string file, string args, bool quiet = true)
        {
            var psi = new ProcessStartInfo(file, args) { UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true };
            using (var p = Process.Start(psi))
            {
                string o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                p.WaitForExit();
                if (!quiet || p.ExitCode != 0) { if (!quiet) Console.Write(o); }
                return p.ExitCode;
            }
        }

        static bool ServiceExists()
        {
            return ServiceController.GetServices().Any(s => s.ServiceName.Equals(Program.ServiceName, StringComparison.OrdinalIgnoreCase));
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

        public static int Install(int intervalMs)
        {
            // Retire the PowerShell version if present
            if (Run("schtasks.exe", "/Query /TN LocalSubnetGuard") == 0)
            {
                Run("schtasks.exe", "/End /TN LocalSubnetGuard");
                Run("schtasks.exe", "/Delete /TN LocalSubnetGuard /F");
                Console.WriteLine("Removed old PowerShell scheduled task 'LocalSubnetGuard'.");
            }

            StopService();
            Directory.CreateDirectory(InstallDir);
            string src = Assembly.GetExecutingAssembly().Location;
            string dst = Path.Combine(InstallDir, "LocalSubnetGuard.exe");
            if (!string.Equals(Path.GetFullPath(src), Path.GetFullPath(dst), StringComparison.OrdinalIgnoreCase))
                File.Copy(src, dst, true);

            string bin = "\\\"" + dst + "\\\" " + intervalMs;
            if (ServiceExists())
                Run("sc.exe", "config " + Program.ServiceName + " binPath= \"" + bin + "\" start= auto");
            else if (Run("sc.exe", "create " + Program.ServiceName + " binPath= \"" + bin + "\" start= auto DisplayName= \"Local Subnet Guard\"", false) != 0)
                return 1;

            Run("sc.exe", "description " + Program.ServiceName + " \"Keeps connected-subnet traffic on its local NIC; defeats NUD failover to the default gateway.\"");
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
            if (ServiceExists()) Run("sc.exe", "delete " + Program.ServiceName, false);
            try { Firewall.RemoveAll(); } catch { }
            Console.WriteLine("Service and firewall rules removed. (" + InstallDir + " left in place.)");
            return 0;
        }
    }

    // ------------------------------------------------------------------ logging
    static class Log
    {
        public static bool Echo;
        static readonly object _lock = new object();
        public static string PathName
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "LocalSubnetGuard", "LocalSubnetGuard.log"); }
        }
        public static void Write(string msg)
        {
            string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff") + "  " + msg;
            if (Echo) Console.WriteLine(line);
            lock (_lock)
            {
                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(PathName));
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
