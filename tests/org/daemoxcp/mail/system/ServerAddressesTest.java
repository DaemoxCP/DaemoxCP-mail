package org.daemoxcp.mail.system;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import org.daemoxcp.mail.util.Shell;

/**
 * The server's addresses (ServerAddresses): reading the state, adding and removing IPv6, taking IPv4 again by DHCP,
 * cleaning what is left of IPv4. Asked on 18/11/2026: IPv4, IPv6, only one, both, and back, safely.
 *
 *  1. Reading: ifconfig, netstat, the provider's suggestion (Hetzner's network configuration), the address checks.
 *  2. Adding IPv6 on a simulated FreeBSD (every command answered as FreeBSD 15 does): the exact commands, live and
 *     without touching IPv4, rc.conf only after the probe, the previous lines kept.
 *  3. When it goes wrong: the probe fails, the address is duplicated, the route is refused: everything as before,
 *     rc.conf untouched.
 *  4. Removing IPv6: the previous rc.conf lines come back; refused while mail is IPv6 only.
 *  5. IPv4: the clean-up refuses while IPv4 still reaches the internet; never a whole-network restart.
 *  6. In the sources: never "service netif" or "service routing", never pkill.
 *  7. On the VM, as root (-De2e.vm=yes): the real ifconfig and route with a documentation address (2001:db8::/32),
 *     the probe forced, rc.conf a copy. Added, then removed: the interface exactly as before. A failing probe leaves
 *     nothing.
 *
 * Usage: java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.ServerAddressesTest [-De2e.vm=yes]
 */
public class ServerAddressesTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        Path tmp = Files.createTempDirectory("server-addresses");
        JobJournal.dir = tmp.resolve("jobs");
        ServerAddresses.stateFile = tmp.resolve("server-addresses.json");
        ServerAddresses.rcConf = tmp.resolve("rc.conf");
        ServerAddresses.dadWait = Duration.ofSeconds(3);
        try {
            reading();
            simulated(tmp);
            sources();
            if ("yes".equals(System.getProperty("e2e.vm")) && "root".equals(System.getProperty("user.name"))) onTheVm(tmp);
            else System.out.println("\n(7. needs the VM, as root, with -De2e.vm=yes: skipped)");
        } finally {
            ServerAddresses.runner = Shell::run;
            try (Stream<Path> s = Files.walk(tmp)) {
                for (Path p : s.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(p);
            }
        }
        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        if (failed > 0) System.exit(1);
    }

    // ===================== 1 =====================

    static final String IFCONFIG = "vtnet0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500\n"
            + "\tinet 192.0.2.10 netmask 0xffffffff broadcast 192.0.2.10\n"
            + "\tinet6 fe80::9400:3ff:fe1a:2b3c%vtnet0 prefixlen 64 scopeid 0x1\n"
            + "\tinet6 fd12:3456:789a:1:a8bb:ccff:fedd:eeff prefixlen 64 autoconf\n"
            + "\tinet6 2a01:4f8:c012:abcd::1 prefixlen 64\n"
            + "\tinet6 2a01:4f8:c012:abcd::2 prefixlen 64 tentative\n"
            + "\tnd6 options=21<PERFORMNUD,AUTO_LINKLOCAL>\n";

    static void reading() {
        System.out.println("== 1. Reading ==");
        check("IPv4 addresses: " + ServerAddresses.addresses(IFCONFIG, false), ServerAddresses.addresses(IFCONFIG, false).equals(List.of("192.0.2.10")));
        check("IPv6: only the global ones that are ready (no link-local, no local fd12::, no tentative): " + ServerAddresses.addresses(IFCONFIG, true),
                ServerAddresses.addresses(IFCONFIG, true).equals(List.of("2a01:4f8:c012:abcd::1")));
        String n6 = "Routing tables\n\nInternet6:\nDestination        Gateway            Flags     Netif Expire\ndefault            fe80::1%vtnet0     UGS      vtnet0\n::1                link#2             UHS         lo0\n";
        check("the IPv6 default route and its interface", "fe80::1%vtnet0".equals(ServerAddresses.defaultRoute(n6)) && "vtnet0".equals(ServerAddresses.defaultRouteInterface(n6)));
        check("no default route", ServerAddresses.defaultRoute("Internet6:\n::1 link#2 UHS lo0\n") == null);
        check("sshd listening on IPv6, from sockstat", ServerAddresses.listensOn("root     sshd       812   4  tcp6   *:22   *:*\n")
                && !ServerAddresses.listensOn("root     sshd       812   3  tcp4   *:22   *:*\n"));

        String meta = "network-config:\n  config:\n  - mac_address: 96:00:03:1a:2b:3c\n    name: eth0\n    subnets:\n"
                + "    - ipv4: true\n      type: dhcp\n    - address: 2a01:4f8:c012:abcd::1/64\n      gateway: fe80::1\n      ipv6: true\n      type: static\n    type: physical\n  version: 1\n";
        ServerAddresses.Suggestion s = ServerAddresses.parseHetzner(meta, "vtnet0");
        check("Hetzner's network configuration: the address, the prefix, the gateway with the interface (" + s + ")",
                s != null && s.address().equals("2a01:4f8:c012:abcd::1") && s.prefix() == 64 && s.gateway().equals("fe80::1%vtnet0") && s.source().equals("hetzner"));
        check("no IPv6 in the metadata: no suggestion", ServerAddresses.parseHetzner("hostname: x\npublic-ipv4: 192.0.2.10\n", "vtnet0") == null);
        check("a local or documentation address is not a suggestion",
                ServerAddresses.parseHetzner("    - address: fd00::1/64\n      gateway: fe80::1\n", "vtnet0") == null
                        && ServerAddresses.parseHetzner("    - address: 2001:db8::1/64\n      gateway: fe80::1\n", "vtnet0") == null);

        check("the short form (RFC 5952)", ServerAddresses.compress(v6("2a01:04f8:c012:abcd:0000:0000:0000:0001")).equals("2a01:4f8:c012:abcd::1")
                && ServerAddresses.compress(v6("2001:db8:0:1:0:0:0:1")).equals("2001:db8:0:1::1")
                && ServerAddresses.compress(v6("2001:db8:0:0:1:0:0:1")).equals("2001:db8::1:0:0:1")
                && ServerAddresses.compress(v6("fe80::1")).equals("fe80::1"));
        check("what is global: 2000::/3, not documentation, not local", ServerAddresses.isGlobal(v6("2a01:4f8::1"))
                && !ServerAddresses.isGlobal(v6("2001:db8::1")) && !ServerAddresses.isGlobal(v6("fd00::1")) && !ServerAddresses.isGlobal(v6("fe80::1")));
        check("the checks of what is typed", ServerAddresses.checkIpv6("2a01:4f8::1", 64, "fe80::1") == null
                && "server.addr.badAddress".equals(ServerAddresses.checkIpv6("192.0.2.1", 64, "fe80::1"))
                && "server.addr.badAddress".equals(ServerAddresses.checkIpv6("2a01:4f8::1; rm -rf /", 64, "fe80::1"))
                && "server.addr.notGlobal".equals(ServerAddresses.checkIpv6("fd00::1", 64, "fe80::1"))
                && "server.addr.badPrefix".equals(ServerAddresses.checkIpv6("2a01:4f8::1", 0, "fe80::1"))
                && "server.addr.badPrefix".equals(ServerAddresses.checkIpv6("2a01:4f8::1", 129, "fe80::1"))
                && "server.addr.badGateway".equals(ServerAddresses.checkIpv6("2a01:4f8::1", 64, "gateway")));
        check("the gateway: link-local with the interface, global as it is", "fe80::1%vtnet0".equals(ServerAddresses.gatewayFor("fe80::1", "vtnet0"))
                && "2a01:4f8::1".equals(ServerAddresses.gatewayFor("2a01:4f8:0:0::1", "vtnet0")));
        try {
            Path rc = Files.createTempFile("rc", ".conf");
            Path saved = ServerAddresses.rcConf;
            ServerAddresses.rcConf = rc;
            Files.writeString(rc, "hostname=\"mail\"\nifconfig_vtnet0=\"DHCP\"\n  ifconfig_vtnet0_ipv6='inet6 accept_rtadv' # SLAAC\nsshd_enable=YES # on\nifconfig_vtnet0=\"inet 192.0.2.10/32\"\n");
            check("rc.conf values read from the file: quoted, single-quoted, bare with a comment, the last assignment wins",
                    "inet6 accept_rtadv".equals(ServerAddresses.rc("ifconfig_vtnet0_ipv6")) && "YES".equals(ServerAddresses.rc("sshd_enable"))
                            && "inet 192.0.2.10/32".equals(ServerAddresses.rc("ifconfig_vtnet0")));
            check("a variable the file does not have is empty, never the default of /etc/defaults/rc.conf (ipv6_defaultrouter=\"NO\")",
                    "".equals(ServerAddresses.rc("ipv6_defaultrouter")) && "".equals(ServerAddresses.rc("defaultrouter")));
            ServerAddresses.rcConf = saved;
            Files.deleteIfExists(rc);
        } catch (Exception e) {
            check("rc.conf reading: " + e, false);
        }
        check("the address of an rc.conf line", "2a01:4f8::1".equals(ServerAddresses.fromRcLine("inet6 2a01:4f8::1 prefixlen 64"))
                && "2a01:4f8::1".equals(ServerAddresses.fromRcLine("inet6 2a01:4f8::1/64")) && ServerAddresses.fromRcLine("inet6 accept_rtadv") == null);
    }

    static Inet6Address v6(String s) {
        return (Inet6Address) InetAddress.ofLiteral(s);
    }

    // ===================== 2-5: a simulated FreeBSD =====================

    /** A FreeBSD that answers the commands ServerAddresses runs, and records them. */
    static final class FakeBsd implements ServerAddresses.Runner {
        final List<String> v4 = new ArrayList<>(List.of("192.0.2.10"));
        final List<String> v6 = new ArrayList<>();
        final Map<String, String> rc = new LinkedHashMap<>();
        String route4 = "192.0.2.1", route6 = null;
        boolean ifdisabled = true, duplicate = false, refuseRoute = false;
        int tentativePolls = 1;
        final List<String> commands = new ArrayList<>();

        public Shell.Result run(Duration timeout, String... cmd) {
            String c = String.join(" ", cmd);
            commands.add(c);
            String out = "";
            int exit = 0;
            if (c.equals("netstat -rn -f inet")) out = route4 == null ? "" : "default " + route4 + " UGS vtnet0\n";
            else if (c.equals("netstat -rn -f inet6")) out = route6 == null ? "" : "default " + route6 + " UGS vtnet0\n";
            else if (c.equals("ifconfig vtnet0")) out = ifconfig(false);
            else if (c.equals("ifconfig vtnet0 inet6")) out = ifconfig(true);
            else if (c.equals("ifconfig vtnet0 inet6 -ifdisabled")) ifdisabled = false;
            else if (c.equals("ifconfig vtnet0 inet6 ifdisabled")) ifdisabled = true;
            else if (c.matches("ifconfig vtnet0 inet6 \\S+ prefixlen \\d+ alias")) v6.add(cmd[3]);
            else if (c.matches("ifconfig vtnet0 inet6 \\S+ -alias")) exit = v6.remove(cmd[3]) ? 0 : 1;
            else if (c.matches("ifconfig vtnet0 inet \\S+ -alias")) exit = v4.remove(cmd[3]) ? 0 : 1;
            else if (c.startsWith("route -6 add default ")) {
                if (refuseRoute || route6 != null) exit = 1;
                else route6 = cmd[4];
            } else if (c.startsWith("route -6 delete default")) {
                exit = route6 == null ? 1 : 0;
                route6 = null;
            } else if (c.startsWith("route -4 delete default")) route4 = null;
            else if (c.startsWith("sysrc -n -f ")) {
                String v = rc.get(cmd[4]);
                if (v == null) exit = 1;
                else out = v + "\n";
            } else if (c.startsWith("sysrc -f ") && cmd.length == 5 && cmd[3].equals("-x")) {
                rc.remove(cmd[4]);
                sync();
            } else if (c.startsWith("sysrc -f ")) {
                String[] kv = cmd[3].split("=", 2);
                rc.put(kv[0], kv[1]);
                sync();
            } else if (c.startsWith("sockstat ")) out = "root sshd 812 4 tcp6 *:22 *:*\n";
            else if (c.startsWith("fetch ")) exit = 1;
            else if (c.startsWith("ifconfig -l")) out = "vtnet0 lo0\n";
            else if (c.startsWith("kill ")) exit = 0;
            else exit = 127;
            return new Shell.Result(exit, out, false, List.of(cmd));
        }

        String ifconfig(boolean nd6) {
            StringBuilder b = new StringBuilder("vtnet0: flags=8843<UP,BROADCAST,RUNNING> mtu 1500\n");
            if (!nd6) for (String a : v4) b.append("\tinet ").append(a).append(" netmask 0xffffffff\n");
            b.append("\tinet6 fe80::1:2%vtnet0 prefixlen 64 scopeid 0x1\n");
            for (String a : v6) {
                String flag = duplicate ? " duplicated" : tentativePolls-- > 0 ? " tentative" : "";
                b.append("\tinet6 ").append(a).append(" prefixlen 64").append(flag).append('\n');
            }
            b.append("\tnd6 options=").append(ifdisabled ? "29<PERFORMNUD,IFDISABLED,AUTO_LINKLOCAL>" : "21<PERFORMNUD,AUTO_LINKLOCAL>").append('\n');
            return b.toString();
        }

        /** rc.conf on disk as sysrc writes it: what ServerAddresses reads. */
        void sync() {
            StringBuilder b = new StringBuilder();
            rc.forEach((k, val) -> b.append(k).append("=\"").append(val).append("\"\n"));
            try { Files.writeString(ServerAddresses.rcConf, b.toString()); } catch (Exception e) { throw new RuntimeException(e); }
        }

        boolean ran(String regex) {
            return commands.stream().anyMatch(c -> c.matches(regex));
        }
    }

    static void simulated(Path tmp) throws Exception {
        System.out.println("\n== 2. Adding IPv6, on a simulated FreeBSD ==");
        Files.writeString(ServerAddresses.rcConf, "ifconfig_vtnet0=\"DHCP\"\nifconfig_vtnet0_ipv6=\"inet6 accept_rtadv\"\n");
        FakeBsd bsd = new FakeBsd();
        bsd.rc.put("ifconfig_vtnet0", "DHCP");
        bsd.rc.put("ifconfig_vtnet0_ipv6", "inet6 accept_rtadv");
        ServerAddresses.runner = bsd;
        ServerAddresses.probe = family -> true;
        ServerAddresses.Result r = ServerAddresses.addIpv6("2a01:4f8:c012:abcd::1", 64, "fe80::1");
        check("done (" + r.message() + "), with its log on disk (" + r.journal() + ")", r.ok() && Files.isRegularFile(JobJournal.dir.resolve(r.journal())));
        check("the interface had IPv6 off: -ifdisabled first", bsd.ran("ifconfig vtnet0 inet6 -ifdisabled"));
        check("the address added live as an alias", bsd.ran("ifconfig vtnet0 inet6 2a01:4f8:c012:abcd::1 prefixlen 64 alias"));
        check("the route with the interface in it", bsd.ran("route -6 add default fe80::1%vtnet0"));
        check("IPv4 not touched (same address, same route, no inet command)", bsd.v4.equals(List.of("192.0.2.10"))
                && "192.0.2.1".equals(bsd.route4) && !bsd.ran("ifconfig vtnet0 inet .*") && !bsd.ran("route -4 .*"));
        check("rc.conf: the static address and the default router", "inet6 2a01:4f8:c012:abcd::1 prefixlen 64".equals(bsd.rc.get("ifconfig_vtnet0_ipv6"))
                && "fe80::1%vtnet0".equals(bsd.rc.get("ipv6_defaultrouter")));
        String state = Files.readString(ServerAddresses.stateFile);
        check("the previous lines kept for the way back", state.contains("\"previousIpv6\": \"inet6 accept_rtadv\"") && state.contains("\"previousRouter\": \"\""));
        check("the state file only for root (0600)",
                java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(ServerAddresses.stateFile)).equals("rw-------"));
        check("a copy of rc.conf beside it", ConfigBackups.copiesOf(tmp, "rc.conf").size() == 1);
        int sysrcBeforeProbe = -1, probeAt = -1;
        // rc.conf is written only after the address works: the first sysrc write comes after the route.
        for (int i = 0; i < bsd.commands.size(); i++) {
            if (bsd.commands.get(i).startsWith("route -6 add")) probeAt = i;
            if (sysrcBeforeProbe < 0 && bsd.commands.get(i).matches("sysrc -f \\S+ \\S+=.*")) sysrcBeforeProbe = i;
        }
        check("rc.conf written only after the address and the route", probeAt >= 0 && sysrcBeforeProbe > probeAt);
        check("a second time: refused, the server already has IPv6", !ServerAddresses.addIpv6("2a01:4f8:c012:abcd::5", 64, "fe80::1").ok());

        System.out.println("\n== 3. When it goes wrong: everything as before ==");
        Path addedState = ServerAddresses.stateFile;
        ServerAddresses.stateFile = tmp.resolve("state-of-the-failures.json");
        for (String why : List.of("probe", "duplicate", "route")) {
            FakeBsd b = new FakeBsd();
            b.rc.put("ifconfig_vtnet0_ipv6", "inet6 accept_rtadv");
            ServerAddresses.runner = b;
            Files.deleteIfExists(ServerAddresses.stateFile);
            ServerAddresses.probe = family -> !why.equals("probe");
            b.duplicate = why.equals("duplicate");
            b.refuseRoute = why.equals("route");
            ServerAddresses.Result x = ServerAddresses.addIpv6("2a01:4f8:c012:abcd::1", 64, "fe80::1");
            String expected = why.equals("probe") ? "server.addr.probeFailedV6" : why.equals("duplicate") ? "server.addr.duplicated" : "server.addr.routeFailed";
            check(why + ": refused (" + x.message() + ")", !x.ok() && expected.equals(x.message()));
            check(why + ": no address, no route, IPv6 off again", b.v6.isEmpty() && b.route6 == null && b.ifdisabled);
            check(why + ": rc.conf and the state file untouched", "inet6 accept_rtadv".equals(b.rc.get("ifconfig_vtnet0_ipv6"))
                    && !b.rc.containsKey("ipv6_defaultrouter") && !Files.exists(ServerAddresses.stateFile));
        }
        FakeBsd bad = new FakeBsd();
        ServerAddresses.runner = bad;
        check("a typed address with other characters: refused before any command",
                !ServerAddresses.addIpv6("2a01:4f8::1 alias; reboot", 64, "fe80::1").ok() && !bad.ran("ifconfig vtnet0 inet6 .*alias"));

        ServerAddresses.stateFile = addedState;

        System.out.println("\n== 4. Removing IPv6: the previous lines come back ==");
        ServerAddresses.runner = bsd;
        ServerAddresses.probe = family -> true;
        // Mail on IPv4 or both: removing is allowed (from Postfix: no database in this test).
        r = ServerAddresses.removeIpv6();
        check("done (" + r.message() + ")", r.ok());
        check("route and address removed live", bsd.route6 == null && bsd.v6.isEmpty() && bsd.ran("route -6 delete default")
                && bsd.ran("ifconfig vtnet0 inet6 2a01:4f8:c012:abcd::1 -alias"));
        check("rc.conf: the line there was before (accept_rtadv), no default router", "inet6 accept_rtadv".equals(bsd.rc.get("ifconfig_vtnet0_ipv6"))
                && !bsd.rc.containsKey("ipv6_defaultrouter"));
        check("the state file is gone", !Files.exists(ServerAddresses.stateFile));
        check("IPv4 never touched", bsd.v4.equals(List.of("192.0.2.10")) && "192.0.2.1".equals(bsd.route4));
        r = ServerAddresses.removeIpv6();
        check("nothing left to remove: says so", !r.ok() && "server.addr.v6NotFound".equals(r.message()));

        System.out.println("\n== 5. IPv4 ==");
        FakeBsd v = new FakeBsd();
        v.v6.add("2a01:4f8:c012:abcd::1");
        v.route6 = "fe80::1%vtnet0";
        v.tentativePolls = 0;
        v.rc.put("ifconfig_vtnet0", "DHCP");
        ServerAddresses.runner = v;
        ServerAddresses.probe = family -> true;
        r = ServerAddresses.cleanIpv4();
        check("IPv4 still reaches the internet: the clean-up refuses (" + r.message() + ")", !r.ok() && "server.addr.v4StillWorks".equals(r.message())
                && v.v4.equals(List.of("192.0.2.10")) && "DHCP".equals(v.rc.get("ifconfig_vtnet0")));
        ServerAddresses.probe = family -> family.equals("ipv6");
        r = ServerAddresses.cleanIpv4();
        check("removed by the provider (no IPv4 out): the leftovers go", r.ok() && v.v4.isEmpty() && v.route4 == null
                && !v.rc.containsKey("ifconfig_vtnet0") && v.route6 != null && v.v6.size() == 1);
        ServerAddresses.probe = family -> false;
        FakeBsd w = new FakeBsd();
        w.v6.add("2a01:4f8:c012:abcd::1");
        w.route6 = "fe80::1%vtnet0";
        w.tentativePolls = 0;
        ServerAddresses.runner = w;
        check("without a working IPv6 the IPv4 configuration stays", !ServerAddresses.cleanIpv4().ok() && w.v4.size() == 1);
        ServerAddresses.probe = family -> true;
    }

    // ===================== 6 =====================

    static void sources() throws Exception {
        System.out.println("\n== 6. In the sources ==");
        Path src = Path.of("src/main/java/org/daemoxcp/mail/system/ServerAddresses.java");
        if (!Files.isRegularFile(src)) {
            check("the sources are here (run from the folder with src/)", false);
            return;
        }
        String code = Files.readString(src);
        // Only the code, not the comments that explain why these commands are never used.
        StringBuilder only = new StringBuilder();
        for (String line : code.split("\n")) {
            String t = line.trim();
            if (t.startsWith("*") || t.startsWith("/*") || t.startsWith("//")) continue;
            only.append(line).append('\n');
        }
        String c = only.toString();
        check("never \"netif\" or \"routing\" (they remove every address, or every route of both families)",
                !c.contains("\"netif\"") && !c.contains("\"routing\"") && !c.contains("netif restart") && !c.contains("routing restart"));
        check("never pkill or killall: dhclient is stopped by the PID in its file", !c.contains("pkill") && !c.contains("killall"));
        check("never sh -c: every command with its arguments", !c.contains("runShell") && !c.contains("\"sh\", \"-c\""));
        check("SSH never touched: no sshd_config, no service sshd, no pfctl (sshd is only read in sockstat)",
                !c.contains("sshd_config") && !c.contains("\"service\", \"sshd\"") && !c.contains("pfctl"));
    }

    // ===================== 7 =====================

    static void onTheVm(Path tmp) throws Exception {
        System.out.println("\n== 7. On the VM: the real ifconfig and route ==");
        ServerAddresses.runner = Shell::run;
        ServerAddresses.acceptTestAddresses = true;
        Files.copy(Path.of("/etc/rc.conf"), ServerAddresses.rcConf, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        Files.deleteIfExists(ServerAddresses.stateFile);
        String iface = ServerAddresses.outsideInterface();
        String before = live(iface);
        String rcBefore = Files.readString(ServerAddresses.rcConf);
        check("the interface: " + iface + "; no global IPv6 and no IPv6 default route to start with",
                iface != null && ServerAddresses.read().v6().addresses().isEmpty() && !ServerAddresses.read().v6().route());

        ServerAddresses.probe = family -> false;
        ServerAddresses.Result r = ServerAddresses.addIpv6("2001:db8:dead::5", 64, "fe80::1");
        check("the probe fails: refused (" + r.message() + ")", !r.ok() && "server.addr.probeFailedV6".equals(r.message()));
        check("  the interface and the routes exactly as before", live(iface).equals(before));
        check("  rc.conf (the copy) as before", Files.readString(ServerAddresses.rcConf).equals(rcBefore));

        ServerAddresses.probe = family -> true;
        r = ServerAddresses.addIpv6("2001:db8:dead::5", 64, "fe80::1");
        check("the probe passes: added (" + r.message() + ")", r.ok());
        ServerAddresses.State s = ServerAddresses.read();
        check("  the address is there and ready, the default route via fe80::1%" + iface,
                s.v6().addresses().contains("2001:db8:dead::5") && ("fe80::1%" + iface).equals(s.v6().gateway()));
        check("  IPv4 untouched: its address and its default route are still there", s.v4().present());
        check("  rc.conf (the copy) has the lines", Files.readString(ServerAddresses.rcConf).contains("ifconfig_" + iface + "_ipv6=\"inet6 2001:db8:dead::5 prefixlen 64\"")
                && Files.readString(ServerAddresses.rcConf).contains("ipv6_defaultrouter=\"fe80::1%" + iface + "\""));

        r = ServerAddresses.removeIpv6();
        check("removed (" + r.message() + ")", r.ok());
        check("  the interface and the routes exactly as before", live(iface).equals(before));
        check("  rc.conf (the copy) as before", Files.readString(ServerAddresses.rcConf).equals(rcBefore));
        ServerAddresses.acceptTestAddresses = false;
    }

    /** What matters of the live network: the inet6 lines of the interface (without the lifetimes) and the default routes. */
    static String live(String iface) throws Exception {
        StringBuilder b = new StringBuilder();
        for (String l : run("ifconfig", iface, "inet6").output().split("\n"))
            if (l.trim().startsWith("inet6 ")) b.append(l.trim().replaceAll(" pltime \\d+ vltime \\d+", "")).append('\n');
        for (String f : List.of("inet", "inet6"))
            for (String l : run("netstat", "-rn", "-f", f).output().split("\n")) if (l.startsWith("default")) b.append(l.trim()).append('\n');
        return b.toString();
    }

    static Shell.Result run(String... cmd) {
        return Shell.run(Duration.ofSeconds(10), cmd);
    }
}
