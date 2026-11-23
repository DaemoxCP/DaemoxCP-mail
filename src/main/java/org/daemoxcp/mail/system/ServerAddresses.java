package org.daemoxcp.mail.system;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.daemoxcp.mail.util.Shell;
import org.json.JSONObject;

/**
 * The server's addresses, IPv4 and IPv6: what it has (address, route, way out to the internet) and the steps to
 * add or remove one, each safe and with its own way back (requested by the owner on 2026-11-18: "I want IPv6,
 * I don't want it any more, I want only IPv4 ... ONLY if the software allows it").
 *
 * This is the "what the server has" plane. Which family the mail uses is the other plane, IpFamily.
 *
 * The rules, read in the documentation of FreeBSD 15 (rc.conf(5), ifconfig(8), route(8), rc.d/netif and routing,
 * network.subr) and of Hetzner Cloud before writing:
 *  - NEVER "service netif restart" nor "service routing restart": the first removes ALL the addresses of the
 *    interface and turns it off, the second deletes the routes of both families (including the one SSH arrives
 *    from). Only commands that touch the family in question are used: ifconfig ... alias/-alias, route -6/-4
 *    add/delete default, dhclient.
 *  - A static IPv6: ifconfig_IF_ipv6="inet6 ADDRESS prefixlen N" and ipv6_defaultrouter (fe80::1%IF on Hetzner,
 *    with the interface name: without it, a link-local route is not valid). Live, first "inet6 -ifdisabled": the
 *    interface comes up with IPv6 off if rc.conf does not turn it on.
 *  - A new address is "tentative" until duplicate address detection (DAD) finishes: we wait, and if it turns out
 *    "duplicated" we go back.
 *  - Before keeping a change, a real test: going out to the internet in that family (fetch -4/-6 towards two
 *    services that have both A and AAAA, checked on 2026-11-18). If it does not get out, everything as it was,
 *    rc.conf included.
 *  - rc.conf is written only after the test, with a copy beside it first (ConfigBackups), and what was there
 *    before is kept in a panel file: removing IPv6 puts the previous lines back, it does not just delete them.
 *  - The panel never removes IPv4 from a server where it works: the provider removes it (Hetzner: server off,
 *    console). Afterwards, the panel cleans up the leftover configuration. Putting it back is DHCP, as Hetzner
 *    gives it.
 * SSH is never touched: neither its configuration nor its rule in pf.
 */
public final class ServerAddresses {

    private static final Logger LOGGER = Logger.getLogger(ServerAddresses.class.getName());

    /** rc.conf: the real one, or a copy in the tests. */
    static Path rcConf = Path.of("/etc/rc.conf");
    /** What was in rc.conf before the panel added an address, to put it back when removing it. */
    static Path stateFile = Path.of(DataFolderRename.NEW, "server-addresses.json");
    /** Two services with A and AAAA (FreeBSD pkg on Fastly, Cloudflare): it is enough that one answers. */
    static final List<String> PROBE_URLS = List.of("https://pkg.freebsd.org/", "https://www.cloudflare.com/ips-v6");
    /** The internal service of Hetzner Cloud: its network configuration (undocumented) carries the IPv6 block. */
    static final String HETZNER_METADATA = "http://169.254.169.254/hetzner/v1/metadata";

    static final Pattern IFACE = Pattern.compile("[a-z][a-z0-9]{0,14}");
    /** The characters of an address as it is written: hexadecimal digits, the colon, the dot. Nothing else. */
    static final Pattern ADDRESS_CHARS = Pattern.compile("[0-9A-Fa-f:.]{2,45}");

    /** Runs a command: Shell.run, or a fake one in the tests. */
    interface Runner { Shell.Result run(Duration timeout, String... cmd); }
    static Runner runner = Shell::run;
    /** The exit test in a family ("ipv4" or "ipv6"): the real one, or a fake one in the tests. */
    static Predicate<String> probe = ServerAddresses::realProbe;
    /** Only in the tests on the VM: also accepts documentation addresses (2001:db8::/32) as "global". */
    static boolean acceptTestAddresses = false;
    /** How long to wait, at most, for duplicate address detection to finish. */
    static Duration dadWait = Duration.ofSeconds(8);

    private ServerAddresses() {}

    // ===================== the status =====================

    /**
     * A family: the addresses (without link-local ones), whether it has the default route and where to, the
     * rc.conf line.
     */
    public record Side(List<String> addresses, boolean route, String gateway, String rcLine) {
        public boolean present() { return !addresses.isEmpty() && route; }
    }

    /** The server: the outward interface, IPv4 and IPv6, and an IPv6 suggested by the provider (or null). */
    public record State(String iface, Side v4, Side v6, Suggestion suggestion, boolean v6Managed, boolean sshOnV6) {}

    /** An IPv6 the provider assigned to the server: address, prefix, route and where it was read from. */
    public record Suggestion(String address, int prefix, String gateway, String source) {}

    /** The result of a step: done or not, the reason, the name of the log on disk. */
    public record Result(boolean ok, String message, String journal) {}

    /** The status, without asking the provider for an IPv6 to suggest (which can mean a few seconds of waiting). */
    public static State read() {
        return read(false);
    }

    /** The status for the guide: with the IPv6 the provider suggests, if the server has none. */
    public static State readForGuide() {
        return read(true);
    }

    static State read(boolean withSuggestion) {
        String iface = outsideInterface();
        String ifconfig = iface == null ? "" : run(10, "ifconfig", iface).output();
        String route4 = run(10, "netstat", "-rn", "-f", "inet").output();
        String route6 = run(10, "netstat", "-rn", "-f", "inet6").output();
        Side v4 = new Side(addresses(ifconfig, false), defaultRoute(route4) != null, defaultRoute(route4),
                iface == null ? "" : rc("ifconfig_" + iface));
        Side v6 = new Side(addresses(ifconfig, true), defaultRoute(route6) != null, defaultRoute(route6),
                iface == null ? "" : rc("ifconfig_" + iface + "_ipv6"));
        Suggestion s = withSuggestion && v6.addresses().isEmpty() && iface != null ? suggestIpv6(iface) : null;
        return new State(iface, v4, v6, s, Files.isRegularFile(stateFile),
                listensOn(run(10, "sockstat", "-6", "-l", "-P", "tcp", "-p", "22").output()));
    }

    /** The outward interface: the one of the default route (IPv4, then IPv6), otherwise the first one that is up. */
    static String outsideInterface() {
        for (String f : List.of("inet", "inet6")) {
            String i = defaultRouteInterface(run(10, "netstat", "-rn", "-f", f).output());
            if (i != null) return i;
        }
        for (String i : run(10, "ifconfig", "-l", "-u").outputTrim().split("\\s+"))
            if (IFACE.matcher(i).matches() && !i.startsWith("lo")) return i;
        return null;
    }

    /**
     * The addresses of a family in an ifconfig output, without link-local, loopback and those not ready yet. For
     * IPv6 only the global ones: a local address (fd00::/8, like the one the test network hands out by itself) does
     * not lead to the internet and does not count as "IPv6 present".
     */
    static List<String> addresses(String ifconfig, boolean v6) {
        List<String> out = new ArrayList<>();
        if (ifconfig == null) return out;
        for (String line : ifconfig.split("\n")) {
            String t = line.trim();
            if (!t.startsWith(v6 ? "inet6 " : "inet ")) continue;
            if (v6 && (t.contains(" tentative") || t.contains(" duplicated") || t.contains(" detached"))) continue;
            String a = t.split("\\s+")[1].replaceFirst("%.*$", "");
            InetAddress ia = literal(a);
            if (ia == null || ia.isLoopbackAddress() || ia.isLinkLocalAddress()) continue;
            if (v6 && !(ia instanceof Inet6Address i6 && isGlobal(i6))) continue;
            if (!v6 && !(ia instanceof Inet4Address)) continue;
            out.add(v6 ? compress((Inet6Address) ia) : ia.getHostAddress());
        }
        return out;
    }

    /** The default route in a netstat -rn output: where it leads, or null. */
    static String defaultRoute(String netstat) {
        String[] f = defaultLine(netstat);
        return f == null ? null : f[1];
    }

    static String defaultRouteInterface(String netstat) {
        String[] f = defaultLine(netstat);
        if (f == null || f.length < 4) return null;
        String i = f[f.length - 1];
        return IFACE.matcher(i).matches() && !i.startsWith("lo") ? i : null;
    }

    private static String[] defaultLine(String netstat) {
        if (netstat == null) return null;
        for (String line : netstat.split("\n")) {
            String t = line.trim();
            if (t.startsWith("default ")) return t.split("\\s+");
        }
        return null;
    }

    /**
     * Whether sshd listens on IPv6 on port 22 (sockstat -6 -l -p 22): without it, an IPv6-only server can no
     * longer be reached.
     */
    static boolean listensOn(String sockstat) {
        if (sockstat == null) return false;
        for (String line : sockstat.split("\n"))
            if (line.contains("sshd") && line.contains(":22") && (line.contains("tcp6") || line.contains("tcp46"))) return true;
        return false;
    }

    /**
     * A value written in rc.conf, empty if the file does not have it. Read from the file and not with "sysrc -n -f":
     * sysrc also gives the value of /etc/defaults/rc.conf when the file does not have it (ipv6_defaultrouter="NO"),
     * and when going back the panel would have written a line that was not there before (seen on the VM on
     * 2026-11-18). The last assignment wins, as in the shell.
     */
    static String rc(String variable) {
        try {
            if (!Files.isRegularFile(rcConf)) return "";
            String v = "";
            Matcher m = Pattern.compile("(?m)^[ \\t]*" + Pattern.quote(variable) + "=(.*)$").matcher(Files.readString(rcConf, StandardCharsets.UTF_8));
            while (m.find()) v = unquote(m.group(1));
            return v;
        } catch (Exception e) {
            return "";
        }
    }

    /** The value of an rc.conf assignment: between double or single quotes, or up to the first space or "#". */
    static String unquote(String raw) {
        String t = raw.trim();
        if (t.startsWith("\"") || t.startsWith("'")) {
            int end = t.indexOf(t.charAt(0), 1);
            return end > 0 ? t.substring(1, end) : t.substring(1);
        }
        int hash = t.indexOf('#');
        if (hash >= 0) t = t.substring(0, hash);
        String[] w = t.trim().split("\\s+");
        return w.length == 0 ? "" : w[0];
    }

    // ===================== the provider's suggestion =====================

    /**
     * The IPv6 block that Hetzner Cloud assigned, from the network configuration of its internal service: Hetzner
     * documents only the IPv4 fields of that service, but the network configuration (the one cloud-init reads) also
     * carries the IPv6 address and the route (measured on the production server on 2026-11-18). If it is not there
     * or cannot be understood: null, and the guide asks the administrator for the address.
     */
    static Suggestion suggestIpv6(String iface) {
        Shell.Result r = run(8, "fetch", "-q", "-T", "4", "-o", "-", HETZNER_METADATA);
        if (!r.success()) return null;
        return parseHetzner(r.output(), iface);
    }

    private static final Pattern YAML_ADDRESS = Pattern.compile("(?m)^\\s*-?\\s*address:\\s*['\"]?([0-9A-Fa-f:]+)/(\\d{1,3})['\"]?\\s*$");
    private static final Pattern YAML_GATEWAY = Pattern.compile("(?m)^\\s*-?\\s*gateway:\\s*['\"]?([0-9A-Fa-f:]+)['\"]?\\s*$");

    static Suggestion parseHetzner(String metadata, String iface) {
        if (metadata == null) return null;
        Matcher a = YAML_ADDRESS.matcher(metadata);
        String address = null;
        int prefix = 0;
        while (a.find()) {
            InetAddress ia = literal(a.group(1));
            if (ia instanceof Inet6Address i6 && isGlobal(i6)) {
                prefix = Integer.parseInt(a.group(2));
                address = compress(i6);
                break;
            }
        }
        if (address == null || prefix < 1 || prefix > 128) return null;
        String gateway = null;
        Matcher g = YAML_GATEWAY.matcher(metadata);
        while (g.find()) {
            if (literal(g.group(1)) instanceof Inet6Address) { gateway = g.group(1).toLowerCase(java.util.Locale.ROOT); break; }
        }
        if (gateway == null) return null;
        return new Suggestion(address, prefix, gatewayFor(gateway, iface), "hetzner");
    }

    // ===================== addresses =====================

    static InetAddress literal(String s) {
        if (s == null || !ADDRESS_CHARS.matcher(s).matches()) return null;
        try {
            return InetAddress.ofLiteral(s);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** An IPv6 reachable from the internet: 2000::/3, except documentation (2001:db8::/32). */
    static boolean isGlobal(Inet6Address a) {
        byte[] b = a.getAddress();
        boolean doc = (b[0] & 0xff) == 0x20 && (b[1] & 0xff) == 0x01 && (b[2] & 0xff) == 0x0d && (b[3] & 0xff) == 0xb8;
        if (acceptTestAddresses && doc) return true;
        return (b[0] & 0xe0) == 0x20 && !doc;
    }

    /** The RFC 5952 short form: lowercase, leading zeros removed, the longest run of zeros (at least two) as "::". */
    static String compress(Inet6Address a) {
        byte[] b = a.getAddress();
        int[] g = new int[8];
        for (int i = 0; i < 8; i++) g[i] = ((b[2 * i] & 0xff) << 8) | (b[2 * i + 1] & 0xff);
        int bestStart = -1, bestLen = 0;
        for (int i = 0; i < 8; ) {
            if (g[i] != 0) { i++; continue; }
            int j = i;
            while (j < 8 && g[j] == 0) j++;
            if (j - i > bestLen && j - i >= 2) { bestStart = i; bestLen = j - i; }
            i = j;
        }
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            if (i == bestStart) {
                s.append("::");
                i += bestLen - 1;
                continue;
            }
            if (s.length() > 0 && s.charAt(s.length() - 1) != ':') s.append(':');
            s.append(Integer.toHexString(g[i]));
        }
        return s.toString();
    }

    /**
     * The part of the address after the provider's block: "::1" for 2a01:4f8:c012:abcd::1 in a /64. It is the part
     * the Hetzner console asks for the reverse DNS of an IPv6 (docs.hetzner.com/cloud/servers/cloud-server-rdns/:
     * only the interface part is written). Null if the address or the prefix is not valid. Pure.
     */
    static String hostPart(String address, int prefix) {
        InetAddress a = literal(address);
        if (!(a instanceof Inet6Address a6) || prefix < 1 || prefix > 127) return null;
        byte[] b = a6.getAddress(), host = new byte[16];
        for (int i = 0; i < 16; i++) {
            int before = i * 8;
            if (before >= prefix) host[i] = b[i];
            else if (before + 8 > prefix) host[i] = (byte) (b[i] & (0xff >> (prefix - before)));
        }
        try {
            return compress((Inet6Address) InetAddress.getByAddress(host));
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * The machine's provider, from its firmware (kenv smbios.system.maker): "hetzner", or empty if another one
     * or unknown.
     */
    public static String provider() {
        String maker = run(5, "kenv", "-q", "smbios.system.maker").outputTrim().toLowerCase(java.util.Locale.ROOT);
        return maker.contains("hetzner") ? "hetzner" : "";
    }

    /**
     * The prefix of the server's IPv6: the one the panel wrote, or the one in rc.conf, or 64 (the providers'
     * block).
     */
    static int prefixOf(String iface) {
        JSONObject saved = readState();
        if (saved != null && saved.optInt("prefix", 0) > 0) return saved.optInt("prefix");
        Matcher m = Pattern.compile("prefixlen\\s+(\\d{1,3})|/(\\d{1,3})").matcher(iface == null ? "" : rc("ifconfig_" + iface + "_ipv6"));
        if (m.find()) return Integer.parseInt(m.group(1) != null ? m.group(1) : m.group(2));
        return 64;
    }

    /**
     * The part of the server's IPv6 after the block, for the reverse DNS in the provider's console; null if it
     * has no IPv6.
     */
    public static String hostPartNow(State s) {
        if (s == null || s.v6().addresses().isEmpty()) return null;
        return hostPart(s.v6().addresses().get(0), prefixOf(s.iface()));
    }

    /** The IPv6 route as route(8) wants it: a link-local address carries the interface name (fe80::1%vtnet0). */
    static String gatewayFor(String gateway, String iface) {
        InetAddress ia = literal(gateway.replaceFirst("%.*$", ""));
        if (!(ia instanceof Inet6Address i6)) return null;
        return i6.isLinkLocalAddress() ? compress(i6) + "%" + iface : compress(i6);
    }

    /**
     * Checks what the administrator wrote (or what the provider suggested): null if it is fine, otherwise the
     * reason, as a language key. The address must be a global IPv6, the prefix between 1 and 128, the route an
     * IPv6 (link-local or global).
     */
    static String checkIpv6(String address, int prefix, String gateway) {
        InetAddress a = literal(address);
        if (!(a instanceof Inet6Address a6)) return "server.addr.badAddress";
        if (!isGlobal(a6)) return "server.addr.notGlobal";
        if (prefix < 1 || prefix > 128) return "server.addr.badPrefix";
        if (gateway == null || !(literal(gateway.replaceFirst("%.*$", "")) instanceof Inet6Address)) return "server.addr.badGateway";
        return null;
    }

    // ===================== the exit test =====================

    /** Whether the server gets out to the internet in that family ("ipv4" or "ipv6"), now. */
    public static boolean goesOut(String family) {
        return probe.test(family);
    }

    static boolean realProbe(String family) {
        String flag = "ipv6".equals(family) ? "-6" : "-4";
        for (String url : PROBE_URLS) {
            if (run(15, "fetch", flag, "-q", "-T", "8", "-o", "/dev/null", url).success()) return true;
        }
        return false;
    }

    // ===================== adding and removing IPv6 =====================

    /**
     * Adds the IPv6: live without touching IPv4, waits for the address to be ready, the route, the exit test;
     * only if the test passes does it write it in rc.conf. If a step fails, everything as before.
     */
    public static synchronized Result addIpv6(String address, int prefix, String gateway) {
        Job job = new Job("add-ipv6");
        try {
            State s = read();
            if (s.iface() == null) return job.fail("server.addr.noInterface");
            String bad = checkIpv6(address, prefix, gateway);
            if (bad != null) return job.fail(bad);
            if (!s.v6().addresses().isEmpty()) return job.fail("server.addr.v6Already");
            if (s.v6().route()) return job.fail("server.addr.v6RouteAlready");
            String iface = s.iface();
            String addr = compress((Inet6Address) literal(address));
            String gw = gatewayFor(gateway, iface);
            job.line("interface " + iface + ", address " + addr + "/" + prefix + ", default route " + gw);

            String nd6 = run(10, "ifconfig", iface, "inet6").output();
            boolean wasDisabled = nd6.contains("IFDISABLED");
            if (wasDisabled && !job.step(run(10, "ifconfig", iface, "inet6", "-ifdisabled"))) return job.fail("server.addr.liveFailed");
            if (!job.step(run(10, "ifconfig", iface, "inet6", addr, "prefixlen", String.valueOf(prefix), "alias"))) {
                undoV6(job, iface, addr, null, wasDisabled);
                return job.fail("server.addr.liveFailed");
            }
            String dad = waitReady(iface, addr);
            if (dad != null) {
                job.line("address not usable: " + dad);
                undoV6(job, iface, addr, null, wasDisabled);
                return job.fail("duplicated".equals(dad) ? "server.addr.duplicated" : "server.addr.notReady");
            }
            if (!job.step(run(10, "route", "-6", "add", "default", gw))) {
                undoV6(job, iface, addr, null, wasDisabled);
                return job.fail("server.addr.routeFailed");
            }
            job.line("probe: going out to the internet over IPv6");
            if (!probe.test("ipv6")) {
                undoV6(job, iface, addr, gw, wasDisabled);
                return job.fail("server.addr.probeFailedV6");
            }
            job.line("probe: OK");

            // Only now rc.conf, with what was there before set aside.
            JSONObject saved = new JSONObject()
                    .put("iface", iface).put("address", addr).put("prefix", prefix).put("gateway", gw)
                    .put("previousIpv6", rc("ifconfig_" + iface + "_ipv6"))
                    .put("previousRouter", rc("ipv6_defaultrouter"));
            backupRcConf(job);
            boolean written = job.step(run(10, "sysrc", "-f", rcConf.toString(), "ifconfig_" + iface + "_ipv6=inet6 " + addr + " prefixlen " + prefix))
                    && job.step(run(10, "sysrc", "-f", rcConf.toString(), "ipv6_defaultrouter=" + gw));
            if (!written) {
                restoreRc(job, iface, saved);
                undoV6(job, iface, addr, gw, wasDisabled);
                return job.fail("server.addr.rcFailed");
            }
            writeState(saved);
            LOGGER.info("[ServerAddresses] DONE: IPv6 " + addr + "/" + prefix + " on " + iface + ", default route " + gw);
            return job.ok("server.addr.v6Added");
        } catch (Exception e) {
            return job.error(e);
        }
    }

    /**
     * Removes the IPv6 the panel had added (or the one written in rc.conf): the route, the address, and in
     * rc.conf the previous lines. The guide gets here after moving the mail to IPv4 only and removing the AAAA
     * record; from the console it can also be done right away (it is the way out). It refuses only if the mail
     * is on IPv6 ONLY: it would stop completely.
     */
    public static synchronized Result removeIpv6() {
        Job job = new Job("remove-ipv6");
        try {
            State s = read();
            if (s.iface() == null) return job.fail("server.addr.noInterface");
            if (IpFamily.effective() == IpFamily.Family.IPV6) return job.fail("server.addr.mailV6Only");
            JSONObject saved = readState();
            String iface = saved != null ? saved.optString("iface", s.iface()) : s.iface();
            if (!IFACE.matcher(iface).matches()) return job.fail("server.addr.noInterface");
            String addr = saved != null ? saved.optString("address", "") : fromRcLine(rc("ifconfig_" + iface + "_ipv6"));
            String gw = saved != null ? saved.optString("gateway", "") : rc("ipv6_defaultrouter");
            if ((addr == null || addr.isEmpty()) && s.v6().addresses().size() == 1) addr = s.v6().addresses().get(0);
            if (addr == null || addr.isEmpty()) return job.fail("server.addr.v6NotFound");
            job.line("interface " + iface + ", address " + addr + ", default route " + gw);

            if (s.v6().route()) job.step(run(10, "route", "-6", "delete", "default"));
            job.step(run(10, "ifconfig", iface, "inet6", addr, "-alias"));
            backupRcConf(job);
            restoreRc(job, iface, saved != null ? saved : new JSONObject().put("previousIpv6", "").put("previousRouter", ""));
            deleteState();
            if (!probe.test("ipv4")) job.line("WARNING: IPv4 does not go out to the internet (it did not depend on this change)");
            LOGGER.info("[ServerAddresses] DONE: IPv6 " + addr + " removed from " + iface);
            return job.ok("server.addr.v6Removed");
        } catch (Exception e) {
            return job.error(e);
        }
    }

    /** The address of an "inet6 ADDRESS prefixlen N" line (or "inet6 ADDRESS/N"), or null. */
    static String fromRcLine(String line) {
        if (line == null) return null;
        Matcher m = Pattern.compile("inet6\\s+([0-9A-Fa-f:]+)(?:/\\d+)?").matcher(line);
        while (m.find()) {
            InetAddress ia = literal(m.group(1));
            if (ia instanceof Inet6Address i6 && !i6.isLinkLocalAddress()) return compress(i6);
        }
        return null;
    }

    /** Waits until the address is no longer "tentative": null if it is ready, "duplicated" or "timeout". */
    static String waitReady(String iface, String addr) throws InterruptedException {
        long until = System.nanoTime() + dadWait.toNanos();
        while (true) {
            String out = run(10, "ifconfig", iface, "inet6").output();
            String line = null;
            for (String l : out.split("\n")) if (l.contains(" " + addr + " ") || l.contains(" " + addr + "%")) line = l;
            if (line == null) return "missing";
            if (line.contains("duplicated")) return "duplicated";
            if (!line.contains("tentative")) return null;
            if (System.nanoTime() > until) return "timeout";
            Thread.sleep(300);
        }
    }

    private static void undoV6(Job job, String iface, String addr, String gw, boolean wasDisabled) {
        job.line("going back: nothing stays");
        if (gw != null) job.step(run(10, "route", "-6", "delete", "default", gw));
        job.step(run(10, "ifconfig", iface, "inet6", addr, "-alias"));
        if (wasDisabled) job.step(run(10, "ifconfig", iface, "inet6", "ifdisabled"));
    }

    /**
     * Puts the two previous IPv6 lines back in rc.conf: with their value, or removed if they were not there
     * before.
     */
    private static void restoreRc(Job job, String iface, JSONObject saved) {
        String prevIf = saved.optString("previousIpv6", "");
        String prevRouter = saved.optString("previousRouter", "");
        String varIf = "ifconfig_" + iface + "_ipv6";
        job.step(prevIf.isEmpty() ? run(10, "sysrc", "-f", rcConf.toString(), "-x", varIf) : run(10, "sysrc", "-f", rcConf.toString(), varIf + "=" + prevIf));
        job.step(prevRouter.isEmpty() ? run(10, "sysrc", "-f", rcConf.toString(), "-x", "ipv6_defaultrouter")
                : run(10, "sysrc", "-f", rcConf.toString(), "ipv6_defaultrouter=" + prevRouter));
    }

    // ===================== IPv4: putting it back, cleaning up its configuration =====================

    /**
     * Puts IPv4 back with DHCP, as Hetzner gives it, after the provider has reassigned it: dhclient on the
     * interface (IPv6 is not touched), the exit test, and only then ifconfig_IF="DHCP" in rc.conf.
     */
    public static synchronized Result addIpv4() {
        Job job = new Job("add-ipv4");
        try {
            State s = read();
            if (s.iface() == null) return job.fail("server.addr.noInterface");
            if (s.v4().present() && probe.test("ipv4")) return job.ok("server.addr.v4Already");
            String iface = s.iface();
            String previous = rc("ifconfig_" + iface);
            if (!job.step(run(90, "dhclient", iface))) {
                stopDhclient(job, iface);
                return job.fail("server.addr.dhcpFailed");
            }
            if (!probe.test("ipv4")) {
                stopDhclient(job, iface);
                for (String a : addresses(run(10, "ifconfig", iface).output(), false)) job.step(run(10, "ifconfig", iface, "inet", a, "-alias"));
                job.step(run(10, "route", "-4", "delete", "default"));
                return job.fail("server.addr.probeFailedV4");
            }
            backupRcConf(job);
            if (!job.step(run(10, "sysrc", "-f", rcConf.toString(), "ifconfig_" + iface + "=DHCP"))) return job.fail("server.addr.rcFailed");
            job.line("previous ifconfig_" + iface + ": " + (previous.isEmpty() ? "(none)" : previous));
            LOGGER.info("[ServerAddresses] DONE: IPv4 by DHCP on " + iface);
            return job.ok("server.addr.v4Added");
        } catch (Exception e) {
            return job.error(e);
        }
    }

    /**
     * After the provider has removed IPv4: removes the leftover configuration (static address, route, dhclient,
     * ifconfig_IF and defaultrouter in rc.conf). It refuses if IPv4 still gets out to the internet: in that case
     * the provider has not removed it, and removing it from the server would close a route that works.
     */
    public static synchronized Result cleanIpv4() {
        Job job = new Job("clean-ipv4");
        try {
            State s = read();
            if (s.iface() == null) return job.fail("server.addr.noInterface");
            if (!s.v6().present() || !probe.test("ipv6")) return job.fail("server.addr.v6NotComplete");
            if (probe.test("ipv4")) return job.fail("server.addr.v4StillWorks");
            String iface = s.iface();
            stopDhclient(job, iface);
            if (s.v4().route()) job.step(run(10, "route", "-4", "delete", "default"));
            for (String a : s.v4().addresses()) job.step(run(10, "ifconfig", iface, "inet", a, "-alias"));
            backupRcConf(job);
            job.line("previous ifconfig_" + iface + ": " + rc("ifconfig_" + iface) + ", defaultrouter: " + rc("defaultrouter"));
            job.step(run(10, "sysrc", "-f", rcConf.toString(), "-x", "ifconfig_" + iface));
            job.step(run(10, "sysrc", "-f", rcConf.toString(), "-x", "defaultrouter"));
            LOGGER.info("[ServerAddresses] DONE: the IPv4 configuration left on " + iface + " removed (the provider removed the address)");
            return job.ok("server.addr.v4Cleaned");
        } catch (Exception e) {
            return job.error(e);
        }
    }

    /** Stops the dhclient of that interface by exact PID, from its file: never by name. */
    private static void stopDhclient(Job job, String iface) {
        Path pid = Path.of("/var/run/dhclient/dhclient." + iface + ".pid");
        try {
            if (!Files.isRegularFile(pid)) return;
            String p = Files.readString(pid, StandardCharsets.UTF_8).trim();
            if (p.matches("[0-9]{1,7}")) job.step(run(10, "kill", p));
        } catch (Exception e) {
            job.line("dhclient not stopped: " + e.getMessage());
        }
    }

    // ===================== rc.conf, the state file, the log =====================

    private static void backupRcConf(Job job) {
        try {
            job.line("copy of rc.conf: " + ConfigBackups.copy(rcConf, StandardCopyOption.COPY_ATTRIBUTES));
        } catch (Exception e) {
            job.line("copy of rc.conf not made: " + e.getMessage());
        }
    }

    static JSONObject readState() {
        try {
            return Files.isRegularFile(stateFile) ? new JSONObject(Files.readString(stateFile, StandardCharsets.UTF_8)) : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static void writeState(JSONObject o) throws Exception {
        Files.createDirectories(stateFile.getParent());
        Path tmp = stateFile.resolveSibling(stateFile.getFileName() + ".new");
        Files.writeString(tmp, o.toString(2), StandardCharsets.UTF_8);
        Files.setPosixFilePermissions(tmp, PosixFilePermissions.fromString("rw-------"));
        Files.move(tmp, stateFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    private static void deleteState() {
        try { Files.deleteIfExists(stateFile); } catch (Exception ignored) { }
    }

    private static Shell.Result run(int seconds, String... cmd) {
        return runner.run(Duration.ofSeconds(seconds), cmd);
    }

    /** A job: its log on disk (JobJournal) and the result. Every command ends up in it with its result. */
    static final class Job {
        final Path journal;
        final long started = System.currentTimeMillis();

        Job(String type) {
            journal = JobJournal.open("server-addresses-" + type + "-" + started, "server-addresses", started);
        }

        void line(String text) { JobJournal.append(journal, text); }

        boolean step(Shell.Result r) {
            line("$ " + String.join(" ", r.command()) + " -> " + (r.success() ? "ok" : "exit " + r.exitCode() + (r.timedOut() ? " (timeout)" : ""))
                    + (r.outputTrim().isEmpty() ? "" : ": " + r.outputTrim().replace('\n', ' ')));
            return r.success();
        }

        String name() { return journal == null ? "" : journal.getFileName().toString(); }

        Result ok(String key) {
            JobJournal.end(journal, "done", null, key, (System.currentTimeMillis() - started) / 1000);
            return new Result(true, key, name());
        }

        Result fail(String key) {
            JobJournal.end(journal, "failed", key, null, (System.currentTimeMillis() - started) / 1000);
            LOGGER.warning("[ServerAddresses] not done: " + key);
            return new Result(false, key, name());
        }

        Result error(Exception e) {
            JobJournal.end(journal, "failed", String.valueOf(e), null, (System.currentTimeMillis() - started) / 1000);
            LOGGER.warning("[ServerAddresses] failed: " + e);
            return new Result(false, "server.addr.error", name());
        }
    }
}
