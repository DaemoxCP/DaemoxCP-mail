package org.daemoxcp.mail.system;

import org.daemoxcp.mail.util.Shell;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The address family the mail server uses to talk to the world: IPv4 and IPv6 together, IPv4 only or IPv6 only,
 * as the administrator chooses in "Settings" (asked by the owner on 2026-11-17: "if I want only ipv6, you have to
 * let me do it, same for ipv4").
 *
 * <p>What follows the choice: the ports on which Postfix ({@code inet_protocols}), Dovecot ({@code listen}) and
 * nginx (the {@code listen} lines of the webmail and of the public surface on 443) listen, and the pf rule that
 * lets mail and web in. The panel (2096) and the HTTP challenge of the certificates are Java sockets, which cannot
 * refuse IPv4 on an IPv6 socket: for them pf enforces the family, with the same rule. SSH never follows it: its pf
 * rule stays without a family, and sshd is not touched. The internal addresses (127.0.0.1, ::1) do not follow it:
 * the services talk to each other as always.
 *
 * <p>The fourth choice, "IPv6 outbound only" (asked by the owner on 2026-11-19, "the way Apple does it"): the
 * server receives only over IPv4 (mail, webmail, panel), and over IPv6 mail only goes out. A single name, the mail
 * one, with its AAAA and its reverse DNS as with both: whoever tries to deliver over IPv6 immediately gets a
 * rejection from pf and falls back to IPv4.
 *
 * <p>Universal configurations (asked by the owner on 2026-11-19: "make the configurations universal, so that then
 * it is only the panel that adapts"): Postfix, Dovecot and nginx always listen on IPv4 and on IPv6, written once;
 * pf decides the family (the services rule with its family, an immediate rejection on the other one, and mail that
 * does not go out over IPv6 with IPv4 only). Changing the choice does not rewrite the services and does not restart
 * them: only pf, and a Postfix reload if the outbound preference changes (IPv6 only). The first pass on a server
 * that had already chosen brings them to the universal form, once.
 *
 * <p>Until the administrator chooses, nothing changes at startup: the services stay as they are, and the page shows
 * the family Postfix uses. A choice is applied service by service, each with its own check (postfix check,
 * doveconf, nginx -t, and then the ports really listening in that family); at the first one that does not match,
 * all the files are put back as they were and the services already touched are restarted, and the previous choice
 * stays.
 */
public final class IpFamily {

    private static final Logger LOGGER = Logger.getLogger(IpFamily.class.getName());

    /** The choice, in panel_settings: "both", "ipv4", "ipv6" or "ipv6out". Without a row, no choice. */
    public static final String SETTING = "ip_family";

    static final String POSTCONF = "/usr/local/sbin/postconf";
    static final String POSTFIX = "/usr/local/sbin/postfix";
    static final String DOVECOT_CONF = "/usr/local/etc/dovecot/dovecot.conf";
    static final String DOVECONF = "/usr/local/bin/doveconf";
    static final String NGINX_CONF = "/usr/local/etc/nginx/nginx.conf";

    /**
     * IPv6 only does not remove the IPv4 127.0.0.1: the webmail talks to Dovecot (127.0.0.1:993) and to Postfix
     * (127.0.0.1:587), Postfix to the antispam filter (inet:127.0.0.1:11332) and to the sending limits, all over IPv4
     * on the loopback. With inet_protocols = ipv6 Postfix no longer opens or uses any IPv4 socket (postconf(5): the
     * parameter applies to the connections Postfix opens and to those it accepts), and with listen = :: Dovecot does
     * not answer on 127.0.0.1: the webmail no longer sent mail and mail passed without antispam (found on 2026-11-18
     * while building the addresses guide). Therefore: Postfix stays on "all" and prefers IPv6 for sending
     * (smtp_address_preference = ipv6), Dovecot listens on :: and on 127.0.0.1, and whoever comes from outside over
     * IPv4 is stopped by pf (the mail rule with "inet6"). On a server without IPv4, 127.0.0.1 stays on the loopback
     * (rc.d/routing).
     */
    public enum Family {
        BOTH("both", "all", "*, ::", ""),
        IPV4("ipv4", "ipv4", "*", "inet "),
        IPV6("ipv6", "all", "::, 127.0.0.1", "inet6 "),
        /** Only IPv4 comes in; over IPv6 mail only goes out (pf as with IPv4 only, but mail also goes out over IPv6). */
        IPV6_OUT("ipv6out", "all", "*, ::", "inet ");

        /** The saved value. */
        public final String key;
        /** Postfix's inet_protocols. */
        public final String postfix;
        /** Dovecot's listen. */
        public final String dovecot;
        /** The pf word before "proto", with the space; empty for both. */
        public final String pf;

        Family(String key, String postfix, String dovecot, String pf) {
            this.key = key;
            this.postfix = postfix;
            this.dovecot = dovecot;
            this.pf = pf;
        }

        /** The server receives over IPv4 (and mail goes out over IPv4). */
        public boolean v4() { return this != IPV6; }

        /** The server receives over IPv6: it listens on IPv6, the mail name has the AAAA. Not with IPV6_OUT. */
        public boolean v6() { return this == BOTH || this == IPV6; }

        /** Mail goes out over IPv6: it needs the IPv6 reverse DNS, forward-confirmed. */
        public boolean sends6() { return this != IPV4; }

        /** The family of that saved value, or null. */
        public static Family of(String key) {
            if (key == null) return null;
            for (Family f : values()) if (f.key.equals(key.trim().toLowerCase(Locale.ROOT))) return f;
            return null;
        }
    }

    private IpFamily() {}

    // ===================== the choice =====================

    /** The administrator's choice, or null if they never chose (or the database does not answer). */
    public static Family chosen() {
        org.daemoxcp.mail.database.MailDatabase db = org.daemoxcp.mail.Main.mailDatabase;
        if (db == null) return null;
        try {
            return Family.of(db.getSetting(SETTING, ""));
        } catch (Exception e) {
            return null;
        }
    }

    /** The one in use: the choice; without it, Postfix's; without Postfix, both. */
    public static Family effective() {
        Family c = chosen();
        if (c != null) return c;
        Family p = fromPostfix(postconf("-h", "inet_protocols"));
        return p == null ? Family.BOTH : p;
    }

    /** Dovecot's listen value: the one of the choice, or both if the administrator has not chosen. */
    public static String dovecotListen() {
        Family c = chosen();
        return c == null ? Family.BOTH.dovecot : c.dovecot;
    }

    /** The pf word for the services rule: empty if the administrator has not chosen (as before). */
    public static String pfKeyword() {
        Family c = chosen();
        return c == null ? "" : c.pf;
    }

    /** Whether pf must keep mail out of outbound IPv6: with IPv4 only chosen (Postfix is universal, on "all"). */
    public static boolean pfBlocksSmtpOut6() {
        Family c = chosen();
        return c != null && !c.sends6();
    }

    // ===================== pure functions =====================

    /** The family of an inet_protocols value, or null if it is not one of those that can be read. Pure. */
    static Family fromPostfix(String value) {
        if (value == null) return null;
        String v = value.trim().toLowerCase(Locale.ROOT).replaceAll("[\\s,]+", " ");
        return switch (v) {
            case "all", "ipv4 ipv6", "ipv6 ipv4" -> Family.BOTH;
            case "ipv4" -> Family.IPV4;
            case "ipv6" -> Family.IPV6;
            default -> null;
        };
    }

    private static final Pattern DOVECOT_LISTEN = Pattern.compile("(?m)^(listen\\s*=\\s*)(.*)$");

    /**
     * dovecot.conf with the listen line of that family, or null if there is nothing to change. Only one listen line
     * in the first column, the general one the panel writes: the others (inside the listeners, indented) are not
     * touched; with none or more than one it is not the panel's file and it is not changed. Pure.
     */
    static String withDovecotListen(String conf, Family f) {
        if (conf == null || f == null) return null;
        Matcher m = DOVECOT_LISTEN.matcher(conf);
        if (!m.find()) return null;
        int start = m.start(), end = m.end();
        String prefix = m.group(1), value = m.group(2).trim();
        if (m.find()) return null;
        if (value.replaceAll("\\s+", "").equals(f.dovecot.replaceAll("\\s+", ""))) return null;
        return conf.substring(0, start) + prefix + f.dovecot + conf.substring(end);
    }

    /**
     * The nginx text with the listen lines of that port for that family: each group of consecutive listen lines for
     * the port (IPv4 "listen 8443 ..." and IPv6 "listen [::]:8443 ...") becomes the IPv4 line, the IPv6 one or both,
     * with the options of the group's first line (ssl, default_server...). The lines of other ports and the rest of
     * the text stay as they are. With f null the text comes back as it is. Pure.
     */
    public static String withNginxListen(String conf, int port, Family f) {
        if (conf == null || f == null) return conf;
        Pattern one = Pattern.compile("^(\\s*)listen\\s+(\\[::\\]:|0\\.0\\.0\\.0:|\\*:)?" + port + "(?![0-9])([^;]*);\\s*$");
        String[] lines = conf.split("\n", -1);
        StringBuilder out = new StringBuilder();
        int i = 0;
        while (i < lines.length) {
            Matcher m = one.matcher(lines[i]);
            if (!m.matches()) {
                out.append(lines[i]);
                if (i < lines.length - 1) out.append('\n');
                i++;
                continue;
            }
            String indent = m.group(1);
            String options = m.group(3).replaceAll("\\s+ipv6only=(on|off)", "");
            int j = i;
            while (j < lines.length && one.matcher(lines[j]).matches()) j++;
            List<String> group = new ArrayList<>();
            if (f.v4()) group.add(indent + "listen " + port + options + ";");
            if (f.v6()) group.add(indent + "listen [::]:" + port + options + ";");
            out.append(String.join("\n", group));
            if (j < lines.length) out.append('\n');
            i = j;
        }
        return out.toString();
    }

    /**
     * The families in which a TCP port listens, from the output of {@code sockstat -46l -P tcp}: {v4, v6}. tcp46 (one
     * socket for both) counts for both. Pure.
     */
    static boolean[] listening(String sockstat, int port) {
        boolean v4 = false, v6 = false;
        if (sockstat == null) return new boolean[]{false, false};
        for (String line : sockstat.split("\n")) {
            String[] c = line.trim().split("\\s+");
            if (c.length < 6 || !c[5].endsWith(":" + port)) continue;
            if (c[4].equals("tcp4") || c[4].equals("tcp46")) v4 = true;
            if (c[4].equals("tcp6") || c[4].equals("tcp46")) v6 = true;
        }
        return new boolean[]{v4, v6};
    }

    /**
     * True if the port listens in the families of f: both, or IPv4 only (no IPv6), or IPv6 (with IPv6 only an IPv4
     * one may be there, the Dovecot loopback one and Postfix's on "all": pf stops it from outside). Pure.
     */
    static boolean listensAs(String sockstat, int port, Family f) {
        boolean[] l = listening(sockstat, port);
        return switch (f) {
            case BOTH -> l[0] && l[1];
            case IPV4 -> l[0] && !l[1];
            case IPV6 -> l[1];
            case IPV6_OUT -> l[0];
        };
    }

    /** smtp_address_preference: with IPv6 only, mail is sent over IPv6 first; otherwise Postfix's value ("any"). Pure. */
    static String postfixPreference(Family f) {
        return f == Family.IPV6 ? "ipv6" : "any";
    }

    /** True if among the routes of netstat -rn there is a default one. Pure. */
    static boolean hasDefaultRoute(String netstat) {
        if (netstat == null) return false;
        for (String line : netstat.split("\n")) if (line.trim().startsWith("default ")) return true;
        return false;
    }

    // ===================== applying it =====================

    /** The outcome of a choice: done, to be confirmed (with the warnings), or refused (with the reason). */
    public record Outcome(boolean done, boolean confirm, List<String> warnings, String error) {
        static Outcome ok(List<String> w) { return new Outcome(true, false, w, null); }
        static Outcome ask(List<String> w) { return new Outcome(false, true, w, null); }
        static Outcome no(String why) { return new Outcome(false, false, List.of(), why); }
    }

    /**
     * The administrator's choice. Before changing anything: the server must have an address and a route in the family
     * that remains (IPv4 only or IPv6 only); then the warnings, which ask for a confirmation. Once confirmed, it is
     * applied service by service; if one does not match, everything goes back as it was and the previous choice stays.
     * via is the address of whoever chooses, as the panel sees it (r18: behind Cloudflare the browser's, not the
     * Cloudflare node's; the Cloudflare-server leg is covered by warnCloudflare), null from the console: if the choice
     * closes exactly that family, a warning says so first.
     */
    public static synchronized Outcome choose(Family f, boolean confirmed, String via) {
        org.daemoxcp.mail.database.MailDatabase db = org.daemoxcp.mail.Main.mailDatabase;
        if (db == null) return Outcome.no(org.daemoxcp.mail.i18n.I18n.tr("server.ipf.noDatabase"));
        if (f == null) return Outcome.no(org.daemoxcp.mail.i18n.I18n.tr("server.badRequest"));
        String missing = missingNetwork(f);
        if (missing != null) return Outcome.no(missing);
        // From the panel, mail goes over IPv6 only with the IPv6 reverse DNS in place (Gmail and Microsoft refuse
        // without it). Not from the console: it is the way out, and it must always work.
        if (via != null) {
            String ptr = missingPtr6(f);
            if (ptr != null) return Outcome.no(ptr);
        }
        List<String> warnings = warnings(f, via);
        if (!confirmed && !warnings.isEmpty()) return Outcome.ask(warnings);

        // First pf with the new choice, then the services in the universal form (from the second time on they do not
        // change): so Postfix on "all" never sends over IPv6 before pf keeps it out, if the choice is IPv4 only.
        String before = db.getSetting(SETTING, "");
        db.setSetting(SETTING, f.key);
        org.daemoxcp.mail.security.PfPolicy.ensureAtBoot();
        String problem = align(f);
        if (problem != null) {
            db.setSetting(SETTING, before == null ? "" : before);
            org.daemoxcp.mail.security.PfPolicy.ensureAtBoot();
            return Outcome.no(problem);
        }
        LOGGER.info("[IpFamily] DONE: the server now speaks " + f.key + " (pf; Postfix, Dovecot, nginx listen on both)");
        return Outcome.ok(warnings);
    }

    /**
     * At the start of the root part: if the administrator has chosen, the services as the choice says. At the second
     * start, nothing.
     */
    public static void ensureAtBoot() {
        try {
            Family c = chosen();
            if (c == null) return;
            String problem = align(c);
            if (problem != null) LOGGER.warning("[IpFamily] " + problem);
        } catch (Throwable t) {
            LOGGER.warning("[IpFamily] ensureAtBoot exception: " + t.getMessage());
        }
    }

    /** The reason why the family cannot be chosen on this server, or null. */
    static String missingNetwork(Family f) {
        boolean v4 = false, v6 = false;
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (ni.isLoopback() || !ni.isUp()) continue;
                for (InetAddress a : Collections.list(ni.getInetAddresses())) {
                    if (a instanceof Inet4Address) v4 = true;
                    if (a instanceof Inet6Address && !a.isLinkLocalAddress()) v6 = true;
                }
            }
        } catch (Exception e) {
            return org.daemoxcp.mail.i18n.I18n.tr("server.ipf.noInterfaces");
        }
        boolean route4 = hasDefaultRoute(Shell.run(Duration.ofSeconds(10), "netstat", "-rn", "-f", "inet").output());
        boolean route6 = hasDefaultRoute(Shell.run(Duration.ofSeconds(10), "netstat", "-rn", "-f", "inet6").output());
        if (f == Family.IPV4 && !(v4 && route4)) return org.daemoxcp.mail.i18n.I18n.tr("server.ipf.noIpv4");
        if (f == Family.IPV6 && !(v6 && route6)) return org.daemoxcp.mail.i18n.I18n.tr("server.ipf.noIpv6");
        if (f == Family.IPV6_OUT && !(v4 && route4)) return org.daemoxcp.mail.i18n.I18n.tr("server.ipf.noIpv4");
        if (f == Family.IPV6_OUT && !(v6 && route6)) return org.daemoxcp.mail.i18n.I18n.tr("server.ipf.noIpv6");
        if (f == Family.BOTH && !(v4 && route4) && !(v6 && route6)) return org.daemoxcp.mail.i18n.I18n.tr("server.ipf.noNetwork");
        return null;
    }

    /**
     * If the family brings mail onto IPv6 (even outbound only) and the server has a global IPv6, the reverse DNS of
     * that address must give the mail name, and the name must lead back to the address: otherwise the reason. Without a
     * global IPv6 it is not needed (mail does not go out over IPv6); without a mail name it cannot be checked and it
     * does not block.
     */
    static String missingPtr6(Family f) {
        if (!f.sends6()) return null;
        ServerAddresses.State s = ServerAddresses.read();
        if (s.v6().addresses().isEmpty()) return null;
        org.daemoxcp.mail.database.MailDatabase db = org.daemoxcp.mail.Main.mailDatabase;
        String host = db == null ? "" : db.getSetting("mail_hostname", "");
        if (host == null || !host.matches("[a-zA-Z0-9.-]{1,253}")) return null;
        String ip = s.v6().addresses().get(0);
        org.daemoxcp.mail.security.ReverseDns.Check c = org.daemoxcp.mail.security.ReverseDns.check(ip, host);
        return c.ok() ? null : org.daemoxcp.mail.i18n.I18n.tr("server.ipf.noPtr6", Map.of("ip", ip, "h", host));
    }

    /**
     * The warnings of a choice without making it: the addresses guide shows them in its single confirmation and then
     * chooses with "confirmed", so whoever ticks the checkbox "Mail also comes in over IPv6" sees one window, not two.
     */
    public static List<String> preview(Family f, String via) {
        return f == null ? List.of() : warnings(f, via);
    }

    /** What whoever chooses must know first: what stops working with that family. */
    static List<String> warnings(Family f, String via) {
        List<String> w = new ArrayList<>();
        Family reachedBy = connectionFamily(via);
        if (reachedBy == Family.IPV4 && !f.v4()) w.add(org.daemoxcp.mail.i18n.I18n.tr("server.ipf.warnYouV4"));
        if (reachedBy == Family.IPV6 && !f.v6()) w.add(org.daemoxcp.mail.i18n.I18n.tr("server.ipf.warnYouV6"));
        org.daemoxcp.mail.database.MailDatabase db = org.daemoxcp.mail.Main.mailDatabase;
        String host = db == null ? "" : db.getSetting("mail_hostname", "");
        boolean hostOk = host != null && host.matches("[a-zA-Z0-9.-]{1,253}");
        if (f == Family.IPV4 && hostOk && !dig("AAAA", host).isEmpty())
            w.add(org.daemoxcp.mail.i18n.I18n.tr("server.ipf.warnAaaa", Map.of("h", host)));

        if (f == Family.IPV6) {
            w.add(org.daemoxcp.mail.i18n.I18n.tr("server.ipf.warnV6Only"));
            if (hostOk && !dig("A", host).isEmpty())
                w.add(org.daemoxcp.mail.i18n.I18n.tr("server.ipf.warnA", Map.of("h", host)));
            w.add(org.daemoxcp.mail.i18n.I18n.tr("server.ipf.warnCloudflare"));
        }
        return w;
    }

    /**
     * The family of a connection, from its address: IPV4 or IPV6, null if it is the loopback (an SSH tunnel, which pf
     * does not filter and which stays anyway) or if unknown. An IPv4 address seen from an IPv6 socket (::ffff:a.b.c.d)
     * is IPv4: that is the family the choice closes.
     */
    public static Family connectionFamily(String address) {
        if (address == null || address.isBlank()) return null;
        try {
            InetAddress a = InetAddress.ofLiteral(address.trim().replaceFirst("%.*$", ""));   // without the zone (%vtnet0)
            if (a.isLoopbackAddress() || a.isAnyLocalAddress()) return null;
            return a instanceof Inet4Address ? Family.IPV4 : Family.IPV6;
        } catch (Exception e) {
            return null;
        }
    }

    /** The record as it is now, asked of the server that publishes it (FreshDns), not of the resolver's cache. */
    private static String dig(String type, String host) {
        return org.daemoxcp.mail.security.FreshDns.query(type, host);
    }

    /**
     * Postfix, Dovecot and nginx in the universal form: listening on IPv4 and on IPv6, whatever f is (pf decides the
     * family); of f only Postfix's outbound preference counts. Null if done (or if it was already so); otherwise the
     * reason, with all the files put back as they were and the services already touched restarted.
     */
    static synchronized String align(Family f) {
        Map<Path, byte[]> before = new LinkedHashMap<>();
        List<String> touched = new ArrayList<>();
        try {
            String why = postfix(f, before, touched);
            if (why == null) why = dovecot(Family.BOTH, before, touched);
            if (why == null) why = nginx(Family.BOTH, before, touched);
            if (why == null) return null;
            restore(before, touched);
            return why;
        } catch (Exception e) {
            restore(before, touched);
            return "not applied: " + e.getMessage();
        }
    }

    private static String postfix(Family f, Map<Path, byte[]> before, List<String> touched) throws Exception {
        if (!Files.isExecutable(Path.of(POSTCONF))) return null;
        String preference = postfixPreference(f);
        boolean protocols = fromPostfix(postconf("-h", "inet_protocols")) != Family.BOTH;
        if (!protocols && preference.equals(postconf("-h", "smtp_address_preference").trim())) return null;
        Path mainCf = Path.of(postconf("-h", "config_directory"), "main.cf");
        if (!Files.isRegularFile(mainCf)) return "Postfix: " + mainCf + " not found";
        before.put(mainCf, Files.readAllBytes(mainCf));
        boolean checkedBefore = Shell.run(Duration.ofSeconds(60), POSTFIX, "check").success();
        Shell.Result r = Shell.run(Duration.ofSeconds(30), POSTCONF, "-e", "inet_protocols=" + Family.BOTH.postfix,
                "smtp_address_preference=" + preference);
        if (!r.success()) return "Postfix: postconf -e failed: " + r.outputTrim();
        if (checkedBefore && !Shell.run(Duration.ofSeconds(60), POSTFIX, "check").success())
            return "Postfix: postfix check refuses inet_protocols = " + Family.BOTH.postfix;
        touched.add("postfix");
        if (!protocols) {
            // Only the outbound preference changes: a reload is enough, the sockets stay.
            Shell.run(Duration.ofSeconds(60), "service", "postfix", "reload");
            return null;
        }
        // inet_protocols needs a restart: a reload keeps the sockets open. It happens only once (universal form).
        Shell.run(Duration.ofSeconds(90), "service", "postfix", "restart");
        if (!waitListening(25, Family.BOTH)) return "Postfix: after the restart port 25 does not listen on IPv4 and IPv6";
        return null;
    }

    private static String dovecot(Family f, Map<Path, byte[]> before, List<String> touched) throws Exception {
        Path conf = Path.of(DOVECOT_CONF);
        if (!Files.isRegularFile(conf) || !Files.isExecutable(Path.of(DOVECONF))) return null;
        String current = Files.readString(conf, StandardCharsets.UTF_8);
        String next = withDovecotListen(current, f);
        if (next == null) return null;
        before.put(conf, current.getBytes(StandardCharsets.UTF_8));
        replace(conf, next);
        if (!Shell.run(Duration.ofSeconds(15), DOVECONF, "-n").success())
            return "Dovecot: doveconf refuses listen = " + f.dovecot;
        touched.add("dovecot");
        Shell.run(Duration.ofSeconds(90), "service", "dovecot", "restart");
        if (!waitListening(993, f)) return "Dovecot: after the restart port 993 does not listen as " + f.key;
        return null;
    }

    private static String nginx(Family f, Map<Path, byte[]> before, List<String> touched) throws Exception {
        if (Shell.resolve("nginx") == null) return null;
        Map<Path, Integer> files = new LinkedHashMap<>();
        Integer webmail = webmailPort();
        if (webmail != null && Files.isRegularFile(Path.of(NGINX_CONF))) files.put(Path.of(NGINX_CONF), webmail);
        Path surface = publicSurfaceFile();
        if (surface != null) files.put(surface, 443);
        List<Integer> ports = new ArrayList<>();
        for (Map.Entry<Path, Integer> e : files.entrySet()) {
            String current = Files.readString(e.getKey(), StandardCharsets.UTF_8);
            String next = withNginxListen(current, e.getValue(), f);
            if (next.equals(current)) continue;
            before.put(e.getKey(), current.getBytes(StandardCharsets.UTF_8));
            replace(e.getKey(), next);
            ports.add(e.getValue());
        }
        if (ports.isEmpty()) return null;
        Shell.Result t = Shell.run(Duration.ofSeconds(30), "nginx", "-t");
        if (!t.success()) return "nginx: nginx -t refuses the listen lines for " + f.key + ": " + t.outputTrim();
        touched.add("nginx");
        Shell.run(Duration.ofSeconds(60), "service", "nginx", "reload");
        for (int p : ports) if (!waitListening(p, f)) return "nginx: after the reload port " + p + " does not listen as " + f.key;
        return null;
    }

    /** The webmail port from the panel configuration, or null. */
    private static Integer webmailPort() {
        try {
            String p = org.daemoxcp.mail.Main.dbManager == null ? null : org.daemoxcp.mail.Main.dbManager.getRoundcubePort();
            return p != null && p.trim().matches("[0-9]{1,5}") ? Integer.parseInt(p.trim()) : null;
        } catch (Exception e) {
            return null;
        }
    }

    /** The file of the public surface on 443, where nginx really reads it (nginx -T), or null. */
    private static Path publicSurfaceFile() {
        Shell.Result t = Shell.run(Duration.ofSeconds(20), "nginx", "-T");
        if (!t.success()) return null;
        Matcher m = Pattern.compile("(?m)^# configuration file (\\S+):").matcher(t.output());
        while (m.find()) {
            Path p = Path.of(m.group(1));
            if (p.getFileName() != null && p.getFileName().toString().equals(WebProtection.FILE_NAME) && Files.isRegularFile(p)) return p;
        }
        return null;
    }

    private static boolean waitListening(int port, Family f) throws InterruptedException {
        for (int i = 0; i < 30; i++) {
            if (listensAs(Shell.run(Duration.ofSeconds(15), "sockstat", "-46l", "-P", "tcp").output(), port, f)) return true;
            Thread.sleep(500);
        }
        return false;
    }

    /** Writes alongside and replaces with a rename, keeping owner and permissions. */
    private static void replace(Path p, String content) throws Exception {
        Path tmp = p.resolveSibling("." + p.getFileName() + ".ipfamily");
        Files.copy(p, tmp, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
        Files.writeString(tmp, content, StandardCharsets.UTF_8);
        Files.move(tmp, p, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    /** The files as they were, and the services already touched restarted (nginx reloaded). */
    private static void restore(Map<Path, byte[]> before, List<String> touched) {
        for (Map.Entry<Path, byte[]> e : before.entrySet()) {
            try {
                Files.write(e.getKey(), e.getValue());
            } catch (Exception ex) {
                LOGGER.warning("[IpFamily] " + e.getKey() + " could not be put back: " + ex.getMessage());
            }
        }
        for (String s : touched)
            Shell.run(Duration.ofSeconds(90), "service", s, s.equals("nginx") ? "reload" : "restart");
        if (!before.isEmpty()) LOGGER.warning("[IpFamily] ROLLED_BACK: " + before.keySet() + " put back, " + touched + " restarted");
    }

    private static String postconf(String... args) {
        if (!Files.isExecutable(Path.of(POSTCONF))) return "";
        String[] cmd = new String[args.length + 1];
        cmd[0] = POSTCONF;
        System.arraycopy(args, 0, cmd, 1, args.length);
        Shell.Result r = Shell.run(Duration.ofSeconds(15), cmd);
        return r.success() ? r.outputTrim() : "";
    }
}
