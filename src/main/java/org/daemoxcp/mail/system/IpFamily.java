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
 * La famiglia di indirizzi con cui il server di posta parla con il mondo: IPv4 e IPv6 insieme, solo IPv4 o solo IPv6,
 * come sceglie l'amministratore nelle Impostazioni (chiesto dal committente il 17/11/2026: «se voglio solo l'ipv6,
 * devi lasciarmelo fare, idem per l'ipv4»).
 *
 * <p>Cosa segue la scelta: le porte su cui Postfix ({@code inet_protocols}), Dovecot ({@code listen}) e nginx (le righe
 * {@code listen} della webmail e della superficie pubblica sulla 443) ascoltano, e la regola di pf che fa entrare
 * posta e web. Il pannello (2096) e la sfida HTTP dei certificati sono socket Java, che non sanno rifiutare IPv4 su un
 * socket IPv6: per loro la famiglia la fa rispettare pf, con la stessa regola. Non la segue mai SSH: la sua regola di pf
 * resta senza famiglia, e sshd non si tocca. Non la seguono gli indirizzi interni (127.0.0.1, ::1): i servizi parlano
 * fra loro come sempre.
 *
 * <p>Finche' l'amministratore non sceglie, all'avvio non cambia niente: i servizi restano come sono, e la pagina
 * mostra la famiglia che usa Postfix. Una scelta si applica servizio per servizio, ognuno col suo controllo (postfix
 * check, doveconf, nginx -t, e poi le porte davvero in ascolto in quella famiglia); al primo che non torna si rimettono
 * tutti i file com'erano e si riavviano i servizi gia' toccati, e la scelta di prima resta.
 */
public final class IpFamily {

    private static final Logger LOGGER = Logger.getLogger(IpFamily.class.getName());

    /** La scelta, in panel_settings: "both", "ipv4" o "ipv6". Senza riga, nessuna scelta. */
    public static final String SETTING = "ip_family";

    static final String POSTCONF = "/usr/local/sbin/postconf";
    static final String POSTFIX = "/usr/local/sbin/postfix";
    static final String DOVECOT_CONF = "/usr/local/etc/dovecot/dovecot.conf";
    static final String DOVECONF = "/usr/local/bin/doveconf";
    static final String NGINX_CONF = "/usr/local/etc/nginx/nginx.conf";

    public enum Family {
        BOTH("both", "all", "*, ::", ""),
        IPV4("ipv4", "ipv4", "*", "inet "),
        IPV6("ipv6", "ipv6", "::", "inet6 ");

        /** Il valore salvato. */
        public final String key;
        /** inet_protocols di Postfix. */
        public final String postfix;
        /** listen di Dovecot. */
        public final String dovecot;
        /** La parola di pf davanti a "proto", con lo spazio; vuota per tutte e due. */
        public final String pf;

        Family(String key, String postfix, String dovecot, String pf) {
            this.key = key;
            this.postfix = postfix;
            this.dovecot = dovecot;
            this.pf = pf;
        }

        public boolean v4() { return this != IPV6; }

        public boolean v6() { return this != IPV4; }

        /** La famiglia di quel valore salvato, o null. */
        public static Family of(String key) {
            if (key == null) return null;
            for (Family f : values()) if (f.key.equals(key.trim().toLowerCase(Locale.ROOT))) return f;
            return null;
        }
    }

    private IpFamily() {}

    // ===================== la scelta =====================

    /** La scelta dell'amministratore, o null se non ha mai scelto (o il database non risponde). */
    public static Family chosen() {
        org.daemoxcp.mail.database.MailDatabase db = org.daemoxcp.mail.Main.mailDatabase;
        if (db == null) return null;
        try {
            return Family.of(db.getSetting(SETTING, ""));
        } catch (Exception e) {
            return null;
        }
    }

    /** Quella in uso: la scelta; senza, quella di Postfix; senza Postfix, tutte e due. */
    public static Family effective() {
        Family c = chosen();
        if (c != null) return c;
        Family p = fromPostfix(postconf("-h", "inet_protocols"));
        return p == null ? Family.BOTH : p;
    }

    /** Il valore di listen di Dovecot: quello della scelta, o tutte e due se l'amministratore non ha scelto. */
    public static String dovecotListen() {
        Family c = chosen();
        return c == null ? Family.BOTH.dovecot : c.dovecot;
    }

    /** La parola di pf per la regola dei servizi: vuota se l'amministratore non ha scelto (come prima). */
    public static String pfKeyword() {
        Family c = chosen();
        return c == null ? "" : c.pf;
    }

    // ===================== funzioni pure =====================

    /** La famiglia di un valore di inet_protocols, o null se non e' uno di quelli che si sanno leggere. Puro. */
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
     * dovecot.conf con la riga listen di quella famiglia, o null se non c'e' niente da cambiare. Solo una riga listen
     * in prima colonna, quella generale che scrive il pannello: le altre (dentro i listener, rientrate) non si toccano;
     * con nessuna o piu' d'una non e' il file del pannello e non lo si cambia. Puro.
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
     * Il testo di nginx con le righe listen di quella porta per quella famiglia: ogni gruppo di righe listen consecutive
     * per la porta (IPv4 "listen 8443 ..." e IPv6 "listen [::]:8443 ...") diventa la riga IPv4, quella IPv6 o tutte e
     * due, con le opzioni della prima riga del gruppo (ssl, default_server...). Le righe di altre porte e il resto del
     * testo restano come sono. Con f null il testo torna com'e'. Puro.
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
     * Le famiglie in cui una porta TCP ascolta, dall'uscita di {@code sockstat -46l -P tcp}: {v4, v6}. tcp46 (un socket
     * per tutte e due) conta per entrambe. Puro.
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

    /** Vero se la porta ascolta esattamente nelle famiglie di f (nessuna in piu', nessuna in meno). Puro. */
    static boolean listensAs(String sockstat, int port, Family f) {
        boolean[] l = listening(sockstat, port);
        return l[0] == f.v4() && l[1] == f.v6();
    }

    /** Vero se fra le rotte di netstat -rn ce n'e' una predefinita. Puro. */
    static boolean hasDefaultRoute(String netstat) {
        if (netstat == null) return false;
        for (String line : netstat.split("\n")) if (line.trim().startsWith("default ")) return true;
        return false;
    }

    // ===================== l'applicazione =====================

    /** L'esito di una scelta: fatta, da confermare (con gli avvisi), o rifiutata (col motivo). */
    public record Outcome(boolean done, boolean confirm, List<String> warnings, String error) {
        static Outcome ok(List<String> w) { return new Outcome(true, false, w, null); }
        static Outcome ask(List<String> w) { return new Outcome(false, true, w, null); }
        static Outcome no(String why) { return new Outcome(false, false, List.of(), why); }
    }

    /**
     * La scelta dell'amministratore. Prima di cambiare qualcosa: il server deve avere un indirizzo e una rotta nella
     * famiglia che resta (solo IPv4 o solo IPv6); poi gli avvisi, che chiedono una conferma. Confermata, la si applica
     * servizio per servizio; se uno non torna, tutto com'era e la scelta di prima resta. via e' l'indirizzo di chi
     * sceglie come lo vede il pannello (r18: dietro Cloudflare quello del browser, non del nodo di Cloudflare; il
     * tratto Cloudflare-server lo dice warnCloudflare), null dalla console: se la scelta chiude proprio quella
     * famiglia, un avviso lo dice prima.
     */
    public static synchronized Outcome choose(Family f, boolean confirmed, String via) {
        org.daemoxcp.mail.database.MailDatabase db = org.daemoxcp.mail.Main.mailDatabase;
        if (db == null) return Outcome.no(org.daemoxcp.mail.i18n.I18n.tr("server.ipf.noDatabase"));
        if (f == null) return Outcome.no(org.daemoxcp.mail.i18n.I18n.tr("server.badRequest"));
        String missing = missingNetwork(f);
        if (missing != null) return Outcome.no(missing);
        List<String> warnings = warnings(f, via);
        if (!confirmed && !warnings.isEmpty()) return Outcome.ask(warnings);

        String problem = align(f);
        if (problem != null) return Outcome.no(problem);
        db.setSetting(SETTING, f.key);
        org.daemoxcp.mail.security.PfPolicy.ensureAtBoot();
        LOGGER.info("[IpFamily] DONE: the server now speaks " + f.key + " (Postfix, Dovecot, nginx, pf)");
        return Outcome.ok(warnings);
    }

    /** All'avvio della parte root: se l'amministratore ha scelto, i servizi come la scelta. Al secondo avvio niente. */
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

    /** Il motivo per cui la famiglia non si puo' scegliere su questo server, o null. */
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
        if (f == Family.BOTH && !(v4 && route4) && !(v6 && route6)) return org.daemoxcp.mail.i18n.I18n.tr("server.ipf.noNetwork");
        return null;
    }

    /** Quello che chi sceglie deve sapere prima: cosa smette di funzionare con quella famiglia. */
    static List<String> warnings(Family f, String via) {
        List<String> w = new ArrayList<>();
        Family reachedBy = connectionFamily(via);
        if (reachedBy != null && f != Family.BOTH && reachedBy != f)
            w.add(org.daemoxcp.mail.i18n.I18n.tr(reachedBy == Family.IPV4 ? "server.ipf.warnYouV4" : "server.ipf.warnYouV6"));
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
     * La famiglia di una connessione, dal suo indirizzo: IPV4 o IPV6, null se e' il loopback (un tunnel SSH, che pf
     * non filtra e che resta comunque) o se non si sa. Un indirizzo IPv4 visto da un socket IPv6 (::ffff:a.b.c.d) e'
     * IPv4: e' quella la famiglia che la scelta chiude.
     */
    static Family connectionFamily(String address) {
        if (address == null || address.isBlank()) return null;
        try {
            InetAddress a = InetAddress.ofLiteral(address.trim().replaceFirst("%.*$", ""));   // senza la zona (%vtnet0)
            if (a.isLoopbackAddress() || a.isAnyLocalAddress()) return null;
            return a instanceof Inet4Address ? Family.IPV4 : Family.IPV6;
        } catch (Exception e) {
            return null;
        }
    }

    private static String dig(String type, String host) {
        return Shell.run(Duration.ofSeconds(10), "dig", "+short", type, host).outputTrim();
    }

    /**
     * Postfix, Dovecot e nginx nella famiglia f. Null se e' fatto (o se era gia' cosi'); altrimenti il motivo, con tutti
     * i file rimessi com'erano e i servizi gia' toccati riavviati.
     */
    static synchronized String align(Family f) {
        Map<Path, byte[]> before = new LinkedHashMap<>();
        List<String> touched = new ArrayList<>();
        try {
            String why = postfix(f, before, touched);
            if (why == null) why = dovecot(f, before, touched);
            if (why == null) why = nginx(f, before, touched);
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
        Family now = fromPostfix(postconf("-h", "inet_protocols"));
        if (now == f) return null;
        Path mainCf = Path.of(postconf("-h", "config_directory"), "main.cf");
        if (!Files.isRegularFile(mainCf)) return "Postfix: " + mainCf + " not found";
        before.put(mainCf, Files.readAllBytes(mainCf));
        boolean checkedBefore = Shell.run(Duration.ofSeconds(60), POSTFIX, "check").success();
        Shell.Result r = Shell.run(Duration.ofSeconds(30), POSTCONF, "-e", "inet_protocols=" + f.postfix);
        if (!r.success()) return "Postfix: postconf -e failed: " + r.outputTrim();
        if (checkedBefore && !Shell.run(Duration.ofSeconds(60), POSTFIX, "check").success())
            return "Postfix: postfix check refuses inet_protocols = " + f.postfix;
        touched.add("postfix");
        // inet_protocols vuole un riavvio: un reload tiene i socket aperti.
        Shell.run(Duration.ofSeconds(90), "service", "postfix", "restart");
        if (!waitListening(25, f)) return "Postfix: after the restart port 25 does not listen as " + f.key;
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

    /** La porta della webmail dalla configurazione del pannello, o null. */
    private static Integer webmailPort() {
        try {
            String p = org.daemoxcp.mail.Main.dbManager == null ? null : org.daemoxcp.mail.Main.dbManager.getRoundcubePort();
            return p != null && p.trim().matches("[0-9]{1,5}") ? Integer.parseInt(p.trim()) : null;
        } catch (Exception e) {
            return null;
        }
    }

    /** Il file della superficie pubblica sulla 443, dove nginx lo legge davvero (nginx -T), o null. */
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

    /** Scrive accanto e sostituisce con un rename, tenendo proprietario e permessi. */
    private static void replace(Path p, String content) throws Exception {
        Path tmp = p.resolveSibling("." + p.getFileName() + ".ipfamily");
        Files.copy(p, tmp, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
        Files.writeString(tmp, content, StandardCharsets.UTF_8);
        Files.move(tmp, p, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    /** I file com'erano, e i servizi gia' toccati riavviati (nginx ricaricato). */
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
