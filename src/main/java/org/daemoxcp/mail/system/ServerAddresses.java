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
 * Gli indirizzi del server, IPv4 e IPv6: cosa ha (indirizzo, strada, uscita su internet) e i passi per aggiungerne o
 * toglierne uno, ognuno sicuro e con la sua strada di ritorno (chiesto dal committente il 18/11/2026: «voglio l'ipv6,
 * non lo voglio piu', voglio solo l'ipv4 ... SOLO se i software lo permettono»).
 *
 * Questo e' il piano «cosa ha il server». Quale famiglia usa la posta e' l'altro piano, IpFamily.
 *
 * Le regole, lette nella documentazione di FreeBSD 15 (rc.conf(5), ifconfig(8), route(8), rc.d/netif e routing,
 * network.subr) e di Hetzner Cloud prima di scrivere:
 *  - MAI «service netif restart» ne' «service routing restart»: il primo toglie TUTTI gli indirizzi dell'interfaccia e
 *    la spegne, il secondo cancella le strade di tutte e due le famiglie (anche quella da cui arriva SSH). Si usano solo
 *    comandi che toccano la famiglia in questione: ifconfig ... alias/-alias, route -6/-4 add/delete default, dhclient.
 *  - Un IPv6 statico: ifconfig_IF_ipv6="inet6 INDIRIZZO prefixlen N" e ipv6_defaultrouter (fe80::1%IF su Hetzner, col
 *    nome dell'interfaccia: senza, una strada link-local non vale). Dal vivo prima «inet6 -ifdisabled»: l'interfaccia
 *    nasce con l'IPv6 spento se rc.conf non lo accende.
 *  - Un indirizzo nuovo e' «tentative» finche' la verifica dei doppioni (DAD) non finisce: si aspetta, e se risulta
 *    «duplicated» si torna indietro.
 *  - Prima di tenere un cambiamento, una prova vera: uscire su internet in quella famiglia (fetch -4/-6 verso due
 *    servizi che hanno sia A sia AAAA, controllati il 18/11/2026). Se non esce, tutto com'era, rc.conf compreso.
 *  - rc.conf si scrive solo dopo la prova, con una copia accanto prima (ConfigBackups), e quello che c'era prima si
 *    tiene in un file del pannello: togliere l'IPv6 rimette le righe di prima, non le cancella e basta.
 *  - L'IPv4 il pannello non lo toglie mai da un server dove funziona: lo toglie il provider (Hetzner: server spento,
 *    console). Dopo, il pannello pulisce la configurazione rimasta. Rimetterlo e' DHCP, come lo da' Hetzner.
 * SSH non si tocca mai: ne' la sua configurazione ne' la sua regola in pf.
 */
public final class ServerAddresses {

    private static final Logger LOGGER = Logger.getLogger(ServerAddresses.class.getName());

    /** rc.conf: quello vero, oppure una copia nelle prove. */
    static Path rcConf = Path.of("/etc/rc.conf");
    /** Quello che c'era in rc.conf prima che il pannello aggiungesse un indirizzo, per rimetterlo togliendolo. */
    static Path stateFile = Path.of(DataFolderRename.NEW, "server-addresses.json");
    /** Due servizi con A e AAAA (pkg di FreeBSD su Fastly, Cloudflare): basta che uno risponda. */
    static final List<String> PROBE_URLS = List.of("https://pkg.freebsd.org/", "https://www.cloudflare.com/ips-v6");
    /** Il servizio interno di Hetzner Cloud: la sua configurazione di rete (non documentata) porta il blocco IPv6. */
    static final String HETZNER_METADATA = "http://169.254.169.254/hetzner/v1/metadata";

    static final Pattern IFACE = Pattern.compile("[a-z][a-z0-9]{0,14}");
    /** I caratteri di un indirizzo come lo si scrive: cifre esadecimali, i due punti, il punto. Nient'altro. */
    static final Pattern ADDRESS_CHARS = Pattern.compile("[0-9A-Fa-f:.]{2,45}");

    /** Esegue un comando: Shell.run, oppure un finto nelle prove. */
    interface Runner { Shell.Result run(Duration timeout, String... cmd); }
    static Runner runner = Shell::run;
    /** La prova di uscita in una famiglia ("ipv4" o "ipv6"): quella vera, oppure una finta nelle prove. */
    static Predicate<String> probe = ServerAddresses::realProbe;
    /** Solo nelle prove sulla VM: accetta anche gli indirizzi di documentazione (2001:db8::/32) come «globali». */
    static boolean acceptTestAddresses = false;
    /** Quanto si aspetta la fine della verifica dei doppioni, al massimo. */
    static Duration dadWait = Duration.ofSeconds(8);

    private ServerAddresses() {}

    // ===================== lo stato =====================

    /** Una famiglia: gli indirizzi (senza i link-local), se ha la strada di default e verso dove, la riga di rc.conf. */
    public record Side(List<String> addresses, boolean route, String gateway, String rcLine) {
        public boolean present() { return !addresses.isEmpty() && route; }
    }

    /** Il server: l'interfaccia verso fuori, IPv4 e IPv6, e un IPv6 suggerito dal provider (o null). */
    public record State(String iface, Side v4, Side v6, Suggestion suggestion, boolean v6Managed, boolean sshOnV6) {}

    /** Un IPv6 che il provider ha assegnato al server: indirizzo, prefisso, strada e da dove lo si e' letto. */
    public record Suggestion(String address, int prefix, String gateway, String source) {}

    /** L'esito di un passo: fatto o no, il motivo, il nome del registro su disco. */
    public record Result(boolean ok, String message, String journal) {}

    /** Lo stato, senza chiedere al provider un IPv6 da suggerire (che puo' voler dire qualche secondo di attesa). */
    public static State read() {
        return read(false);
    }

    /** Lo stato per la guida: con l'IPv6 che il provider suggerisce, se il server non ne ha uno. */
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

    /** L'interfaccia verso fuori: quella della strada di default (IPv4, poi IPv6), altrimenti la prima accesa. */
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
     * Gli indirizzi di una famiglia in un'uscita di ifconfig, senza link-local, loopback e quelli non ancora pronti. Per
     * l'IPv6 solo quelli globali: un indirizzo locale (fd00::/8, come quello che la rete di prova da' da sola) non porta
     * su internet e non conta come «IPv6 presente».
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

    /** La strada di default in un'uscita di netstat -rn: dove porta, o null. */
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

    /** Se sshd ascolta in IPv6 sulla 22 (sockstat -6 -l -p 22): senza, un server solo IPv6 non lo si raggiunge piu'. */
    static boolean listensOn(String sockstat) {
        if (sockstat == null) return false;
        for (String line : sockstat.split("\n"))
            if (line.contains("sshd") && line.contains(":22") && (line.contains("tcp6") || line.contains("tcp46"))) return true;
        return false;
    }

    /**
     * Un valore scritto in rc.conf, vuoto se il file non lo ha. Letto dal file e non con «sysrc -n -f»: sysrc da' anche
     * il valore di /etc/defaults/rc.conf quando il file non lo ha (ipv6_defaultrouter="NO"), e tornando indietro il
     * pannello avrebbe scritto una riga che prima non c'era (visto sulla VM il 18/11/2026). L'ultima assegnazione vale,
     * come per la shell.
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

    /** Il valore di un'assegnazione di rc.conf: fra virgolette doppie o semplici, o fino al primo spazio o «#». */
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

    // ===================== il suggerimento del provider =====================

    /**
     * Il blocco IPv6 che Hetzner Cloud ha assegnato, dalla configurazione di rete del suo servizio interno: Hetzner
     * documenta solo i campi IPv4 di quel servizio, ma la configurazione di rete (quella che legge cloud-init) porta
     * anche l'indirizzo IPv6 e la strada (misurato sul server vero il 18/11/2026). Se non c'e' o non si capisce: null,
     * e la guida chiede l'indirizzo all'amministratore.
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

    // ===================== indirizzi =====================

    static InetAddress literal(String s) {
        if (s == null || !ADDRESS_CHARS.matcher(s).matches()) return null;
        try {
            return InetAddress.ofLiteral(s);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** Un IPv6 raggiungibile da internet: 2000::/3, tranne la documentazione (2001:db8::/32). */
    static boolean isGlobal(Inet6Address a) {
        byte[] b = a.getAddress();
        boolean doc = (b[0] & 0xff) == 0x20 && (b[1] & 0xff) == 0x01 && (b[2] & 0xff) == 0x0d && (b[3] & 0xff) == 0xb8;
        if (acceptTestAddresses && doc) return true;
        return (b[0] & 0xe0) == 0x20 && !doc;
    }

    /** La forma corta di RFC 5952: minuscole, zeri iniziali tolti, la serie di zeri piu' lunga (almeno due) come "::". */
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

    /** La strada IPv6 come la vuole route(8): un indirizzo link-local porta il nome dell'interfaccia (fe80::1%vtnet0). */
    static String gatewayFor(String gateway, String iface) {
        InetAddress ia = literal(gateway.replaceFirst("%.*$", ""));
        if (!(ia instanceof Inet6Address i6)) return null;
        return i6.isLinkLocalAddress() ? compress(i6) + "%" + iface : compress(i6);
    }

    /**
     * Controlla quello che l'amministratore ha scritto (o che il provider ha suggerito): null se va bene, altrimenti il
     * motivo, come chiave della lingua. L'indirizzo dev'essere un IPv6 globale, il prefisso fra 1 e 128, la strada un
     * IPv6 (link-local o globale).
     */
    static String checkIpv6(String address, int prefix, String gateway) {
        InetAddress a = literal(address);
        if (!(a instanceof Inet6Address a6)) return "server.addr.badAddress";
        if (!isGlobal(a6)) return "server.addr.notGlobal";
        if (prefix < 1 || prefix > 128) return "server.addr.badPrefix";
        if (gateway == null || !(literal(gateway.replaceFirst("%.*$", "")) instanceof Inet6Address)) return "server.addr.badGateway";
        return null;
    }

    // ===================== la prova di uscita =====================

    /** Se il server esce su internet in quella famiglia ("ipv4" o "ipv6"), adesso. */
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

    // ===================== aggiungere e togliere l'IPv6 =====================

    /**
     * Aggiunge l'IPv6: dal vivo senza toccare l'IPv4, aspetta che l'indirizzo sia pronto, la strada, la prova di uscita;
     * solo se la prova passa lo scrive in rc.conf. Se un passo non va, tutto come prima.
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

            // Solo adesso rc.conf, con quello che c'era prima messo da parte.
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
     * Toglie l'IPv6 che il pannello aveva aggiunto (o quello scritto in rc.conf): la strada, l'indirizzo, e in rc.conf le
     * righe di prima. La guida ci arriva dopo aver portato la posta in solo IPv4 e tolto il record AAAA; da console si
     * puo' anche subito (e' la via d'uscita). Solo se la posta e' in SOLO IPv6 si rifiuta: si fermerebbe del tutto.
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

    /** L'indirizzo di una riga «inet6 INDIRIZZO prefixlen N» (o «inet6 INDIRIZZO/N»), o null. */
    static String fromRcLine(String line) {
        if (line == null) return null;
        Matcher m = Pattern.compile("inet6\\s+([0-9A-Fa-f:]+)(?:/\\d+)?").matcher(line);
        while (m.find()) {
            InetAddress ia = literal(m.group(1));
            if (ia instanceof Inet6Address i6 && !i6.isLinkLocalAddress()) return compress(i6);
        }
        return null;
    }

    /** Aspetta che l'indirizzo non sia piu' «tentative»: null se e' pronto, «duplicated» o «timeout». */
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

    /** Rimette in rc.conf le due righe IPv6 di prima: col loro valore, o tolte se prima non c'erano. */
    private static void restoreRc(Job job, String iface, JSONObject saved) {
        String prevIf = saved.optString("previousIpv6", "");
        String prevRouter = saved.optString("previousRouter", "");
        String varIf = "ifconfig_" + iface + "_ipv6";
        job.step(prevIf.isEmpty() ? run(10, "sysrc", "-f", rcConf.toString(), "-x", varIf) : run(10, "sysrc", "-f", rcConf.toString(), varIf + "=" + prevIf));
        job.step(prevRouter.isEmpty() ? run(10, "sysrc", "-f", rcConf.toString(), "-x", "ipv6_defaultrouter")
                : run(10, "sysrc", "-f", rcConf.toString(), "ipv6_defaultrouter=" + prevRouter));
    }

    // ===================== IPv4: rimetterlo, pulirne la configurazione =====================

    /**
     * Rimette l'IPv4 con DHCP, come lo da' Hetzner, dopo che il provider l'ha riassegnato: dhclient sull'interfaccia
     * (l'IPv6 non si tocca), la prova di uscita, e solo allora ifconfig_IF="DHCP" in rc.conf.
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
     * Dopo che il provider ha tolto l'IPv4: toglie la configurazione rimasta (indirizzo fermo, strada, dhclient,
     * ifconfig_IF e defaultrouter in rc.conf). Si rifiuta se l'IPv4 esce ancora su internet: in quel caso il provider
     * non l'ha tolto, e toglierlo dal server chiuderebbe una strada che funziona.
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

    /** Ferma il dhclient di quell'interfaccia per PID esatto, dal suo file: mai per nome. */
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

    // ===================== rc.conf, il file di stato, il registro =====================

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

    /** Un lavoro: il suo registro su disco (JobJournal) e l'esito. Ogni comando ci finisce con l'esito. */
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
