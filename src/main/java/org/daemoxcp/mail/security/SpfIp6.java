package org.daemoxcp.mail.security;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;

import org.daemoxcp.mail.database.MailDatabase;

/**
 * L'IPv6 del server nell'SPF dei domini, quando la posta in IPv6 esce soltanto.
 *
 * <p>Perche'. L'SPF che scrive il pannello e' «v=spf1 ip4:IPv4 mx -all» (con «ip6:IPv6» quando il server riceve anche
 * in IPv6). Chi riceve una mail in IPv6 controlla l'SPF con l'indirizzo IPv6: «mx» lo autorizza solo se il nome della
 * posta ha l'AAAA di quell'indirizzo. Con la posta in IPv6 solo in uscita il nome della posta NON ha l'AAAA (nessuno
 * deve consegnare in IPv6): senza «ip6:» l'SPF fallisce e Gmail rifiuta. Quindi ogni dominio ospitato ha bisogno di
 * «ip6:IPv6».
 *
 * <p>Cosa tocca. Solo l'SPF nella forma del pannello: «v=spf1 [ip4:...] [ip6:...] mx -all», in quest'ordine. Un SPF
 * scritto a mano (include di altri, ~all, altri meccanismi) non si riscrive: il pannello dice quale dominio e cosa
 * aggiungere. Tornando a solo IPv4 si toglie «ip6:» dai record del pannello: un indirizzo che il server non usa piu'
 * (e che il provider potrebbe dare a un altro) non deve poter spedire per i tuoi domini.
 */
public final class SpfIp6 {

    private SpfIp6() {}

    /** Lo stato dell'SPF dei domini: se tutti autorizzano l'IPv6, se in qualcuno c'e' l'ip6 del pannello, quali no. */
    public record Status(boolean allCovered, boolean anyPanelIp6, List<String> uncovered) {}

    /** L'esito di un cambiamento: fatto o no, la chiave del testo e i suoi valori. */
    public record Outcome(boolean ok, String key, Map<String, String> args) {}

    // ===================== funzioni pure =====================

    /** I termini di un SPF, in minuscolo (i nomi dei meccanismi non distinguono le maiuscole, RFC 7208). */
    static String[] terms(String spf) {
        return spf == null ? new String[0] : spf.trim().toLowerCase(Locale.ROOT).split("\\s+");
    }

    /** Se e' la forma del pannello: v=spf1, poi ip4: facoltativo, ip6: facoltativo, mx, -all. Puro. */
    static boolean isPanelForm(String spf) {
        String[] t = terms(spf);
        int i = 0;
        if (t.length < 3 || !t[i++].equals("v=spf1")) return false;
        if (i < t.length && t[i].startsWith("ip4:")) i++;
        if (i < t.length && t[i].startsWith("ip6:")) i++;
        return t.length == i + 2 && t[i].equals("mx") && t[i + 1].equals("-all");
    }

    /** Se nella forma del pannello c'e' un ip6:. Puro. */
    static boolean hasPanelIp6(String spf) {
        if (!isPanelForm(spf)) return false;
        for (String t : terms(spf)) if (t.startsWith("ip6:")) return true;
        return false;
    }

    /** L'SPF del pannello con ip6:IPv6 (al posto di un ip6 di prima); null se e' gia' cosi' o non e' del pannello. Puro. */
    static String withIp6(String spf, String ip6) {
        if (!isPanelForm(spf) || !validIp6(ip6)) return null;
        String ip4 = null;
        for (String t : terms(spf)) if (t.startsWith("ip4:")) ip4 = t;
        String next = "v=spf1" + (ip4 == null ? "" : " " + ip4) + " ip6:" + ip6.toLowerCase(Locale.ROOT) + " mx -all";
        return next.equals(String.join(" ", terms(spf))) ? null : next;
    }

    /** L'SPF del pannello senza ip6:; null se non ce l'ha o non e' del pannello. Puro. */
    static String withoutIp6(String spf) {
        if (!hasPanelIp6(spf)) return null;
        StringBuilder b = new StringBuilder();
        for (String t : terms(spf)) if (!t.startsWith("ip6:")) b.append(b.length() == 0 ? "" : " ").append(t);
        return b.toString();
    }

    /**
     * Se l'SPF autorizza l'indirizzo IPv6 con un ip6: (con o senza «+», con o senza /lunghezza) che lo contiene.
     * «-ip6:», «~ip6:», «?ip6:» non autorizzano. Puro.
     */
    public static boolean covers(String spf, String ip6) {
        byte[] addr = bytes(ip6);
        if (addr == null) return false;
        for (String t : terms(spf)) {
            String m = t.startsWith("+") ? t.substring(1) : t;
            if (!m.startsWith("ip6:")) continue;
            String net = m.substring(4);
            int len = 128;
            int slash = net.indexOf('/');
            if (slash >= 0) {
                try {
                    len = Integer.parseInt(net.substring(slash + 1));
                } catch (NumberFormatException e) {
                    continue;
                }
                net = net.substring(0, slash);
            }
            byte[] n = bytes(net);
            if (n == null || len < 0 || len > 128) continue;
            if (samePrefix(addr, n, len)) return true;
        }
        return false;
    }

    private static boolean samePrefix(byte[] a, byte[] b, int bits) {
        for (int i = 0; i < bits; i++) {
            int mask = 0x80 >> (i % 8);
            if ((a[i / 8] & mask) != (b[i / 8] & mask)) return false;
        }
        return true;
    }

    private static byte[] bytes(String ip6) {
        if (!validIp6(ip6)) return null;
        try {
            InetAddress a = InetAddress.ofLiteral(ip6);
            byte[] b = a.getAddress();
            return b.length == 16 ? b : null;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    static boolean validIp6(String s) {
        return s != null && s.matches("[0-9A-Fa-f:]{2,39}") && s.contains(":");
    }

    /** I record SPF fra i TXT di un nome (quelli che cominciano con «v=spf1»). Puro. */
    static List<String> spfRecords(List<String> txt) {
        List<String> out = new ArrayList<>();
        for (String r : txt) {
            String l = r.trim().toLowerCase(Locale.ROOT);
            if (l.equals("v=spf1") || l.startsWith("v=spf1 ")) out.add(r.trim());
        }
        return out;
    }

    /**
     * Lo stato dell'SPF di quei domini, con la domanda dei TXT data da chi chiama (nelle prove un finto): un dominio
     * senza SPF, o con piu' d'uno (che non vale), non autorizza. Puro rispetto a txt.
     */
    static Status status(List<String> domains, Function<String, String> txt, String ip6) {
        List<String> uncovered = new ArrayList<>();
        boolean anyPanel = false;
        for (String d : domains) {
            List<String> spf = spfRecords(DnsRules.recordTxt(txt.apply(d)));
            if (spf.size() != 1) {
                uncovered.add(d);
                continue;
            }
            if (hasPanelIp6(spf.get(0))) anyPanel = true;
            if (!covers(spf.get(0), ip6)) uncovered.add(d);
        }
        return new Status(uncovered.isEmpty() && !domains.isEmpty(), anyPanel, uncovered);
    }

    // ===================== col DNS e con Cloudflare =====================

    /** I domini ospitati, in minuscolo; vuoto se il database non risponde. */
    static List<String> domains(MailDatabase db) {
        List<String> out = new ArrayList<>();
        if (db == null) return out;
        try {
            for (MailDatabase.Domain d : db.getDomains())
                if (d.domain != null && HostRecords.validHost(d.domain)) out.add(d.domain.toLowerCase(Locale.ROOT));
        } catch (Exception e) {
            // nessun dominio da leggere: nessuno da controllare
        }
        return out;
    }

    /** Lo stato dell'SPF dei domini ospitati, chiesto a chi lo pubblica (FreshDns). */
    public static Status status(MailDatabase db, String ip6) {
        return status(domains(db), d -> FreshDns.query("TXT", d), ip6);
    }

    /**
     * Mette (add) o toglie l'ip6 del server nell'SPF del pannello di ogni dominio ospitato, su Cloudflare. Gli SPF
     * scritti a mano non si toccano: l'esito li elenca, con l'indirizzo da aggiungere. Un dominio gia' a posto conta
     * come fatto.
     */
    public static Outcome apply(MailDatabase db, CloudflareManager cf, String ip6, boolean add) {
        if (add && !validIp6(ip6)) return new Outcome(false, "server.hr.noIp", Map.of("t", "AAAA"));
        if (db == null || cf == null) return new Outcome(false, "server.spf6.noAccount", Map.of("list", "-"));
        List<String> changed = new ArrayList<>(), custom = new ArrayList<>(), noAccount = new ArrayList<>(), failed = new ArrayList<>();
        List<MailDatabase.Domain> all;
        try {
            all = db.getDomains();
        } catch (Exception e) {
            return new Outcome(false, "server.requestFailed", Map.of());
        }
        for (MailDatabase.Domain d : all) {
            String domain = d.domain == null ? "" : d.domain.toLowerCase(Locale.ROOT);
            if (!HostRecords.validHost(domain)) continue;
            try {
                MailDatabase.CloudflareAccount acct = cf.getAccountForDomain(d.id);
                CloudflareManager.ZoneLookup zl = acct == null ? null : cf.findZone(acct.apiToken, domain);
                if (zl == null || !zl.found) {
                    noAccount.add(domain);
                    continue;
                }
                List<CloudflareManager.TxtRecordInfo> spf = new ArrayList<>();
                for (CloudflareManager.TxtRecordInfo r : cf.listTxtRecordsContaining(acct.apiToken, zl.zoneId, domain)) {
                    String v = DnsRules.cloudflareContent(r.content);
                    if (r.name != null && r.name.equalsIgnoreCase(domain) && !spfRecords(List.of(v)).isEmpty()) spf.add(r);
                }
                if (spf.size() != 1) {
                    custom.add(domain);
                    continue;
                }
                CloudflareManager.TxtRecordInfo r = spf.get(0);
                String current = DnsRules.cloudflareContent(r.content);
                String next = add ? withIp6(current, ip6) : withoutIp6(current);
                if (next == null) {
                    boolean fine = add ? covers(current, ip6) : !hasPanelIp6(current);
                    if (!fine) custom.add(domain);
                    continue;
                }
                CloudflareManager.RecordOp op = cf.updateTxtRecord(acct.apiToken, zl.zoneId, r.id, r.name, next, r.ttl);
                if (op.success) changed.add(domain);
                else failed.add(domain + " (" + op.error + ")");
            } catch (Exception e) {
                failed.add(domain + " (" + e.getMessage() + ")");
            }
        }
        if (!custom.isEmpty())
            return new Outcome(false, add ? "server.spf6.custom" : "server.spf6.customRemove",
                    Map.of("list", String.join(", ", custom), "ip", String.valueOf(ip6)));
        if (!noAccount.isEmpty()) return new Outcome(false, "server.spf6.noAccount", Map.of("list", String.join(", ", noAccount)));
        if (!failed.isEmpty()) return new Outcome(false, "server.spf6.failed", Map.of("list", String.join(", ", failed)));
        if (changed.isEmpty()) return new Outcome(true, "server.spf6.nothing", Map.of());
        return new Outcome(true, add ? "server.spf6.added" : "server.spf6.removed", Map.of("list", String.join(", ", changed)));
    }
}
