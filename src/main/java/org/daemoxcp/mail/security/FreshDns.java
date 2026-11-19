package org.daemoxcp.mail.security;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.daemoxcp.mail.util.Shell;

/**
 * Una domanda DNS a chi comanda il nome: i server autorevoli della sua zona, senza passare dalla memoria del
 * risolutore del server.
 *
 * <p>Perche'. Il server ha un suo risolutore (local_unbound) che ricorda le risposte, anche quelle negative: un «nessun
 * nome» o un «nessun AAAA» resta valido fino al TTL negativo della zona (lo SOA minimum: 86400 s per il DNS inverso di
 * Hetzner, che unbound accorcia a un'ora al massimo). Visto sul server vero il 19/11/2026: l'amministratore aveva gia'
 * salvato il DNS inverso IPv6, Hetzner, Cloudflare e Google lo davano, e la guida degli indirizzi diceva ancora «nessun
 * nome» per altri 12 minuti, perche' l'aveva chiesto al risolutore prima che fosse salvato. Lo stesso sarebbe successo
 * col record AAAA appena scritto su Cloudflare. Per sapere com'e' adesso un record che l'amministratore o il pannello
 * hanno appena cambiato si chiede a chi lo pubblica.
 *
 * <p>Come. Lo SOA dice qual e' la zona del nome (anche da una risposta negativa); i suoi NS dicono a chi chiedere;
 * a ognuno si chiede senza ricorsione (+norecurse), con un'attesa breve. Se nessuno risponde (una rete che chiude la
 * porta 53 verso fuori, un server autorevole spento) si chiede al risolutore del server come prima: una risposta forse
 * vecchia e' meglio di nessuna. I nomi che arrivano dal DNS (la zona, i server) passano dagli stessi caratteri ammessi
 * dei nomi che chiede il pannello prima di diventare un argomento di dig; dig gira senza shell.
 */
public final class FreshDns {

    /** I tipi che il pannello chiede: nient'altro arriva a dig. */
    static final java.util.Set<String> TYPES = java.util.Set.of("A", "AAAA", "PTR", "MX", "TXT");
    /** Un nome DNS: lettere, cifre, punto e trattino (i nomi del DNS inverso ci rientrano), al massimo 253. */
    static final Pattern NAME = Pattern.compile("[A-Za-z0-9.-]{1,253}");
    /** La riga dello SOA in +noall +answer +authority: il primo campo e' la zona. */
    private static final Pattern SOA_LINE = Pattern.compile("(?m)^(\\S+)\\s+\\d+\\s+IN\\s+SOA\\s");
    /** Quanti server della zona si provano, al massimo. */
    static final int MAX_SERVERS = 4;

    /**
     * dig con i suoi argomenti: l'uscita se dig ha avuto una risposta (codice 0), null se no (nessun server raggiunto,
     * tempo scaduto). Quello vero, oppure un finto nelle prove.
     */
    static Function<String[], String> dig = args -> {
        Shell.Result r = Shell.run(Duration.ofSeconds(12), args);
        return r.success() ? r.outputTrim() : null;
    };

    private FreshDns() {}

    /**
     * Le risposte di quel tipo per quel nome, come le da' dig +short (una per riga), chieste ai server della sua zona;
     * se nessuno di loro risponde, al risolutore del server. Vuoto se il record non c'e' (o il nome non e' valido).
     */
    public static String query(String type, String name) {
        if (type == null || !TYPES.contains(type) || !validName(name)) return "";
        String zone = zoneOf(name);
        if (zone != null) {
            for (String server : servers(zone)) {
                String out = dig.apply(new String[] {"dig", "+short", "+norecurse", "+time=3", "+tries=1", "@" + server, type, name});
                if (out != null && !out.contains(";;")) return out;
            }
        }
        String out = dig.apply(new String[] {"dig", "+short", type, name});
        return out == null || out.contains(";;") ? "" : out;
    }

    /** Il nome del DNS inverso di un indirizzo: 10.2.0.192.in-addr.arpa, o i 32 mezzi byte al contrario e ip6.arpa. */
    public static String reverseName(InetAddress a) {
        byte[] b = a.getAddress();
        StringBuilder s = new StringBuilder();
        if (a instanceof Inet4Address) {
            for (int i = 3; i >= 0; i--) s.append(b[i] & 0xff).append('.');
            return s.append("in-addr.arpa").toString();
        }
        for (int i = 15; i >= 0; i--) {
            int v = b[i] & 0xff;
            s.append(Character.forDigit(v & 0xf, 16)).append('.').append(Character.forDigit(v >> 4, 16)).append('.');
        }
        return s.append("ip6.arpa").toString();
    }

    /** La zona del nome, dallo SOA che il risolutore da' con la risposta (anche negativa); null se non si sa. */
    static String zoneOf(String name) {
        String out = dig.apply(new String[] {"dig", "+noall", "+answer", "+authority", "SOA", name});
        if (out == null) return null;
        Matcher m = SOA_LINE.matcher(out);
        if (!m.find()) return null;
        String zone = strip(m.group(1));
        return validName(zone) ? zone : null;
    }

    /** I server autorevoli della zona (i suoi NS), al massimo MAX_SERVERS, solo nomi validi. */
    static List<String> servers(String zone) {
        List<String> out = new ArrayList<>();
        String ns = dig.apply(new String[] {"dig", "+short", "NS", zone});
        if (ns == null) return out;
        for (String line : ns.split("\n")) {
            String s = strip(line.trim());
            if (validName(s) && s.contains(".") && !out.contains(s)) out.add(s);
            if (out.size() == MAX_SERVERS) break;
        }
        return out;
    }

    static boolean validName(String s) {
        return s != null && NAME.matcher(s).matches() && !s.startsWith("-") && !s.startsWith(".");
    }

    private static String strip(String s) {
        s = s.toLowerCase(Locale.ROOT);
        return s.endsWith(".") ? s.substring(0, s.length() - 1) : s;
    }
}
