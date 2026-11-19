package org.daemoxcp.mail.security;

import java.net.InetAddress;
import java.util.Locale;
import java.util.function.BiFunction;

/**
 * Il DNS inverso di un indirizzo, IPv4 o IPv6, e la sua conferma all'andata: il nome che il PTR dice deve essere quello
 * del server di posta, e quel nome deve puntare di nuovo allo stesso indirizzo (A per l'IPv4, AAAA per l'IPv6).
 *
 * Gmail lo pretende da chi spedisce (support.google.com/a/answer/81126: «550 5.7.1 This message does not meet IPv6
 * sending guidelines regarding PTR records and authentication»), Microsoft 365 anche (450 4.7.25 senza PTR per l'IPv6).
 * Il controllo di prima (DnsRecordsGenerator.checkPtrAndFcrdns) cercava sempre un record A: per un IPv6 non poteva mai
 * tornare. Questo vale per tutte e due le famiglie.
 *
 * Le domande vanno ai server che pubblicano i record (FreshDns), non alla memoria del risolutore del server: il DNS
 * inverso appena salvato dall'amministratore si vede subito.
 */
public final class ReverseDns {

    /** Esito: va bene o no, il PTR trovato (o null), e il motivo come chiave della lingua (null se va bene). */
    public record Check(boolean ok, String ptr, String reason) {
        /**
         * Il DNS inverso da' il nome del server di posta, anche se quel nome non torna ancora all'indirizzo. E' il
         * passo dell'amministratore nella guida: il ritorno (il record A o AAAA) lo scrive il pannello DOPO, e chi lo
         * pretendesse qui bloccherebbe la guida per sempre (visto sul server vero: DNS inverso IPv6 giusto, nessun
         * AAAA ancora, passo fermo). Il controllo intero (ok) resta quello che serve prima di spedire.
         */
        public boolean givesName() {
            return ok || "server.rdns.notBack".equals(reason);
        }
    }

    /** La domanda al DNS (tipo, nome): ai server che pubblicano il record (FreshDns), oppure un finto nelle prove. */
    static BiFunction<String, String, String> lookup = FreshDns::query;

    private ReverseDns() {}

    public static Check check(String ip, String hostname) {
        InetAddress a = literal(ip);
        if (a == null) return new Check(false, null, "server.rdns.noIp");
        if (hostname == null || !hostname.matches("[A-Za-z0-9.-]{1,253}")) return new Check(false, null, "server.rdns.noHost");
        String ptr = firstName(lookup.apply("PTR", FreshDns.reverseName(a)));
        if (ptr == null) return new Check(false, null, "server.rdns.none");
        if (!ptr.equalsIgnoreCase(hostname)) return new Check(false, ptr, "server.rdns.otherName");
        String fwd = lookup.apply(a instanceof java.net.Inet6Address ? "AAAA" : "A", ptr);
        if (!DnsRecordsGenerator.containsAddress(fwd, ip)) return new Check(false, ptr, "server.rdns.notBack");
        return new Check(true, ptr, null);
    }

    /** Il primo nome di un'uscita di dig +short, senza il punto finale; null se non c'e'. */
    static String firstName(String out) {
        if (out == null) return null;
        for (String line : out.split("\n")) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith(";")) continue;
            if (t.endsWith(".")) t = t.substring(0, t.length() - 1);
            return t.matches("[A-Za-z0-9.-]{1,253}") ? t.toLowerCase(Locale.ROOT) : null;
        }
        return null;
    }

    private static InetAddress literal(String s) {
        if (s == null || !s.matches("[0-9A-Fa-f:.]{2,45}")) return null;
        try {
            return InetAddress.ofLiteral(s);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
