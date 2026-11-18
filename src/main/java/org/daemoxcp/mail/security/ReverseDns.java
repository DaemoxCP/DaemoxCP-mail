package org.daemoxcp.mail.security;

import java.net.InetAddress;
import java.time.Duration;
import java.util.Locale;
import java.util.function.Function;

import org.daemoxcp.mail.util.Shell;

/**
 * Il DNS inverso di un indirizzo, IPv4 o IPv6, e la sua conferma all'andata: il nome che il PTR dice deve essere quello
 * del server di posta, e quel nome deve puntare di nuovo allo stesso indirizzo (A per l'IPv4, AAAA per l'IPv6).
 *
 * Gmail lo pretende da chi spedisce (support.google.com/a/answer/81126: «550 5.7.1 This message does not meet IPv6
 * sending guidelines regarding PTR records and authentication»), Microsoft 365 anche (450 4.7.25 senza PTR per l'IPv6).
 * Il controllo di prima (DnsRecordsGenerator.checkPtrAndFcrdns) cercava sempre un record A: per un IPv6 non poteva mai
 * tornare. Questo vale per tutte e due le famiglie.
 */
public final class ReverseDns {

    /** Esito: va bene o no, il PTR trovato (o null), e il motivo come chiave della lingua (null se va bene). */
    public record Check(boolean ok, String ptr, String reason) {}

    /** dig con i suoi argomenti: quello vero, oppure un finto nelle prove. */
    static Function<String[], String> dig = args -> Shell.run(Duration.ofSeconds(10), args).outputTrim();

    private ReverseDns() {}

    public static Check check(String ip, String hostname) {
        InetAddress a = literal(ip);
        if (a == null) return new Check(false, null, "server.rdns.noIp");
        if (hostname == null || !hostname.matches("[A-Za-z0-9.-]{1,253}")) return new Check(false, null, "server.rdns.noHost");
        String rev = dig.apply(new String[] {"dig", "+short", "-x", ip});
        String ptr = firstName(rev);
        if (ptr == null) return new Check(false, null, "server.rdns.none");
        if (!ptr.equalsIgnoreCase(hostname)) return new Check(false, ptr, "server.rdns.otherName");
        String fwd = dig.apply(new String[] {"dig", "+short", a instanceof java.net.Inet6Address ? "AAAA" : "A", ptr});
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
