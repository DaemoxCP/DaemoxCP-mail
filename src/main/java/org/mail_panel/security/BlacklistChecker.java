package org.mail_panel.security;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.*;
import java.util.concurrent.*;

/**
 * Verifica se un IP è in blacklist DNS (DNSBL) e se un dominio è in
 * RHSBL (Right-Hand-Side blacklist, per i domini).
 *
 * Tutte le query sono DNS-based — gratis, veloci, no auth richiesta.
 * Massimo 3 secondi per blacklist, parallelo con thread pool.
 *
 * Liste utilizzate (le più rilevanti per reputation email):
 *  - Spamhaus ZEN: combina SBL + XBL + PBL (la più importante)
 *  - SpamCop: feedback loop dei principali ISP
 *  - Barracuda BRBL: usato da molti gateway antispam
 *  - SORBS, UCEPROTECT, Mailspike, PSBL: altri secondari
 *
 * Quando un IP è "listed", il response code (127.0.0.X) indica il motivo
 * specifico — è documentato sul sito di ogni blacklist.
 */
public class BlacklistChecker {

    /**
     * DNSBL per IP — risposta {@code 127.0.0.X} = listed.
     */
    // NOTA: SpamCop (bl.spamcop.net) è marcato come WEB-ONLY perché il loro NS
    // restituisce timeout cronico via DNS query da molte reti.
    // Il check via DNS è skippato; viene proposto il link per la verifica manuale.
    private static final List<DnsblEntry> IP_BLACKLISTS = Arrays.asList(
        new DnsblEntry("zen.spamhaus.org",            "Spamhaus ZEN",      "https://check.spamhaus.org/"),
        new DnsblEntry("bl.spamcop.net",              "SpamCop",           "https://www.spamcop.net/w3m?action=checkblock&ip=", /*webOnly=*/ true,
            "Verifica manuale via web (il loro NS DNS è cronicamente irraggiungibile)"),
        new DnsblEntry("b.barracudacentral.org",      "Barracuda BRBL",    "https://www.barracudacentral.org/lookups/lookup-reputation"),
        new DnsblEntry("dnsbl.sorbs.net",             "SORBS DNSBL",       "https://www.sorbs.net/lookup.shtml"),
        new DnsblEntry("psbl.surriel.com",            "PSBL",              "https://psbl.org/"),
        new DnsblEntry("cbl.abuseat.org",             "CBL (Abuseat)",     "https://www.abuseat.org/lookup.cgi"),
        new DnsblEntry("dnsbl-1.uceprotect.net",      "UCEPROTECT-1",      "https://www.uceprotect.net/en/rblcheck.php"),
        new DnsblEntry("bl.mailspike.net",            "Mailspike",         "https://mailspike.org/"),
        new DnsblEntry("truncate.gbudb.net",          "GBUdb Truncate",    "http://gbudb.com/truncate/"),
        new DnsblEntry("0spam.fusionzero.com",        "0spam",             "https://0spam.fusionzero.com/"),
        new DnsblEntry("backscatter.spameatingmonkey.net", "SEM Backscatter", "https://spameatingmonkey.com/lookup/"),
        new DnsblEntry("bl.blocklist.de",             "blocklist.de",      "https://www.blocklist.de/")
    );

    /**
     * RHSBL per domini — risposta {@code 127.0.0.X} = listed.
     */
    private static final List<DnsblEntry> DOMAIN_BLACKLISTS = Arrays.asList(
        new DnsblEntry("dbl.spamhaus.org",   "Spamhaus DBL",    "https://check.spamhaus.org/"),
        new DnsblEntry("multi.surbl.org",    "SURBL Multi",     "https://www.surbl.org/surbl-analysis"),
        new DnsblEntry("dbl.nordspam.com",   "NordSpam DBL",    "https://www.nordspam.com/")
    );

    public static class DnsblEntry {
        public final String zone;
        public final String name;
        public final String lookupUrl;
        /** Se true, il check via DNS viene skippato e si invita l'utente a verificare via browser. */
        public final boolean webOnly;
        /** Messaggio mostrato quando webOnly=true. */
        public final String webOnlyMessage;

        public DnsblEntry(String zone, String name, String lookupUrl) {
            this(zone, name, lookupUrl, false, null);
        }

        public DnsblEntry(String zone, String name, String lookupUrl, boolean webOnly, String webOnlyMessage) {
            this.zone = zone;
            this.name = name;
            this.lookupUrl = lookupUrl;
            this.webOnly = webOnly;
            this.webOnlyMessage = webOnlyMessage;
        }
    }

    public static class CheckResult {
        public String blacklistName;
        public String blacklistZone;
        public String lookupUrl;
        public boolean listed;
        public String responseCode;   // 127.0.0.X se listed
        public String message;
        public boolean error;          // true se timeout o errore tecnico
        public boolean webOnly;        // true se il check è solo via web
    }

    public static class BlacklistReport {
        public String target;          // IP o dominio
        public String type;            // "IP" o "DOMAIN"
        public List<CheckResult> results = new ArrayList<>();
        public int listedCount;
        public int cleanCount;
        public int errorCount;
        public int webOnlyCount;
        public long elapsedMs;
    }

    /**
     * Verifica un IP contro tutte le DNSBL note.
     * Esegue in parallelo, max 3 sec per blacklist.
     */
    public BlacklistReport checkIp(String ip) {
        BlacklistReport report = new BlacklistReport();
        report.target = ip;
        report.type = "IP";
        if (!isValidIPv4(ip)) {
            report.results = new ArrayList<>();
            return report;
        }

        long start = System.currentTimeMillis();
        String reversed = reverseIpv4(ip);
        ExecutorService pool = Executors.newFixedThreadPool(Math.min(IP_BLACKLISTS.size(), 12));
        List<Future<CheckResult>> futures = new ArrayList<>();

        for (DnsblEntry bl : IP_BLACKLISTS) {
            if (bl.webOnly) {
                // Genera direttamente un risultato "web-only" senza eseguire query DNS
                final DnsblEntry blFinal = bl;
                final String ipFinal = ip;
                futures.add(pool.submit(() -> {
                    CheckResult cr = new CheckResult();
                    cr.blacklistName = blFinal.name;
                    cr.blacklistZone = blFinal.zone;
                    // L'URL di SpamCop accetta il parametro ip in fondo, se manca lo concateno
                    cr.lookupUrl = blFinal.lookupUrl + (blFinal.lookupUrl.endsWith("=") ? ipFinal : "");
                    cr.webOnly = true;
                    cr.message = blFinal.webOnlyMessage != null
                        ? blFinal.webOnlyMessage
                        : "Verifica manuale via web";
                    return cr;
                }));
            } else {
                futures.add(pool.submit(() -> queryDnsbl(reversed + "." + bl.zone, bl)));
            }
        }
        for (Future<CheckResult> f : futures) {
            try {
                CheckResult r = f.get(35, TimeUnit.SECONDS); // copre 2 retry (max ~28s)
                report.results.add(r);
                if (r.webOnly) report.webOnlyCount++;
                else if (r.error) report.errorCount++;
                else if (r.listed) report.listedCount++;
                else report.cleanCount++;
            } catch (Exception e) {
                report.errorCount++;
            }
        }
        pool.shutdownNow();
        report.elapsedMs = System.currentTimeMillis() - start;
        // Ordina: prima i listed (urgenti), poi gli error, poi i clean
        report.results.sort((a, b) -> {
            // Ordine: listed → error → clean → webOnly (in fondo, sono informational)
            int sa = a.listed ? 0 : (a.error ? 1 : (a.webOnly ? 3 : 2));
            int sb = b.listed ? 0 : (b.error ? 1 : (b.webOnly ? 3 : 2));
            return Integer.compare(sa, sb);
        });
        return report;
    }

    /** Verifica un dominio contro le RHSBL. */
    public BlacklistReport checkDomain(String domain) {
        BlacklistReport report = new BlacklistReport();
        report.target = domain;
        report.type = "DOMAIN";
        if (!InputValidator.isValidDomain(domain)) {
            return report;
        }

        long start = System.currentTimeMillis();
        ExecutorService pool = Executors.newFixedThreadPool(Math.min(DOMAIN_BLACKLISTS.size(), 6));
        List<Future<CheckResult>> futures = new ArrayList<>();

        for (DnsblEntry bl : DOMAIN_BLACKLISTS) {
            futures.add(pool.submit(() -> queryDnsbl(domain + "." + bl.zone, bl)));
        }
        for (Future<CheckResult> f : futures) {
            try {
                CheckResult r = f.get(35, TimeUnit.SECONDS); // copre 2 retry (max ~28s)
                report.results.add(r);
                if (r.webOnly) report.webOnlyCount++;
                else if (r.error) report.errorCount++;
                else if (r.listed) report.listedCount++;
                else report.cleanCount++;
            } catch (Exception e) {
                report.errorCount++;
            }
        }
        pool.shutdownNow();
        report.elapsedMs = System.currentTimeMillis() - start;
        report.results.sort((a, b) -> {
            // Ordine: listed → error → clean → webOnly (in fondo, sono informational)
            int sa = a.listed ? 0 : (a.error ? 1 : (a.webOnly ? 3 : 2));
            int sb = b.listed ? 0 : (b.error ? 1 : (b.webOnly ? 3 : 2));
            return Integer.compare(sa, sb);
        });
        return report;
    }

    /**
     * Esegue una query DNS A contro {@code queryHost}. Se la risposta inizia con
     * 127.0.0.X = listed. Vuoto o NXDOMAIN = clean.
     * Con auto-retry: se primo tentativo va in timeout, retry con timeout più ampio.
     */
    private CheckResult queryDnsbl(String queryHost, DnsblEntry bl) {
        CheckResult r = queryDnsblOnce(queryHost, bl, 5, 2);
        // Auto-retry su timeout: alcune blacklist (SpamCop, UCEPROTECT) hanno
        // NS server lenti o intermittenti dalla nostra rete
        if (r.error && r.message != null && r.message.toLowerCase().contains("timeout")) {
            CheckResult retry = queryDnsblOnce(queryHost, bl, 8, 3);
            if (!retry.error || (retry.message != null && retry.message.equals("Pulito"))) {
                return retry;
            }
            // Se anche il secondo tentativo fallisce, aggiorna il messaggio
            r.message = "Timeout dopo 2 tentativi (~25s totali) — il DNSBL sembra irraggiungibile";
        }
        return r;
    }

    private CheckResult queryDnsblOnce(String queryHost, DnsblEntry bl, int timeSeconds, int tries) {
        CheckResult r = new CheckResult();
        r.blacklistName = bl.name;
        r.blacklistZone = bl.zone;
        r.lookupUrl = bl.lookupUrl;
        try {
            int totalTimeout = timeSeconds * tries + 3; // wall clock max
            // TODO: migrate to Shell.run when touched
            ProcessBuilder pb = new ProcessBuilder("dig", "+short",
                "+time=" + timeSeconds, "+tries=" + tries, "A", queryHost);
            org.mail_panel.util.Shell.applicaPath(pb);
            // Merge stderr in stdout: dig stampa errori di rete su stderr con prefisso ';;'
            pb.redirectErrorStream(true);
            Process p = pb.start();
            StringBuilder out = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) out.append(line).append("\n");
            }
            boolean done = p.waitFor(totalTimeout, TimeUnit.SECONDS);
            if (!done) {
                p.destroyForcibly();
                r.error = true;
                r.message = "Timeout (>" + totalTimeout + "s)";
                return r;
            }
            String response = out.toString().trim();

            // Filtra righe di errore di dig (cominciano con ';;') e righe vuote.
            // Tieni solo le risposte effettive (IP o nulla).
            StringBuilder filtered = new StringBuilder();
            String digError = null;
            for (String line : response.split("\n")) {
                String t = line.trim();
                if (t.isEmpty()) continue;
                if (t.startsWith(";;")) {
                    // Salva l'errore dig (es. "communications error", "connection refused")
                    if (digError == null) {
                        digError = t.replaceFirst(";;\\s*", "");
                        // taglia se troppo lungo
                        if (digError.length() > 120) digError = digError.substring(0, 120) + "...";
                    }
                    continue;
                }
                filtered.append(t).append("\n");
            }
            String cleaned = filtered.toString().trim();

            if (cleaned.isEmpty()) {
                if (digError != null) {
                    r.error = true;
                    if (digError.toLowerCase().contains("timed out")) {
                        r.message = "Timeout — il resolver DNS non risponde (probabile rate limit del DNSBL)";
                    } else if (digError.toLowerCase().contains("connection refused")) {
                        r.message = "Connessione rifiutata dal resolver DNS";
                    } else {
                        r.message = "Errore DNS: " + digError;
                    }
                } else {
                    r.listed = false;
                    r.message = "Pulito";
                }
                return r;
            }

            // Prima riga = response IP (es. 127.0.0.2)
            String firstLine = cleaned.split("\n")[0].trim();

            // Codici di ERRORE di Spamhaus (non sono "listed"):
            //   127.255.255.252 = TYPHON (Spamhaus internal)
            //   127.255.255.253 = QUERY type prohibited
            //   127.255.255.254 = Query via OPEN/PUBLIC RESOLVER not allowed
            //   127.255.255.255 = Excessive queries / rate limited
            // Altri DNSBL possono usare 127.0.0.1 come "errore" o 127.X come info.
            if (firstLine.startsWith("127.255.255.")) {
                r.error = true;
                r.responseCode = firstLine;
                String specific = switch (firstLine) {
                    case "127.255.255.252" -> "Errore interno Spamhaus";
                    case "127.255.255.253" -> "Tipo query non permesso";
                    case "127.255.255.254" -> "Resolver DNS pubblico bloccato (usa resolver locale tipo unbound)";
                    case "127.255.255.255" -> "Rate limit / quota superata — usa resolver locale";
                    default -> "Errore blacklist (codice " + firstLine + ")";
                };
                r.message = specific;
            } else if (firstLine.startsWith("127.")) {
                r.listed = true;
                r.responseCode = firstLine;
                r.message = "LISTED (" + firstLine + ")";
            } else {
                // Risposta inattesa
                r.error = true;
                r.message = "Risposta inattesa: " + firstLine;
            }
        } catch (Exception e) {
            r.error = true;
            r.message = "Errore: " + e.getMessage();
        }
        return r;
    }

    /** Inverte un IPv4 in ottetti per query DNSBL. Es: 1.2.3.4 → 4.3.2.1 */
    private static String reverseIpv4(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return ip;
        return parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0];
    }

    private static boolean isValidIPv4(String s) {
        if (s == null) return false;
        return s.matches("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
    }
}
