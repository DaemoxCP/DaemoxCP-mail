package org.daemoxcp.mail.security;

import java.io.BufferedReader;
import org.daemoxcp.mail.i18n.I18n;
import java.io.InputStreamReader;
import java.util.*;
import java.util.concurrent.*;

/**
 * Checks whether an IP is on a DNS blacklist (DNSBL) and whether a domain is on an
 * RHSBL (Right-Hand-Side blacklist, for domains).
 *
 * All queries are DNS-based: free, fast, no auth required.
 * At most 3 seconds per blacklist, in parallel with a thread pool.
 *
 * Lists used (the most relevant for email reputation):
 *  - Spamhaus ZEN: combines SBL + XBL + PBL (the most important)
 *  - SpamCop: feedback loop of the main ISPs
 *  - Barracuda BRBL: used by many antispam gateways
 *  - SORBS, UCEPROTECT, Mailspike, PSBL: other, secondary ones
 *
 * When an IP is "listed", the response code (127.0.0.X) indicates the specific
 * reason; it is documented on the site of each blacklist.
 */
public class BlacklistChecker {

    /**
     * DNSBL for IPs -- answer {@code 127.0.0.X} = listed.
     */
    // NOTE: SpamCop (bl.spamcop.net) is marked as WEB-ONLY because their NS
    // chronically times out on DNS queries from many networks.
    // The DNS check is skipped; the link for manual verification is offered instead.
    private static final List<DnsblEntry> IP_BLACKLISTS = Arrays.asList(
        new DnsblEntry("zen.spamhaus.org",            "Spamhaus ZEN",      "https://check.spamhaus.org/"),
        new DnsblEntry("bl.spamcop.net",              "SpamCop",           "https://www.spamcop.net/w3m?action=checkblock&ip=", /*webOnly=*/ true,
            "server.bl.spamcopWebOnly"),
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
     * RHSBL for domains -- answer {@code 127.0.0.X} = listed.
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
        /** If true, the DNS check is skipped and the user is invited to check via browser. */
        public final boolean webOnly;
        /** Message shown when webOnly=true. */
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
        public String responseCode;   // 127.0.0.X if listed
        public String message;
        public boolean error;          // true on timeout or technical error
        public boolean webOnly;        // true if the check is web-only
    }

    public static class BlacklistReport {
        public String target;          // IP or domain
        public String type;            // "IP" o "DOMAIN"
        public List<CheckResult> results = new ArrayList<>();
        public int listedCount;
        public int cleanCount;
        public int errorCount;
        public int webOnlyCount;
        public long elapsedMs;
    }

    /**
     * Checks an IP against all the known DNSBLs.
     * Runs in parallel, max 3 sec per blacklist.
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
                // Directly produces a "web-only" result without running DNS queries
                final DnsblEntry blFinal = bl;
                final String ipFinal = ip;
                futures.add(pool.submit(I18n.withCurrentCallable(() -> {
                    CheckResult cr = new CheckResult();
                    cr.blacklistName = blFinal.name;
                    cr.blacklistZone = blFinal.zone;
                    // The SpamCop URL accepts the ip parameter at the end; if it is missing I append it
                    cr.lookupUrl = blFinal.lookupUrl + (blFinal.lookupUrl.endsWith("=") ? ipFinal : "");
                    cr.webOnly = true;
                    cr.message = blFinal.webOnlyMessage != null
                        ? I18n.tr(blFinal.webOnlyMessage)
                        : I18n.tr("server.bl.webOnly");
                    return cr;
                })));
            } else {
                futures.add(pool.submit(I18n.withCurrentCallable(() -> queryDnsbl(reversed + "." + bl.zone, bl))));
            }
        }
        for (Future<CheckResult> f : futures) {
            try {
                CheckResult r = f.get(35, TimeUnit.SECONDS); // covers 2 retries (max ~28s)
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
        // Sort: first the listed (urgent), then the errors, then the clean
        report.results.sort((a, b) -> {
            // Order: listed -> error -> clean -> webOnly (at the bottom, they are informational)
            int sa = a.listed ? 0 : (a.error ? 1 : (a.webOnly ? 3 : 2));
            int sb = b.listed ? 0 : (b.error ? 1 : (b.webOnly ? 3 : 2));
            return Integer.compare(sa, sb);
        });
        return report;
    }

    /** Checks a domain against the RHSBLs. */
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
            futures.add(pool.submit(I18n.withCurrentCallable(() -> queryDnsbl(domain + "." + bl.zone, bl))));
        }
        for (Future<CheckResult> f : futures) {
            try {
                CheckResult r = f.get(35, TimeUnit.SECONDS); // covers 2 retries (max ~28s)
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
            // Order: listed -> error -> clean -> webOnly (at the bottom, they are informational)
            int sa = a.listed ? 0 : (a.error ? 1 : (a.webOnly ? 3 : 2));
            int sb = b.listed ? 0 : (b.error ? 1 : (b.webOnly ? 3 : 2));
            return Integer.compare(sa, sb);
        });
        return report;
    }

    /**
     * Runs a DNS A query against {@code queryHost}. If the answer starts with
     * 127.0.0.X = listed. Empty or NXDOMAIN = clean.
     * With auto-retry: if the first attempt times out, retry with a longer timeout.
     */
    private CheckResult queryDnsbl(String queryHost, DnsblEntry bl) {
        CheckResult r = queryDnsblOnce(queryHost, bl, 5, 2);
        // Auto-retry on timeout: some blacklists (SpamCop, UCEPROTECT) have
        // NS servers that are slow or intermittent from our network
        if (r.error && r.message != null && r.message.toLowerCase().contains("timeout")) {
            CheckResult retry = queryDnsblOnce(queryHost, bl, 8, 3);
            if (!retry.error || (retry.message != null && retry.message.equals(I18n.tr("server.bl.clean")))) {
                return retry;
            }
            // If the second attempt fails too, update the message
            r.message = I18n.tr("server.bl.timeout2");
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
            org.daemoxcp.mail.util.Shell.applyPath(pb);
            // Merge stderr into stdout: dig prints network errors on stderr with the ';;' prefix
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

            // Filter out dig error lines (they start with ';;') and empty lines.
            // Keep only the actual answers (IP or nothing).
            StringBuilder filtered = new StringBuilder();
            String digError = null;
            for (String line : response.split("\n")) {
                String t = line.trim();
                if (t.isEmpty()) continue;
                if (t.startsWith(";;")) {
                    // Save the dig error (e.g. "communications error", "connection refused")
                    if (digError == null) {
                        digError = t.replaceFirst(";;\\s*", "");
                        // truncate if too long
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
                        r.message = I18n.tr("server.bl.timeout");
                    } else if (digError.toLowerCase().contains("connection refused")) {
                        r.message = I18n.tr("server.bl.refused");
                    } else {
                        r.message = I18n.tr("server.bl.dnsError", java.util.Map.of("err", String.valueOf(digError)));
                    }
                } else {
                    r.listed = false;
                    r.message = I18n.tr("server.bl.clean");
                }
                return r;
            }

            // First line = response IP (e.g. 127.0.0.2)
            String firstLine = cleaned.split("\n")[0].trim();

            // Spamhaus ERROR codes (they are not "listed"):
            //   127.255.255.252 = TYPHON (Spamhaus internal)
            //   127.255.255.253 = QUERY type prohibited
            //   127.255.255.254 = Query via OPEN/PUBLIC RESOLVER not allowed
            //   127.255.255.255 = Excessive queries / rate limited
            // Other DNSBLs may use 127.0.0.1 as an "error" or 127.X as info.
            if (firstLine.startsWith("127.255.255.")) {
                r.error = true;
                r.responseCode = firstLine;
                String specific = switch (firstLine) {
                    case "127.255.255.252" -> I18n.tr("server.bl.shInternal");
                    case "127.255.255.253" -> I18n.tr("server.bl.shType");
                    case "127.255.255.254" -> I18n.tr("server.bl.shPublic");
                    case "127.255.255.255" -> I18n.tr("server.bl.shRate");
                    default -> I18n.tr("server.bl.blError", java.util.Map.of("c", String.valueOf(firstLine)));
                };
                r.message = specific;
            } else if (firstLine.startsWith("127.")) {
                r.listed = true;
                r.responseCode = firstLine;
                r.message = I18n.tr("server.bl.listed", java.util.Map.of("c", String.valueOf(firstLine)));
            } else {
                // Unexpected answer
                r.error = true;
                r.message = I18n.tr("server.bl.unexpected", java.util.Map.of("c", String.valueOf(firstLine)));
            }
        } catch (Exception e) {
            r.error = true;
            r.message = I18n.tr("server.bl.error", java.util.Map.of("err", org.daemoxcp.mail.util.ErrorText.detail("BlacklistChecker", e)));
        }
        return r;
    }

    /** Reverses an IPv4 by octets for DNSBL queries. E.g.: 1.2.3.4 -> 4.3.2.1 */
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
