package org.daemoxcp.mail.security;

import java.util.ArrayList;
import org.daemoxcp.mail.i18n.I18n;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;

/**
 * The rules that SPF, DMARC and MTA-STS records must follow, taken from the specifications in
 * force and written as pure functions: no network, no process, no database. That way
 * they can be tested with hand-made values, which is the only way to know whether they tell the truth.
 *
 * Sources (verified, not from memory):
 *  - SPF:     RFC 7208
 *  - DMARC:   RFC 9989 (May 2026, replaces RFC 7489) and RFC 9990 for the reports
 *  - MTA-STS: RFC 8461 Section 3.1, compared against two real senders (see onlyMtaSts)
 *
 * Three rules alone are worth this whole file, because they describe silent failures:
 *
 *  1. SPF, Section 4.5: if a name has TWO records starting with "v=spf1", the result
 *     is not "the first one wins": it is "permerror". SPF stops working altogether.
 *  2. DMARC, Section 4: if a name has two valid DMARC records, ALL of them are discarded.
 *     The policy disappears, and nobody warns anybody.
 *  3. MTA-STS, Section 3.1: if _mta-sts has two v=STSv1 records, senders act as if
 *     MTA-STS were not there. The policy is still served, and nobody reads it.
 *
 * In all three cases mail keeps flowing and whoever looks sees nothing broken:
 * with SPF and DMARC until one day it starts landing in spam, with MTA-STS never, because
 * the only effect is that incoming mail loses the protection: whoever sits in the middle can
 * again strip its TLS. That is why the panel must be able to recognize them before creating a
 * record, not after.
 */
public final class DnsRules {

    private DnsRules() {}

    /*
     * ===================================================================
     * Raw TXT records
     * ===================================================================
     */

    /**
     * Turns the output of {@code dig +short TXT <name>} into one record per element.
     *
     * Two details that look like nitpicking and are not:
     *  - each LINE is a separate record (a name can have many);
     *  - inside a line, a long record is split into several quoted strings, and
     *    RFC 7208 Section 3.3 says they must be joined WITHOUT adding spaces. Whoever joins them
     *    with a space breaks long DKIM keys and does not notice, because the record keeps
     *    "looking" right.
     */
    public static List<String> recordTxt(String digOutput) {
        List<String> outside = new ArrayList<>();
        if (digOutput == null) return outside;
        for (String line : digOutput.split("\n")) {
            String t = line.trim();
            if (t.isEmpty()) continue;
            StringBuilder joined = new StringBuilder();
            boolean inside = false, seen = false;
            for (int i = 0; i < t.length(); i++) {
                char c = t.charAt(i);
                if (c == '\\' && inside && i + 1 < t.length()) { joined.append(t.charAt(++i)); continue; }
                if (c == '"') { inside = !inside; seen = true; continue; }
                if (inside) joined.append(c);
            }
            String r = seen ? joined.toString() : t;
            if (!r.isEmpty()) outside.add(r);
        }
        return outside;
    }

    /**
     * The content of a record as the Cloudflare API returns it, reduced to the real
     * value. Cloudflare sometimes delivers the TXT already bare and sometimes wrapped in quotes,
     * depending on how it was created.
     *
     * It is not a cosmetic detail: if the quotes stay, "\"v=spf1 ...\"" does not start
     * with "v=spf1", the panel concludes there is no SPF, and adds a second one.
     * Two SPFs on the same name give "permerror": the check meant to prevent the
     * failure would have caused it.
     *
     * recordTxt is reused, which already knows how to join multiple strings and remove the quotes:
     * two functions that do the same thing are two functions that one day diverge.
     */
    public static String cloudflareContent(String raw) {
        List<String> l = recordTxt(raw);
        return l.isEmpty() ? "" : l.get(0);
    }

    /* ===================================================================
     * SPF - RFC 7208
     * =================================================================== */

    /**
     * The only records that count as SPF. Section 4.5: the record must begin with the version
     * section exactly "v=spf1", terminated by a space or by the end of the record.
     * So "v=spf10 ..." is NOT an SPF record and must be discarded, not accepted for resemblance.
     *
     * The comparison is case-insensitive: the ABNF of RFC 7208 uses simple literal strings,
     * which in ABNF (RFC 5234) are case-insensitive unless prefixed with %s. DMARC instead uses
     * %s"DMARC1", and that is why further down the comparison is case-sensitive: it is not
     * carelessness, it is the difference between the two specifications.
     */
    public static List<String> onlySpf(List<String> record) {
        List<String> outside = new ArrayList<>();
        if (record == null) return outside;
        for (String r : record) {
            if (r == null) continue;
            String s = r.trim();
            String b = s.toLowerCase(Locale.ROOT);
            if (b.equals("v=spf1") || b.startsWith("v=spf1 ")) outside.add(s);
        }
        return outside;
    }

    /** The terms of an SPF record, with the version skipped. */
    public static List<String> terms(String spf) {
        List<String> outside = new ArrayList<>();
        if (spf == null) return outside;
        boolean first = true;
        for (String t : spf.trim().split("\\s+")) {
            if (t.isEmpty()) continue;
            if (first) { first = false; continue; } // "v=spf1"
            outside.add(t);
        }
        return outside;
    }

    /** Removes the leading qualifier (+ - ~ ?), which is not part of the name. */
    public static String withoutQualifier(String term) {
        if (term == null || term.isEmpty()) return "";
        char q = term.charAt(0);
        return (q == '+' || q == '-' || q == '~' || q == '?') ? term.substring(1) : term;
    }

    /** The name of the mechanism or modifier: the part before ':', '=' or '/'. */
    public static String mechanismName(String term) {
        String t = withoutQualifier(term);
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (c == ':' || c == '=' || c == '/') return t.substring(0, i).toLowerCase(Locale.ROOT);
        }
        return t.toLowerCase(Locale.ROOT);
    }

    /** The value after ':' or '=', empty if the term has none. */
    public static String mechanismValue(String term) {
        String t = withoutQualifier(term);
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (c == ':' || c == '=') return t.substring(i + 1);
        }
        return "";
    }

    /** The terms that cost a DNS lookup, Section 4.6.4. */
    private static boolean costsALookup(String name) {
        return name.equals("include") || name.equals("a") || name.equals("mx")
            || name.equals("ptr") || name.equals("exists") || name.equals("redirect");
    }

    /**
     * How many DNS lookups THIS record costs, without going into the "include"s.
     *
     * The name says "direct" on purpose: Section 4.6.4 sets the limit of 10 on the whole
     * evaluation, and each "include" brings in others that can only be known by resolving them. So
     * this number is a MINIMUM, and must be presented as such. A count passing itself off
     * as a total would say "6 out of 10, all good" in front of a record that is actually already
     * over the limit: a check that gives false reassurance is worse than no check.
     */
    public static int directDnsLookups(String spf) {
        int n = 0;
        for (String t : terms(spf)) if (costsALookup(mechanismName(t))) n++;
        return n;
    }

    /** How many terms bring in other lookups that cannot be known from here. */
    public static int includeCount(String spf) {
        int n = 0;
        for (String t : terms(spf)) {
            String name = mechanismName(t);
            if (name.equals("include") || name.equals("redirect")) n++;
        }
        return n;
    }

    /** The mechanism is there as a real term, not as a piece of another word. */
    public static boolean hasMechanism(String spf, String name) {
        for (String t : terms(spf)) if (mechanismName(t).equals(name)) return true;
        return false;
    }

    /** How the record ends: "-all", "~all", "?all", "+all" or null if it does not end. */
    public static String closing(String spf) {
        String found = null;
        for (String t : terms(spf)) {
            if (mechanismName(t).equals("all")) {
                char q = t.isEmpty() ? '+' : t.charAt(0);
                found = (q == '-' || q == '~' || q == '?' || q == '+') ? (q + "all") : "+all";
            }
        }
        return found;
    }

    /**
     * The address falls within the ip4 spec, taking the prefix into account.
     * Without this, "ip4:203.0.113.0/24" would turn out not to contain 203.0.113.7 and the
     * panel would say "SPF does not authorize the server" in front of a perfectly correct SPF.
     */
    public static boolean ip4Covers(String spec, String ip) {
        if (spec == null || ip == null) return false;
        String network = spec, bit = "32";
        int s = spec.indexOf('/');
        if (s >= 0) { network = spec.substring(0, s); bit = spec.substring(s + 1); }
        long r = toNumber(network), a = toNumber(ip);
        if (r < 0 || a < 0) return false;
        int p;
        try { p = Integer.parseInt(bit.trim()); } catch (Exception e) { return false; }
        if (p < 0 || p > 32) return false;
        if (p == 0) return true;
        long mask = (0xFFFFFFFFL << (32 - p)) & 0xFFFFFFFFL;
        return (r & mask) == (a & mask);
    }

    private static long toNumber(String ip) {
        if (ip == null) return -1;
        String[] p = ip.trim().split("\\.");
        if (p.length != 4) return -1;
        long v = 0;
        for (String x : p) {
            if (x.isEmpty() || x.length() > 3) return -1;
            for (int i = 0; i < x.length(); i++) if (!Character.isDigit(x.charAt(i))) return -1;
            int n = Integer.parseInt(x);
            if (n > 255) return -1;
            v = (v << 8) | n;
        }
        return v;
    }

    /** The SPF authorizes that IP with an explicit ip4 (prefixes included). */
    public static boolean authorizeIp4(String spf, String ip) {
        if (ip == null || ip.isBlank()) return false;
        for (String t : terms(spf)) {
            if (!mechanismName(t).equals("ip4")) continue;
            if (ip4Covers(mechanismValue(t), ip)) return true;
        }
        return false;
    }

    public static class SpfOutcome {
        public int howMany;
        public boolean valid;
        public String record;
        public String problem;
        public boolean explicitAuthorization, viaMx, viaA;
        public int directLookups, include;
        public String closing;
        public final List<String> warnings = new ArrayList<>();
    }

    public static SpfOutcome analyzeSpf(List<String> recordTxt, String ipServer) {
        SpfOutcome e = new SpfOutcome();
        List<String> spf = onlySpf(recordTxt);
        e.howMany = spf.size();

        if (e.howMany == 0) {
            e.valid = false;
            e.problem = I18n.tr("server.dnsrules.spfNone");
            return e;
        }
        if (e.howMany > 1) {
            e.valid = false;
            e.problem = I18n.tr("server.dnsrules.spfMany", java.util.Map.of("n", String.valueOf(e.howMany)));
            e.record = String.join("  ||  ", spf);
            return e;
        }

        e.valid = true;
        e.record = spf.get(0);
        e.explicitAuthorization = authorizeIp4(e.record, ipServer);
        e.viaMx = hasMechanism(e.record, "mx");
        e.viaA = hasMechanism(e.record, "a");
        e.directLookups = directDnsLookups(e.record);
        e.include = includeCount(e.record);
        e.closing = closing(e.record);

        if (e.directLookups > 10)
            e.warnings.add(I18n.tr("server.dnsrules.spfLookups", java.util.Map.of("n", String.valueOf(e.directLookups))));
        else if (e.include > 0)
            e.warnings.add(e.include == 1
                       ? I18n.tr("server.dnsrules.spfDirect.one", java.util.Map.of("n", String.valueOf(e.directLookups)))
                       : I18n.tr("server.dnsrules.spfDirect.other", java.util.Map.of("n", String.valueOf(e.directLookups), "includes", String.valueOf(e.include))));

        if (e.closing == null)
            e.warnings.add(I18n.tr("server.dnsrules.spfNoAll"));
        else if (e.closing.equals("+all"))
            e.warnings.add(I18n.tr("server.dnsrules.spfPlusAll"));

        return e;
    }

    /* ===================================================================
     * MTA-STS - RFC 8461
     * =================================================================== */

    /**
     * The records of the _mta-sts name that at least one sender counts as MTA-STS.
     *
     * Section 3.1: "records that do not begin with "v=STSv1;" are discarded. If the number of
     * resulting records is not one [...] senders MUST assume the recipient domain does not
     * have an available MTA-STS Policy". With two records the first does not win: for senders
     * MTA-STS is not there, and nobody reads the policy served. It is the same silent
     * failure as two SPFs and two DMARCs.
     *
     * The filter is the widest among those of the real senders, which do not count in the same
     * way: postfix-mta-sts-resolver keeps the records starting with "v=STSv1" with the exact
     * case; mailauth (Nodemailer) normally ignores case and surrounding spaces and
     * wants the ";". A record that even just one of them counts, counts here: if for some
     * sender there are two records, the panel cannot say MTA-STS is active.
     */
    public static boolean eMtaSts(String r) {
        return r != null && r.trim().toLowerCase(Locale.ROOT).startsWith("v=stsv1");
    }

    public static List<String> onlyMtaSts(List<String> record) {
        List<String> outside = new ArrayList<>();
        if (record == null) return outside;
        for (String r : record) if (eMtaSts(r)) outside.add(r.trim());
        return outside;
    }

    /*
     * ===================================================================
     * Names and SRV records
     * ===================================================================
     */

    /**
     * Two DNS names denote the same host.
     *
     * The comparison is EXACT, not by containment: "xmail.esempio.it".contains("mail.esempio.it")
     * is true, and a check written that way promotes a record that points elsewhere. It is the same
     * mistake that on SPF let a record that did not authorize the server pass as good.
     * The trailing dot of the absolute name and case do not matter.
     */
    public static boolean sameName(String a, String b) {
        if (a == null || b == null) return false;
        String x = a.trim().toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
        String y = b.trim().toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
        return !x.isEmpty() && x.equals(y);
    }

    /** The four fields of an SRV record: priority, weight, port, target. */
    public static class Srv {
        public int priority, weight, port;
        public String destination;
    }

    /** Reads "0 1 993 mail.esempio.it." Returns null if the line does not have that shape. */
    public static Srv analyzeSrv(String line) {
        if (line == null) return null;
        String[] p = line.trim().split("\\s+");
        if (p.length < 4) return null;
        try {
            Srv s = new Srv();
            s.priority = Integer.parseInt(p[0]);
            s.weight = Integer.parseInt(p[1]);
            s.port = Integer.parseInt(p[2]);
            s.destination = p[3].trim();
            return s;
        } catch (Exception e) {
            return null;
        }
    }

    /* ===================================================================
     * DMARC - RFC 9989 / RFC 9990
     * =================================================================== */

    /** Tags removed by RFC 9989: if they are still in the record, they no longer do anything. */
    public static final String[] REMOVED_TAGS = { "pct", "ri", "rf" };

    /** The tags that RFC 9989 defines. A whitelist, not a list of forbidden things. */
    public static final String[] KNOWN_TAGS = {
        "v", "p", "sp", "np", "adkim", "aspf", "rua", "ruf", "fo", "psd", "t"
    };

    /**
     * It is a DMARC record. Section 4: the "v" tag must be the FIRST one, and its value is
     * case-sensitive ("%s'DMARC1'" in the ABNF). If it is not first, is missing, or the value is
     * different, the whole record must be ignored.
     */
    public static boolean eDmarc(String r) {
        if (r == null) return false;
        String s = r.trim();
        int pv = s.indexOf(';');
        String first = (pv < 0 ? s : s.substring(0, pv)).trim();
        int eq = first.indexOf('=');
        if (eq < 0) return false;
        return first.substring(0, eq).trim().equalsIgnoreCase("v")
            && first.substring(eq + 1).trim().equals("DMARC1");
    }

    public static List<String> onlyDmarc(List<String> record) {
        List<String> outside = new ArrayList<>();
        if (record == null) return outside;
        for (String r : record) if (eDmarc(r)) outside.add(r.trim());
        return outside;
    }

    /**
     * The tags of a record written as "name=value; name=value".
     * The syntax is the same for DMARC and for DKIM keys, so there is only one parser:
     * two identical parsers are two parsers that one day behave differently.
     */
    public static LinkedHashMap<String, String> tag(String r) {
        return tagDmarc(r);
    }

    /**
     * The records that are DKIM keys. The criterion is the presence of the "p=" tag, which contains
     * the key: RFC 6376 Section 3.6.1 makes the "v=" tag only RECOMMENDED, with "DKIM1" as the
     * default value, so requiring it would exclude valid records.
     */
    public static List<String> onlyDkim(List<String> record) {
        List<String> outside = new ArrayList<>();
        if (record == null) return outside;
        for (String r : record) {
            if (r == null || r.isBlank()) continue;
            LinkedHashMap<String, String> t = tagDmarc(r);
            if (t.containsKey("p")) outside.add(r.trim());
        }
        return outside;
    }

    /** The public key declared in the record, without spaces: some DNS servers insert them. */
    public static String dkimKey(String record) {
        String p = tagDmarc(record).get("p");
        return p == null ? null : p.replaceAll("\\s+", "");
    }

    /** The record's tags, in the order they appear. Names in lowercase. */
    public static LinkedHashMap<String, String> tagDmarc(String r) {
        LinkedHashMap<String, String> m = new LinkedHashMap<>();
        if (r == null) return m;
        for (String piece : r.split(";")) {
            String p = piece.trim();
            if (p.isEmpty()) continue;
            int eq = p.indexOf('=');
            if (eq <= 0) continue;
            m.put(p.substring(0, eq).trim().toLowerCase(Locale.ROOT), p.substring(eq + 1).trim());
        }
        return m;
    }

    /** The mailto: addresses declared in a rua or ruf tag, without the size limit. */
    public static List<String> reportAddresses(String tagValue) {
        List<String> outside = new ArrayList<>();
        if (tagValue == null) return outside;
        for (String u : tagValue.split(",")) {
            String s = u.trim();
            if (s.toLowerCase(Locale.ROOT).startsWith("mailto:")) s = s.substring(7);
            int b = s.indexOf('!');            // "!10m": size limit, not part of the address
            if (b >= 0) s = s.substring(0, b);
            s = s.trim();
            if (!s.isEmpty()) outside.add(s);
        }
        return outside;
    }

    /** The part after the at sign. */
    public static String hostOf(String address) {
        if (address == null) return "";
        int a = address.lastIndexOf('@');
        return a < 0 ? "" : address.substring(a + 1).trim().toLowerCase(Locale.ROOT);
    }

    /**
     * The name to query to know whether the destination domain accepts reports for
     * another domain. RFC 9990 Section 4: take the destination host, prepend
     * "_report._dmarc" to it, and in front of that the domain that published the policy.
     * Example from the specification: blue.example.com._report._dmarc.red.example.net
     */
    public static String reportAuthorizationName(String policyDomain, String destinationHost) {
        return policyDomain.toLowerCase(Locale.ROOT) + "._report._dmarc."
             + destinationHost.toLowerCase(Locale.ROOT);
    }

    /**
     * Is external authorization needed? RFC 9990 Section 4 requires it when the policy
     * domain and the address domain do NOT match. Here we answer "no" only when the
     * match is certain: same name, or one a subdomain of the other. In the other cases we
     * answer "yes", and the panel goes to check whether the record is there.
     *
     * The caution is deliberate: saying "not needed" when it is in fact needed means letting
     * the reports never arrive, without any check flagging it.
     */
    public static boolean needsAuthorization(String policyDomain, String destinationHost) {
        if (policyDomain == null || destinationHost == null) return true;
        String a = policyDomain.trim().toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
        String b = destinationHost.trim().toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
        if (a.isEmpty() || b.isEmpty()) return true;
        if (a.equals(b)) return false;
        return !(a.endsWith("." + b) || b.endsWith("." + a));
    }

    /**
     * Changes ONLY the value of the "p" tag, leaving all the rest of the record intact.
     *
     * The record is not rebuilt from scratch: if someone added "sp=", "fo=" or a
     * second address in "rua", rewriting it from the start would make those parts disappear
     * without anyone noticing. Here one value is replaced and that is all, also preserving the
     * original spacing, so the before/after comparison shows a single difference.
     *
     * If the "p" tag is not there, it is inserted right after "v=DMARC1", which is the right place:
     * the specification wants "v" first, and says nothing about the order of the others.
     *
     * Returns null if the record is not a valid DMARC: better to do nothing than
     * produce a random string.
     */
    public static String changePolicy(String record, String fresh) {
        if (record == null || fresh == null) return null;
        String n = fresh.trim().toLowerCase(Locale.ROOT);
        if (!List.of("none", "quarantine", "reject").contains(n)) return null;
        if (!eDmarc(record)) return null;

        String[] pieces = record.split(";", -1);
        for (int i = 0; i < pieces.length; i++) {
            String piece = pieces[i];
            int eq = piece.indexOf('=');
            if (eq < 0) continue;
            if (!piece.substring(0, eq).trim().equalsIgnoreCase("p")) continue;
            // The space preceding the tag is preserved, if there was one.
            String before = piece.substring(0, eq + 1);
            pieces[i] = before + n;
            return String.join(";", pieces);
        }

        // No "p" tag: it is added after the version, imitating the record's spacing.
        // The record's spacing is imitated if there is one to imitate; when there is
        // nothing to deduce it from, the readable form is chosen, which is the one the panel
        // uses when it writes a record from scratch.
        String separator = !record.contains(";") ? "; " : (record.contains("; ") ? "; " : ";");
        int endV = record.indexOf(';');
        if (endV < 0) return record.trim() + separator + "p=" + n;
        String rest = record.substring(endV + 1);
        return record.substring(0, endV) + separator + "p=" + n
             + (rest.trim().isEmpty() ? "" : ";" + rest);
    }

    public static class DmarcOutcome {
        public int howMany;
        public boolean valid;
        public String record;
        public String problem;
        public String policy, subdomainPolicy, nonexistentPolicy, test;
        public LinkedHashMap<String, String> tag = new LinkedHashMap<>();
        public final List<String> rua = new ArrayList<>();
        public final List<String> toAuthorize = new ArrayList<>();
        public final List<String> warnings = new ArrayList<>();
    }

    public static DmarcOutcome analyzeDmarc(List<String> recordTxt, String domain) {
        DmarcOutcome e = new DmarcOutcome();
        List<String> dm = onlyDmarc(recordTxt);
        e.howMany = dm.size();

        if (e.howMany == 0) {
            e.valid = false;
            e.problem = I18n.tr("server.dnsrules.dmarcNone");
            return e;
        }
        if (e.howMany > 1) {
            e.valid = false;
            e.problem = I18n.tr("server.dnsrules.dmarcMany", java.util.Map.of("n", String.valueOf(e.howMany)));
            e.record = String.join("  ||  ", dm);
            return e;
        }

        e.valid = true;
        e.record = dm.get(0);
        e.tag = tagDmarc(e.record);
        e.policy = e.tag.get("p");
        e.subdomainPolicy = e.tag.get("sp");
        e.nonexistentPolicy = e.tag.get("np");
        e.test = e.tag.get("t");

        if (e.policy == null)
            e.warnings.add(I18n.tr("server.dnsrules.dmarcNoP"));
        else if (!java.util.List.of("none", "quarantine", "reject").contains(e.policy.toLowerCase(Locale.ROOT)))
            e.warnings.add(I18n.tr("server.dnsrules.dmarcBadP", java.util.Map.of("p", String.valueOf(e.policy))));

        for (String dead : REMOVED_TAGS)
            if (e.tag.containsKey(dead))
                e.warnings.add(I18n.tr("server.dnsrules.dmarcRemovedTag", java.util.Map.of("tag", String.valueOf(dead + "=" + e.tag.get(dead))))
                           + ("pct".equals(dead) ? " " + I18n.tr("server.dnsrules.dmarcPct") : ""));

        for (String tag : e.tag.keySet()) {
            boolean known = false;
            for (String n : KNOWN_TAGS) if (n.equals(tag)) { known = true; break; }
            boolean removed = false;
            for (String n : REMOVED_TAGS) if (n.equals(tag)) { removed = true; break; }
            if (!known && !removed)
                e.warnings.add(I18n.tr("server.dnsrules.dmarcUnknownTag", java.util.Map.of("tag", String.valueOf(tag))));
        }

        String rua = e.tag.get("rua");
        if (rua == null || rua.isBlank()) {
            e.warnings.add(I18n.tr("server.dnsrules.dmarcNoRua"));
        } else {
            for (String ind : reportAddresses(rua)) {
                e.rua.add(ind);
                String host = hostOf(ind);
                if (host.isEmpty()) {
                    e.warnings.add(I18n.tr("server.dnsrules.ruaNoDomain", java.util.Map.of("addr", String.valueOf(ind))));
                } else if (needsAuthorization(domain, host)) {
                    e.toAuthorize.add(reportAuthorizationName(domain, host));
                }
            }
        }

        if (e.test != null && e.test.equalsIgnoreCase("y"))
            e.warnings.add(I18n.tr("server.dnsrules.dmarcTest"));

        return e;
    }
}
