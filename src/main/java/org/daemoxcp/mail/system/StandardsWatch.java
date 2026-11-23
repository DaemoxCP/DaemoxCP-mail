package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.daemoxcp.mail.i18n.I18n;
import org.json.JSONObject;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Watches on its own whether something has changed under the panel's feet.
 *
 * The problem it solves: the rules the panel is built on change, and until now we
 * noticed by chance, while we were doing something else. On 2026-09-01 it happened with DMARC:
 * the panel was written on RFC 7489, which by May 2026 had already been replaced by three
 * new documents - and nobody had said so.
 *
 * That discovery, however, could be automated, because the RFC Editor publishes the status of
 * every document in a form a program can read:
 *   https://www.rfc-editor.org/rfc/rfcNNNN.json  ->  { "obsoleted_by": [...], "updated_by": [...] }
 * That is 1.3 KB per request. Querying it once a day costs nothing and turns a lucky
 * discovery into a warning.
 *
 * What it does NOT do, so as not to promise more than it delivers: it does not read the new
 * documents and does not say what changed. It says that they came out and which part of the
 * panel they affect. Reading them remains a job to do by hand, but at least we know it has to be done.
 */
public class StandardsWatch {

    /**
     * The rules the panel is built on, with what we already know about them.
     *
     * The last two columns are the snapshot taken on 2026-09-01 by reading the sources: they serve
     * to tell "replaced" apart from "replaced by something we already knew". Without them,
     * the panel would report the same things every day and people would learn to ignore it.
     *
     * number | what it governs in the panel | known replaced-by | known updated-by
     */
    private static final String[][] STANDARD = {
        { "7208", "server.watch.std.7208",                 "",                  "7372,8553,8616" },
        { "6376", "server.watch.std.6376",                "",                  "8301,8463,8553,8616" },
        { "8301", "server.watch.std.8301",      "",                  "" },
        { "9989", "server.watch.std.9989",                "",                  "" },
        { "9990", "server.watch.std.9990",       "",                  "" },
        { "9991", "server.watch.std.9991",                      "",                  "" },
        // These three updates were found by the watch itself on its first run,
        // on 2026-09-01. They are marked as known only AFTER they were read and verified:
        //  - RFC 8553 moves the names with an underscore into a registry: nothing changes for us.
        //  - RFC 8314 is the specification of 465, which we had already read.
        //  - RFC 8997 deprecates TLS 1.0 and 1.1 for mail submission and access. Verified:
        //    Dovecot has ssl_min_protocol = TLSv1.2 and Postfix excludes !TLSv1, !TLSv1.1.
        //    Already compliant, nothing to do - but we know it because we looked.
        { "6186", "server.watch.std.6186", "",                  "8314,8553" },
        { "6409", "server.watch.std.6409", "",               "8314" },
        { "8314", "server.watch.std.8314",                        "",                  "8997" },
        { "8461", "server.watch.std.8461",     "",                  "" },
    };

    private StandardsWatch() {}

    /*
     * ===================================================================
     * Pure part: tested without the network
     * ===================================================================
     */

    /** What is there now that we did not know. Order kept, no duplicates. */
    public static List<String> news(String knownCommaSeparated, List<String> current) {
        Set<String> known = new LinkedHashSet<>();
        if (knownCommaSeparated != null)
            for (String n : knownCommaSeparated.split(","))
                if (!n.trim().isEmpty()) known.add(normalize(n));
        List<String> outside = new ArrayList<>();
        if (current == null) return outside;
        for (String a : current) {
            String x = normalize(a);
            if (x.isEmpty() || known.contains(x)) continue;
            if (!outside.contains(x)) outside.add(x);
        }
        return outside;
    }

    /** "RFC9989", "rfc 9989", " 9989 " all become "9989". */
    public static String normalize(String rfc) {
        if (rfc == null) return "";
        String s = rfc.trim().toUpperCase(java.util.Locale.ROOT).replace(" ", "");
        if (s.startsWith("RFC")) s = s.substring(3);
        return s.trim();
    }

    /*
     * ===================================================================
     * Part that queries the RFC Editor
     * ===================================================================
     */

    public static JSONObject check() {
        JSONObject r = new JSONObject().put("success", true);
        JSONArray lines = new JSONArray();
        int replaced = 0, updated = 0, unread = 0;

        HttpClient http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(8))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();

        for (String[] s : STANDARD) {
            JSONObject o = new JSONObject().put("rfc", s[0]).put("governs", I18n.tr(s[1]));
            try {
                HttpRequest req = HttpRequest.newBuilder()
                        .uri(URI.create("https://www.rfc-editor.org/rfc/rfc" + s[0] + ".json"))
                        .timeout(Duration.ofSeconds(12))
                        .header("Accept", "application/json")
                        .GET().build();
                HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
                if (resp.statusCode() != 200) {
                    o.put("read", false).put("problem", I18n.tr("server.watch.editorStatus", java.util.Map.of("c", String.valueOf(resp.statusCode()))));
                    unread++; lines.put(o); continue;
                }
                JSONObject j = new JSONObject(resp.body());
                o.put("read", true).put("title", j.optString("title", ""))
                 .put("state", j.optString("status", ""));

                List<String> obs = list(j.optJSONArray("obsoleted_by"));
                List<String> upd = list(j.optJSONArray("updated_by"));
                List<String> newObs = news(s[2], obs);
                List<String> newUpd = news(s[3], upd);

                o.put("replacedBy", new JSONArray(newObs));
                o.put("updatedBy", new JSONArray(newUpd));
                if (!newObs.isEmpty()) {
                    replaced++;
                    o.put("severity", 2).put("comment", I18n.tr("server.watch.obsoleted", java.util.Map.of("n", String.valueOf(s[0]), "by", String.valueOf(describe(newObs)), "topic", String.valueOf(I18n.tr(s[1])))));
                } else if (!newUpd.isEmpty()) {
                    updated++;
                    o.put("severity", 1).put("comment", I18n.tr("server.watch.updated", java.util.Map.of("n", String.valueOf(s[0]), "by", String.valueOf(describe(newUpd)), "topic", String.valueOf(I18n.tr(s[1])))));
                } else {
                    o.put("severity", 0).put("comment", I18n.tr("server.watch.nothingNew"));
                }
            } catch (Exception e) {
                // A check that did not succeed is not an "all clear".
                o.put("read", false).put("severity", 3)
                 .put("problem", I18n.tr("server.watch.editorFailed", java.util.Map.of("err", String.valueOf(e.getClass().getSimpleName()))));
                unread++;
            }
            lines.put(o);
        }

        r.put("standard", lines).put("replaced", replaced)
         .put("updated", updated).put("unread", unread);
        r.put("source", "https://www.rfc-editor.org/rfc/rfcNNNN.json");
        r.put("note", replaced > 0
                ? (replaced == 1 ? I18n.tr("server.watch.sumObsoleted.one")
                                   : I18n.tr("server.watch.sumObsoleted.other", java.util.Map.of("n", String.valueOf(replaced))))
                : updated > 0
                ? I18n.tr("server.watch.sumUpdated", java.util.Map.of("n", String.valueOf(updated)))
                : unread > 0
                ? I18n.tr("server.watch.sumUnread", java.util.Map.of("n", String.valueOf(unread)))
                : I18n.tr("server.watch.sumAllCurrent"));
        return r;
    }

    private static List<String> list(JSONArray a) {
        List<String> l = new ArrayList<>();
        if (a == null) return l;
        for (int i = 0; i < a.length(); i++) l.add(a.optString(i, ""));
        return l;
    }

    private static String describe(List<String> rfc) {
        List<String> rfcList = new ArrayList<>();
        for (String x : rfc) rfcList.add("RFC " + x);
        return String.join(", ", rfcList);
    }

    /** The entries to put in the periodic report: only what deserves to be read. */
    public static List<String> forReport(JSONObject check) {
        List<String> outside = new ArrayList<>();
        if (check == null || !check.optBoolean("success", false)) return outside;
        JSONArray a = check.optJSONArray("standard");
        if (a == null) return outside;
        for (int i = 0; i < a.length(); i++) {
            JSONObject o = a.getJSONObject(i);
            int g = o.optInt("severity", 0);
            if (g == 1 || g == 2) outside.add(o.optString("comment"));
        }
        return outside;
    }

    /*
     * ===================================================================
     * What changed: extraction from the text of the document
     * ===================================================================
     */

    /**
     * Cleans the text of an RFC of the pagination clutter: page breaks,
     * "[Page 42]" and the headers repeated at the top of every page. Without this, the list of
     * changes comes out broken up by lines that do not belong there.
     */
    public static String cleanUp(String text) {
        if (text == null) return "";
        StringBuilder sb = new StringBuilder();
        for (String r : text.split("\n")) {
            String t = r.replace("\f", "");
            if (t.matches("^.*\\[Page \\d+\\]\\s*$")) continue;
            if (t.matches("^RFC \\d+\\s+.*\\s+[A-Z][a-z]+ \\d{4}\\s*$")) continue;
            sb.append(t).append("\n");
        }
        return sb.toString();
    }

    /** Looks like the start of a new top-level section. */
    private static boolean newSection(String line) {
        return line.matches("^(?:Appendix\\s+[A-Z]|[0-9]+)\\.\\s+\\S.*")
            || line.matches("^(?:Acknowledge?ments|Authors?'? Addresses?|Contributors|"
                          + "Normative References|Informative References|References|Index)\\s*$");
    }

    /**
     * The appendix in which the authors list what changed compared with the previous
     * document. It is not made up: many revision RFCs contain it, written by those who
     * made the changes. RFC 9989 has "Appendix C. Changes from RFC 7489", RFC 6376 has
     * "Appendix E. Changes since RFC 4871".
     *
     * The LAST occurrence of the heading is taken: the first one is in the table of contents.
     */
    public static String changeList(String rfcText) {
        String t = cleanUp(rfcText);
        String[] lines = t.split("\n");
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(
                "^\\s*(?:Appendix\\s+)?[A-Z0-9]{1,4}(?:\\.[0-9]+)*\\.?\\s+"
              // Between "Changes" and "from/since" there can be other words: RFC 7208 has the title
              // "Changes in Implementation Requirements from RFC 4408". But "from" or "since"
              // must be there: without the constraint, "Changes in Policy During a Reporting
              // Period" (RFC 9990 Section 3.3) would be mistaken for a list of changes.
              + "(?:(?:Summary of\\s+)?Changes?\\b[^.]{0,60}?\\b(?:from|since)\\b.*|Change\\s+Log\\b.*)$",
                java.util.regex.Pattern.CASE_INSENSITIVE);
        int start = -1;
        for (int i = 0; i < lines.length; i++) {
            String r = lines[i];
            if (!p.matcher(r).matches()) continue;
            // The lines of the table of contents end with dots and a page number.
            if (r.matches("^.*\\.\\s*\\.\\s*\\..*\\d+\\s*$")) continue;
            start = i;
        }
        if (start < 0) return null;

        StringBuilder sb = new StringBuilder(lines[start].trim()).append("\n");
        for (int i = start + 1; i < lines.length; i++) {
            if (newSection(lines[i])) break;
            sb.append(lines[i]).append("\n");
        }
        String out = sb.toString().replaceAll("\n{3,}", "\n\n").trim();
        return out.isEmpty() ? null : out;
    }

    /** The abstract: it is always there, and serves as a fallback when the list of changes is missing. */
    public static String abstractOf(String rfcText) {
        String t = cleanUp(rfcText);
        String[] lines = t.split("\n");
        int start = -1;
        for (int i = 0; i < lines.length; i++)
            if (lines[i].trim().equalsIgnoreCase("Abstract")) { start = i; break; }
        if (start < 0) return null;
        StringBuilder sb = new StringBuilder();
        for (int i = start + 1; i < lines.length; i++) {
            String r = lines[i];
            String tt = r.trim();
            if (tt.equalsIgnoreCase("Status of This Memo")
                    || tt.equalsIgnoreCase("Copyright Notice")
                    || tt.equalsIgnoreCase("Table of Contents")
                    || newSection(r)) break;
            sb.append(r).append("\n");
        }
        String out = sb.toString().replaceAll("\n{3,}", "\n\n").trim();
        return out.isEmpty() ? null : out;
    }

    /**
     * Downloads the new document and extracts what it says about itself: first the list of
     * changes, and if there is none, the abstract.
     *
     * This does NOT say whether the panel must be changed: it says what changed in the document.
     * Deciding whether it touches our code remains a reading job - but starting from the list
     * written by the authors is quite another thing than starting from a hundred and eighty pages.
     */
    public static JSONObject whatChanged(String number) { return whatChanged(number, number); }

    /**
     * @param number     the new document, to download
     * @param reference the panel's specification it refers to, to know which
     *                   identifiers to cross-check (for an update they are different)
     */
    public static JSONObject whatChanged(String number, String reference) {
        JSONObject r = new JSONObject().put("rfc", normalize(number));
        String n = normalize(number);
        if (!n.matches("[0-9]{1,5}"))
            return r.put("success", false).put("error", I18n.tr("server.watch.badNumber"));
        try {
            HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(8)).build();
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create("https://www.rfc-editor.org/rfc/rfc" + n + ".txt"))
                    .timeout(Duration.ofSeconds(30)).GET().build();
            HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200)
                return r.put("success", false)
                        .put("error", I18n.tr("server.watch.editorStatus", java.util.Map.of("c", String.valueOf(resp.statusCode()))));
            String text = resp.body();
            r.put("success", true).put("bytes", text.length());

            String changes = changeList(text);
            if (changes != null) {
                r.put("type", "list").put("text", changes)
                 .put("note", I18n.tr("server.watch.changeList"));
                // Cross-check with what the panel really uses.
                List<String> touches = linesTouching(changes, identifiersOf(reference));
                r.put("concernsYou", new JSONArray(touches));
                r.put("crossNote", touches.isEmpty()
                        ? I18n.tr("server.watch.crossNone")
                        : touches.size() == 1
                          ? I18n.tr("server.watch.crossSome.one")
                          : I18n.tr("server.watch.crossSome.other", java.util.Map.of("n", String.valueOf(touches.size()))));
                return r;
            }

            String ab = abstractOf(text);
            if (ab != null)
                return r.put("type", "abstract").put("text", ab)
                        .put("note", I18n.tr("server.watch.abstract"));

            return r.put("success", false)
                    .put("error", I18n.tr("server.watch.noChangesNoAbstract"));
        } catch (Exception e) {
            return r.put("success", false)
                    .put("error", I18n.tr("server.watch.downloadFailed", java.util.Map.of("err", String.valueOf(e.getClass().getSimpleName()))));
        }
    }

    /*
     * ===================================================================
     * Which lines of the list really touch this panel
     * ===================================================================
     */

    /**
     * The identifiers that the panel really writes or recognises, for each specification.
     *
     * They serve to cross-check the list of changes with what the panel does: if a line of the
     * list names "pct" and the panel writes DMARC records, that line should be read before
     * the others. It is the same reasoning I did by hand with a grep on 2026-09-01,
     * written down once and for all.
     *
     * WATCH OUT for how the result is read: the cross-check says "these lines concern you
     * for sure", NOT "only these concern you". A change described in words without
     * naming the tag slips through. Presenting it as a complete filter would be the way to
     * skip exactly the line that mattered.
     *
     * number | comma-separated identifiers
     */
    private static final String[][] RELEVANT = {
        { "7208", "v=spf1,ip4,ip6,include,redirect,exists,all,mx,ptr,permerror,10" },
        { "6376", "rsa-sha256,rsa-sha1,_domainkey,k=rsa,selector,2048,1024" },
        { "8301", "rsa-sha256,rsa-sha1,2048,1024,4096" },
        { "9989", "pct,rua,ruf,adkim,aspf,sp,np,psd,fo,ri,rf,DMARC1,tree walk,none,quarantine,reject" },
        { "9990", "rua,_report._dmarc,gzip,aggregate" },
        { "9991", "ruf,fo,failure" },
        { "6186", "_imaps._tcp,_submission._tcp,993,587,SRV" },
        { "6409", "AUTH,MAIL,submission,587" },
        { "8314", "465,submissions,implicit,STARTTLS,TLS 1.2,TLS 1.1,TLS 1.0" },
        { "8461", "_mta-sts,mta-sts.txt,policy,max_age" },
    };

    private static String identifiersOf(String rfc) {
        String n = normalize(rfc);
        for (String[] x : RELEVANT) if (x[0].equals(n)) return x[1];
        return "";
    }

    /**
     * The lines of the list that name something the panel uses.
     *
     * The comparison is on whole words when the identifier is made of letters and
     * digits only: searching for "all" as a substring would find it inside "finally", "小" inside
     * anything, and the report would become noise. It is the same mistake that, on SPF,
     * let a record that did not authorise the server pass as good.
     */
    public static List<String> linesTouching(String list, String identifiers) {
        List<String> outside = new ArrayList<>();
        if (list == null || identifiers == null) return outside;
        List<String> keys = new ArrayList<>();
        for (String k : identifiers.split(",")) if (!k.trim().isEmpty()) keys.add(k.trim());
        if (keys.isEmpty()) return outside;

        for (String line : list.split("\n")) {
            String r = line.trim();
            if (r.length() < 3) continue;
            LinkedHashSet<String> found = new LinkedHashSet<>();
            for (String k : keys) if (containsIdentifier(line, k)) found.add(k);
            if (!found.isEmpty()) outside.add(String.join(", ", found) + "  ->  " + r);
        }
        return outside;
    }

    /** Whole word for alphanumeric identifiers, substring for the others. */
    public static boolean containsIdentifier(String line, String key) {
        if (line == null || key == null || key.isEmpty()) return false;
        boolean simple = key.chars().allMatch(c -> Character.isLetterOrDigit(c));
        if (!simple) return line.toLowerCase(java.util.Locale.ROOT)
                                  .contains(key.toLowerCase(java.util.Locale.ROOT));
        return java.util.regex.Pattern
                .compile("(?<![A-Za-z0-9])" + java.util.regex.Pattern.quote(key) + "(?![A-Za-z0-9])",
                         java.util.regex.Pattern.CASE_INSENSITIVE)
                .matcher(line).find();
    }

    static String[][] standardForTest() { return Arrays.stream(STANDARD).toArray(String[][]::new); }
}
