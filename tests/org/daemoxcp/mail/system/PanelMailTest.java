package org.daemoxcp.mail.system;

import org.json.JSONArray;
import org.json.JSONObject;
import org.daemoxcp.mail.i18n.I18n;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The panel's emails: envelope, encodings and content.
 *
 * The defect of 05/11/2026: the owner receives from the real server an email from "Control panel"
 * with subject "[freebsd] 1 thing to do - 05/11/2026". Neither which panel, nor which server
 * ("freebsd" is hostname(1), the server is called mail.domain-b.test), nor what to do. On top of
 * that the report's footer showed a "\n" written out literally, and the message was text only.
 *
 * Tested here, without touching the system:
 *  - the envelope: sender "Mail control panel (server)", subject in RFC 2047 within 75 characters
 *    per word, Date, Message-ID, Content-Language, Auto-Submitted, multipart with text and HTML in
 *    quoted-printable that decode exactly into what was written;
 *  - the report: the subject says the server and what to do, every item has its urgency in words,
 *    title, explanation and place in the panel, in text and in HTML, in both languages, without
 *    bare language keys, without literal "\n", with HTML that lets no markup through from the data;
 *  - the codes: the code in the body but not in the subject nor in the preview, the IP of who asked
 *    for it only in the messages that go to the administrator, never in the email change.
 *
 * It runs on the VM like the others:
 *   java -cp "tests:target/freebsd-mail-panel-1.0.jar" org.daemoxcp.mail.system.PanelMailTest
 * With -Dpanelmail.dump=<folder> it also writes the composed messages (.eml), to look at them in a
 * mail program.
 */
public class PanelMailTest {

    private static int failed = 0, passed = 0;

    private static final ZonedDateTime WHEN = ZonedDateTime.of(2026, 11, 5, 20, 15, 0, 0, ZoneId.of("UTC"));
    private static final String SERVER = "mail.example.org";
    // The Italian texts are read from it.json, never written here; the Italian date is formatted
    // here with the Italian locale, apart from the panel's patterns.
    private static final String IT_PRODUCT = I18n.t("it", "mail.common.product");
    private static final String IT_DATE = WHEN.format(DateTimeFormatter.ofPattern("d MMMM yyyy", Locale.ITALIAN));
    private static final String IT_WHEN = WHEN.format(DateTimeFormatter.ofPattern(I18n.t("it", "mail.common.dateTimePattern"), Locale.ITALIAN));

    public static void main(String[] args) throws Exception {
        envelope();
        serverName();
        report();
        codes();
        texts();
        dump();
        System.out.println("\n" + passed + " passed, " + failed + " failed");
        if (failed > 0) System.exit(1);
    }

    // ===================== the envelope =====================

    static void envelope() {
        System.out.println("== the envelope ==");
        String long1 = "A very long line with accented letters: café, naïve, résumé, façade, déjà vu, Zoë — "
                + "and more text ".repeat(12) + "end.";
        String tricky = "a=b\tinner tab, trailing space \ntrailing space \n\n=3D not decoded\n" + long1 + "\nlast";
        String qp = PanelMail.quotedPrintable(tricky);
        check("quoted-printable: no line over 76", qp.lines().allMatch(l -> l.length() <= 76));
        check("quoted-printable: printable ASCII only (and the TAB inside the line, which the standard allows)", qp.chars().allMatch(c -> c == '\r' || c == '\n' || c == '\t' || (c >= 32 && c < 127)));
        check("quoted-printable: it decodes exactly into the starting text", qpDecode(qp).equals(tricky.replace("\r\n", "\n")));
        check("quoted-printable: the space at the end of a line becomes =20", qp.contains("space=20\r\n"));
        check("quoted-printable: '=' becomes =3D", qp.contains("a=3Db"));

        String subject = "[mail.example.org] Urgent: Apply 2 security fixes, and 2 more things to do - report of 5 November 2026 — café";
        String h = PanelMail.encodeHeader(subject, 9);
        List<String> words = new ArrayList<>();
        Matcher m = Pattern.compile("=\\?UTF-8\\?B\\?([A-Za-z0-9+/=]*)\\?=").matcher(h);
        StringBuilder decoded = new StringBuilder();
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        while (m.find()) { words.add(m.group()); bytes.writeBytes(Base64.getDecoder().decode(m.group(1))); }
        decoded.append(bytes.toString(StandardCharsets.UTF_8));
        check("RFC 2047: several encoded words for a long subject", words.size() > 1);
        check("RFC 2047: every encoded word within 75 characters", words.stream().allMatch(w -> w.length() <= 75));
        check("RFC 2047: the words join back into the exact subject", decoded.toString().equals(subject));
        check("RFC 2047: lines folded with CRLF and a space", h.contains("\r\n ") && !h.contains("\n\n"));
        check("RFC 2047: an ASCII subject stays as it is", PanelMail.encodeHeader("[mail.example.org] All good", 9).equals("[mail.example.org] All good"));
        check("header: a newline in the subject does not open a new header",
                !PanelMail.encodeHeader("x\r\nBcc: someone@example.com", 9).contains("\n"));

        String from = PanelMail.address(PanelMail.senderName("en", SERVER), "no-reply@example.org");
        check("sender: \"Mail control panel (mail.example.org)\" <no-reply@example.org>",
                from.equals("\"Mail control panel (mail.example.org)\" <no-reply@example.org>"));
        check("sender: the quotes in the name are escaped", PanelMail.address("A \"B\"", "x@example.org").equals("\"A \\\"B\\\"\" <x@example.org>"));
        check("sender: a non-ASCII name goes into RFC 2047", PanelMail.address("Panel café", "x@example.org").startsWith("=?UTF-8?B?"));
        check("sender without a server: the panel's name only", PanelMail.senderName("en", "").equals("Mail control panel"));
        check("sender in Italian: the product name from it.json, with the server", PanelMail.senderName("it", SERVER).equals(IT_PRODUCT + " (mail.example.org)"));

        PanelMail.Message msg = new PanelMail.Message("Test café", tricky, "<p>café</p>", "it");
        String raw = PanelMail.compose(PanelMail.senderName("it", SERVER), "no-reply@example.org", "admin@example.org", msg,
                "report.1@example.org", WHEN);
        String head = raw.substring(0, raw.indexOf("\r\n\r\n"));
        check("envelope: From with the panel's and the server's name", ("\"" + IT_PRODUCT + " (mail.example.org)\" <no-reply@example.org>").equals(unfold(head, "From")));
        check("envelope: Date in RFC 5322 form", head.contains("\r\nDate: Thu, 5 Nov 2026 20:15:00 +0000"));
        check("envelope: Message-ID", head.contains("\r\nMessage-ID: <report.1@example.org>"));
        check("envelope: Content-Language", head.contains("\r\nContent-Language: it"));
        check("envelope: Auto-Submitted and X-Auto-Response-Suppress", head.contains("\r\nAuto-Submitted: auto-generated") && head.contains("\r\nX-Auto-Response-Suppress: All"));
        Matcher bm = Pattern.compile("boundary=\"([^\"]+)\"").matcher(head);
        check("envelope: multipart/alternative with its boundary", head.contains("Content-Type: multipart/alternative;") && bm.find());
        String boundary = bm.group(1);
        String[] parts = raw.split("--" + Pattern.quote(boundary));
        check("envelope: two parts and the closing", parts.length == 4 && parts[3].startsWith("--"));
        check("envelope: first the text, then the HTML (programs show the last one they can read)",
                parts[1].contains("Content-Type: text/plain; charset=UTF-8") && parts[2].contains("Content-Type: text/html; charset=UTF-8"));
        check("envelope: the text decodes into what was written", qpDecode(body(parts[1])).equals(tricky));
        check("envelope: the HTML decodes into what was written", qpDecode(body(parts[2])).equals("<p>café</p>"));
        check("envelope: no line over 78 characters", raw.lines().allMatch(l -> l.length() <= 78));
        check("envelope: lines ended by CRLF", !raw.replace("\r\n", "").contains("\n"));

        // The real long headers: the panel's name in Italian with a long server, an ASCII subject
        // of a hundred characters, an accented subject of a hundred.
        PanelMail.Message longOnes = new PanelMail.Message(
                "[mail.example.org] Urgent: Restart the stopped services: dovecot, and 3 more - report of 5 November 2026",
                "x", "<p>x</p>", "it");
        String raw2 = PanelMail.compose(PanelMail.senderName("it", "main-mail-server.a-very-long-example.org"), "no-reply@a-very-long-example.org",
                "admin@example.org", longOnes, "report.2@example.org", WHEN);
        String head2 = raw2.substring(0, raw2.indexOf("\r\n\r\n"));
        check("long headers: no line over 78", head2.lines().allMatch(l -> l.length() <= 78));
        String from2 = unfold(head2, "From");
        check("long headers: a name that does not fit between quotes goes into encoded words, which join back identical",
                from2.startsWith("=?UTF-8?B?") && from2.endsWith(" <no-reply@a-very-long-example.org>")
                && decodeWords(from2.substring(0, from2.lastIndexOf(" <"))).equals(IT_PRODUCT + " (main-mail-server.a-very-long-example.org)"));
        check("long headers: the folded subject joins back identical",
                unfold(head2, "Subject").equals(longOnes.subject()));
        String raw3 = PanelMail.compose("x", "a@example.org", "b@example.org", new PanelMail.Message(subject, "x", "y", "it"),
                "report.3@example.org", WHEN);
        check("long headers: the encoded subject fits in the 78 too", raw3.substring(0, raw3.indexOf("\r\n\r\n")).lines().allMatch(l -> l.length() <= 78));
    }

    /** RFC 2047's encoded words joined: the space between two encoded words does not count. */
    private static String decodeWords(String s) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        Matcher m = Pattern.compile("=\\?UTF-8\\?B\\?([A-Za-z0-9+/=]*)\\?=").matcher(s);
        while (m.find()) bytes.writeBytes(Base64.getDecoder().decode(m.group(1)));
        return bytes.toString(StandardCharsets.UTF_8);
    }

    /** The value of a header with its folded lines joined (RFC 5322, 2.2.3). */
    private static String unfold(String head, String name) {
        String u = head.replace("\r\n ", " ").replace("\r\n\t", "\t");
        for (String l : u.split("\r\n")) if (l.startsWith(name + ": ")) return l.substring(name.length() + 2);
        return null;
    }

    /**
     * The server's name, on the real system: without the panel's database Postfix says it
     * (myhostname), not hostname(1). On the VM hostname(1) is "freebsdlocal" and myhostname
     * "mail.rehearsal.test", as on the real server "freebsd" and "mail.domain-b.test": it is exactly
     * the case that produced "[freebsd] 1 thing to do". Without postconf (on the Mac) it is skipped.
     */
    static void serverName() throws Exception {
        System.out.println("\n== the server's name ==");
        String postfix = run("postconf", "-h", "myhostname");
        String host = run("hostname");
        if (postfix.isEmpty()) { System.out.println("  (postconf is not here: check skipped)"); return; }
        String name = PanelMail.serverName();
        System.out.println("  hostname(1) " + host + ", myhostname " + postfix + ", the panel uses " + name);
        check("the server's name is Postfix's", name.equals(postfix.toLowerCase()));
        if (!host.equalsIgnoreCase(postfix))
            check("and not hostname(1)'s, which is different here", !name.equalsIgnoreCase(host));
    }

    private static String run(String... cmd) {
        try {
            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            return p.waitFor() == 0 ? out : "";
        } catch (Exception e) { return ""; }
    }

    private static String body(String part) {
        String p = part.substring(part.indexOf("\r\n\r\n") + 4);
        return p.endsWith("\r\n") ? p.substring(0, p.length() - 2) : p;
    }

    static String qpDecode(String s) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        String t = s.replace("=\r\n", "").replace("\r\n", "\n");
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (c == '=' && i + 2 < t.length()) {
                out.write(Integer.parseInt(t.substring(i + 1, i + 3), 16));
                i += 2;
            } else out.write(c);
        }
        return out.toString(StandardCharsets.UTF_8);
    }

    // ===================== the report =====================

    static JSONObject data(JSONArray toDo) {
        return new JSONObject()
                .put("toDo", toDo)
                .put("system", new JSONObject().put("installedKernel", "15.1-RELEASE-p3").put("runningKernel", "15.1-RELEASE-p2")
                        .put("userland", "15.1-RELEASE-p3").put("arch", "arm64").put("endOfSupport", "31/12/2026"))
                .put("daysToEndOfSupport", 56)
                .put("branch", new JSONObject().put("branch", "quarterly"))
                .put("totalPackages", 143).put("lockedPackageCount", 40).put("packagesWithUpdate", 3)
                .put("toUpdate", new JSONArray().put("nginx 1.30.5,3 -> 1.30.6,3 (protected: pkg upgrade skips it)").put("<script>alert(1)</script> 1 -> 2"))
                .put("vulnDbDays", 0).put("vulnDbUpdatedNow", true).put("catalogDays", 2).put("catalogDate", "03/11/2026")
                .put("refreshedCatalog", true)
                .put("vulnWithRemedy", new JSONArray().put("nginx: 1.30.5,3 -> 1.30.6,3"))
                .put("vulnWithoutRemedy", new JSONArray())
                .put("certificate", new JSONObject().put("name", "mail.example.org").put("issuer", "R11 (Let's Encrypt)")
                        .put("expired", false).put("days", 10).put("expiresOn", "15 November 2026"))
                .put("services", new JSONArray().put(new JSONObject().put("name", "postfix").put("active", true))
                        .put(new JSONObject().put("name", "dovecot").put("active", false)))
                .put("inactiveServices", new JSONArray().put("dovecot"))
                .put("missingLibraries", new JSONArray())
                .put("space", "zroot/ROOT/default   29G   5.1G   24G    18%    /")
                .put("environments", new JSONObject().put("success", true).put("environments", new JSONArray()
                        .put(new JSONObject().put("name", "default").put("space", "4.3G").put("state", "in use now and at the next restart"))));
    }

    static JSONObject item(int urgency, String title, String what, String where) {
        JSONObject o = new JSONObject().put("urgency", urgency).put("what", what).put("where", where);
        if (title != null) o.put("title", title);
        return o;
    }

    static void report() {
        System.out.println("\n== the report ==");
        JSONArray four = new JSONArray()
                .put(item(0, "Restart the stopped services: dovecot", "Services NOT running: dovecot", "Panel home"))
                .put(item(1, "Apply 1 security fix", "1 vulnerable package has a fix available: nginx: 1.30.5,3 -> 1.30.6,3", "Updates -> Guided update of a protected package"))
                .put(item(1, "Renew the TLS certificate (it expires in 10 days)", "The TLS certificate expires in 10 days.", "SSL certificates"))
                .put(item(2, null, "An item from an older producer, without a title.", "Updates"));
        ReportMail.Context en = new ReportMail.Context("en", SERVER, "admin@example.org", true, "weekly", WHEN);
        PanelMail.Message m = ReportMail.message(en, data(four));
        System.out.println("  subject: " + m.subject());
        check("subject: server, urgency, the most urgent thing, how many others, date",
                m.subject().equals("[mail.example.org] Urgent: Restart the stopped services: dovecot, and 3 more things to do - report of 5 November 2026"));
        check("subject: no more generic \"thing to do\" nor numeric date", !m.subject().contains("thing to do") && !m.subject().contains("05/11/2026"));
        for (int i = 0; i < four.length(); i++) {
            JSONObject x = four.getJSONObject(i);
            String title = ReportMail.title(x);
            check("text: the item \"" + title + "\" is there, with the place in the panel",
                    flat(m.text()).contains(title) && flat(m.text()).contains(x.getString("where")));
            check("HTML: the item \"" + title + "\" is there, with the place in the panel",
                    m.html().contains(PanelMail.esc(title)) && m.html().contains(PanelMail.esc(x.getString("where").replace(" -> ", " → "))));
        }
        check("text: the urgencies in words, not only colours", m.text().contains("[Act now]") && m.text().contains("[Urgent]") && m.text().contains("[To do]"));
        check("HTML: the urgencies in words", m.html().contains(">Act now<") && m.html().contains(">Urgent<") && m.html().contains(">To do<"));
        check("an item without a title uses its text", flat(m.text()).contains("An item from an older producer, without a title."));
        check("status at the top: how many, and how many urgent", m.text().contains("4 THINGS TO DO") && flat(m.text()).contains("3 are urgent and come first."));
        check("kind of report and time with the zone", m.text().contains("Weekly report, 5 November 2026 at 20:15 UTC"));
        check("the status sections, in text and in HTML", List.of("System", "Packages", "Known vulnerabilities", "TLS certificate",
                "Services", "Libraries", "Disk space", "Ways back (boot environments)").stream()
                .allMatch(s -> m.text().contains(s.toUpperCase()) && m.html().contains(">" + PanelMail.esc(s) + "<")));
        check("architecture: from the key operatingSystem really sets (\"arch\")", flat(m.text()).contains("Architecture: arm64"));
        check("space: the df line said in words", flat(m.text()).contains("File system /: 18% used, 24G free of 29G"));
        check("certificate: name, issuer, expiry", flat(m.text()).contains("Expiry: in 10 days, on 15 November 2026"));
        check("footer: why it arrives and how to stop it", flat(m.text()).contains("sent automatically by the mail control panel of mail.example.org to admin@example.org")
                && flat(m.text()).contains("Settings, Periodic email report"));
        check("no \\n written out literally (the old footer showed it)", !m.text().contains("\\n") && !m.html().contains("\\n"));
        check("text: no line over 72 columns, except words that do not break",
                m.text().lines().allMatch(l -> l.length() <= 72 || !l.trim().contains(" ")));
        check("HTML: the data carry no markup (<script> from the package names)",
                !m.html().contains("<script>") && m.html().contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        check("HTML: language declared and a single h1", m.html().contains("<html lang=\"en\">") && count(m.html(), "<h1") == 1);
        check("HTML: layout tables declared as such, data tables with th scope",
                m.html().contains("role=\"presentation\"") && m.html().contains("<th scope=\"row\""));
        check("HTML: no external resource, no link", !m.html().contains("http://") && !m.html().contains("https://")
                && !m.html().contains("<a ") && !m.html().contains("<img") && !m.html().contains("<link"));
        check("HTML: hidden preview line with the first things to do",
                m.html().contains("display:none") && m.html().contains("4 things to do: Restart the stopped services: dovecot; Apply 1 security fix;"));

        JSONArray one = new JSONArray().put(item(2, "Update 3 packages", "3 packages have a newer version in the repository.", "Updates -> Maintenance plan"));
        check("subject with one non-urgent item", ReportMail.message(en, data(one)).subject()
                .equals("[mail.example.org] To do: Update 3 packages - report of 5 November 2026"));
        PanelMail.Message none = ReportMail.message(en, data(new JSONArray()));
        check("subject with nothing to do", none.subject().equals("[mail.example.org] All good, nothing to do - report of 5 November 2026"));
        check("with nothing to do it says so in one line", none.text().contains("ALL GOOD: NOTHING TO DO") && !none.text().contains("WHAT TO DO"));

        ReportMail.Context onRequest = new ReportMail.Context("en", SERVER, "admin@example.org", false, "weekly", WHEN);
        PanelMail.Message manual = ReportMail.message(onRequest, data(one));
        check("sent from the button: it says so, and does not pass itself off as weekly",
                manual.text().contains("Report sent on request from the panel") && !manual.text().contains("Weekly report"));

        ReportMail.Context it = new ReportMail.Context("it", "mail.example.it", "admin@example.it", true, "monthly", WHEN);
        PanelMail.Message mi = ReportMail.message(it, data(new JSONArray().put(item(1, "Apply 2 security fixes", "x", "Updates")).put(item(3, "Update the package catalog", "y", "Updates"))));
        System.out.println("  subject: " + mi.subject());
        check("Italian: subject, from it.json's templates", mi.subject().equals(I18n.t("it", "mail.report.subject.urgent", Map.of("server", "mail.example.it",
                "title", "Apply 2 security fixes", "more", I18n.t("it", "mail.report.subject.more.one"),
                "date", I18n.t("it", "mail.report.subject.date", Map.of("date", IT_DATE))))));
        check("Italian: the month in Italian, not in English (" + IT_DATE + ")", mi.subject().contains(IT_DATE) && !mi.subject().contains("November"));
        check("Italian: monthly report, date with the month in full", mi.text().contains(I18n.t("it", "mail.report.kind.monthly") + ", " + IT_WHEN));
        check("Italian: html lang=it", mi.html().contains("<html lang=\"it\">"));

        ReportMail.Context noName = new ReportMail.Context("en", "", "admin@example.org", true, "weekly", WHEN);
        check("without the server's name: 'mail server', not empty brackets", ReportMail.message(noName, data(one)).subject().startsWith("[mail server] "));
    }

    // ===================== the codes =====================

    static void codes() {
        System.out.println("\n== the codes ==");
        for (CodeMail.Kind k : CodeMail.Kind.values()) {
            for (String lang : List.of("en", "it")) {
                PanelMail.Message m = CodeMail.message(k, lang, SERVER, "482913", 10, "203.0.113.7", WHEN);
                String name = k + "/" + lang;
                check(name + ": the code in the text and in the HTML", m.text().contains("482913") && m.html().contains(">482913<"));
                Matcher d = Pattern.compile("\\b(\\d{6})\\b").matcher(m.text());
                check(name + ": the first six-digit number in the text is the code (the tests look for it that way)", d.find() && d.group(1).equals("482913"));
                check(name + ": the code NOT in the subject", !m.subject().contains("482913"));
                String pre = m.html().substring(m.html().indexOf("display:none"), m.html().indexOf("</div>", m.html().indexOf("display:none")));
                check(name + ": the code NOT in the preview line", !pre.contains("482913"));
                check(name + ": the subject says the server", m.subject().startsWith("[" + SERVER + "] "));
                check(name + ": the IP of who asked for it " + (k == CodeMail.Kind.EMAIL_CHANGE ? "is NOT there (it goes to a new address)" : "is there"),
                        (k == CodeMail.Kind.EMAIL_CHANGE) != (m.text().contains("203.0.113.7") && m.html().contains("203.0.113.7")));
                check(name + ": when it was asked for", flat(m.text()).contains(lang.equals("en") ? "5 November 2026 at 20:15 UTC" : IT_WHEN));
                check(name + ": validity in minutes", m.text().contains("10"));
                check(name + ": no link", !m.html().contains("<a ") && !m.html().contains("http"));
            }
        }
        PanelMail.Message en = CodeMail.message(CodeMail.Kind.LOGIN, "en", SERVER, "482913", 10, "203.0.113.7", WHEN);
        check("sign-in: subject", en.subject().equals("[mail.example.org] Your sign-in code for the mail control panel"));
        PanelMail.Message ip6 = CodeMail.message(CodeMail.Kind.LOGIN, "en", SERVER, "482913", 10, "2001:db8:123:456::1", WHEN);
        Matcher d = Pattern.compile("\\b(\\d{6})\\b").matcher(ip6.text());
        check("sign-in from IPv6: the first six-digit number is still the code", d.find() && d.group(1).equals("482913"));
    }

    // ===================== the texts =====================

    /**
     * No bare language key (I18n.t returns the key when the text is missing): every form is composed
     * in both languages and "mail.report." / "mail.code." / "mail.common." is looked for in the
     * result.
     */
    static void texts() {
        System.out.println("\n== the texts ==");
        Pattern rawKey = Pattern.compile("\\bmail\\.(?:report|code|common)\\.[A-Za-z]");
        List<String> outputs = new ArrayList<>();
        for (String lang : List.of("en", "it")) {
            for (boolean auto : List.of(true, false))
                for (String f : List.of("daily", "weekly", "monthly"))
                    for (JSONArray todo : List.of(new JSONArray(), new JSONArray().put(item(3, "x", "y", "z")),
                            new JSONArray().put(item(0, "a", "b", "c")).put(item(2, "d", "e", "f")))) {
                        PanelMail.Message m = ReportMail.message(new ReportMail.Context(lang, SERVER, "a@example.org", auto, f, WHEN), data(todo));
                        outputs.add(m.subject()); outputs.add(m.text()); outputs.add(m.html());
                    }
            JSONObject d = data(new JSONArray());
            d.put("certificate", new JSONObject().put("name", "x").put("issuer", "y").put("expired", true).put("expiresOn", "1 November 2026"));
            d.put("vulnWithRemedy", new JSONArray()).put("vulnCountMismatch", "z").put("vulnNotUnderstood", new JSONArray().put("q"));
            d.put("missingLibraries", new JSONArray().put("p")).put("vulnDbDays", 3).put("catalogDays", -1).put("space", "strange");
            PanelMail.Message m = ReportMail.message(new ReportMail.Context(lang, "", "a@example.org", true, "weekly", WHEN), d);
            outputs.add(m.subject()); outputs.add(m.text()); outputs.add(m.html());
            for (CodeMail.Kind k : CodeMail.Kind.values()) {
                PanelMail.Message c = CodeMail.message(k, lang, "", "123456", 15, "", WHEN);
                outputs.add(c.subject()); outputs.add(c.text()); outputs.add(c.html());
            }
        }
        List<String> leaks = new ArrayList<>();
        for (String o : outputs) { Matcher x = rawKey.matcher(o); while (x.find()) leaks.add(o.substring(x.start(), Math.min(o.length(), x.start() + 50))); }
        check(outputs.size() + " composed forms: no bare language key" + (leaks.isEmpty() ? "" : ": " + leaks.subList(0, Math.min(5, leaks.size()))), leaks.isEmpty());
        check("no form still says just \"Control panel\"",
                outputs.stream().noneMatch(o -> o.matches("(?s).*(?<!Mail )Control panel.*")));
        check("no form has a brace left from a placeholder", outputs.stream().noneMatch(o -> o.matches("(?s).*\\{[A-Za-z]+\\}.*")));
    }

    /** With -Dpanelmail.dump=<folder>: the composed messages, to open in a mail program. */
    static void dump() throws Exception {
        String dir = System.getProperty("panelmail.dump");
        if (dir == null) return;
        java.nio.file.Path d = java.nio.file.Path.of(dir);
        java.nio.file.Files.createDirectories(d);
        JSONArray four = new JSONArray()
                .put(item(0, "Restart the stopped services: dovecot", "Services NOT running: dovecot", "Panel home"))
                .put(item(1, "Apply 1 security fix", "1 vulnerable package has a fix available: nginx: 1.30.5,3 -> 1.30.6,3 (protected: pkg upgrade will not apply this fix)", "Updates -> Guided update of a protected package"))
                .put(item(2, "Update 3 packages", "3 packages have a newer version in the repository.", "Updates -> Maintenance plan"));
        write(d, "report-en.eml", ReportMail.message(new ReportMail.Context("en", SERVER, "admin@example.org", true, "weekly", WHEN), data(four)));
        write(d, "report-none-it.eml", ReportMail.message(new ReportMail.Context("it", SERVER, "admin@example.org", true, "weekly", WHEN), data(new JSONArray())));
        write(d, "code-login-en.eml", CodeMail.message(CodeMail.Kind.LOGIN, "en", SERVER, "482913", 10, "203.0.113.7", WHEN));
        System.out.println("  written in " + d);
    }

    private static void write(java.nio.file.Path d, String name, PanelMail.Message m) throws Exception {
        java.nio.file.Files.writeString(d.resolve(name), PanelMail.compose(PanelMail.senderName(m.lang(), SERVER),
                "no-reply@example.org", "admin@example.org", m, "test." + name + "@example.org", WHEN));
    }

    private static String flat(String s) { return s.replaceAll("\\s+", " "); }

    private static int count(String s, String what) {
        int n = 0;
        for (int i = s.indexOf(what); i >= 0; i = s.indexOf(what, i + 1)) n++;
        return n;
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + name);
        if (ok) passed++; else failed++;
    }
}
