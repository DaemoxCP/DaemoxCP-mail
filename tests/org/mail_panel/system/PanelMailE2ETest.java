package org.mail_panel.system;

import org.json.JSONObject;
import org.mail_panel.i18n.I18n;
import org.mail_panel.security.LoginCodes;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * The panel's emails delivered for real: from Postfix's sendmail to the mailbox.
 *
 * It sends to a test mailbox on the server the report (in Italian, "on request") and the three
 * code emails (in English), with the same functions the panel uses: sendNow and the Mailer of
 * LoginCodes. Then it looks for them in the Maildir by Message-ID and checks the message AS IT
 * ARRIVED, after Postfix, the milter and Dovecot:
 *  - the displayed sender, the decoded subject, the envelope headers;
 *  - the DKIM signature, if the sender's domain has one;
 *  - le due parti, testo e HTML, decodificate.
 * It leaves a copy of every message in -Dpanelmail.copies=<folder>, to open it in a mail
 * program.
 *
 * It touches the system (it sends real mail), so it only runs with -De2e.vm=yes:
 *   java -De2e.vm=yes -Dpanelmail.to=alice@rehearsal.test \
 *        -Dpanelmail.maildir=/var/vmail/rehearsal.test/alice -Dpanelmail.copies=/var/tmp/panel-emails/copies \
 *        -cp "tests:target/freebsd-mail-panel-1.0.jar" org.mail_panel.system.PanelMailE2ETest
 * The report gathers the real data (pkg, services, space): it takes a couple of minutes.
 */
public class PanelMailE2ETest {

    private static int failed = 0, passed = 0;

    public static void main(String[] args) throws Exception {
        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("Without -De2e.vm=yes this test does nothing: it sends real mail.");
            return;
        }
        String to = System.getProperty("panelmail.to");
        Path maildir = Path.of(System.getProperty("panelmail.maildir"));
        Path copies = Path.of(System.getProperty("panelmail.copies", "/var/tmp/panel-emails/copies"));
        Files.createDirectories(copies);
        String server = PanelMail.serverName();
        System.out.println("server " + server + ", recipient " + to);

        // --- the report, in Italian, from the panel's button ---
        I18n.setCurrent("it");
        JSONObject r;
        try { r = PeriodicReport.sendNow(to, false); }
        finally { I18n.clearCurrent(); }
        System.out.println("report: " + r.optString("note", r.optString("error")));
        check("report: delivered", r.optBoolean("success") && !r.optBoolean("warning"));
        String reportId = messageId(r.optString("output"));
        Path report = waitFor(maildir, reportId);
        check("report: arrived in the mailbox", report != null);
        if (report != null) {
            String raw = Files.readString(report, StandardCharsets.ISO_8859_1);
            Files.writeString(copies.resolve("report-it.eml"), raw, StandardCharsets.ISO_8859_1);
            arrived("report", raw, server, "it", r.optString("subject"));
        }

        // --- the three codes, in English, with the panel's Mailer ---
        for (CodeMail.Kind kind : CodeMail.Kind.values()) {
            PanelMail.Message m = CodeMail.message(kind, "en", server, "482913", 10, "192.168.1.1", ZonedDateTime.now());
            long before = System.currentTimeMillis();
            boolean sent;
            try { LoginCodes.mailer.send(to, m); sent = true; }
            catch (Exception e) { sent = false; System.out.println("  " + e.getMessage()); }
            check(kind + ": Postfix l'ha accettato", sent);
            Path got = waitForSubject(maildir, m.subject(), before);
            check(kind + ": arrived in the mailbox", got != null);
            if (got == null) continue;
            String raw = Files.readString(got, StandardCharsets.ISO_8859_1);
            Files.writeString(copies.resolve("code-" + kind.name().toLowerCase() + "-en.eml"), raw, StandardCharsets.ISO_8859_1);
            arrived(kind.toString(), raw, server, "en", m.subject());
            check(kind + ": the code in the text that arrived", PanelMailTest.qpDecode(part(raw, "text/plain")).contains("482913"));
        }

        System.out.println("\n" + passed + " passed, " + failed + " failed");
        if (failed > 0) System.exit(1);
    }

    /** The message as it arrived: envelope, signature, parts. */
    static void arrived(String name, String raw, String server, String lang, String subject) {
        String head = raw.substring(0, Math.max(0, raw.indexOf("\r\n\r\n") >= 0 ? raw.indexOf("\r\n\r\n") : raw.indexOf("\n\n")))
                .replace("\r\n", "\n");
        String unfolded = head.replace("\n ", " ").replace("\n\t", "\t");
        String from = header(unfolded, "From");
        System.out.println("  " + name + " From: " + from);
        System.out.println("  " + name + " Subject: " + decode(header(unfolded, "Subject")));
        String expectedName = PanelMail.senderName(lang, server);
        check(name + ": the displayed sender is \"" + expectedName + "\"",
                from != null && (from.startsWith("\"" + expectedName + "\"") || decode(from).startsWith(expectedName)));
        check(name + ": the subject that arrived is the one composed", subject.equals(decode(header(unfolded, "Subject"))));
        check(name + ": Date, Message-ID, Content-Language, Auto-Submitted",
                header(unfolded, "Date") != null && header(unfolded, "Message-ID") != null
                && lang.equals(header(unfolded, "Content-Language")) && "auto-generated".equals(header(unfolded, "Auto-Submitted")));
        String dkim = header(unfolded, "DKIM-Signature");
        System.out.println("  " + name + " DKIM-Signature: " + (dkim == null ? "(none)" : dkim.replaceAll("b=[^;]*", "b=...").substring(0, Math.min(90, dkim.length()))));
        String text = PanelMailTest.qpDecode(part(raw, "text/plain"));
        String html = PanelMailTest.qpDecode(part(raw, "text/html"));
        check(name + ": the text part is there and names the server", text.contains(server));
        check(name + ": the HTML part is there, with the language", html.contains("<html lang=\"" + lang + "\">") && html.contains(PanelMail.esc(server)));
    }

    static String header(String unfolded, String name) {
        for (String l : unfolded.split("\n"))
            if (l.regionMatches(true, 0, name + ":", 0, name.length() + 1)) return l.substring(name.length() + 1).trim();
        return null;
    }

    /** The RFC 2047 (B) encoded words of a header, joined; the rest as it is. */
    static String decode(String h) {
        if (h == null) return null;
        Matcher m = Pattern.compile("=\\?UTF-8\\?B\\?([A-Za-z0-9+/=]*)\\?=(\\s+(?==\\?))?").matcher(h);
        StringBuilder out = new StringBuilder();
        while (m.find())
            m.appendReplacement(out, Matcher.quoteReplacement(new String(java.util.Base64.getDecoder().decode(m.group(1)), StandardCharsets.UTF_8)));
        m.appendTail(out);
        return out.toString();
    }

    /** The body (still in quoted-printable) of the part with that type. */
    static String part(String raw, String type) {
        String r = raw.replace("\r\n", "\n");
        int i = r.indexOf("Content-Type: " + type);
        if (i < 0) return "";
        int start = r.indexOf("\n\n", i) + 2;
        int end = r.indexOf("\n--", start);
        return r.substring(start, end < 0 ? r.length() : end).replace("\n", "\r\n");
    }

    static String messageId(String output) {
        Matcher m = Pattern.compile("Message-ID: <([^>]+)>").matcher(output);
        return m.find() ? m.group(1) : "";
    }

    static Path waitFor(Path maildir, String messageId) throws Exception {
        for (int i = 0; i < 30 && !messageId.isEmpty(); i++) {
            for (Path p : files(maildir))
                if (Files.readString(p, StandardCharsets.ISO_8859_1).contains("<" + messageId + ">")) return p;
            Thread.sleep(1000);
        }
        return null;
    }

    static Path waitForSubject(Path maildir, String subject, long after) throws Exception {
        for (int i = 0; i < 30; i++) {
            for (Path p : files(maildir)) {
                if (Files.getLastModifiedTime(p).toMillis() < after - 2000) continue;
                String raw = Files.readString(p, StandardCharsets.ISO_8859_1);
                String head = raw.substring(0, Math.max(0, raw.indexOf("\n\n") >= 0 ? raw.indexOf("\n\n") : raw.indexOf("\r\n\r\n"))).replace("\r\n", "\n");
                if (subject.equals(decode(header(head.replace("\n ", " "), "Subject")))) return p;
            }
            Thread.sleep(1000);
        }
        return null;
    }

    static List<Path> files(Path maildir) throws Exception {
        List<Path> l = new ArrayList<>();
        for (String sub : List.of("new", "cur"))
            if (Files.isDirectory(maildir.resolve(sub)))
                try (Stream<Path> s = Files.list(maildir.resolve(sub))) { s.forEach(l::add); }
        return l;
    }

    private static void check(String name, boolean ok) {
        System.out.println((ok ? "  ok   " : "  FAIL ") + name);
        if (ok) passed++; else failed++;
    }
}
