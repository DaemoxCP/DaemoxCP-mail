package org.daemoxcp.mail.security;

import org.daemoxcp.mail.webserver.SSLMailServer;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The panel's fail2ban filter, measured with fail2ban-regex and not deduced.
 *
 * The log line and the filter are two halves of the same thing (r26): SSLMailServer.auditLine
 * writes the line, Fail2banAutoSetup.filterContent writes the filter, and here both are taken FROM
 * THE CODE. Changing only one breaks nothing visibly — the panel starts, the Firewall page says "jail
 * active" — simply nobody gets blocked any more, which cannot be told from "nobody is trying".
 *
 * What must be tested here, and that compiling would not tell:
 *  - fail2ban recognises the DATE of every line. Without a date it does not stop blocking: it uses
 *    the time it read the line, so when the service restarts an old log is read again as if it had
 *    just happened;
 *  - the failregex takes the line in the TWO forms fail2ban can give it: with the date (when the
 *    datepattern does not match) and without (when it matches, because then it removes it). The
 *    old "^\S+ \[" held one form only and stood up by chance, on the nanosecond decimals;
 *  - a SUCCESSFUL sign-in line makes nobody be blocked.
 *
 * It runs on the VM, where fail2ban is:
 *   java -cp "tests:&lt;dir&gt;/daemoxcp-mail-1.0.jar" org.daemoxcp.mail.security.Fail2banFilterTest
 */
public class Fail2banFilterTest {

    static int failed = 0;
    static final PrintStream OUT = System.out;

    static void check(String what, boolean ok) {
        OUT.println((ok ? "  OK   " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    /** The old filter, word for word: it is used to measure that the new one takes more. */
    static final String OLD_FILTER = "[Definition]\n\n"
            + "failregex = ^\\S+ \\[(?:LOGIN_FAILURE|LOGIN_2FA_FAILURE|LOGIN_INVALID_INPUT"
            + "|LOGIN_BLOCKED|CSRF_FAILURE)\\] ip=<HOST>\n\n"
            + "ignoreregex = ^\\S+ \\[(?:LOGIN_SUCCESS)\\]\n\n"
            + "datepattern = ^%%Y-%%m-%%dT%%H:%%M:%%S\n";

    public static void main(String[] args) throws Exception {
        Path home = Files.createTempDirectory("fail2ban-filter");

        OUT.println("\n== The line the panel writes ==");
        String line = SSLMailServer.auditLine("LOGIN_FAILURE", "203.0.113.9", "admin", "passkey refused");
        OUT.println("  " + line.trim());
        check("it ends with the Z of UTC, not with the local time",
                line.matches("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z \\[.*\n"));
        check("it has no nanosecond decimals, which before held the filter up by chance",
                !line.substring(0, line.indexOf(' ')).contains("."));
        // r13: the moment is UTC, not the server's time. It is measured against the UTC clock, not
        // against this machine's time zone.
        String nowUtc = java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString();
        check("and it really is UTC (" + line.substring(0, 20) + " against " + nowUtc + ")",
                Math.abs(java.time.Instant.parse(line.substring(0, line.indexOf(' ')))
                        .getEpochSecond() - java.time.Instant.now().getEpochSecond()) <= 2);
        check("the address and the user are where the filter looks for them",
                line.contains("[LOGIN_FAILURE] ip=203.0.113.9 user=admin"));

        OUT.println("\n== fail2ban reads that log with the panel's filter ==");
        if (!Files.isExecutable(Path.of("/usr/local/bin/fail2ban-regex"))) {
            check("fail2ban-regex is there (this test must be run on the VM, not on the Mac)", false);
            OUT.println("\n" + failed + " CHECKS FAILED");
            System.exit(1);
        }

        // The log: real lines, taken from the code. Ten failures and five successful sign-ins, plus
        // the forms that used to get lost.
        StringBuilder log = new StringBuilder();
        for (int i = 0; i < 10; i++)
            log.append(SSLMailServer.auditLine("LOGIN_FAILURE", "203.0.113." + (10 + i), "admin", "code refused"));
        for (int i = 0; i < 5; i++)
            log.append(SSLMailServer.auditLine("LOGIN_SUCCESS", "203.0.113." + (10 + i), "admin", "ok"));
        log.append(SSLMailServer.auditLine("CSRF_FAILURE", "198.51.100.7", "", "bad token"));
        log.append(SSLMailServer.auditLine("PASSKEY_REGISTER_FAILED", "198.51.100.8", "admin", "refused"));
        Path logFile = home.resolve("daemoxcp-mail-auth.log");
        Files.writeString(logFile, log, StandardCharsets.UTF_8);
        int lines = log.toString().split("\n").length;

        Path filter = home.resolve("daemoxcp-mail-auth.conf");
        Files.writeString(filter, Fail2banAutoSetup.filterContent(), StandardCharsets.UTF_8);
        Result now = fail2banRegex(logFile, filter);
        OUT.println("  " + now);
        check("fail2ban recognises the date of ALL the " + lines + " lines", now.dates == lines);
        check("it takes the 12 failures and nothing else", now.matched == 12);
        check("the 5 successful sign-ins make nobody be blocked", now.missed == 5);

        OUT.println("\n== With the old filter, on the same lines ==");
        Path old = home.resolve("old.conf");
        Files.writeString(old, OLD_FILTER, StandardCharsets.UTF_8);
        Result before = fail2banRegex(logFile, old);
        OUT.println("  " + before);
        // Here is the defect: the Z does not fit in the old datepattern, so fail2ban recognises NO
        // date and uses the time it reads. And with no date removed, the old failregex takes the
        // lines all the same: that is why nothing showed.
        check("the old datepattern does not recognise a single date (" + before.dates + " of "
                + lines + "): it is the defect, not a matter of taste", before.dates == 0);
        check("the new one recognises " + now.dates + " of " + lines, now.dates > before.dates);

        OUT.println("\n== And with the date removed, which is the form fail2ban really passes ==");
        // When the datepattern matches, fail2ban removes the date BEFORE searching. It is measured
        // by giving the filter a log already without the date: the old failregex takes nothing any
        // more, because a space is left where it wants an \S+.
        StringBuilder stripped = new StringBuilder();
        for (String l : log.toString().split("\n"))
            stripped.append(l.substring(l.indexOf(' '))).append("\n");    // the date gone, the space stays
        Path strippedFile = home.resolve("stripped.log");
        Files.writeString(strippedFile, stripped, StandardCharsets.UTF_8);
        Result oldStripped = fail2banRegex(strippedFile, old);
        Result newStripped = fail2banRegex(strippedFile, filter);
        OUT.println("  old: " + oldStripped);
        OUT.println("  new: " + newStripped);
        check("the old failregex takes nothing any more without the date (" + oldStripped.matched + ")",
                oldStripped.matched == 0);
        check("the new one takes all 12 failures even so (" + newStripped.matched + ")",
                newStripped.matched == 12);

        OUT.println("\n== The anchor that decides whether a block really stops a packet ==");
        check("it recognises anchor \"f2b/*\"",
                Fail2banAutoSetup.hasF2bAnchor("set skip on lo\nanchor \"f2b/*\"\npass\n"));
        check("it recognises anchor f2b/* without quotes",
                Fail2banAutoSetup.hasF2bAnchor("anchor f2b/*\n"));
        check("a COMMENTED line does not count",
                !Fail2banAutoSetup.hasF2bAnchor("# anchor \"f2b/*\"\npass\n"));
        check("and a pf.conf that does not name it does not have it",
                !Fail2banAutoSetup.hasF2bAnchor("set skip on lo\ntable <permaban> persist\npass\n"));

        OUT.println("\n== An old panel filter is rewritten, a hand-made one is not ==");
        check("today's one is left alone",
                !Fail2banAutoSetup.shouldRewriteFilter(Fail2banAutoSetup.filterContent()));
        check("an old one written by the panel is rewritten",
                Fail2banAutoSetup.shouldRewriteFilter(Fail2banAutoSetup.MARKER + "\n" + OLD_FILTER));
        for (String signature : org.daemoxcp.mail.system.LegacyNames.oldNamesOf(Fail2banAutoSetup.MARKER_SECTION, Fail2banAutoSetup.MARKER))
            check("one with the old signature is rewritten even if the rest is the same as today",
                    Fail2banAutoSetup.shouldRewriteFilter(Fail2banAutoSetup.filterContent().replace(Fail2banAutoSetup.MARKER, signature)));
        check("the old signature is in the data file",
                !org.daemoxcp.mail.system.LegacyNames.oldNamesOf(Fail2banAutoSetup.MARKER_SECTION, Fail2banAutoSetup.MARKER).isEmpty());
        check("one edited by hand is not touched",
                !Fail2banAutoSetup.shouldRewriteFilter("# my filter\n" + OLD_FILTER));
        check("if it is not there it is written", Fail2banAutoSetup.shouldRewriteFilter(null));

        OUT.println("\n" + (failed == 0 ? "ALL GREEN" : failed + " CHECKS FAILED"));
        System.exit(failed == 0 ? 0 : 1);
    }

    /** What matters in fail2ban-regex's output. */
    record Result(int matched, int missed, int dates) {
        @Override public String toString() {
            return matched + " lines taken, " + missed + " not, " + dates + " dates recognised";
        }
    }

    static final Pattern LINES = Pattern.compile("Lines: (\\d+) lines, (\\d+) ignored, (\\d+) matched, (\\d+) missed");
    // "|  [10] ^Year-Month-DayT24hour:Minute:SecondZone offset". The pattern starts with '^', not
    // with a letter: the first version looked for \w+ and counted zero dates whatever had really
    // happened.
    static final Pattern DATE_HIT = Pattern.compile("\\|\\s*\\[(\\d+)\\]\\s+\\S+.*");

    static Result fail2banRegex(Path log, Path filter) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("/usr/local/bin/fail2ban-regex",
                log.toAbsolutePath().toString(), filter.toAbsolutePath().toString());
        pb.redirectErrorStream(true);
        Process p = pb.start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        p.waitFor();
        Matcher m = LINES.matcher(out);
        if (!m.find()) {
            OUT.println(out);
            throw new IllegalStateException("fail2ban-regex did not print the summary");
        }
        int matched = Integer.parseInt(m.group(3)), missed = Integer.parseInt(m.group(4));
        // The dates: the "Date template hits" section lists [N] per pattern. If the section is
        // empty, no date was recognised.
        int dates = 0;
        boolean inDates = false;
        for (String l : out.split("\n")) {
            if (l.startsWith("Date template hits")) { inDates = true; continue; }
            if (inDates) {
                if (l.startsWith("`-")) break;
                Matcher d = DATE_HIT.matcher(l);
                if (d.matches()) dates += Integer.parseInt(d.group(1));
            }
        }
        return new Result(matched, missed, dates);
    }
}
