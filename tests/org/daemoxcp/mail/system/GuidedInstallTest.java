package org.daemoxcp.mail.system;

import org.json.JSONObject;

import java.io.IOException;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * The guided installation's checks that need no system (reperti 242, 244, 246):
 *  1. the time zone of menu option 1: an IANA name known to Java and present as a plain file in zoneinfo; never a
 *     path, a link, ".." or a made-up name; the current one read from /var/db/zoneinfo, UTC when unknown;
 *  2. the three names before installing from the menu: the webmail name no longer the factory example, every name a
 *     full domain name, mail and web on different names (the mail name stays out of Cloudflare's proxy); a panel
 *     without a name of its own is a warning, not a stop;
 *  3. outbound port 25: open as soon as one big mail server answers, blocked when the names resolve and nobody
 *     answers, unknown when no name resolves.
 *   java -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.GuidedInstallTest
 */
public class GuidedInstallTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("== 1. The time zone");
        Path zi = Files.createTempDirectory("zoneinfo-test");
        try {
            Files.createDirectories(zi.resolve("Europe"));
            Files.writeString(zi.resolve("Europe/Rome"), "TZif");
            Files.writeString(zi.resolve("UTC"), "TZif");
            Files.createDirectories(zi.resolve("America/Argentina"));
            Files.writeString(zi.resolve("America/Argentina/Buenos_Aires"), "TZif");
            Files.createSymbolicLink(zi.resolve("Europe/Linked"), zi.resolve("Europe/Rome"));
            check("Europe/Rome, UTC and a three-level name are accepted",
                    SystemTimeZone.problem("Europe/Rome", zi) == null && SystemTimeZone.problem("UTC", zi) == null
                    && SystemTimeZone.problem("America/Argentina/Buenos_Aires", zi) == null);
            for (String bad : new String[]{"", " ", "../etc/passwd", "/etc/localtime", "Europe/Rome; rm -rf /",
                    "Europe/../UTC", "Europe/Nowhere", "Europe/Linked", "Europe/London"})
                check("refused: \"" + bad + "\"", SystemTimeZone.problem(bad, zi) != null);
            Path cur = zi.resolve("current");
            Files.writeString(cur, "Europe/Rome\n");
            check("the current one read from the file", SystemTimeZone.current(cur).equals("Europe/Rome"));
            Files.writeString(cur, "../../evil\n");
            check("a strange current one becomes UTC", SystemTimeZone.current(cur).equals("UTC"));
            check("no file: UTC", SystemTimeZone.current(zi.resolve("missing")).equals("UTC"));
        } finally {
            try (var w = Files.walk(zi)) { w.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete()); }
        }

        System.out.println("\n== 2. The three names before installing");
        InstallNames.Result r = InstallNames.check("mail.example.org", "webmail.example.org", "panel.example.net");
        check("three distinct full names: go, no warning", r.problems().isEmpty() && r.warnings().isEmpty());
        r = InstallNames.check("mail.example.org", InstallNames.DEFAULT_WEBMAIL, "panel.example.net");
        check("the factory webmail name: stop, pointing to option 3", r.problems().size() == 1
                && r.problems().get(0).contains("option 3"));
        r = InstallNames.check("mail.example.org", "MAIL.example.org", "panel.example.net");
        check("webmail equal to the mail name (any case): stop", r.problems().size() == 1
                && r.problems().get(0).contains("differ"));
        r = InstallNames.check("mail.example.org", "webmail.example.org", "mail.example.org");
        check("panel equal to the mail name: stop", r.problems().size() == 1);
        r = InstallNames.check("mail", "webmail.example.org", "panel.example.net");
        check("a mail name without a dot: stop", r.problems().size() == 1);
        r = InstallNames.check("mail.example.org", "webmail.example.org", "0.0.0.0");
        check("a panel without a name: a warning, not a stop", r.problems().isEmpty() && r.warnings().size() == 1);
        r = InstallNames.check("mail.example.org", "webmail.example.org", "127.0.0.1");
        check("a panel on an IP: a warning", r.problems().isEmpty() && r.warnings().size() == 1);

        System.out.println("\n== 3. Outbound port 25");
        OutboundSmtp.Dialer before = OutboundSmtp.dialer;
        try {
            OutboundSmtp.dialer = host -> "220 mx.example ESMTP";
            JSONObject o = OutboundSmtp.check();
            check("the first answers: open, one host tried", "open".equals(o.getString("state"))
                    && o.getJSONArray("tried").length() == 1);
            OutboundSmtp.dialer = host -> { throw new java.net.SocketTimeoutException("connect timed out"); };
            o = OutboundSmtp.check();
            check("nobody answers, names resolve: blocked, all three tried", "blocked".equals(o.getString("state"))
                    && o.getJSONArray("tried").length() == 3);
            OutboundSmtp.dialer = host -> { throw new UnknownHostException(host); };
            check("no name resolves: unknown", "unknown".equals(OutboundSmtp.check().getString("state")));
            OutboundSmtp.dialer = host -> {
                if (host.contains("google")) throw new IOException("refused");
                return "554 no service";
            };
            o = OutboundSmtp.check();
            check("the second answers even with a refusal: open, on the second", "open".equals(o.getString("state"))
                    && o.getString("openOn").equals(OutboundSmtp.HOSTS.get(1)));
        } finally {
            OutboundSmtp.dialer = before;
        }

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }
}
