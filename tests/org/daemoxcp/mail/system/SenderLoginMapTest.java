package org.daemoxcp.mail.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import org.daemoxcp.mail.util.Shell;

/**
 * A client that signs in sends only from its own addresses (SenderLoginMap). Measured on the VM on 20/11/2026: Postfix
 * had no smtpd_sender_login_maps, so a mailbox signed in could send as another mailbox of the server (signed with the
 * domain's DKIM key) or as anybody else.
 *  1. the decision: the panel's settings (or ours already) are applied, ours with the file current is nothing,
 *     anything written by hand is left alone. On 20/11/2026, after build 816, the real server logged «restriction
 *     `reject_authenticated_sender_login_mismatch' ignored: no SASL support» on port 25: the check was in main.cf, and
 *     port 25 has no AUTH any more. Now it is on the submission ports only (587 and 465, -o in master.cf), and a server
 *     with the check in main.cf (builds 795-818) gets it moved;
 *  2. the table: a mailbox owns its address even when it does not receive, an alias belongs to its destination, both
 *     lookups use the key; the restrictions: main.cf the installer's without the check, the submission ports the same
 *     with reject_authenticated_sender_login_mismatch first;
 *  3. the map file takes the aliases map's connection and only changes the query;
 *  4. both installers write the map, main.cf without the check and master.cf with it on 587 and 465, MailDbUsers keeps
 *     the file with Postfix's MySQL user and runs its query, and the panel's start runs the repair after MailDbUsers
 *     and MailboxAddressMap;
 *  5. with -De2e.vm=yes, as root on the VM: Postfix has the settings above, postmap answers a mailbox with itself, and
 *     with XCLIENT LOGIN on port 587 and on port 465 (allowed from 127.0.0.1 only for the test, then removed) a client
 *     signed in as a mailbox gets its own address accepted, another address of the same domain and an outside address
 *     refused with 553; without a login, mail from outside naming the same address is still accepted on port 25, and
 *     Postfix logs no «ignored: no SASL support» for it. Nothing is delivered: RSET after RCPT.
 *   java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.SenderLoginMapTest
 */
public class SenderLoginMapTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] a) throws Exception {
        String dir = "/usr/local/etc/postfix", own = "mysql:" + dir + "/" + SenderLoginMap.FILE;
        String panel = "permit_mynetworks, permit_sasl_authenticated, reject_non_fqdn_sender, reject_unknown_sender_domain";
        String wanted = org.daemoxcp.mail.scripts.PostfixMaps.SUBMISSION_SENDER_RESTRICTIONS;
        String withCheck = "reject_authenticated_sender_login_mismatch, " + panel;

        System.out.println("== 1. The decision");
        check("Postfix not installed: nothing", SenderLoginMap.decide(false, dir, true, true, "", panel, "", "").action() == SenderLoginMap.Action.NOTHING);
        check("not the panel's Postfix (no aliases map): nothing", SenderLoginMap.decide(true, dir, false, true, "", panel, "", "").action() == SenderLoginMap.Action.NOTHING);
        check("the installer's settings of before the check: apply", SenderLoginMap.decide(true, dir, true, false, "", panel, "", "").action() == SenderLoginMap.Action.APPLY);
        SenderLoginMap.Decision moved = SenderLoginMap.decide(true, dir, true, true, own, withCheck, "", "");
        check("the check in main.cf (builds 795-818, port 25 too): apply, moved to 587 and 465 (" + moved.reason() + ")",
                moved.action() == SenderLoginMap.Action.APPLY && moved.reason().contains("port 25"));
        check("already in place, file current: nothing", SenderLoginMap.decide(true, dir, true, true, own, panel, wanted, wanted).action() == SenderLoginMap.Action.NOTHING);
        check("in place but the file says something else: apply again", SenderLoginMap.decide(true, dir, true, false, own, panel, wanted, wanted).action() == SenderLoginMap.Action.APPLY);
        check("written one line per item, as main.cf has it: the same", SenderLoginMap.decide(true, dir, true, true, own,
                panel.replace(", ", ",\n    "), wanted, wanted).action() == SenderLoginMap.Action.NOTHING);
        check("on 587 only (465 not yet): apply", SenderLoginMap.decide(true, dir, true, true, own, panel, wanted, "").action() == SenderLoginMap.Action.APPLY);
        check("a login map of someone else's: left alone", SenderLoginMap.decide(true, dir, true, false, "hash:/etc/x", panel, "", "").action() == SenderLoginMap.Action.LEFT_ALONE);
        check("restrictions written by hand: left alone", SenderLoginMap.decide(true, dir, true, false, "", "permit_mynetworks, reject", "", "").action() == SenderLoginMap.Action.LEFT_ALONE);
        check("restrictions on 587 written by hand: left alone", SenderLoginMap.decide(true, dir, true, true, own, panel, "permit_sasl_authenticated,reject", "").action() == SenderLoginMap.Action.LEFT_ALONE);
        // Measured on the VM on 21/11/2026: run by the panel with its full path, postconf names itself with it, and a
        // first version that knew only «postconf: » took the warning for a value written by hand (left alone).
        check("postconf -Ph of a setting master.cf does not have: empty, from a shell", SenderLoginMap.masterValue(
                "postconf: warning: unmatched request: \"submission/inet/smtpd_sender_restrictions\"").isEmpty());
        check("  and run with its full path, as the panel runs it", SenderLoginMap.masterValue(
                "/usr/local/sbin/postconf: warning: unmatched request: \"submission/inet/smtpd_sender_restrictions\"").isEmpty());
        check("  a value set in master.cf stays", SenderLoginMap.masterValue(wanted).equals(wanted));
        check("the real repair reads it this way", SenderLoginMap.masterValue(
                "/usr/local/sbin/postconf: warning: unmatched request: \"smtps/inet/smtpd_sender_restrictions\"").isEmpty()
                && SenderLoginMap.decide(true, dir, true, true, own, withCheck,
                SenderLoginMap.masterValue("/usr/local/sbin/postconf: warning: unmatched request: \"submission/inet/smtpd_sender_restrictions\""),
                SenderLoginMap.masterValue("/usr/local/sbin/postconf: warning: unmatched request: \"smtps/inet/smtpd_sender_restrictions\"")).action()
                == SenderLoginMap.Action.APPLY);

        System.out.println("\n== 2. The table and the restrictions");
        String q = SenderLoginMap.QUERY;
        check("a mailbox owns its address, also when it does not receive", q.contains("SELECT email FROM mailboxes WHERE email='%s' AND active=1")
                && !q.contains("receive_enabled"));
        check("an alias belongs to its destination", q.contains("SELECT destination FROM aliases WHERE source='%s' AND active=1"));
        check("both lookups use the key", q.split("%s", -1).length == 3);
        check("on the submission ports: the check first, then main.cf's restrictions", SenderLoginMap.WANTED_SENDER.get(0).equals("reject_authenticated_sender_login_mismatch")
                && SenderLoginMap.WANTED_SENDER.subList(1, SenderLoginMap.WANTED_SENDER.size()).equals(SenderLoginMap.PANEL_SENDER));
        check("only for clients that sign in (not reject_sender_login_mismatch)", !wanted.contains("reject_sender_login_mismatch"));
        check("main.cf (port 25 too) without the check", MailboxAddressMap.tables(org.daemoxcp.mail.scripts.PostfixMaps.SENDER_RESTRICTIONS).equals(SenderLoginMap.PANEL_SENDER));
        check("no spaces in the -o value", !wanted.contains(" "));

        System.out.println("\n== 3. The map file");
        String aliases = "user = daemoxcp_mail_postfix\npassword = secret\nhosts = 127.0.0.1\ndbname = daemoxcp_mail\n"
                + "query = SELECT destination FROM aliases WHERE source='%s' AND active=1\n";
        String map = MailboxAddressMap.mapText(aliases, q);
        check("the aliases map's connection, the sender query", map != null && map.startsWith("user = daemoxcp_mail_postfix\npassword = secret\nhosts = 127.0.0.1\ndbname = daemoxcp_mail\n")
                && map.contains("\nquery = " + q + "\n") && map.split("query =", -1).length == 2);
        check("the catch-all map still gets its own query", MailboxAddressMap.mapText(aliases).contains("query = " + MailboxAddressMap.QUERY + "\n"));

        System.out.println("\n== 4. Where it is written");
        String installer = new org.daemoxcp.mail.scripts.FullMailServerScript().getScriptContent();
        check("main.cf: the login map", installer.contains("\nsmtpd_sender_login_maps = " + own + "\n"));
        check("main.cf: smtpd_sender_restrictions without the check", installer.contains("\nsmtpd_sender_restrictions =\n    permit_mynetworks,\n    permit_sasl_authenticated,\n")
                && installer.split("reject_authenticated_sender_login_mismatch", -1).length == 3);
        String line = "\n  -o smtpd_sender_restrictions=" + wanted + "\n";
        int sub = installer.indexOf("\nsubmission inet"), smtps = installer.indexOf("\nsmtps     inet"), pickup = installer.indexOf("\npickup ");
        check("master.cf: the check on 587 and on 465", sub > 0 && smtps > sub && pickup > smtps
                && installer.indexOf(line, sub) > sub && installer.indexOf(line, sub) < smtps
                && installer.indexOf(line, smtps) > smtps && installer.indexOf(line, smtps) < pickup);
        String stack = new org.daemoxcp.mail.scripts.FullMailStackScript().getScriptContent();
        // In that installer the line comes out as «name =value»: a text block drops the space before the closing quotes.
        check("the other installer: the same in main.cf and on 587 and 465", java.util.regex.Pattern.compile(
                        "\nsmtpd_sender_restrictions = ?" + java.util.regex.Pattern.quote(panel) + "\n").matcher(stack).find()
                && stack.split(java.util.regex.Pattern.quote(line), -1).length == 3);
        int file = installer.indexOf("cat > /usr/local/etc/postfix/" + SenderLoginMap.FILE + " << MYSQL_SENDER_LOGIN\n");
        check("the map, with the same connection lines as the others", file > 0
                && installer.startsWith("user = $MYSQL_USER\npassword = $MYSQL_PASSWORD\nhosts = 127.0.0.1\ndbname = $MYSQL_DATABASE\nquery = " + q + "\nMYSQL_SENDER_LOGIN\n",
                installer.indexOf('\n', file) + 1));
        check("MailDbUsers keeps it with Postfix's MySQL user", MailDbUsers.POSTFIX_MAPS.contains(SenderLoginMap.FILE));
        String catalog = org.daemoxcp.mail.database.SqlCatalog.MAILDB_POSTFIX_SENDER_LOOKUP;
        check("  and runs the same query", catalog.replace(" = ?", "='%s'").replace("active = 1", "active=1").equals(q));
        String mdu = Files.readString(Path.of("src/main/java/org/daemoxcp/mail/system/MailDbUsers.java"));
        check("  binding every ?", mdu.contains("ps.setString(i, PROBE)") && mdu.contains("SqlCatalog.MAILDB_POSTFIX_SENDER_LOOKUP"));
        String server = Files.readString(Path.of("src/main/java/org/daemoxcp/mail/webserver/SSLMailServer.java"));
        int users = server.indexOf("MailDbUsers.ensureAtBoot();"), addresses = server.indexOf("MailboxAddressMap.ensureAtBoot();"),
                senders = server.indexOf("SenderLoginMap.ensureAtBoot();");
        check("the panel's start runs the repair after MailDbUsers and MailboxAddressMap", users > 0 && addresses > users && senders > addresses);

        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("\n  (part 5 skipped: it talks to Postfix on the TEST VM, turned on with -De2e.vm=yes)");
        } else {
            live();
        }

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }

    // ===================== 5. On the VM =====================

    static void live() throws Exception {
        System.out.println("\n== 5. Live, on the VM");
        String maps = sh("postconf -h smtpd_sender_login_maps").trim();
        check("Postfix has the login map (" + maps + ")", maps.equals("mysql:/usr/local/etc/postfix/" + SenderLoginMap.FILE));
        check("main.cf without the check", MailboxAddressMap.tables(sh("postconf -h smtpd_sender_restrictions")).equals(SenderLoginMap.PANEL_SENDER));
        for (String service : SenderLoginMap.SUBMISSION_SERVICES)
            check(service + ": the check first", MailboxAddressMap.tables(SenderLoginMap.masterSetting(service)).equals(SenderLoginMap.WANTED_SENDER));
        String user = null;
        for (String u : sh("doveadm user '*'").trim().split("\\s+")) if (u.contains("@")) { user = u; break; }
        if (user == null) { check("a mailbox to try with", false); return; }
        String domain = user.substring(user.indexOf('@') + 1);
        check("postmap: " + user + " owns its address", List.of(sh("postmap -q " + user + " " + maps).trim().split("[,\\s]+")).contains(user));
        check("postmap: an address nobody has, no owner", sh("postmap -q nobody-" + System.nanoTime() + "@" + domain + " " + maps).trim().isEmpty());

        String before = sh("postconf -h smtpd_authorized_xclient_hosts").trim();
        if (!before.isEmpty()) { check("smtpd_authorized_xclient_hosts empty before the test (it is '" + before + "')", false); return; }
        sh("postconf -e smtpd_authorized_xclient_hosts=127.0.0.1 && postfix reload");
        try {
            Thread.sleep(1500);
            String other = "not-" + user.substring(0, user.indexOf('@')) + "-" + System.nanoTime() + "@" + domain;
            for (int port : new int[]{587, 465}) {
                check("port " + port + ", signed in as " + user + ", from its own address: accepted", rcpt(user, user, user, port).startsWith("250"));
                String r1 = rcpt(user, other, user, port);
                check("  from another address of " + domain + ": refused (" + r1 + ")", r1.startsWith("553") && r1.contains("not owned by user"));
                String r2 = rcpt(user, "someone@example.org", user, port);
                check("  from an outside address: refused (" + r2 + ")", r2.startsWith("553") && r2.contains("not owned by user"));
            }
            long warnings = noSaslWarnings();
            String r3 = rcpt(null, other, user, 25);
            check("not signed in (mail from outside on port 25), the same sender: not refused for it (" + r3 + ")", r3.startsWith("250") && !r3.contains("not owned"));
            Thread.sleep(1500);
            check("  and no «ignored: no SASL support» in the mail log for it", noSaslWarnings() == warnings);
        } finally {
            sh("postconf -X smtpd_authorized_xclient_hosts && postfix reload");
            check("XCLIENT taken away again", sh("postconf -n").lines().noneMatch(l -> l.startsWith("smtpd_authorized_xclient_hosts")));
        }
    }

    /**
     * MAIL FROM and RCPT TO: the answer to RCPT. Signed in (login not null): on port 587 after STARTTLS or on port 465
     * (TLS from the start), with XCLIENT LOGIN, where SASL is on (on port 25 it is off, and Postfix does not take XCLIENT
     * LOGIN as signed in: measured); not signed in: on port 25, as the other mail servers.
     */
    static String rcpt(String login, String from, String to, int port) {
        String xclient = login == null ? "" : "printf 'XCLIENT LOGIN=" + login + "\\r\\n'; sleep 1; printf 'EHLO e2e.test\\r\\n'; sleep 1; ";
        String client = port == 25 ? "timeout -f 30 nc 127.0.0.1 25"
                : port == 465 ? "timeout -f 30 openssl s_client -crlf -quiet -connect 127.0.0.1:465 2>/dev/null"
                : "timeout -f 30 openssl s_client -starttls smtp -crlf -quiet -connect 127.0.0.1:587 2>/dev/null";
        String out = sh("{ sleep 2; printf 'EHLO e2e.test\\r\\n'; sleep 1; " + xclient + "printf 'MAIL FROM:<" + from + ">\\r\\n'; sleep 1; "
                + "printf 'RCPT TO:<" + to + ">\\r\\n'; sleep 1; printf 'RSET\\r\\n'; sleep 1; printf 'QUIT\\r\\n'; sleep 1; } | " + client);
        String last = "";
        boolean afterMail = false;
        for (String line : out.split("\r?\n")) {
            if (line.startsWith("250 2.1.0")) { afterMail = true; continue; }
            if (afterMail && line.length() > 3 && Character.isDigit(line.charAt(0))) return line.trim();
            if (line.length() > 3 && (line.charAt(0) == '4' || line.charAt(0) == '5')) last = line.trim();
        }
        return last;
    }

    /** How many «ignored: no SASL support» lines the mail log has now. */
    static long noSaslWarnings() {
        return sh("grep -c 'ignored: no SASL support' /var/log/maillog").lines().findFirst().map(String::trim)
                .filter(x -> x.matches("\\d+")).map(Long::parseLong).orElse(0L);
    }

    static String sh(String command) {
        return Shell.run(Duration.ofSeconds(60), "sh", "-c", command).output();
    }
}
