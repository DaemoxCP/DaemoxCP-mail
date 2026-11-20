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
 *  1. the decision: the panel's two settings (or ours already) are applied, ours with the file current is nothing,
 *     anything written by hand is left alone;
 *  2. the table: a mailbox owns its address even when it does not receive, an alias belongs to its destination, both
 *     lookups use the key; the restrictions are the installer's with reject_authenticated_sender_login_mismatch first;
 *  3. the map file takes the aliases map's connection and only changes the query;
 *  4. the installer writes the map and the two settings, MailDbUsers keeps the file with Postfix's MySQL user and runs
 *     its query, and the panel's start runs the repair after MailDbUsers and MailboxAddressMap;
 *  5. with -De2e.vm=yes, as root on the VM: postmap answers a mailbox with itself, and with XCLIENT LOGIN on port 587
 *     (allowed from 127.0.0.1 only for the test, then removed) a client signed in as a mailbox gets its own address accepted, another
 *     address of the same domain and an outside address refused with 553; without a login, mail from outside naming
 *     the same address is still accepted (port 25 does not change). Nothing is delivered: RSET after RCPT.
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
        String wanted = org.daemoxcp.mail.scripts.PostfixMaps.SENDER_RESTRICTIONS;

        System.out.println("== 1. The decision");
        check("Postfix not installed: nothing", SenderLoginMap.decide(false, dir, true, true, "", panel).action() == SenderLoginMap.Action.NOTHING);
        check("not the panel's Postfix (no aliases map): nothing", SenderLoginMap.decide(true, dir, false, true, "", panel).action() == SenderLoginMap.Action.NOTHING);
        check("the installer's settings of before: apply", SenderLoginMap.decide(true, dir, true, false, "", panel).action() == SenderLoginMap.Action.APPLY);
        check("already in place, file current: nothing", SenderLoginMap.decide(true, dir, true, true, own, wanted).action() == SenderLoginMap.Action.NOTHING);
        check("in place but the file says something else: apply again", SenderLoginMap.decide(true, dir, true, false, own, wanted).action() == SenderLoginMap.Action.APPLY);
        check("written one line per item, as main.cf has it: the same", SenderLoginMap.decide(true, dir, true, true, own,
                wanted.replace(", ", ",\n    ")).action() == SenderLoginMap.Action.NOTHING);
        check("a login map of someone else's: left alone", SenderLoginMap.decide(true, dir, true, false, "hash:/etc/x", panel).action() == SenderLoginMap.Action.LEFT_ALONE);
        check("restrictions written by hand: left alone", SenderLoginMap.decide(true, dir, true, false, "", "permit_mynetworks, reject").action() == SenderLoginMap.Action.LEFT_ALONE);

        System.out.println("\n== 2. The table and the restrictions");
        String q = SenderLoginMap.QUERY;
        check("a mailbox owns its address, also when it does not receive", q.contains("SELECT email FROM mailboxes WHERE email='%s' AND active=1")
                && !q.contains("receive_enabled"));
        check("an alias belongs to its destination", q.contains("SELECT destination FROM aliases WHERE source='%s' AND active=1"));
        check("both lookups use the key", q.split("%s", -1).length == 3);
        check("the check first, then the installer's restrictions", SenderLoginMap.WANTED_SENDER.get(0).equals("reject_authenticated_sender_login_mismatch")
                && SenderLoginMap.WANTED_SENDER.subList(1, SenderLoginMap.WANTED_SENDER.size()).equals(SenderLoginMap.PANEL_SENDER));
        check("only for clients that sign in (port 25 does not change)", !wanted.contains("reject_sender_login_mismatch"));

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
        check("main.cf: the check first in smtpd_sender_restrictions", installer.contains("\nsmtpd_sender_restrictions =\n    reject_authenticated_sender_login_mismatch,\n    permit_mynetworks,\n"));
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
        check("and the check first", MailboxAddressMap.tables(sh("postconf -h smtpd_sender_restrictions")).equals(SenderLoginMap.WANTED_SENDER));
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
            check("signed in as " + user + ", from its own address: accepted", rcpt(user, user, user).startsWith("250"));
            String r1 = rcpt(user, other, user);
            check("  from another address of " + domain + ": refused (" + r1 + ")", r1.startsWith("553") && r1.contains("not owned by user"));
            String r2 = rcpt(user, "someone@example.org", user);
            check("  from an outside address: refused (" + r2 + ")", r2.startsWith("553") && r2.contains("not owned by user"));
            String r3 = rcpt(null, other, user);
            check("not signed in (mail from outside on port 25), the same sender: not refused for it (" + r3 + ")", !r3.contains("not owned"));
        } finally {
            sh("postconf -X smtpd_authorized_xclient_hosts && postfix reload");
            check("XCLIENT taken away again", sh("postconf -n").lines().noneMatch(l -> l.startsWith("smtpd_authorized_xclient_hosts")));
        }
    }

    /**
     * MAIL FROM and RCPT TO: the answer to RCPT. Signed in (login not null): on port 587 after STARTTLS, with XCLIENT
     * LOGIN, where SASL is on (on port 25 it is off, and Postfix does not take XCLIENT LOGIN as signed in: measured);
     * not signed in: on port 25, as the other mail servers.
     */
    static String rcpt(String login, String from, String to) {
        String xclient = login == null ? "" : "printf 'XCLIENT LOGIN=" + login + "\\r\\n'; sleep 1; printf 'EHLO e2e.test\\r\\n'; sleep 1; ";
        String client = login == null ? "timeout -f 30 nc 127.0.0.1 25"
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

    static String sh(String command) {
        return Shell.run(Duration.ofSeconds(60), "sh", "-c", command).output();
    }
}
