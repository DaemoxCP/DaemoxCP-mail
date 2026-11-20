package org.daemoxcp.mail.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import org.daemoxcp.mail.util.Shell;

/**
 * A client that signs in writes in the From header only its own sender address (HeaderFromCheck). Measured on the VM on
 * 20/11/2026: with SenderLoginMap the envelope was checked, but a mailbox signed in on port 587 with its own envelope
 * and «From: boss@» of the same domain went through, signed with the domain's DKIM key.
 *  1. the decision: only on the panel's Rspamd (the milter proxy); missing or an older panel file: apply; the current
 *     file: nothing; a file of the same name written by hand: left alone;
 *  2. the rule: it looks only at clients that sign in (task:get_user), runs before any other check (prefilter) and
 *     rejects with set_pre_result; the From must be one address in one header, the envelope or the mailbox;
 *  3. the installer writes the same file at the same path, and the panel's start runs the repair after RspamdController;
 *     the verdict on the two probe scans;
 *  4. with -De2e.vm=yes, as root on the VM: the file in place; rspamc as a signed-in user (own From, capitals, alias as
 *     envelope, empty envelope with the mailbox: pass; another address, an outside address, empty envelope with another
 *     address, two From headers: reject; not signed in: not looked at); through Postfix on port 587 with XCLIENT LOGIN
 *     (allowed from 127.0.0.1 only for the test, then removed) the own From is queued and another address of the domain
 *     gets 554 with the panel's text; on port 25, not signed in, the same From is not refused for it. The messages that
 *     get through are delivered to the test mailbox itself and expunged at the end.
 *   java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.HeaderFromCheckTest
 */
public class HeaderFromCheckTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] a) throws Exception {
        String proxy = "bind_socket = \"127.0.0.1:11332\";\nmilter = yes;\ntimeout = 120s;\n";
        String rule = HeaderFromCheck.content();

        System.out.println("== 1. The decision");
        check("Rspamd not installed: nothing", HeaderFromCheck.decide(false, proxy, null) == HeaderFromCheck.Action.NOTHING);
        check("no milter proxy of the panel: nothing", HeaderFromCheck.decide(true, null, null) == HeaderFromCheck.Action.NOTHING);
        check("a proxy that is not a milter: nothing", HeaderFromCheck.decide(true, "bind_socket = \"127.0.0.1:11332\";\n", null) == HeaderFromCheck.Action.NOTHING);
        check("the file is missing: apply", HeaderFromCheck.decide(true, proxy, null) == HeaderFromCheck.Action.APPLY);
        check("the current file: nothing", HeaderFromCheck.decide(true, proxy, rule) == HeaderFromCheck.Action.NOTHING);
        check("an older file of the panel: apply", HeaderFromCheck.decide(true, proxy, "-- " + PanelMarker.WRITTEN + ", old\n") == HeaderFromCheck.Action.APPLY);
        check("a file of the same name written by hand: left alone", HeaderFromCheck.decide(true, proxy, "-- mine\n") == HeaderFromCheck.Action.LEFT_ALONE);
        check("something that is not a file (empty text): left alone", HeaderFromCheck.decide(true, proxy, "") == HeaderFromCheck.Action.LEFT_ALONE);

        System.out.println("\n== 2. The rule");
        check("only clients that sign in", rule.contains("local user = task:get_user()\n  if not user or user == '' then return false end"));
        check("before any other check, rejecting", rule.contains("type = 'prefilter'") && rule.contains("task:set_pre_result{action = 'reject'"));
        check("the panel's text in the reply", rule.contains("message = '" + HeaderFromCheck.REPLY + "'"));
        check("one From header", rule.contains("if #headers ~= 1 then"));
        check("one address in it", rule.contains("from and #from == 1 and from[1].addr and from[1].addr ~= ''"));
        check("the envelope or the mailbox, without regard to case",
                rule.contains("if addr ~= user and (envelope == '' or addr ~= envelope) then") && rule.contains("user = user:lower()")
                && rule.contains("local addr = from[1].addr:lower()"));
        check("written by the panel, a symbol with no score", rule.startsWith("-- " + PanelMarker.WRITTEN) && rule.contains("score = 0.0"));
        check("loaded by Rspamd from lua.local.d", HeaderFromCheck.PATH.equals("/usr/local/etc/rspamd/lua.local.d/daemoxcp-header-from.lua"));

        System.out.println("\n== 3. Where it is written, and the verdict");
        String installer = new org.daemoxcp.mail.scripts.FullMailServerScript().getScriptContent();
        check("the installer writes the same file", installer.contains("cat > " + HeaderFromCheck.PATH + " << 'RSPAMD_HEADER_FROM'\n"
                + rule + "RSPAMD_HEADER_FROM\n"));
        check("  after creating the folder", installer.indexOf("mkdir -p /usr/local/etc/rspamd/lua.local.d\n")
                < installer.indexOf("cat > " + HeaderFromCheck.PATH));
        String server = Files.readString(Path.of("src/main/java/org/daemoxcp/mail/webserver/SSLMailServer.java"));
        int controller = server.indexOf("RspamdController.ensureAtBoot();"), from = server.indexOf("HeaderFromCheck.ensureAtBoot();");
        check("the panel's start runs the repair after RspamdController", controller > 0 && from > controller);
        String sym = HeaderFromCheck.SYMBOL;
        check("verdict: own passes, other rejected: fine", HeaderFromCheck.judge("Action: no action\n", "Action: reject\n" + sym) == null);
        check("verdict: no answer", HeaderFromCheck.judge(null, "Action: reject\n" + sym) != null);
        check("verdict: own refused", HeaderFromCheck.judge("Action: reject\n" + sym, "Action: reject\n" + sym) != null);
        check("verdict: other not refused", HeaderFromCheck.judge("Action: no action\n", "Action: add header\n") != null);
        check("verdict: the symbol without the reject", HeaderFromCheck.judge("Action: no action\n", "Action: no action\n" + sym) != null);

        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("\n  (part 4 skipped: it talks to Rspamd and Postfix on the TEST VM, turned on with -De2e.vm=yes)");
        } else {
            live();
        }

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }

    // ===================== 4. On the VM =====================

    static final String SUBJECT = "header-from-e2e-" + System.nanoTime();

    static void live() throws Exception {
        System.out.println("\n== 4. Live, on the VM");
        Path file = Path.of(HeaderFromCheck.PATH);
        check("the file is the panel's", Files.isRegularFile(file) && HeaderFromCheck.content().equals(Files.readString(file)));
        String user = null;
        for (String u : sh("doveadm user '*'").trim().split("\\s+")) if (u.contains("@")) { user = u; break; }
        if (user == null) { check("a mailbox to try with", false); return; }
        String domain = user.substring(user.indexOf('@') + 1), other = "boss-" + System.nanoTime() + "@" + domain;

        System.out.println("  -- rspamc, as a signed-in user");
        check("own From: passes", !scan(user, user, "<" + user + ">").contains(HeaderFromCheck.SYMBOL));
        check("own From in capitals: passes", !scan(user, user, "<" + user.toUpperCase() + ">").contains(HeaderFromCheck.SYMBOL));
        check("an alias as envelope and From: passes", !scan(user, "alias@" + domain, "Alias <alias@" + domain + ">").contains(HeaderFromCheck.SYMBOL));
        check("empty envelope, the mailbox in From: passes", !scan(user, "<>", "<" + user + ">").contains(HeaderFromCheck.SYMBOL));
        check("another address of the domain: rejected", rejected(scan(user, user, "Boss <" + other + ">")));
        check("an outside address: rejected", rejected(scan(user, user, "<someone@example.org>")));
        check("empty envelope, another address in From: rejected", rejected(scan(user, "<>", "<" + other + ">")));
        check("two From headers: rejected", rejected(scan(user, user, "<" + user + ">\r\nFrom: <" + other + ">")));
        check("two addresses in one From: rejected", rejected(scan(user, user, "<" + user + ">, <" + other + ">")));
        check("not signed in, From not the envelope: not looked at", !scan(null, "list@example.org", "<" + other + ">").contains(HeaderFromCheck.SYMBOL));

        System.out.println("  -- through Postfix");
        String before = sh("postconf -h smtpd_authorized_xclient_hosts").trim();
        if (!before.isEmpty()) { check("smtpd_authorized_xclient_hosts empty before the test (it is '" + before + "')", false); return; }
        sh("postconf -e smtpd_authorized_xclient_hosts=127.0.0.1 && postfix reload");
        try {
            Thread.sleep(1500);
            String own = smtp(user, user, "<" + user + ">", user);
            check("587 signed in, own From: queued (" + own + ")", own.startsWith("250 2.0.0"));
            String refused = smtp(user, user, "Boss <" + other + ">", user);
            check("587 signed in, another address in From: 554 with the panel's text (" + refused + ")",
                    refused.startsWith("554 5.7.1") && refused.contains(HeaderFromCheck.REPLY));
            String outside = smtp(null, "list@example.org", "Boss <" + other + ">", user);
            check("25 not signed in, the same From: not refused for it (" + outside + ")", !outside.contains(HeaderFromCheck.REPLY));
        } finally {
            sh("postconf -X smtpd_authorized_xclient_hosts && postfix reload");
            check("XCLIENT taken away again", sh("postconf -n").lines().noneMatch(l -> l.startsWith("smtpd_authorized_xclient_hosts")));
            Thread.sleep(4000);
            sh("doveadm expunge -u " + user + " mailbox '*' header Subject " + SUBJECT);
            check("the test messages expunged", sh("doveadm search -u " + user + " mailbox '*' header Subject " + SUBJECT).isBlank());
        }
    }

    static boolean rejected(String out) {
        return out.contains(HeaderFromCheck.SYMBOL) && out.contains("Action: reject");
    }

    /** rspamc on the normal worker: user null for mail that does not sign in. */
    static String scan(String user, String envelope, String headerFrom) {
        String msg = "From: " + headerFrom + "\r\nTo: <bob@example.org>\r\nSubject: " + SUBJECT + "\r\nMessage-ID: <"
                + System.nanoTime() + "@e2e.test>\r\n\r\nhello\r\n";
        java.util.List<String> cmd = new java.util.ArrayList<>(java.util.List.of(RspamdUser.RSPAMC, "-h", "127.0.0.1:11333"));
        if (user != null) cmd.addAll(java.util.List.of("--user", user, "--ip", "127.0.0.1"));
        else cmd.addAll(java.util.List.of("--ip", "192.0.2.10"));
        cmd.addAll(java.util.List.of("--from", envelope, "--rcpt", "bob@example.org", "symbols"));
        return Shell.runWithInput(Duration.ofSeconds(60), msg, cmd.toArray(new String[0])).output();
    }

    /**
     * A whole message through Postfix: signed in (login not null) on port 587 after STARTTLS with XCLIENT LOGIN, not
     * signed in on port 25. The last answer: the one to the end of DATA.
     */
    static String smtp(String login, String envelope, String headerFrom, String to) {
        String xclient = login == null ? "" : "printf 'XCLIENT LOGIN=" + login + "\\r\\n'; sleep 1; printf 'EHLO e2e.test\\r\\n'; sleep 1; ";
        String client = login == null ? "timeout -f 40 nc 127.0.0.1 25"
                : "timeout -f 40 openssl s_client -starttls smtp -crlf -quiet -connect 127.0.0.1:587 2>/dev/null";
        String out = sh("{ sleep 2; printf 'EHLO e2e.test\\r\\n'; sleep 1; " + xclient
                + "printf 'MAIL FROM:<" + envelope + ">\\r\\n'; sleep 1; printf 'RCPT TO:<" + to + ">\\r\\n'; sleep 1; "
                + "printf 'DATA\\r\\n'; sleep 1; printf 'From: " + headerFrom + "\\r\\nTo: <" + to + ">\\r\\nSubject: " + SUBJECT
                + "\\r\\nMessage-ID: <" + System.nanoTime() + "@e2e.test>\\r\\n\\r\\nhello\\r\\n.\\r\\n'; sleep 5; "
                + "printf 'QUIT\\r\\n'; sleep 1; } | " + client);
        String last = "";
        for (String line : out.split("\r?\n"))
            if (line.length() > 3 && Character.isDigit(line.charAt(0)) && line.charAt(3) == ' ' && !line.startsWith("221")) last = line.trim();
        return last;
    }

    static String sh(String command) {
        return Shell.run(Duration.ofSeconds(90), "sh", "-c", command).output();
    }
}
