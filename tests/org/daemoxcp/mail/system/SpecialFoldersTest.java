package org.daemoxcp.mail.system;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import org.daemoxcp.mail.util.Shell;

/**
 * The special folders and spam in Junk (SpecialFolders). Measured on the VM on 20/11/2026: mail that Rspamd marked
 * («X-Spam: Yes», action add header) stayed in INBOX, and with the vacation reply on, a spam message delivered over
 * LMTP got its reply («vacation action: sent vacation response»): backscatter towards a forged sender. Dovecot had no
 * namespace, so no special-use folders (RFC 6154) for the mail programs.
 *  1. the conf.d file: the INBOX namespace with Drafts, Sent, Trash and Junk, each with its special_use and auto =
 *     subscribe; on 2.4 the spam script as a «before» script with precedence 1 (before the panel's rules, which keep the
 *     default); on 2.3 sieve_before for the spam script and sieve_before2 for the panel's rules, the same path as
 *     DovecotConfig.SIEVE23;
 *  2. the Sieve script: «X-Spam: Yes» into Junk, then stop;
 *  3. the pure helpers: a namespace written by someone else, the panel's Sieve, \Junk in a LIST answer;
 *  4. the installer writes the same two files for 2.4 and 2.3 (the folder first), and the panel's start runs the repair;
 *  5. with -De2e.vm=yes on the VM: Dovecot reads the script, a mailbox sees the four special folders, the script is
 *     precompiled, and over LMTP with a vacation rule of the panel's: spam goes to Junk with no reply, ordinary mail to
 *     INBOX with its reply. The test mail, the reply and the rule are removed afterwards.
 *   java [-De2e.vm=yes] -cp "tests:target/daemoxcp-mail.jar" org.daemoxcp.mail.system.SpecialFoldersTest
 */
public class SpecialFoldersTest {

    static int failed = 0;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "  OK     " : "  FAILED ") + what);
        if (!ok) failed++;
    }

    public static void main(String[] a) throws Exception {
        String f24 = SpecialFolders.fileContent(true), f23 = SpecialFolders.fileContent(false);

        System.out.println("== 1. The conf.d file");
        for (String[] f : new String[][] {{"2.4", f24}, {"2.3", f23}}) {
            String c = f[1];
            check(f[0] + ": the INBOX namespace", c.contains("namespace inbox {\n  inbox = yes\n"));
            for (String[] m : SpecialFolders.FOLDERS)
                check(f[0] + ":   " + m[0] + " as " + m[1] + ", created and subscribed",
                        c.contains("  mailbox " + m[0] + " {\n    special_use = " + m[1] + "\n    auto = subscribe\n  }\n"));
            check(f[0] + ": no separator or prefix of its own (folder names stay as they are)",
                    !c.contains("separator") && !c.contains("prefix"));
        }
        check("2.4: the spam script before, with precedence 1",
                f24.contains("sieve_script spam_to_junk {\n  type = before\n  driver = file\n  path = " + SpecialFolders.SCRIPT + "\n")
                && f24.contains("  precedence = 1\n") && !f24.contains("plugin {"));
        check("2.3: sieve_before the spam script, sieve_before2 the panel's rules",
                f23.contains("  sieve_before = " + SpecialFolders.SCRIPT + "\n")
                && f23.contains("  sieve_before2 = " + SpecialFolders.PANEL_RULES_23 + "\n") && !f23.contains("sieve_script"));
        check("2.3: the panel's rules are the same path as DovecotConfig.SIEVE23",
                org.daemoxcp.mail.scripts.DovecotConfig.SIEVE23.contains("sieve_before = " + SpecialFolders.PANEL_RULES_23 + "\n"));
        check("the script lives under Dovecot's folder", SpecialFolders.SCRIPT.toString().equals("/usr/local/etc/dovecot/sieve/spam-to-junk.sieve"));

        System.out.println("\n== 2. The Sieve script");
        String script = SpecialFolders.scriptContent();
        check("require fileinto and mailbox", script.contains("require [\"fileinto\", \"mailbox\"];\n"));
        check("X-Spam: Yes into Junk, then stop", script.contains("if header :is \"X-Spam\" \"Yes\" {\n  fileinto :create \"Junk\";\n  stop;\n}\n"));
        check("nothing else acts on the message", script.split("fileinto :").length == 2 && !script.contains("keep")
                && !script.contains("discard") && !script.contains("redirect"));

        System.out.println("\n== 3. The pure helpers");
        check("a namespace of someone else's is seen", SpecialFolders.otherNamespace("protocols = imap\nnamespace inbox {\n  inbox = yes\n}\n", false));
        check("  but not when the file is ours", !SpecialFolders.otherNamespace("namespace inbox {\n}\n", true));
        check("  and no namespace is no namespace", !SpecialFolders.otherNamespace("protocols = imap\nsieve_script panel {\n}\n", false));
        check("the panel's Sieve on 2.4", SpecialFolders.panelSieve("x\nsieve_script panel {\n  type = before\n}\n", true)
                && !SpecialFolders.panelSieve("protocols = imap\n", true));
        check("the panel's Sieve on 2.3", SpecialFolders.panelSieve("plugin {\n  sieve_before = /var/mail/sieve/%d/%n/.dovecot.sieve\n}\n", false));
        check("LIST with \\Junk", SpecialFolders.junkMarked("* LIST (\\Junk) \".\" Junk\r\na OK List completed\r\n")
                && SpecialFolders.junkMarked("* LIST (\\HasNoChildren \\Junk) \".\" \"Junk\"\r\na OK\r\n"));
        check("  a Junk without the flag does not count", !SpecialFolders.junkMarked("* LIST () \".\" Junk\r\na OK\r\n")
                && !SpecialFolders.junkMarked(null) && !SpecialFolders.junkMarked("* LIST (\\Junk) \".\" Spam\r\n"));

        System.out.println("\n== 4. Where it is written");
        boolean conf24 = false, script24 = false;
        for (var f : org.daemoxcp.mail.scripts.DovecotConfig.file24()) {
            if (f.path().equals("conf.d/" + SpecialFolders.FILE_NAME)) conf24 = f.content().equals(f24) && !f.expand();
            if (f.path().equals(SpecialFolders.SCRIPT_IN_ETC)) script24 = f.content().equals(script) && !f.expand();
        }
        check("2.4: the installer writes the same conf.d file and the same script", conf24 && script24);
        var ctor = org.daemoxcp.mail.scripts.DovecotConfig.class.getDeclaredConstructor(String.class, String.class);
        ctor.setAccessible(true);
        String fragment = ctor.newInstance("daemoxcp_mail", "daemoxcp_mail").scriptFragment();
        int dir24 = fragment.indexOf("mkdir -p \"$DOVECOT_ETC/sieve\""), cat24 = fragment.indexOf("cat > \"$DOVECOT_ETC/" + SpecialFolders.SCRIPT_IN_ETC + "\"");
        check("2.4: the sieve folder is made before the script is written", dir24 > 0 && cat24 > dir24);
        int else23 = fragment.indexOf("Writing the configuration in Dovecot 2.3 format");
        check("2.3: the same two files", else23 > 0
                && fragment.indexOf(f23.stripTrailing() + "\nDOVECOT_SPECIAL_FOLDERS\n", else23) > else23
                && fragment.indexOf(script.stripTrailing() + "\nDOVECOT_SPAM_TO_JUNK\n", else23) > else23
                && fragment.indexOf("mkdir -p \"$DOVECOT_ETC/sieve\"", else23) > else23);
        String server = Files.readString(Path.of("src/main/java/org/daemoxcp/mail/webserver/SSLMailServer.java"));
        int binaries = server.indexOf("org.daemoxcp.mail.system.SieveBinaries.ensureAtBoot();");
        int repair = server.indexOf("org.daemoxcp.mail.system.SpecialFolders.ensureAtBoot();");
        check("the panel's start runs the repair, after the panel's Sieve rules", binaries > 0 && repair > binaries);

        if (!"yes".equals(System.getProperty("e2e.vm"))) {
            System.out.println("\n  (part 5 skipped: it delivers mail on the TEST VM, turned on with -De2e.vm=yes)");
        } else {
            live();
        }

        System.out.println(failed == 0 ? "\nALL OK" : "\n" + failed + " CHECKS FAILED");
        System.exit(failed == 0 ? 0 : 1);
    }

    // ===================== 5. On the VM =====================

    static final Path LMTP = Path.of("/var/run/dovecot/lmtp");

    static void live() throws Exception {
        System.out.println("\n== 5. Live, on the VM");
        String conf = sh("doveconf -n");
        check("Dovecot reads the spam script", conf.contains("sieve_script spam_to_junk {") || conf.contains("sieve_before = " + SpecialFolders.SCRIPT));
        Path binary = SieveCompiler.binaryFor(SpecialFolders.SCRIPT);
        check("the script is precompiled, newer than the script", Files.isRegularFile(binary)
                && Files.getLastModifiedTime(binary).compareTo(Files.getLastModifiedTime(SpecialFolders.SCRIPT)) > 0);

        String[] users = sh("doveadm user '*'").trim().split("\\s+");
        String user = null, other = null;
        for (String u : users) {
            if (!u.contains("@")) continue;
            Path rules = panelRules(u);
            if (user == null && !Files.exists(rules)) user = u;
            else if (other == null && !u.equals(user)) other = u;
        }
        if (user == null) { check("a mailbox without panel rules to try on", false); return; }
        String list = sh("printf 'a LIST \"\" \"*\" RETURN (SPECIAL-USE)\\r\\nb LOGOUT\\r\\n' | timeout -f 20 doveadm exec imap -u " + user);
        for (String[] m : SpecialFolders.FOLDERS)
            check("IMAP shows " + m[0] + " as " + m[1], list.matches("(?s).*\\* LIST \\([^)]*\\" + m[1] + "[^)]*\\) \"\\.\" \"?" + m[0] + "\"?\\r?\n.*"));

        Path rules = panelRules(user);
        Path domainDir = rules.getParent().getParent();
        boolean madeDomain = !Files.exists(domainDir), madeUser = !Files.exists(rules.getParent());
        Files.createDirectories(rules.getParent());
        String stamp = String.valueOf(System.currentTimeMillis());
        // A new :handle each run: the vacation reply remembers for a day whom it has already answered.
        Files.writeString(rules, "require [\"vacation\"];\nvacation :days 1 :handle \"" + stamp
                + "\" :subject \"SpecialFoldersTest\" \"Away.\";\n");
        // Compiled like the panel's real rules: without it, Dovecot compiles it at each delivery and writes errors in the maillog.
        check("the test's vacation rule compiles", SieveCompiler.compile(rules).status() == SieveCompiler.Status.COMPILED);
        String sender = other != null ? other : "e2e-sender@" + user.substring(user.indexOf('@') + 1);
        String spamId = "special-folders-spam-" + stamp + "@e2e.test", hamId = "special-folders-ham-" + stamp + "@e2e.test";
        try {
            int inbox0 = count(user, "INBOX"), junk0 = count(user, "Junk");
            check("the folders can be counted (INBOX " + inbox0 + ", Junk " + junk0 + ")", inbox0 >= 0 && junk0 >= 0);
            check("spam accepted over LMTP", deliver(user, sender, spamId, true));
            Thread.sleep(1500);
            String spam = maillog(spamId);
            check("  Dovecot stored it in Junk", spam.contains("stored mail into mailbox 'Junk'") && !spam.contains("mailbox 'INBOX'"));
            check("  one more in Junk", count(user, "Junk") == junk0 + 1);
            check("  none more in INBOX", count(user, "INBOX") == inbox0);
            check("  and the vacation rule did not answer it", !spam.contains("vacation action"));
            check("ordinary mail accepted over LMTP", deliver(user, sender, hamId, false));
            Thread.sleep(1500);
            String ham = maillog(hamId);
            check("  Dovecot stored it in INBOX", ham.contains("mailbox 'INBOX'") && !ham.contains("mailbox 'Junk'"));
            check("  one more in INBOX, none more in Junk", count(user, "INBOX") == inbox0 + 1 && count(user, "Junk") == junk0 + 1);
            check("  and the panel's rule ran on it (vacation answered)", ham.contains("vacation action: sent vacation response"));
        } finally {
            Files.deleteIfExists(rules);
            Files.deleteIfExists(SieveCompiler.binaryFor(rules));
            if (madeUser) Files.deleteIfExists(rules.getParent());
            if (madeDomain) Files.deleteIfExists(domainDir);
            for (String box : new String[] {"INBOX", "Junk"})
                for (String id : new String[] {spamId, hamId})
                    sh("doveadm expunge -u " + user + " mailbox " + box + " header Message-ID '<" + id + ">'");
            // The automatic reply: delivered to "other" (if there is one) or left in the queue; gone in both cases.
            if (other != null) sh("doveadm expunge -u " + other + " mailbox INBOX header Subject SpecialFoldersTest");
            sh("mailq | awk '/^[0-9A-F]+[*!]?[ ]/ {id=$1} /" + sender.replace(".", "\\.") + "/ {sub(/[*!]$/, \"\", id); print id}' | xargs -n1 postsuper -d 2>/dev/null");
        }
    }

    static Path panelRules(String user) {
        int at = user.indexOf('@');
        return Path.of("/var/mail/sieve", user.substring(at + 1), user.substring(0, at), ".dovecot.sieve");
    }

    /** The messages in a folder («Junk messages=3», as doveadm prints it); -1 if doveadm does not say. */
    static int count(String user, String box) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("(?m)\\bmessages=(\\d+)\\s*$")
                .matcher(sh("doveadm mailbox status -u " + user + " messages " + box));
        return m.find() ? Integer.parseInt(m.group(1)) : -1;
    }

    static String maillog(String id) {
        return sh("grep -F '" + id + "' /var/log/maillog");
    }

    /** One message over LMTP to Dovecot's own socket, waiting for each answer; true if Dovecot saved it. */
    static boolean deliver(String to, String from, String id, boolean spam) throws Exception {
        try (SocketChannel ch = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            ch.connect(UnixDomainSocketAddress.of(LMTP));
            BufferedReader in = new BufferedReader(new InputStreamReader(Channels.newInputStream(ch), StandardCharsets.US_ASCII));
            OutputStream out = Channels.newOutputStream(ch);
            if (!last(in).startsWith("220")) return false;
            String[] steps = {"LHLO e2e.test", "MAIL FROM:<" + from + ">", "RCPT TO:<" + to + ">", "DATA"};
            for (String step : steps) {
                out.write((step + "\r\n").getBytes(StandardCharsets.US_ASCII));
                out.flush();
                String reply = last(in);
                if (!(reply.startsWith("250") || reply.startsWith("354"))) return false;
            }
            String body = "From: <" + from + ">\r\nTo: <" + to + ">\r\nSubject: special folders " + (spam ? "spam" : "ham") + "\r\n"
                    + "Message-ID: <" + id + ">\r\n" + (spam ? SpecialFolders.SPAM_HEADER + ": Yes\r\n" : "") + "\r\nHello.\r\n.\r\n";
            out.write(body.getBytes(StandardCharsets.US_ASCII));
            out.flush();
            boolean saved = last(in).startsWith("250");
            out.write("QUIT\r\n".getBytes(StandardCharsets.US_ASCII));
            out.flush();
            return saved;
        }
    }

    static String last(BufferedReader in) throws Exception {
        String line;
        while ((line = in.readLine()) != null) if (line.length() < 4 || line.charAt(3) != '-') return line;
        return "";
    }

    static String sh(String command) {
        return Shell.run(Duration.ofSeconds(60), "sh", "-c", command).output();
    }
}
